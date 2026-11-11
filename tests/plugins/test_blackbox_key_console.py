"""The key console's root A (trust-and-threat-lab C1, §03.2).

``EncryptedRootStore`` keeps root A only encrypted at rest; ``RootSigner``
signs ONE prepared manifest per passphrase + fresh phone code through the
signing choke point, and no console object references the decrypted key
once ``sign()`` returns.
"""

from __future__ import annotations

import base64
import dataclasses
import gc
import json
import stat
import types
from pathlib import Path
from datetime import datetime, timezone, UTC
from typing import List

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from plugins.blackbox.curate.console.root_signer import (
    TOTP_STEP_SECONDS,
    RootSigner,
    RootSignerError,
    TotpSecondFactor,
    totp_code,
)
from plugins.blackbox.curate.console.root_store import EncryptedRootStore, RootStoreError
from plugins.blackbox.curate.watch import SigningLog
from plugins.blackbox.kernel import signing
from plugins.blackbox.kernel.signing.key_manifest import KEY_MANIFEST_STATEMENT
from test_blackbox_curate import FakeNode, _ctx, curators

PASSPHRASE = "correct horse battery staple"
NOW = 1_800_000_000.0


class _Clock:
    def __init__(self, at: float = NOW) -> None:
        self.at = at

    def __call__(self) -> float:
        return self.at


@pytest.fixture
def console(tmp_path, curators):
    """A created root, an enrolled phone factor on a fixed clock, and the signer."""
    clock = _Clock()
    store = EncryptedRootStore(tmp_path / "curate" / "root_a.enc.pem")
    root_hex = store.create(PASSPHRASE)
    factor = TotpSecondFactor(tmp_path / "curate" / "root_a.totp.json", clock=clock)
    uri = factor.enroll()
    secret = base64.b32decode(uri.split("secret=")[1].split("&")[0])
    log = SigningLog(tmp_path / "curate" / "signing_log.jsonl")
    ctx = dataclasses.replace(_ctx(FakeNode(), None), signing_log=log)
    signer = RootSigner(ctx, store, factor)

    def code(offset_steps: int = 0) -> str:
        return totp_code(secret, int(clock.at) // TOTP_STEP_SECONDS + offset_steps)

    return types.SimpleNamespace(store=store, factor=factor, signer=signer, log=log, ctx=ctx, clock=clock,
                                 code=code, root_hex=root_hex, manifest=curators["manifest"])


# -- the store -----------------------------------------------------------------


def test_the_root_file_is_never_written_unencrypted(console):
    raw = console.store.path.read_bytes()
    assert b"-----BEGIN ENCRYPTED PRIVATE KEY-----" in raw
    assert b"BEGIN PRIVATE KEY" not in raw
    assert stat.S_IMODE(console.store.path.stat().st_mode) == 0o600
    assert [p.name for p in console.store.path.parent.iterdir() if ".tmp." in p.name] == []
    assert signing.public_key_hex(console.store.open(PASSPHRASE)) == console.root_hex


def test_the_root_is_created_once_and_needs_a_long_passphrase(console, tmp_path):
    before = console.store.path.read_bytes()
    with pytest.raises(RootStoreError):
        console.store.create(PASSPHRASE)
    assert console.store.path.read_bytes() == before
    with pytest.raises(RootStoreError):
        EncryptedRootStore(tmp_path / "other.enc.pem").create("short")
    assert not (tmp_path / "other.enc.pem").exists()


def test_a_wrong_passphrase_or_an_unencrypted_file_opens_nothing(console, tmp_path):
    with pytest.raises(RootStoreError, match="wrong root passphrase"):
        console.store.open("not the passphrase at all")
    plain = tmp_path / "plain.pem"
    plain.write_bytes(Ed25519PrivateKey.generate().private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    with pytest.raises(RootStoreError, match="not encrypted"):
        EncryptedRootStore(plain).open(PASSPHRASE)
    with pytest.raises(RootStoreError):
        EncryptedRootStore(tmp_path / "missing.pem").open(PASSPHRASE)


# -- the second factor -----------------------------------------------------------


def test_totp_matches_the_rfc_6238_vector():
    # RFC 6238 Appendix B, SHA1, T=59 s → step 1 → 94287082 (the last six digits at 6 digits).
    assert totp_code(b"12345678901234567890", 59 // 30) == "287082"


def test_a_code_works_once_and_only_near_now(console):
    assert not console.factor.consume(console.code(+2))      # outside the drift window
    assert not console.factor.consume("12345")               # wrong shape
    assert not console.factor.consume("abcdef")
    code = console.code()
    assert console.factor.consume(code)
    assert not console.factor.consume(code)                  # replay
    assert not console.factor.consume(console.code(-1))      # older than the accepted step
    console.clock.at += TOTP_STEP_SECONDS
    assert console.factor.consume(console.code())            # the next step's code is fresh


def test_enrolment_is_once_and_an_unenrolled_factor_refuses(console, tmp_path):
    with pytest.raises(RootSignerError):
        console.factor.enroll()
    assert stat.S_IMODE(console.factor._path.stat().st_mode) == 0o600
    assert not TotpSecondFactor(tmp_path / "none.json").consume("123456")


# -- the signer ------------------------------------------------------------------


def test_one_signature_per_passphrase_and_fresh_code_and_it_is_logged(console):
    envelope = console.signer.sign(console.manifest, PASSPHRASE, console.code())

    assert envelope.statement_type == KEY_MANIFEST_STATEMENT
    assert signing.verified_signers(envelope, statement_type=KEY_MANIFEST_STATEMENT,
                                    environment=console.manifest.environment,
                                    graph=console.manifest.graph) == {console.root_hex}
    (row,) = console.log.rows()
    assert (row.kind, row.key, row.action, row.digest) == (KEY_MANIFEST_STATEMENT, console.root_hex, "sign",
                                                           signing.content_id(envelope))


def test_a_second_sign_without_a_fresh_factor_is_refused(console):
    code = console.code()
    console.signer.sign(console.manifest, PASSPHRASE, code)
    with pytest.raises(RootSignerError, match="second factor"):
        console.signer.sign(console.manifest, PASSPHRASE, code)
    assert len(console.log.rows()) == 1


@pytest.mark.parametrize("passphrase, use_valid_code", [("wrong passphrase entirely", True),
                                                         (PASSPHRASE, False)])
def test_a_wrong_passphrase_or_a_wrong_factor_signs_nothing(console, monkeypatch, passphrase, use_valid_code):
    opened: list[object] = []
    real_open = console.store.open
    monkeypatch.setattr(console.store, "open", lambda p: opened.append(p) or real_open(p))
    valid = console.code()
    code = valid if use_valid_code else str((int(valid) + 1) % 10 ** 6).zfill(6)
    with pytest.raises(RootSignerError):
        console.signer.sign(console.manifest, passphrase, code)
    assert console.log.rows() == []
    assert not console.log.path.exists()
    if not use_valid_code:
        assert opened == []                                  # the root is never decrypted on a bad factor
    else:
        assert not console.factor.consume(code)              # the failed attempt still spent the code


def _reaches_a_private_key(roots) -> list[str]:
    """Walk everything reachable from *roots* (skipping modules, classes and
    functions) and name any Ed25519PrivateKey found."""
    seen, found, frontier = set(), [], list(roots)
    while frontier:
        obj = frontier.pop()
        if id(obj) in seen or isinstance(obj, (types.ModuleType, type, types.FunctionType,
                                                types.BuiltinFunctionType)):
            continue
        seen.add(id(obj))
        if isinstance(obj, Ed25519PrivateKey):
            found.append(repr(obj))
            continue
        frontier.extend(gc.get_referents(obj))
    return found


def _console_objects(console) -> list:
    return [console.signer, console.store, console.factor, console.ctx, console.log]


@pytest.mark.parametrize("fails", [False, True])
def test_no_console_object_references_the_root_after_sign_returns(console, monkeypatch, fails):
    captured: list[Ed25519PrivateKey] = []
    real_open = console.store.open

    def spy_open(passphrase):
        key = real_open(passphrase)
        captured.append(key)
        return key

    monkeypatch.setattr(console.store, "open", spy_open)
    if fails:   # the choke point refuses after decryption: the error path must drop the key too
        monkeypatch.setattr(console.log, "record", lambda *a, **k: (_ for _ in ()).throw(ValueError("refused")))
        with pytest.raises(RootSignerError, match="not signed"):
            console.signer.sign(console.manifest, PASSPHRASE, console.code())
    else:
        console.signer.sign(console.manifest, PASSPHRASE, console.code())
    monkeypatch.undo()          # the spy itself is test scaffolding, not a console object
    gc.collect()

    (key,) = captured
    referrers = [r for r in gc.get_referrers(key) if r is not captured]
    console_ids = {id(obj) for obj in _console_objects(console)} | {id(vars(obj)) for obj in _console_objects(console)
                                                                   if hasattr(obj, "__dict__")}
    assert [r for r in referrers if id(r) in console_ids] == []
    assert _reaches_a_private_key(_console_objects(console)) == []


def test_the_totp_state_never_holds_the_root(console):
    console.signer.sign(console.manifest, PASSPHRASE, console.code())
    state = json.loads(Path(console.factor._path).read_text(encoding="utf-8"))
    assert set(state) == {"secret", "last_step"}
    assert b"PRIVATE KEY" not in Path(console.factor._path).read_bytes()


# -- review hardening (C1 verify) ------------------------------------------------


def test_two_factor_objects_on_one_state_file_accept_a_code_once(console):
    """A replayed code is refused across factor objects (or processes), not only
    within one: C2 may build a factor per request. The second object is started
    while the first is between reading and persisting the accepted step."""
    import threading

    other = TotpSecondFactor(console.factor._path, clock=console.clock)
    code = console.code()
    results: list[bool] = []
    real_write = console.factor._write

    def write_after_a_racing_consume(secret, step):
        racer = threading.Thread(target=lambda: results.append(other.consume(code)))
        racer.start()
        racer.join(timeout=0.5)        # with a shared lock the racer waits for us
        real_write(secret, step)
        write_after_a_racing_consume.racer = racer

    console.factor._write = write_after_a_racing_consume
    results.append(console.factor.consume(code))
    write_after_a_racing_consume.racer.join(timeout=5)
    assert sorted(results) == [False, True]


def test_an_unexpected_choke_point_failure_leaves_no_key_in_the_traceback(console, monkeypatch):
    """Only a message crosses out of sign(): an OSError writing the signing log
    must not travel up with frames whose locals still hold the decrypted root."""
    def broken_record(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(console.log, "record", broken_record)
    with pytest.raises(RootSignerError, match="not signed: OSError: disk full") as caught:
        console.signer.sign(console.manifest, PASSPHRASE, console.code())
    error = caught.value
    assert error.__cause__ is None and error.__context__ is None
    held = []
    tb = error.__traceback__
    while tb is not None:
        held += [name for name, value in tb.tb_frame.f_locals.items() if isinstance(value, Ed25519PrivateKey)]
        tb = tb.tb_next
    assert held == []
    assert console.log.rows() == []


# -- the console app: three server-side gates (C2, §03.1) ------------------------

from plugins.blackbox.curate.console.app import (
    SESSION_COOKIE,
    ConsoleSettings,
    create_console_app,
)
from plugins.blackbox.curate.console.session import (
    IDLE_SECONDS,
    LOCKOUT_SECONDS,
    MAX_FAILED_LOGINS,
    MAX_SESSIONS,
    ConsoleSessions,
    hash_login_passphrase,
)

LOGIN = "amos@example.com"
MAGIC_DNS = "curator-a.tail1234.ts.net"
CONSOLE_PASSPHRASE = "console login passphrase"
_CONSOLE_HASH = hash_login_passphrase(CONSOLE_PASSPHRASE)   # scrypt once per module, not per test
TAILSCALE = {"Tailscale-User-Login": LOGIN}
SAME_ORIGIN = {**TAILSCALE, "Origin": f"https://{MAGIC_DNS}"}


@pytest.fixture
def gated():
    """The console app on its MagicDNS host, with a fake monotonic clock."""
    from fastapi.testclient import TestClient

    clock = _Clock(at=1000.0)
    sessions = ConsoleSessions(_CONSOLE_HASH, clock=clock)
    app = create_console_app(ConsoleSettings(LOGIN, MAGIC_DNS, _CONSOLE_HASH), sessions=sessions)

    def client(base_url: str = f"https://{MAGIC_DNS}"):
        return TestClient(app, base_url=base_url)

    def log_in(http) -> str:
        """Sign *http* in; the authenticated session's CSRF token."""
        pending = http.get("/login", headers=TAILSCALE)
        assert pending.status_code == 200
        res = http.post("/login", json={"passphrase": CONSOLE_PASSPHRASE},
                        headers={**SAME_ORIGIN, "X-Blackbox-Token": pending.json()["csrf"]})
        assert res.status_code == 200
        return res.json()["csrf"]

    return types.SimpleNamespace(app=app, sessions=sessions, clock=clock, client=client, log_in=log_in)


def test_forged_tailscale_login_from_loopback_without_a_cookie_is_refused(gated):
    with gated.client("http://127.0.0.1:9720") as http:
        assert http.get("/api/session", headers=TAILSCALE).status_code in (401, 403)
        assert http.post("/logout", headers=TAILSCALE).status_code in (401, 403)
    # Even with a Host a local process can fake, no cookie means no way in.
    with gated.client() as http:
        assert http.get("/api/session", headers=TAILSCALE).status_code == 401
        assert http.post("/logout", headers=SAME_ORIGIN).status_code in (401, 403)


def test_wrong_or_missing_tailscale_login_is_refused_even_when_signed_in(gated):
    with gated.client() as http:
        gated.log_in(http)
        assert http.get("/api/session", headers=TAILSCALE).status_code == 200
        assert http.get("/api/session", headers={"Tailscale-User-Login": "mallory@example.com"}).status_code == 403
        assert http.get("/api/session", headers={"Tailscale-User-Login": LOGIN.upper()}).status_code == 403
        assert http.get("/api/session", headers={"Tailscale-User-Login": LOGIN + " "}).status_code == 403
        assert http.get("/api/session").status_code == 403
        assert http.get("/login", headers={"Tailscale-User-Login": "mallory@example.com"}).status_code == 403


def test_magic_dns_host_only_a_loopback_host_is_refused_even_with_a_valid_session(gated):
    """test_blackbox_browser_boundary's MagicDNS host case, on the real console app."""
    with gated.client() as http:
        gated.log_in(http)
        cookie = http.cookies.get(SESSION_COOKIE)
        assert http.get("/api/session", headers=TAILSCALE).status_code == 200
    for base in ("http://127.0.0.1:9720", "http://localhost:9720", "https://evil.example"):
        with gated.client(base) as http:
            http.cookies.set(SESSION_COOKIE, cookie)
            assert http.get("/api/session", headers=TAILSCALE).status_code == 403, base


def test_cross_site_post_is_refused(gated):
    with gated.client() as http:
        csrf = gated.log_in(http)
        res = http.post("/logout", headers={**TAILSCALE, "Origin": "https://evil.example", "X-Blackbox-Token": csrf})
        assert res.status_code == 403
        assert http.get("/api/session", headers=TAILSCALE).status_code == 200   # still signed in


def test_a_change_without_the_sessions_csrf_token_is_refused(gated):
    with gated.client() as http, gated.client() as other:
        csrf = gated.log_in(http)
        other_csrf = gated.log_in(other)
        assert http.post("/logout", headers=SAME_ORIGIN).status_code == 403
        assert http.post("/logout", headers={**SAME_ORIGIN, "X-Blackbox-Token": other_csrf}).status_code == 403
        assert http.get("/api/session", headers=TAILSCALE).status_code == 200
        assert http.post("/logout", headers={**SAME_ORIGIN, "X-Blackbox-Token": csrf}).status_code == 200
        assert http.get("/api/session", headers=TAILSCALE).status_code == 401


def test_the_login_post_needs_its_pending_sessions_token_and_the_right_passphrase(gated):
    with gated.client() as http:
        csrf = http.get("/login", headers=TAILSCALE).json()["csrf"]
        assert http.post("/login", json={"passphrase": CONSOLE_PASSPHRASE}, headers=SAME_ORIGIN).status_code == 403
        wrong = http.post("/login", json={"passphrase": "guess"}, headers={**SAME_ORIGIN, "X-Blackbox-Token": csrf})
        assert wrong.status_code == 401
        assert http.get("/api/session", headers=TAILSCALE).status_code == 401
        pending_cookie = http.cookies.get(SESSION_COOKIE)
        ok = http.post("/login", json={"passphrase": CONSOLE_PASSPHRASE},
                       headers={**SAME_ORIGIN, "X-Blackbox-Token": csrf})
        assert ok.status_code == 200
        assert http.cookies.get(SESSION_COOKIE) != pending_cookie      # a planted id is worthless after login
        assert not gated.sessions.is_authenticated(pending_cookie)
        assert "samesite=strict" in ok.headers["set-cookie"].lower()
        assert "httponly" in ok.headers["set-cookie"].lower() and "secure" in ok.headers["set-cookie"].lower()


def test_an_idle_session_expires_after_fifteen_minutes(gated):
    with gated.client() as http:
        gated.log_in(http)
        gated.clock.at += IDLE_SECONDS - 1
        assert http.get("/api/session", headers=TAILSCALE).status_code == 200   # activity restarts the clock
        gated.clock.at += IDLE_SECONDS - 1
        assert http.get("/api/session", headers=TAILSCALE).status_code == 200
        gated.clock.at += IDLE_SECONDS
        assert http.get("/api/session", headers=TAILSCALE).status_code == 401


def test_repeated_wrong_passphrases_lock_logins_out():
    clock = _Clock(at=1000.0)
    sessions = ConsoleSessions(_CONSOLE_HASH, clock=clock)
    pending, _csrf = sessions.begin()
    for _ in range(MAX_FAILED_LOGINS):
        assert sessions.login(pending, "guess") is None
    assert sessions.login(pending, CONSOLE_PASSPHRASE) is None        # locked, even with the right one
    clock.at += LOCKOUT_SECONDS
    assert sessions.is_authenticated(sessions.login(sessions.begin()[0], CONSOLE_PASSPHRASE))


def test_a_flood_of_login_forms_neither_grows_memory_nor_logs_the_operator_out():
    sessions = ConsoleSessions(_CONSOLE_HASH, clock=_Clock(at=1000.0))
    signed_in = sessions.login(sessions.begin()[0], CONSOLE_PASSPHRASE)
    for _ in range(MAX_SESSIONS * 3):
        sessions.begin()
    assert len(sessions._sessions) == MAX_SESSIONS
    assert sessions.is_authenticated(signed_in)


def test_an_authenticated_session_cannot_be_logged_in_again():
    sessions = ConsoleSessions(_CONSOLE_HASH, clock=_Clock(at=1000.0))
    signed_in = sessions.login(sessions.begin()[0], CONSOLE_PASSPHRASE)
    assert sessions.login(signed_in, CONSOLE_PASSPHRASE) is None
    assert sessions.login("unknown", CONSOLE_PASSPHRASE) is None


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "[::1]", "", f"{MAGIC_DNS}:443",
                                  "127.0.0.2", "LocalHost"])   # any loopback (kernel.local_http), not three spellings
def test_console_settings_refuse_a_loopback_or_ported_host(host):
    with pytest.raises(ValueError):
        ConsoleSettings(LOGIN, host, _CONSOLE_HASH)


def test_a_malformed_passphrase_hash_fails_at_start_up():
    with pytest.raises(ValueError):
        ConsoleSessions("plaintext-passphrase")
    assert CONSOLE_PASSPHRASE not in _CONSOLE_HASH


def test_the_console_uses_the_kernel_boundary_and_the_dashboard_never_imports_curate():
    import ast

    plugin = Path(__file__).resolve().parents[2] / "plugins" / "blackbox"
    app_tree = ast.parse((plugin / "curate" / "console" / "app.py").read_text(encoding="utf-8"))
    boundary_imports = [(n.level, n.module, [a.name for a in n.names]) for n in ast.walk(app_tree)
                        if isinstance(n, ast.ImportFrom) and "BrowserBoundary" in [a.name for a in n.names]]
    assert boundary_imports == [(3, "kernel.browser_boundary", ["BrowserBoundary"])]
    for path in (plugin / "dashboard").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom):
                assert "curate" not in (node.module or "").split("."), path
                assert "curate" not in [a.name for a in node.names], path


# -- the console routes: join, approve/decline, removal, renewal (C3, §03.2) ------

from plugins.blackbox.curate.console import ConsoleServices, add_console_routes
from plugins.blackbox.curate.console.roster import (
    ConsoleState,
    RosterError,
    SignedList,
    renewal_status,
)
from plugins.blackbox.curate.proposals.proposal import ProposalState, ProposalStore
from plugins.blackbox.kernel.signing import key_manifest as km
from plugins.blackbox.kernel.signing.trust_anchors import RootPins

PASSING_SELF_TEST = {"day": "2027-01-14", "threatsConfirmed": 10, "cleanRejected": 10, "unprovenLeft": 2}
ISSUED = "2027-01-01"   # NOW (1.8e9) is 2027-01-15 UTC


@pytest.fixture
def routed(console, monkeypatch, tmp_path):
    """The console app with the C3 routes over a fake node: one signed-in session,
    root A pinned (any epoch), an effective 3-curator list dated ISSUED."""
    from fastapi.testclient import TestClient

    from plugins.blackbox.curate.console.root_signer import RootSigner

    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "home"))
    (tmp_path / "home" / "curate").mkdir(parents=True)
    node = FakeNode()
    effective = [dataclasses.replace(console.manifest, issued_day=ISSUED)]
    sessions = ConsoleSessions(_CONSOLE_HASH, clock=_Clock(at=1000.0))
    app = create_console_app(ConsoleSettings(LOGIN, MAGIC_DNS, _CONSOLE_HASH), sessions=sessions)
    state = ConsoleState(tmp_path / "home" / "curate" / "console_state.json")
    add_console_routes(app, ConsoleServices(
        context=lambda: dataclasses.replace(_ctx(node, effective[0]), signing_log=console.log),
        signer=lambda ctx: RootSigner(ctx, console.store, console.factor), state=state,
        roots=lambda environment: RootPins.unbound({console.root_hex}), clock=console.clock))
    http = TestClient(app, base_url=f"https://{MAGIC_DNS}")
    pending = http.get("/login", headers=TAILSCALE).json()["csrf"]
    csrf = http.post("/login", json={"passphrase": CONSOLE_PASSPHRASE},
                     headers={**SAME_ORIGIN, "X-Blackbox-Token": pending}).json()["csrf"]
    headers = {**SAME_ORIGIN, "X-Blackbox-Token": csrf}

    def sign_body(**extra):
        return {"passphrase": PASSPHRASE, "secondFactor": console.code(), **extra}

    return types.SimpleNamespace(http=http, headers=headers, node=node, effective=effective, state=state,
                                 console=console, sign_body=sign_body, app=app)


def _new_key() -> str:
    return signing.public_key_hex(Ed25519PrivateKey.generate())


def _join(routed, key: str, operator: str = "operator-d", self_test=None):
    return routed.http.post("/api/join-requests", headers=routed.headers,
                            json={"curatorKey": key, "operator": operator, "selfTest": self_test or PASSING_SELF_TEST})


def _manifest_rows(routed):
    return [row for row in routed.console.log.rows() if row.kind == KEY_MANIFEST_STATEMENT]


def test_a_join_request_stores_key_operator_and_self_test(routed):
    key = _new_key()
    res = _join(routed, key)
    assert res.status_code == 201, res.text
    (stored,) = routed.http.get("/api/join-requests", headers=TAILSCALE).json()["joinRequests"]
    assert stored == {"curatorKey": key, "operator": "operator-d", "selfTest": PASSING_SELF_TEST,
                      "selfTestPassed": True, "receivedAt": NOW, "state": "pending"}
    # Kept on disk (owner-only), and a second request for a waiting key is refused.
    assert [j.curator_key for j in ConsoleState(routed.state._path).joins()] == [key]
    assert stat.S_IMODE(routed.state._path.stat().st_mode) == 0o600
    assert _join(routed, key).status_code == 400


@pytest.mark.parametrize("body", [
    {"curatorKey": "A" * 64, "operator": "x", "selfTest": PASSING_SELF_TEST},
    {"curatorKey": "a" * 64, "operator": " ", "selfTest": PASSING_SELF_TEST},
    {"curatorKey": "a" * 64, "operator": "x", "selfTest": {**PASSING_SELF_TEST, "threatsConfirmed": 11}},
    {"curatorKey": "a" * 64, "operator": "x", "selfTest": {**PASSING_SELF_TEST, "day": "yesterday"}},
    {"curatorKey": "a" * 64, "operator": "x"},
])
def test_an_invalid_join_request_is_refused(routed, body):
    res = routed.http.post("/api/join-requests", headers=routed.headers, json=body)
    assert res.status_code in (400, 422)
    assert routed.state.joins() == []


def test_the_routes_sit_behind_the_gates_and_changes_are_never_gets(routed):
    from fastapi.testclient import TestClient

    with TestClient(routed.app, base_url=f"https://{MAGIC_DNS}") as stranger:   # no session cookie
        assert stranger.get("/api/join-requests", headers=TAILSCALE).status_code == 401
        assert stranger.post("/api/manifest/renew", headers=SAME_ORIGIN, json={}).status_code in (401, 403)
    assert routed.http.post("/api/join-requests", headers=SAME_ORIGIN,       # signed in, no CSRF token
                            json={"curatorKey": "a" * 64}).status_code == 403
    gets = {route.path for route in routed.app.routes if getattr(route, "methods", set()) & {"GET"}}
    assert all(not path.endswith(("/approve", "/decline", "/remove", "/renew", "/publish")) for path in gets)


def test_approve_signs_a_k2_valid_list_logs_it_and_publishes_it(routed):
    key = _new_key()
    _join(routed, key)
    preview = routed.http.get(f"/api/join-requests/{key}/preview", headers=TAILSCALE).json()["diff"]
    assert preview["added"] == [{"curatorKey": key, "operator": "operator-d"}] and preview["version"] == [1, 2]
    assert _manifest_rows(routed) == []                                      # a preview signs nothing

    res = routed.http.post(f"/api/join-requests/{key}/approve", headers=routed.headers, json=routed.sign_body())
    assert res.status_code == 200, res.text
    staged = res.json()
    assert staged["diff"]["issuedDay"] == [ISSUED, "2027-01-15"] and staged["diff"]["narrowing"] is False
    proposal = ProposalStore().get(staged["proposalId"])
    assert proposal.state is ProposalState.APPROVED
    envelope = proposal.parsed()
    verdict = km.verify_manifest(envelope, environment=routed.effective[0].environment,
                                 graph=routed.effective[0].graph, roots=RootPins.unbound({routed.console.root_hex}))
    assert verdict is not None and not verdict.freeze_only
    assert key in verdict.manifest.curator_keys and verdict.manifest.version == 2
    assert km.parse_manifest(envelope.payload) == verdict.manifest            # K2's own parser accepts it
    (row,) = _manifest_rows(routed)
    assert (row.key, row.digest) == (routed.console.root_hex, signing.content_id(envelope))
    assert routed.state.join(key).state.value == "approved"

    wrong = routed.http.post(f"/api/manifests/{proposal.id}/publish", headers=routed.headers,
                             json={"confirmationCode": "00000000"}).json()
    assert wrong["published"] is False
    done = routed.http.post(f"/api/manifests/{proposal.id}/publish", headers=routed.headers,
                            json={"confirmationCode": staged["confirmationCode"]})
    assert done.status_code == 200 and done.json()["published"] is True, done.text
    assert len(routed.node.vm_published) == 1
    assert ProposalStore().get(proposal.id).state is ProposalState.PUBLISHED


def test_a_failed_self_test_cannot_be_approved_and_decline_works(routed):
    key = _new_key()
    _join(routed, key, self_test={**PASSING_SELF_TEST, "unprovenLeft": 1})
    assert routed.http.get("/api/join-requests", headers=TAILSCALE).json()["joinRequests"][0]["selfTestPassed"] is False
    res = routed.http.post(f"/api/join-requests/{key}/approve", headers=routed.headers, json=routed.sign_body())
    assert res.status_code == 400 and "self-test" in res.json()["error"]
    assert routed.http.post(f"/api/join-requests/{key}/decline", headers=routed.headers).json()["state"] == "declined"
    assert routed.http.post(f"/api/join-requests/{key}/approve", headers=routed.headers,
                            json=routed.sign_body()).status_code == 404
    assert _manifest_rows(routed) == []


@pytest.mark.parametrize("threshold", [1, 5])
def test_a_list_outside_the_threshold_table_is_refused_before_anything_is_signed(routed, threshold):
    key = _new_key()
    _join(routed, key)
    res = routed.http.post(f"/api/join-requests/{key}/approve", headers=routed.headers,
                           json=routed.sign_body(threshold=threshold))
    assert res.status_code == 400 and "threshold" in res.json()["error"]
    assert _manifest_rows(routed) == [] and routed.state.join(key).state.value == "pending"


def test_a_removal_that_would_leave_one_operator_is_refused(routed):
    two = dataclasses.replace(routed.effective[0], **km.roster(dict(list(zip(routed.effective[0].curator_keys,
                                                                             routed.effective[0].curator_operators))[:2])))
    routed.effective[0] = two
    res = routed.http.post(f"/api/curators/{two.curator_keys[0]}/remove", headers=routed.headers, json=routed.sign_body())
    assert res.status_code == 400 and "threshold" in res.json()["error"]
    assert _manifest_rows(routed) == []


def test_removal_is_an_immediate_narrowing_list_and_a_second_within_24_h_is_refused(routed):
    first, second = routed.effective[0].curator_keys[:2]
    res = routed.http.post(f"/api/curators/{first}/remove", headers=routed.headers, json=routed.sign_body())
    assert res.status_code == 200, res.text
    change = res.json()["diff"]
    assert change["narrowing"] is True and change["removed"][0]["curatorKey"] == first
    assert change["issuedDay"] == [ISSUED, ISSUED]          # no fresh validity without the waiting period
    proposed = ProposalStore().get(res.json()["proposalId"]).parsed()
    assert km.parse_manifest(proposed.payload).narrows(routed.effective[0])

    routed.console.clock.at += 23 * 3600
    again = routed.http.post(f"/api/curators/{second}/remove", headers=routed.headers, json=routed.sign_body())
    assert again.status_code == 409 and "24 h" in again.json()["error"]
    assert len(_manifest_rows(routed)) == 1
    routed.console.clock.at += 3600 + 1
    later = routed.http.post(f"/api/curators/{second}/remove", headers=routed.headers, json=routed.sign_body())
    assert later.status_code == 200 and later.json()["diff"]["version"] == [1, 3]   # never a repeated order


def test_a_wrong_second_factor_signs_and_stages_nothing(routed):
    key = _new_key()
    _join(routed, key)
    res = routed.http.post(f"/api/join-requests/{key}/approve", headers=routed.headers,
                           json={"passphrase": PASSPHRASE, "secondFactor": "000000"})
    assert res.status_code == 403 and res.json() == {"error": "the root signature was refused"}
    assert _manifest_rows(routed) == [] and routed.state.join(key).state.value == "pending"


def test_a_root_not_pinned_for_the_epoch_is_logged_but_never_staged(routed):
    services = routed.app.state.console_services
    object.__setattr__(services, "roots", lambda environment: RootPins.unbound({"b" * 64}))
    res = routed.http.post("/api/manifest/renew", headers=routed.headers, json=routed.sign_body())
    assert res.status_code == 409 and "not pinned" in res.json()["error"]
    assert len(_manifest_rows(routed)) == 1 and ProposalStore().all() == []


def test_a_damaged_console_state_refuses_every_signature(routed):
    routed.state._path.write_text("{not json", encoding="utf-8")
    res = routed.http.post("/api/manifest/renew", headers=routed.headers, json=routed.sign_body())
    assert res.status_code == 400 and "unreadable" in res.json()["error"]
    assert _manifest_rows(routed) == []
    with pytest.raises(RosterError):
        routed.state.record_list(SignedList(1, 9, False, NOW))   # never overwrites the damaged record


@pytest.mark.parametrize("today, stage, milestone, days_left", [
    ("2027-02-09", "ok", 0, 21),          # day 39
    ("2027-02-10", "reminder", 40, 20),   # day 40
    ("2027-02-19", "reminder", 40, 11),   # day 49: the day-40 reminder is still shown
    ("2027-02-20", "reminder", 50, 10),   # day 50
    ("2027-02-25", "reminder", 55, 5),    # day 55
    ("2027-02-26", "alarm", 55, 4),       # inside 5 days
    ("2027-03-02", "alarm", 55, 0),       # the expiry day
    ("2027-03-03", "alarm", 55, -1),      # expired: curation has stopped
])
def test_renewal_reminders_at_40_50_55_and_the_alarm_inside_5_days(routed, today, stage, milestone, days_left):
    status = renewal_status(routed.effective[0], today)
    assert (status.stage, status.milestone, status.days_left, status.expires) == (stage, milestone, days_left,
                                                                                  "2027-03-02")
    routed.console.clock.at = datetime.fromisoformat(today).replace(hour=12, tzinfo=UTC).timestamp()
    assert routed.http.get("/api/renewal", headers=TAILSCALE).json() == status.as_dict()


@pytest.mark.usefixtures("time_lock_one_day")
def test_renew_dates_the_same_roster_today_and_waits_for_readers(routed):
    res = routed.http.post("/api/manifest/renew", headers=routed.headers, json=routed.sign_body())
    assert res.status_code == 200, res.text
    change = res.json()["diff"]
    assert change["issuedDay"] == [ISSUED, "2027-01-15"] and change["added"] == change["removed"] == []
    again = routed.http.post("/api/manifest/renew", headers=routed.headers, json=routed.sign_body())
    assert again.status_code == 409 and "waiting period" in again.json()["error"]


# -- review hardening (C3 verify): boundaries, the record before the pin check, the race ----


class _AnyFreshCode:
    """A second factor that accepts every code, so two signatures can race."""

    def consume(self, code: str) -> bool:
        return True


def test_a_narrowing_list_exactly_24_h_after_the_last_is_allowed(routed):
    first, second = routed.effective[0].curator_keys[:2]
    assert routed.http.post(f"/api/curators/{first}/remove", headers=routed.headers,
                            json=routed.sign_body()).status_code == 200
    routed.console.clock.at += 24 * 3600 - 1
    assert routed.http.post(f"/api/curators/{second}/remove", headers=routed.headers,
                            json=routed.sign_body()).status_code == 409
    routed.console.clock.at += 1
    assert routed.http.post(f"/api/curators/{second}/remove", headers=routed.headers,
                            json=routed.sign_body()).status_code == 200


def test_another_epochs_narrowing_list_or_version_does_not_count(routed):
    epoch = routed.effective[0].root_epoch
    routed.state.record_list(SignedList(epoch + 1, 40, True, NOW))
    assert routed.state.narrowing_refusal(epoch, NOW) == ""
    assert routed.state.next_version(routed.effective[0]) == routed.effective[0].version + 1
    routed.state.record_list(SignedList(epoch, 7, False, NOW - 10 * 24 * 3600))
    assert routed.state.next_version(routed.effective[0]) == 8


def test_a_signature_on_an_unpinned_root_still_counts_toward_the_version_and_24_h(routed):
    first, _second = routed.effective[0].curator_keys[:2]
    services = routed.app.state.console_services
    object.__setattr__(services, "roots", lambda environment: RootPins.unbound({"b" * 64}))
    res = routed.http.post(f"/api/curators/{first}/remove", headers=routed.headers, json=routed.sign_body())
    assert res.status_code == 409 and len(_manifest_rows(routed)) == 1
    assert routed.state.next_version(routed.effective[0]) == routed.effective[0].version + 2
    assert routed.state.narrowing_refusal(routed.effective[0].root_epoch, routed.console.clock()) != ""


def test_a_root_pinned_only_for_another_epoch_is_freeze_only_and_never_staged(routed):
    services = routed.app.state.console_services
    other = routed.effective[0].root_epoch + 1
    object.__setattr__(services, "roots", lambda environment: RootPins(by_epoch=((other, frozenset({routed.console.root_hex})),)))
    res = routed.http.post("/api/manifest/renew", headers=routed.headers, json=routed.sign_body())
    assert res.status_code == 409 and "not pinned" in res.json()["error"]
    assert ProposalStore().all() == []


def test_the_break_glass_key_cannot_be_removed_by_a_narrowing_list(routed):
    glass = routed.effective[0].curator_keys[0]
    routed.effective[0] = dataclasses.replace(routed.effective[0], break_glass_key=glass)
    res = routed.http.post(f"/api/curators/{glass}/remove", headers=routed.headers, json=routed.sign_body())
    assert res.status_code == 400 and "break-glass" in res.json()["error"]
    assert _manifest_rows(routed) == []


def test_two_removals_racing_sign_one_list_never_two_at_one_order(routed):
    """Double-submit: the 24 h / version checks and the signature are one step, or two
    lists at one order reach readers (a freeze) and the 24 h rule is broken."""
    import threading

    from plugins.blackbox.curate.console.root_signer import RootSigner
    from plugins.blackbox.curate.console.routes import ConsoleActions

    services = routed.app.state.console_services
    barrier = threading.Barrier(2)

    class _SlowSigner(RootSigner):
        def sign(self, prepared_manifest, passphrase, second_factor):
            envelope = super().sign(prepared_manifest, passphrase, second_factor)
            threading.Event().wait(0.3)   # widen the window between the signature and its record
            return envelope

    object.__setattr__(services, "signer", lambda ctx: _SlowSigner(ctx, routed.console.store, _AnyFreshCode()))

    actions = ConsoleActions(services)   # one per app, as add_console_routes makes it
    outcomes: list = []

    def remove(key):
        barrier.wait()
        try:
            outcomes.append(actions.remove(key, PASSPHRASE, "123456")["diff"]["version"])
        except Exception as exc:
            outcomes.append(type(exc).__name__)

    first, second = routed.effective[0].curator_keys[:2]
    threads = [threading.Thread(target=remove, args=(key,)) for key in (first, second)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(_manifest_rows(routed)) == 1, outcomes
    assert sorted(map(str, outcomes)) == sorted(["[1, 2]", "_Refused"]), outcomes


# -- the verb (C3, LES-035) --------------------------------------------------------


def test_the_console_verb_parses_through_the_real_hermes_parser(tmp_path):
    import os
    import subprocess
    import sys

    from test_blackbox_host_arg_names import _REAL_PARSE

    root = Path(__file__).resolve().parents[2]
    env = {**os.environ, "HERMES_HOME": str(tmp_path / "hermes"), "PYTHONPATH": str(root)}
    probe = _REAL_PARSE + "print(json.dumps([args.func.__module__, args.func.__name__]))\n"
    done = subprocess.run([sys.executable, "-c", probe, json.dumps(["blackbox", "curate", "console", "--port", "9710"]),
                           "port"], cwd=root, env=env, capture_output=True, text=True, timeout=120, check=False)
    assert done.returncode == 0, done.stderr[-2000:]
    parsed, (module, name) = (json.loads(line) for line in done.stdout.strip().splitlines()[-2:])
    assert parsed == {"version": False, "command": "blackbox", "value": 9710}
    assert module.endswith("curate.console.commands") and name == "cmd_console"


def test_the_verb_lives_in_the_console_package_and_the_curate_files_stay_small():
    plugin = Path(__file__).resolve().parents[2] / "plugins" / "blackbox" / "curate"
    assert '"console"' not in (plugin / "commands.py").read_text(encoding="utf-8")
    assert "add_console_parser" in (plugin / "console" / "commands.py").read_text(encoding="utf-8")
    for name in ("commands.py", "verbs.py"):
        assert len((plugin / name).read_text(encoding="utf-8").splitlines()) <= 400, name


def test_the_console_verb_refuses_to_start_without_its_settings(monkeypatch, tmp_path, capsys):
    from plugins.blackbox.curate.console.commands import cmd_console

    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path))
    assert cmd_console(types.SimpleNamespace(port=9710, compiled_ruleset=None)) == 2
    assert "console_settings.json" in capsys.readouterr().out
    assert cmd_console(types.SimpleNamespace(port=80, compiled_ruleset=None)) == 2


# -- the console metrics view (C4, §03.4, F-035) -------------------------------------

from decimal import Decimal

from plugins.blackbox.community.statements import curator_view as metrics_cv
from plugins.blackbox.curate.console import (
    METRIC_NAMES,
    MetricsSources,
    PipelineMetrics,
    UpdateUptake,
    WalletBalance,
    collect_metrics,
)
from plugins.blackbox.curate.console.metrics import NEVER, UNAVAILABLE, open_queue_items
from plugins.blackbox.curate.lab.jobs import LabJobStore
from plugins.blackbox.curate.publishing.ledger import BatchEntry, PublishLedger, PublishState
from plugins.blackbox.curate.queue import Lane
from plugins.blackbox.curate.sources import LookupItem
from plugins.blackbox.curate.proposals.transport import ALARM_AFTER_BEATS, DeliveryLedger
from plugins.blackbox.kernel.health.manifest_watch import key_fingerprint

_LAB_PEER = "12D3KooWBJskzr2unXQG9mR3LRZFUJoxWr1PN6hTbyWyKndHXjZM"
_DAY = 86_400


def _fixture_ledger(path: Path) -> PublishLedger:
    """b-1: one definite failure, then a 207 (0.4 TRAC) bound later; b-2: bound (0.6 TRAC). All in 2027-01."""
    clock = _Clock(NOW - 7200)
    ledger = PublishLedger(path, clock=clock)
    ledger.queue("b-1", [BatchEntry("npm:evil@1.0.0", "dependency")])
    ledger.advance("b-1", PublishState.SEALED)
    ledger.advance("b-1", PublishState.SUBMITTED)
    ledger.advance("b-1", PublishState.SEALED, note="node answered 502")
    ledger.advance("b-1", PublishState.SUBMITTED)
    ledger.advance("b-1", PublishState.MINTED, ual="did:dkg:b1", cost_trac="0.4", cost_bytes=1000)
    clock.at = NOW - 3600
    ledger.reconcile_minted("b-1", readable_ual="did:dkg:b1", note="bound the existing UAL")
    ledger.queue("b-2", [BatchEntry("npm:worse@2.0.0", "dependency")])
    ledger.advance("b-2", PublishState.SEALED)
    ledger.advance("b-2", PublishState.SUBMITTED)
    ledger.advance("b-2", PublishState.BOUND, ual="did:dkg:b2", cost_trac="0.6", cost_bytes=2000)
    return ledger


@pytest.fixture
def stores(tmp_path, curators):
    """Every store the metrics read, filled with known values; the context's list dated ISSUED."""
    publish = _fixture_ledger(tmp_path / "publish_ledger.jsonl")
    lab = LabJobStore(tmp_path / "lab" / "jobs.jsonl", clock=_Clock(NOW - 600))
    lab.request("url:https://phish.example.test/a", level=2, image_sha256="b" * 64, lane=Lane.GRADUATION,
                requested_by=_LAB_PEER)
    lab._clock = _Clock(NOW - 60)
    lab.start(lab.request("url:https://phish.example.test/b", level=2, image_sha256="b" * 64,
                          lane=Lane.GRADUATION, requested_by=_LAB_PEER).job.key)
    delivery = DeliveryLedger(tmp_path / "undelivered.json")
    for _ in range(ALARM_AFTER_BEATS):
        delivery.failed("p-stuck", now=NOW - 60)
    delivery.failed("p-fresh", now=NOW - 60)               # one beat: not yet an alarm
    log_path = tmp_path / "signing_log.jsonl"
    log_path.write_text(json.dumps({"kind": "blackbox.heartbeat", "digest": "d", "key": "k", "action": "sign",
                                    "at": NOW - 120}) + "\n", encoding="utf-8")
    manifest = dataclasses.replace(curators["manifest"], issued_day=ISSUED)
    beating = manifest.curator_keys[0]
    view = metrics_cv.CuratorView(manifest=manifest, heartbeats={beating: "2027-01-13"})
    ctx = dataclasses.replace(_ctx(FakeNode(), manifest), view=view)
    items = [LookupItem("dep:npm:evil@1.0.0", Lane.BLOCKABLE_WITH_EVIDENCE, first_seen="2027-01-05"),
             LookupItem("domain:phish.example.test", Lane.FLAG_ONLY_SAMPLING, first_seen="2027-01-14"),
             LookupItem("domain:other.example.test", Lane.FLAG_ONLY_SAMPLING, first_seen="2027-01-15")]
    sources = MetricsSources(
        publish_ledger=lambda: publish, lab_jobs=lambda: lab, delivery=lambda: delivery,
        signing_log=lambda: SigningLog(log_path), queue=lambda _ctx, _today: items,
        wallet=lambda: WalletBalance(trac=Decimal("1.0"), gas=Decimal(5), gas_per_batch=Decimal(1)),
        uptake=lambda: UpdateUptake("0.9.0", NOW - 8 * _DAY, installs_on_release=30, installs_total=40))
    return types.SimpleNamespace(sources=sources, ctx=ctx, manifest=manifest, beating=beating)


def test_every_metric_renders_from_the_fixture_stores(stores):
    shown = collect_metrics(stores.sources, lambda: stores.ctx, NOW).as_dict()

    assert UNAVAILABLE not in json.dumps(shown)
    assert shown["queue_depth_by_lane"] == {"disputes_and_revocations": 0, "blockable_with_evidence": 1,
                                            "graduation": 0, "blockable_needs_reproduction": 0,
                                            "flag_only_sampling": 2}
    assert shown["queue_oldest_age_days"] == 10            # 2027-01-05 → NOW's day 2027-01-15
    assert shown["proposals_awaiting_cosign"] == [{"proposalId": "p-stuck", "beats": ALARM_AFTER_BEATS}]
    assert (shown["publish_failures"], shown["publish_207s"]) == (1, 1)
    assert shown["seconds_since_last_batch"] == 3600
    assert (shown["month_spend_trac"], shown["month_spend_bytes"]) == ("1.0", 3000)
    assert (shown["wallet_trac"], shown["wallet_gas"]) == ("1.0", "5")
    assert (shown["wallet_trac_floor"], shown["wallet_gas_floor"]) == ("1.2", "2")   # two of the largest batch
    assert shown["wallet_below_floor"] is True
    others = {key_fingerprint(key): NEVER for key in stores.manifest.curator_keys if key != stores.beating}
    assert shown["curator_heartbeat_age_days"] == {key_fingerprint(stores.beating): 2, **others}
    assert shown["seconds_since_own_heartbeat"] == 120
    assert shown["manifest_days_to_expiry"] == renewal_status(stores.manifest, "2027-01-15").days_left
    assert (shown["lab_queue_depth"], shown["lab_oldest_job_age_seconds"]) == (2, 600)
    assert (shown["reader_newest_release"], shown["reader_update_uptake"]) == ("0.9.0", 0.75)


def test_missing_stores_render_unavailable_never_a_crash():
    shown = collect_metrics(MetricsSources(publish_ledger=None, lab_jobs=None, delivery=None, signing_log=None),
                            context=None, now=NOW).as_dict()
    assert shown == {name: UNAVAILABLE for name in METRIC_NAMES}


def test_a_broken_store_makes_only_its_own_metrics_unavailable(stores, tmp_path, caplog):
    damaged = tmp_path / "damaged_ledger.jsonl"
    damaged.write_text("{not json\n", encoding="utf-8")

    def node_down():
        raise ConnectionError("http://127.0.0.1:9200 secret-path refused")

    def wallet_down():
        raise TimeoutError("rpc")

    sources = dataclasses.replace(stores.sources, publish_ledger=lambda: PublishLedger(damaged), wallet=wallet_down)
    shown = collect_metrics(sources, node_down, NOW).as_dict()

    for name in ("publish_failures", "publish_207s", "seconds_since_last_batch", "month_spend_trac", "wallet_trac",
                 "wallet_below_floor", "queue_depth_by_lane", "curator_heartbeat_age_days", "manifest_days_to_expiry"):
        assert shown[name] == UNAVAILABLE, name
    assert shown["lab_queue_depth"] == 2 and shown["seconds_since_own_heartbeat"] == 120
    assert "context metrics unavailable (ConnectionError)" in caplog.text
    assert "secret-path" not in caplog.text                 # logged by type only, never the error text


def test_empty_readable_stores_say_never_or_zero_not_unavailable(tmp_path):
    sources = MetricsSources(publish_ledger=lambda: PublishLedger(tmp_path / "none.jsonl"),
                             lab_jobs=lambda: LabJobStore(tmp_path / "lab" / "jobs.jsonl"),
                             delivery=lambda: DeliveryLedger(tmp_path / "undelivered.json"),
                             signing_log=lambda: SigningLog(tmp_path / "signing_log.jsonl"))
    shown = collect_metrics(sources, None, NOW).as_dict()
    assert (shown["seconds_since_last_batch"], shown["seconds_since_own_heartbeat"]) == (NEVER, NEVER)
    assert (shown["publish_failures"], shown["month_spend_trac"], shown["lab_queue_depth"]) == (0, "0", 0)
    assert shown["proposals_awaiting_cosign"] == []


def test_no_floor_without_a_batch_cost_and_uptake_waits_seven_days(tmp_path):
    sources = MetricsSources(publish_ledger=lambda: PublishLedger(tmp_path / "none.jsonl"), lab_jobs=None,
                             delivery=None, signing_log=None,
                             wallet=lambda: WalletBalance(trac=Decimal(3), gas=Decimal(1)),
                             uptake=lambda: UpdateUptake("0.9.1", NOW - 3 * _DAY, 5, 10))
    shown = collect_metrics(sources, None, NOW).as_dict()
    assert shown["wallet_trac"] == "3"
    assert shown["wallet_trac_floor"] == shown["wallet_gas_floor"] == shown["wallet_below_floor"] == UNAVAILABLE
    assert (shown["reader_newest_release"], shown["reader_update_uptake"]) == ("0.9.1", UNAVAILABLE)


def test_the_default_queue_reads_the_compiled_delta_view(curators):
    rules = {"dep:npm:evil@1.0.0": {"counted": 1, "reportReason": "advisory:MAL-1", "firstSeen": NOW - 5 * _DAY},
             "domain:new.example.test": {"counted": 1},                       # no firstSeen: new today
             "domain:odd.example.test": {"counted": 1, "firstSeen": "not a time"},   # unreadable: new today
             "domain:unlisted.example.test": {"counted": 0}}                  # not admitted to a lane
    compiled = types.SimpleNamespace(community=rules, iter_rules=lambda: iter(()))
    items = open_queue_items(_ctx(FakeNode(), curators["manifest"], compiled=compiled), "2027-01-15")
    assert sorted((item.identifier, item.lane) for item in items) == [
        ("dep:npm:evil@1.0.0", Lane.BLOCKABLE_WITH_EVIDENCE), ("domain:new.example.test", Lane.FLAG_ONLY_SAMPLING),
        ("domain:odd.example.test", Lane.FLAG_ONLY_SAMPLING)]
    assert sorted(item.first_seen for item in items) == ["2027-01-10", "2027-01-15", "2027-01-15"]
    assert collect_metrics(MetricsSources(publish_ledger=None, lab_jobs=None, delivery=None, signing_log=None),
                           lambda: _ctx(FakeNode(), curators["manifest"], compiled=compiled), NOW
                           ).as_dict()["queue_oldest_age_days"] == 5   # a blank day would make the queue unavailable
    with pytest.raises(LookupError):
        open_queue_items(_ctx(FakeNode(), curators["manifest"]), "2027-01-15")


def test_an_undated_key_list_has_no_days_to_expiry_but_its_curators_still_render(stores):
    """renewal_status says "undated" for a list without issued_day: that is could-not-tell (LES-011),
    never "0 days left"; the heartbeat ages come from the same context and still show."""
    undated = dataclasses.replace(stores.manifest, issued_day="")
    view = metrics_cv.CuratorView(manifest=undated, heartbeats={stores.beating: "2027-01-13"})
    ctx = dataclasses.replace(stores.ctx, view=view)

    shown = collect_metrics(stores.sources, lambda: ctx, NOW).as_dict()

    assert shown["manifest_days_to_expiry"] == UNAVAILABLE
    assert shown["curator_heartbeat_age_days"][key_fingerprint(stores.beating)] == 2


def test_the_webhook_payload_carries_the_same_metric_names(stores):
    """Criterion 2: W3's sink body is {"kind": "metrics", "metrics": {name: value}} over the SAME names
    the console answers; the record also offers the two methods W3's sinks call (as_payload, lines)."""
    record = collect_metrics(stores.sources, lambda: stores.ctx, NOW)
    payload = record.as_payload()
    assert payload["kind"] == "metrics" and tuple(payload) == ("kind", "metrics")
    assert payload["metrics"] == record.as_dict() and tuple(payload["metrics"]) == METRIC_NAMES
    assert json.loads(json.dumps(payload)) == payload        # JSON-ready (Decimal → text)
    assert tuple(f.name for f in dataclasses.fields(PipelineMetrics)) == METRIC_NAMES
    assert record.lines() == [f"{name}: {value}" for name, value in record.as_dict().items()]
    assert "publish_207s: 1" in record.lines()
    empty = PipelineMetrics()                                # the sink can post before any store answers
    assert empty.as_payload()["metrics"] == {name: UNAVAILABLE for name in METRIC_NAMES}


def test_a_broken_publish_ledger_leaves_the_wallet_balance_readable(stores, tmp_path, caplog):
    """A store's failure takes ONLY its own metrics (LES-011): the balance comes from the chain
    reader, so a damaged ledger hides the floor it sizes, never the balance."""
    damaged = tmp_path / "damaged_ledger.jsonl"
    damaged.write_text("{not json\n", encoding="utf-8")
    sources = dataclasses.replace(stores.sources, publish_ledger=lambda: PublishLedger(damaged))

    shown = collect_metrics(sources, lambda: stores.ctx, NOW).as_dict()

    assert (shown["wallet_trac"], shown["wallet_gas"]) == ("1.0", "5")
    assert shown["wallet_gas_floor"] == "2"                       # gas floor needs no ledger
    assert shown["wallet_trac_floor"] == UNAVAILABLE              # the TRAC floor is sized from the ledger
    assert shown["wallet_below_floor"] is False                   # gas 5 ≥ 2, the only floor that could be told
    assert shown["publish_failures"] == UNAVAILABLE
    assert "publish ledger metrics unavailable" in caplog.text


def test_the_metrics_route_is_read_only_behind_the_gates(routed, monkeypatch, stores):
    from fastapi.testclient import TestClient

    # Re-register the route over the fixture stores (the C3 fixture wired the real-store defaults).
    routed.app.router.routes[:] = [r for r in routed.app.router.routes if getattr(r, "path", "") != "/api/metrics"]
    services = dataclasses.replace(routed.app.state.console_services, context=lambda: stores.ctx,
                                   metrics=stores.sources)
    from plugins.blackbox.curate.console.routes import _add_metrics_route
    _add_metrics_route(routed.app, services)

    res = routed.http.get("/api/metrics", headers=routed.headers)
    assert res.status_code == 200
    assert tuple(res.json()) == METRIC_NAMES and res.json()["publish_207s"] == 1
    assert routed.http.post("/api/metrics", headers=routed.headers).status_code == 405
    with TestClient(routed.app, base_url=f"https://{MAGIC_DNS}") as stranger:     # no session cookie
        assert stranger.get("/api/metrics", headers=TAILSCALE).status_code == 401


def test_the_console_default_services_render_metrics_without_a_node(routed):
    """The C3 fixture's services (real store defaults in an empty curate home): no crash."""
    res = routed.http.get("/api/metrics", headers=routed.headers)
    assert res.status_code == 200 and tuple(res.json()) == METRIC_NAMES
    assert res.json()["seconds_since_last_batch"] == NEVER


@pytest.mark.parametrize("failure, status", [(OSError("disk full"), 500), ("proposal", 409)])
def test_a_console_action_that_fails_to_save_answers_json_not_a_bare_500(failure, status):
    """Every console answer is `{"error"}` (never a traceback, never plain text): a save that
    failed (OSError) or a proposal state refusal escaped as the framework's plain-text 500."""
    pytest.importorskip("fastapi")
    import json as json_module

    from plugins.blackbox.curate.console import routes
    from plugins.blackbox.curate.proposals.proposal import ProposalError

    error = ProposalError("a DRAFT cannot jump to PUBLISHED") if failure == "proposal" else failure

    def work():
        raise error

    answer = routes._answer(work)
    assert answer.status_code == status and "error" in json_module.loads(answer.body)
    assert "disk full" not in answer.body.decode()                     # no internal detail for an I/O failure


def test_the_passphrase_length_limit_is_defined_once():
    from plugins.blackbox.curate.console import app, routes

    assert routes.MAX_PASSPHRASE_LENGTH is app.MAX_PASSPHRASE_LENGTH
