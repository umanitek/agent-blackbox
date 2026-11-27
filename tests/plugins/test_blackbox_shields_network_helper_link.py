"""The plugin's half of the system protection helper's authentication (helper/PLAN.md;
security wave 2, finding 1): plans are signed for the helper's nonce with the per-person key,
reports must carry the helper's signature, and the card says when the two are not paired.

Without this the hardened helper (which obeys only signed plans) refuses every plan from this
plugin, so DNS Shield and the Threat Firewall never apply.
"""

from __future__ import annotations

import json
import time

import pytest

from plugins.blackbox.shields import helper_link
from plugins.blackbox.shields.network import helper, status
from plugins.blackbox.shields.network import mode as network_mode
from plugins.blackbox.shields.network.protect import enforcement
from plugins.blackbox.shields.shield_api import RawAnswer, ShieldApiError, ShieldContext

KEY = bytes([7] * 32)
#: The vector the helper crate checks too (helper/src/link.rs, a_shared_vector_…): one key,
#: nonce and body → the same hex on both sides of the contract.
# A made-up nonce for the tests — not a secret (the secret scanner's generic "api key" rule
# matches any long hex next to KEY).
NONCE = "0123456789abcdef0123456789abcdef"  # gitleaks:allow
PLAN_VECTOR = "556ad530e22f4180c7080a144eb88187e9e5c5668311aa23dc2fd484f285eafa"
#: A report from a helper before 1.6.3 (body only, DEPRECATED) and a v2 report (time + nonce +
#: body; helper/src/link.rs a_report_signature_covers_its_time_and_nonce).
REPORT_VECTOR = "ed7cae0659cb0798e3f55b0bb6586ee82d23ca413253a304832605c7bf4dd449"
REPORT_V2_VECTOR = "6e4673cb0bd283133f4f0e4cb64a08a542446a2ac5bba7b9aefa4fad7dded6e2"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    return tmp_path


def _pair(home_dir) -> None:
    path = helper_link.key_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(KEY)


def _context(body: bytes = b"", headers: dict | None = None) -> ShieldContext:
    return ShieldContext(network_indicators=lambda: None, ask_assistant=lambda _m: None,
                         request_body=body, request_headers={k.lower(): v for k, v in (headers or {}).items()})


def test_the_shared_vector_matches_the_helper_crate():
    assert helper_link.sign_plan(KEY, "abc", b'{"version":"v1"}') == PLAN_VECTOR
    assert helper_link.sign_legacy_report(KEY, b'{"running":true}') == REPORT_VECTOR
    assert helper_link.sign_report(KEY, 1_700_000_000, "000102030405060708090a0b0c0d0e0f", b'{"running":true}') == REPORT_V2_VECTOR


def test_a_plan_is_signed_for_the_helpers_nonce_over_the_exact_bytes(home):
    _pair(home)
    answer = helper_link.signed({"version": "v1", "unchanged": True}, {"nonce": NONCE})
    assert isinstance(answer, RawAnswer)
    signature = answer.headers[helper_link.SIGNATURE_HEADER]
    assert signature == helper_link.sign_plan(KEY, NONCE, answer.body)
    assert json.loads(answer.body) == {"version": "v1", "unchanged": True}


def test_without_a_key_or_a_nonce_the_plan_goes_out_plain(home):
    assert helper_link.signed({"v": 1}, {"nonce": "0123456789abcdef"}) == {"v": 1}   # no key: not paired
    _pair(home)
    assert helper_link.signed({"v": 1}, {}) == {"v": 1}                             # a page, not the helper
    assert helper_link.signed({"v": 1}, {"nonce": "NOT-HEX!"}) == {"v": 1}


def test_a_report_must_carry_the_helpers_signature_once_paired(home):
    body = b'{"running":true}'
    helper_link.require_signed_report(_context(body))                   # not paired: a pre-key helper
    _pair(home)
    with pytest.raises(ShieldApiError) as unsigned:
        helper_link.require_signed_report(_context(body))
    assert unsigned.value.status == 401
    with pytest.raises(ShieldApiError):
        helper_link.require_signed_report(_context(body, {helper_link.HELPER_SIGNATURE_HEADER: "00" * 32}))
    with pytest.raises(ShieldApiError):   # signed, but for other bytes
        helper_link.require_signed_report(_context(b'{"running":false}', {helper_link.HELPER_SIGNATURE_HEADER: REPORT_VECTOR}))
    helper_link.require_signed_report(_context(body, {helper_link.HELPER_SIGNATURE_HEADER: REPORT_VECTOR}))


def _v2(body: bytes, stamp: int, nonce: str = "0d" * 16, key: bytes = KEY) -> ShieldContext:
    return _context(body, {helper_link.HELPER_SIGNATURE_HEADER: helper_link.sign_report(key, stamp, nonce, body),
                           helper_link.HELPER_TIMESTAMP_HEADER: str(stamp), helper_link.HELPER_NONCE_HEADER: nonce})


def test_a_broken_key_file_refuses_every_report_never_reads_as_not_paired(home):
    """Review 2026-11-26, finding 7: a key file of the wrong size or a link let unsigned reports in."""
    path = helper_link.key_path()
    path.parent.mkdir(parents=True)
    path.write_bytes(b"short")
    with pytest.raises(ShieldApiError) as refused:
        helper_link.require_signed_report(_context(b'{"running":true}'))
    assert refused.value.status == 401
    path.unlink()
    path.symlink_to(home / "elsewhere")
    with pytest.raises(ShieldApiError):
        helper_link.require_signed_report(_context(b'{"running":true}'))


def test_a_report_is_fresh_and_new_or_refused(home):
    """Review 2026-11-26, finding 7: the signature covered the body only, so a caught report could
    be replayed. Now its time and a nonce are signed: an old one or a second copy is refused, and
    once this helper has sent one, a body-only signature is refused for good."""
    _pair(home)
    body, now = b'{"running":true}', int(time.time())
    helper_link.require_signed_report(_v2(body, now, "0a" * 16))
    for refused in (_v2(body, now, "0a" * 16),                                   # the same report again
                    _v2(body, now - helper_link.REPORT_FRESH_SECONDS - 5, "0b" * 16),   # an old one
                    _v2(body, now, "0c" * 16, key=bytes(32)),                     # another key
                    _context(body, {helper_link.HELPER_SIGNATURE_HEADER: REPORT_VECTOR})):   # body only, after v2
        with pytest.raises(ShieldApiError) as why:
            helper_link.require_signed_report(refused)
        assert why.value.status == 401


def test_a_key_file_of_the_wrong_kind_is_broken_never_used(home):
    path = helper_link.key_path()
    path.parent.mkdir(parents=True)
    path.write_bytes(b"short")
    assert helper_link.read_key() is None and helper_link.pairing() == helper_link.BROKEN
    path.unlink()
    path.symlink_to(home / "elsewhere")
    (home / "elsewhere").write_bytes(KEY)
    assert helper_link.read_key() is None, "a link is never followed"


def test_the_dashboard_sends_the_plan_bytes_it_signed(home, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from _blackbox_loader import load_blackbox

    _pair(home)
    server = load_blackbox("dashboard.server")
    nonce = "fedcba9876543210fedcba9876543210"
    with TestClient(server.create_app(), base_url="http://127.0.0.1:9700") as client:
        answer = client.get(f"/api/shields/network-shield/api/system-plan?nonce={nonce}")
    assert answer.status_code == 200
    assert answer.headers[helper_link.SIGNATURE_HEADER] == helper_link.sign_plan(KEY, nonce, answer.content)


def test_the_card_says_not_paired_and_shows_the_helpers_health(home, monkeypatch):
    monkeypatch.setattr(helper, "installed", lambda: True)
    mode = network_mode.build(enabled=True, protections=(network_mode.DNS,))
    rows = [row.text for section in status.build(mode).sections for row in section.rows]
    assert "System protection helper not paired" in rows
    _pair(home)
    enforcement.record_report({"running": True, "dns_active": False, "firewall_active": False, "auth": "signed",
                               "pf_enabled": False, "resolver_ok": False, "last_error": "pfctl -E failed"})
    summary = enforcement.summary()
    assert (summary["auth"], summary["pf_enabled"], summary["resolver_ok"], summary["last_error"]) == (
        "signed", False, False, "pfctl -E failed")
    rows = [row.text for section in status.build(mode).sections for row in section.rows]
    assert "System protection helper not paired" not in rows
    assert {"The macOS packet filter is off", "DNS Shield's resolver is not answering", "The helper reported a problem"} <= set(rows)


def test_a_report_with_a_bad_health_field_is_refused(home):
    with pytest.raises(ShieldApiError):
        enforcement.record_report({"running": True, "dns_active": False, "firewall_active": False, "auth": "root"})
    with pytest.raises(ShieldApiError):
        enforcement.record_report({"running": True, "dns_active": False, "firewall_active": False, "pf_enabled": "yes"})


def test_the_enforcement_plan_route_is_signed_and_its_report_route_checks_the_signature(home, monkeypatch):
    """E2E 2026-11-21: the DNS / firewall plan went out unsigned, so the keyed helper applied nothing."""
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from _blackbox_loader import load_blackbox

    _pair(home)
    server = load_blackbox("dashboard.server")
    nonce = "fedcba9876543210fedcba9876543210"
    report = json.dumps({"running": True, "dns_active": False, "firewall_active": False}).encode()
    with TestClient(server.create_app(), base_url="http://127.0.0.1:9700") as client:
        plan = client.get(f"/api/shields/network-shield/api/enforcement?nonce={nonce}")
        token = client.get("/api/session").json()["token"]   # the helper sends the session token too
        unsigned = client.post("/api/shields/network-shield/api/enforcer-report", content=report,
                               headers={"content-type": "application/json", "X-Blackbox-Token": token})
        stamp, report_nonce = int(time.time()), "0e" * 16
        signed = client.post("/api/shields/network-shield/api/enforcer-report", content=report,
                             headers={"content-type": "application/json", "X-Blackbox-Token": token,
                                      helper_link.HELPER_SIGNATURE_HEADER: helper_link.sign_report(KEY, stamp, report_nonce, report),
                                      helper_link.HELPER_TIMESTAMP_HEADER: str(stamp), helper_link.HELPER_NONCE_HEADER: report_nonce})
    assert plan.status_code == 200
    assert plan.headers[helper_link.SIGNATURE_HEADER] == helper_link.sign_plan(KEY, nonce, plan.content)
    assert unsigned.status_code == 401
    assert signed.status_code == 200, signed.text
