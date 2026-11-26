"""Trader Shield's setting (shields/trader/mode.py): read, validated, migrated, kept private.

The setting lives at ``shields.trader`` in the ``blackbox`` config entry. An install saved
before shields holds three legacy keys (``wallet_protection`` / ``protected_wallets`` /
``wallet_addresses``): it still reads as engaged, and its first save writes ``shields.trader``
and retires them. The operator's own addresses are personal data: only the
Settings editor's view carries them. The mode tests moved here from the wallet test files.
``HERMES_HOME``/``BLACKBOX_HOME`` are per-test tmpdirs (root conftest).
"""

import secrets
import threading
import time

import pytest
from _blackbox_loader import load_blackbox
from tests.waiting import wait_until


constants = load_blackbox("kernel.constants")
settings = load_blackbox("kernel.settings")
yaml_files = load_blackbox("kernel.yaml_files")
shields = load_blackbox("shields")
trader_mode = load_blackbox("shields.trader.mode")

TRADER = shields.get("trader")
SHIELDS = shields.settings_validators()   # what the dashboard hands the writer
OWN = "0x" + "ab" * 20


def _entry() -> dict:
    """The persisted ``plugins.entries.blackbox`` entry ({} with no config file)."""
    path = constants.hermes_home() / "config.yaml"
    data = yaml_files.load_yaml(path) if path.exists() else {}
    return ((data or {}).get("plugins") or {}).get("entries", {}).get("blackbox") or {}


def _write_entry(entry: dict) -> None:
    """Persist *entry* as the whole ``blackbox`` entry, the way an older install left it."""
    yaml_files.dump_yaml(constants.hermes_home() / "config.yaml", {"plugins": {"entries": {"blackbox": entry}}})


LEGACY = {"wallet_protection": True, "protected_wallets": ["metamask", "phantom"], "wallet_addresses": [OWN]}


# ------------------------------------------------------------------ the six legacy-key cases


def _added_later() -> tuple[str, ...]:
    """Supported wallets a save that recorded no "offered" list was never offered: everything
    after the first five. Since 2026-11-19 they are guarded without a new save (KI-411)."""
    return tuple(w for w in trader_mode.supported_wallets() if w not in trader_mode.OFFERED_BEFORE_RECORDING)


def test_a_legacy_only_entry_reads_enabled_with_its_wallets_and_addresses():
    mode = trader_mode.from_entry(LEGACY)
    assert mode.enabled is True
    assert trader_mode.wallets(mode) == ("metamask", "phantom", *_added_later()) and trader_mode.addresses(mode) == (OWN,)


def test_one_save_writes_shields_trader_and_retires_every_legacy_key():
    _write_entry({**LEGACY, "mode": "block"})
    result = settings.write_settings({"shields": {"trader": {"enabled": True}}}, validators=SHIELDS)

    assert result["ok"] is True
    entry = _entry()
    assert not set(trader_mode.LEGACY_KEYS) & set(entry)
    # The Engage-style save sent only the switch: the earlier wallets and addresses carried over,
    # with the wallets added since that legacy save (guarded already) now written in the list.
    assert entry["shields"]["trader"] == {"enabled": True, "wallets": ["metamask", "phantom", *_added_later()], "addresses": [OWN],
                                          "offered": list(trader_mode.supported_wallets())}
    assert entry["mode"] == "block"


def test_offered_is_written_by_the_save_never_taken_from_the_payload():
    _write_entry({"mode": "block"})
    payload = {"shields": {"trader": {"enabled": True, "wallets": ["metamask"], "offered": ["metamask"]}}}
    assert settings.write_settings(payload, validators=SHIELDS)["ok"] is True
    assert _entry()["shields"]["trader"]["offered"] == list(trader_mode.supported_wallets())


def test_a_never_saved_legacy_entry_still_reads_engaged():
    _write_entry(LEGACY)
    assert trader_mode.current().enabled is True and TRADER.mode().enabled is True


def test_an_unknown_wallet_id_is_refused_and_nothing_is_written():
    _write_entry(LEGACY)
    shield_id, section, errors, _ = trader_mode.validate({"shields": {"trader": {"wallets": ["metamask", "not-a-wallet"]}}})
    assert (shield_id, section) == ("trader", {}) and errors
    result = settings.write_settings({"shields": {"trader": {"wallets": ["not-a-wallet"]}}}, validators=SHIELDS)
    assert result["ok"] is False and _entry() == LEGACY


def test_only_the_settings_editor_view_carries_an_address():
    shields_routes = load_blackbox("dashboard.shields_routes")
    _write_entry(LEGACY)
    mode = TRADER.mode()
    elsewhere = {
        "dashboard cards": shields_routes.statuses_payload(),
        "events report": shields_routes.events_payload("trader"),
        "shield statuses": [status.as_json() for status in shields.statuses()],
        "shield card": TRADER.status(mode).as_json(),
        "snapshot": shields.snapshot().as_json(),
        "shield record": TRADER.as_json(),
        "kernel settings": settings.read_settings(),
    }
    for name, payload in elsewhere.items():
        assert OWN not in str(payload).lower(), name
    assert shields.settings_view()["trader"]["mode"]["addresses"] == [OWN]   # the one view that edits them


def test_as_json_strips_the_addresses_unless_asked():
    mode = trader_mode.build(enabled=True, addresses=(OWN,))
    assert "addresses" not in mode.as_json()
    assert mode.as_json(include_personal=True)["addresses"] == [OWN]


# ------------------------------------------------------------------ moved from the wallet test files


def test_the_mode_is_off_by_default_and_governs_only_wallet_findings():
    mode = trader_mode.from_entry({})
    assert mode.enabled is False and trader_mode.wallets(mode) == tuple(trader_mode.supported_wallets())
    vault = {"identifier": "fileaccess:terminal:crypto-wallet", "fields": {"wallet": "metamask"}}
    assert not TRADER.allows(vault, mode) and not TRADER.allows({"identifier": "secret:seed-phrase"}, mode)
    assert TRADER.allows({"identifier": "dep:npm:evil@1.0.0"}, mode)   # not a wallet finding: untouched
    chosen = trader_mode.from_entry({"shields": {"trader": {"enabled": True, "wallets": ["MetaMask", "not-a-wallet"]}}})
    assert trader_mode.wallets(chosen) == ("metamask", *_added_later()) and TRADER.allows(vault, chosen)   # unsupported names dropped


def test_engaging_protects_every_supported_wallet_unless_wallets_were_already_chosen():
    """Engage sends only the switch: a first engage protects every supported wallet; an
    earlier choice (e.g. MetaMask only) is kept — plus the wallets that choice was never offered
    (added in later versions), never one it left unticked."""
    engage = {"shields": {"trader": {"enabled": True}}}
    assert settings.write_settings(engage, validators=SHIELDS)["ok"] is True
    assert trader_mode.wallets(trader_mode.current()) == tuple(trader_mode.supported_wallets())
    _write_entry({"wallet_protection": False, "protected_wallets": ["metamask"]})
    assert settings.write_settings(engage, validators=SHIELDS)["ok"] is True
    assert trader_mode.wallets(trader_mode.current()) == ("metamask", *_added_later())
    _write_entry({"shields": {"trader": {"enabled": True, "wallets": ["metamask"], "offered": list(trader_mode.supported_wallets())}}})
    assert trader_mode.wallets(trader_mode.current()) == ("metamask",)   # every other wallet was offered: a choice


def test_settings_accept_the_mode_and_refuse_a_non_boolean():
    assert TRADER.validate({"shields": {"trader": {"enabled": True, "wallets": ["metamask"]}}})[1:3] == (
        {"enabled": True, "wallets": ["metamask"], "addresses": [], "offered": list(trader_mode.supported_wallets())}, [])
    assert TRADER.validate({"shields": {"trader": {"enabled": "yes"}}})[2]
    assert TRADER.validate({"shields": {"trader": "on"}})[2]
    assert TRADER.validate({"mode": "block"})[1:3] == ({}, [])   # the shield is not touched


def test_settings_accept_addresses_lower_cased_and_refuse_anything_else():
    good = "0x" + secrets.token_hex(20)
    section, errors = TRADER.validate({"shields": {"trader": {"addresses": [good.upper().replace("0X", "0x"), good]}}})[1:3]
    assert errors == [] and section["addresses"] == [good]
    for bad in (["0x" + secrets.token_hex(32)], "0x12", ["not an address"], ["0x" + secrets.token_hex(20)] * 51):
        assert TRADER.validate({"shields": {"trader": {"addresses": bad}}})[2], bad


def test_the_mode_carries_the_addresses_lower_cased_and_capped():
    many = ["0x" + secrets.token_hex(20) for _ in range(60)]
    mode = trader_mode.from_entry({"wallet_protection": True, "wallet_addresses": [many[0].upper().replace("0X", "0x")] + many})
    assert trader_mode.addresses(mode)[0] == many[0]
    assert len(trader_mode.addresses(mode)) == trader_mode.MAX_WALLET_ADDRESSES


def test_the_kernel_redacts_own_keys_through_the_shields_address_reader():
    """The kernel reads the listed addresses through the reader Trader hands it (it never imports a shield)."""
    crypto_secrets = load_blackbox("kernel.crypto_secrets")
    key = secrets.token_hex(32)
    _write_entry({"shields": {"trader": {"enabled": True, "addresses": [crypto_secrets.address_of(bytes.fromhex(key))]}}})
    assert key not in crypto_secrets.redact_own_keys(f"debug k={key}")


# ------------------------------------------------------------------ the dashboard composes shields


def test_the_settings_routes_compose_shields_trader_and_a_save_retires_the_legacy_keys(monkeypatch, tmp_path):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    server = load_blackbox("dashboard.server")
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    monkeypatch.setenv("HOME", str(tmp_path))   # the app's agent discovery must not find the real ~/.hermes
    _write_entry(LEGACY)
    with TestClient(server.create_app(), base_url="http://127.0.0.1:9700") as client:
        read = client.get("/api/settings").json()
        token = client.get("/api/session").json()["token"]
        # Every wallet: a save that ADDS protection applies at once (removing one waits for the
        # person's approval — tests/plugins/test_blackbox_approvals.py covers that path).
        everything = list(trader_mode.supported_wallets())
        saved = client.post("/api/settings", json={"shields": {"trader": {"enabled": True, "wallets": everything}}},
                            headers={"X-Blackbox-Token": token})

    assert read["shields"]["trader"]["mode"]["enabled"] is True   # read from the legacy keys
    assert "wallet_protection" not in read
    assert saved.status_code == 200 and saved.json()["settings"]["shields"]["trader"]["mode"]["wallets"] == everything
    entry = _entry()
    assert entry["shields"]["trader"] == {"enabled": True, "wallets": everything, "addresses": [OWN],
                                          "offered": list(trader_mode.supported_wallets())}
    assert not set(trader_mode.LEGACY_KEYS) & set(entry)


def _dashboard(monkeypatch, tmp_path):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    server = load_blackbox("dashboard.server")
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    monkeypatch.setenv("HOME", str(tmp_path))   # the app's agent discovery must not find the real ~/.hermes
    return TestClient(server.create_app(), base_url="http://127.0.0.1:9700")


def _trader_card(client, wait_s=5.0):
    """GET /api/shields until the cache has its first card (it answers [] before that)."""
    deadline = time.monotonic() + wait_s
    while True:
        cards = client.get("/api/shields").json()
        if cards or time.monotonic() > deadline:
            return next(card for card in cards if card["shield_id"] == "trader")
        time.sleep(0.05)   # a poll interval under the deadline above


def test_the_card_read_right_after_a_save_shows_the_saved_wallets(monkeypatch, tmp_path):
    # The trader bench, 2026-10-15: after Save the page re-read GET /api/shields and got the
    # card cached BEFORE the save (stale-while-revalidate), so it kept showing the old wallets.
    # "offered" pins the list: an entry without it also gains wallets added in later releases.
    _write_entry({"shields": {"trader": {"enabled": True, "wallets": ["metamask"], "offered": list(trader_mode.supported_wallets())}}})
    with _dashboard(monkeypatch, tmp_path) as client:
        assert _trader_card(client)["mode"]["wallets"] == ["metamask"]
        token = client.get("/api/session").json()["token"]
        # Adding wallets strengthens protection, so it applies at once (removing waits for approval).
        saved = client.post("/api/settings", json={"shields": {"trader": {"wallets": list(trader_mode.supported_wallets())}}},
                            headers={"X-Blackbox-Token": token})
        assert saved.status_code == 200
        assert _trader_card(client)["mode"]["wallets"] == list(trader_mode.supported_wallets())   # the very next read, no wait


def test_a_refresh_that_began_before_the_save_cannot_put_the_old_card_back(monkeypatch, tmp_path):
    shields_routes = load_blackbox("dashboard.shields_routes")
    real = shields_routes.statuses_payload
    release, entered, slow = threading.Event(), threading.Event(), {"on": False}

    def payload():
        if slow["on"]:
            slow["on"] = False
            entered.set()
            release.wait(5)
            return [{"shield_id": "trader", "mode": {"enabled": True, "wallets": ["stale"]}}]
        return real()

    monkeypatch.setattr(shields_routes, "statuses_payload", payload)
    monkeypatch.setattr(shields_routes, "STATUS_TTL_SECONDS", 0.0)   # every read starts a background refresh
    # "offered" pins the list: an entry without it also gains wallets added in later releases.
    _write_entry({"shields": {"trader": {"enabled": True, "wallets": ["metamask"], "offered": list(trader_mode.supported_wallets())}}})
    with _dashboard(monkeypatch, tmp_path) as client:
        _trader_card(client)
        slow["on"] = True
        deadline = time.monotonic() + 5
        while not entered.is_set() and time.monotonic() < deadline:
            client.get("/api/shields")                  # starts the slow refresh, built from the old mode
            entered.wait(0.02)
        assert entered.is_set()
        token = client.get("/api/session").json()["token"]
        client.post("/api/settings", json={"shields": {"trader": {"wallets": list(trader_mode.supported_wallets())}}},   # adds: applies at once
                    headers={"X-Blackbox-Token": token})
        release.set()                                   # the old refresh now finishes, after the save
        wait_until(lambda: not any(t.name == "blackbox-swr" and t.is_alive() for t in threading.enumerate()),
                   timeout=5, what="the slow refresh to finish")
        for _ in range(5):
            assert _trader_card(client)["mode"]["wallets"] == list(trader_mode.supported_wallets())


# ------------------------------------------------------------------ saves that must retire nothing


@pytest.mark.parametrize("payload", [{"mode": "block"}, {"mode": "block", "shields": {}},
                                     {"mode": "block", "shields": {"trader": {}}}],
                         ids=["no-shields-key", "empty-shields", "empty-trader-section"])
def test_a_save_that_leaves_trader_untouched_keeps_the_legacy_keys(payload):
    """A page built before this setting moved (or one that never read Trader) saves its other settings with
    ``shields: {}``: the install must stay engaged on its legacy keys — an empty section
    means untouched (LES-018)."""
    _write_entry(LEGACY)
    assert settings.write_settings(payload, validators=SHIELDS)["ok"] is True
    entry = _entry()
    assert {key: entry[key] for key in trader_mode.LEGACY_KEYS} == LEGACY
    assert "trader" not in (entry.get("shields") or {})
    assert trader_mode.current().enabled is True


def test_a_refused_trader_save_retires_nothing_even_when_some_fields_were_valid():
    """One bad field refuses the whole section: the valid wallets are not written and the legacy keys stay."""
    _write_entry(LEGACY)
    result = settings.write_settings({"shields": {"trader": {"enabled": "yes", "wallets": ["metamask"]}}},
                                     validators=SHIELDS)
    assert result["ok"] is False and _entry() == LEGACY


def test_with_shields_puts_the_view_where_the_page_reads_it_and_fails_open(monkeypatch):
    """GET answers the view itself; a save answers it under ``settings`` (the page re-renders from that).
    A shield whose view raises leaves the settings answered without ``shields``."""
    routes = load_blackbox("dashboard.shields_routes")
    read = routes.with_shields({"mode": "observe"})
    assert read["shields"]["trader"]["mode"]["enabled"] is False
    saved = routes.with_shields({"ok": False, "errors": ["x"], "settings": {"mode": "observe"}})
    assert "trader" in saved["settings"]["shields"] and "shields" not in saved

    def broken_view():
        raise RuntimeError("a broken shield")

    monkeypatch.setattr(routes.shields, "settings_view", broken_view)
    assert routes.with_shields({"mode": "observe"}) == {"mode": "observe"}
