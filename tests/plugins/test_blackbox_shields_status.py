"""Trader Shield's card (shields/trader/status.py) and ``GET /api/shields`` .

The card says, in the panel's own words, which wallets were found on this machine and
whether each is protected, what is always watched, and two health rows: a chosen pack
that is not supported right now and supported packs a saved list leaves out
The dashboard sanitises the card ONCE where it serves it, serves it
through its 2 s cache, and never carries an address. Since the old wallet panel went, it is the only
source of the card's words: the dashboard draws it as given. The found-wallet assertions
moved here from the old wallet-protection panel's tests.
"""

from __future__ import annotations

import ast
import json
import threading
import time
from pathlib import Path

import pytest

from plugins.blackbox import shields
from plugins.blackbox.dashboard import shields_routes
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.shields.contract import Pack, ShieldMode, ShieldStatus, StatusRow, StatusSection
from plugins.blackbox.shields.trader import detectors, mode as trader_mode, status as trader_status
from plugins.blackbox.shields.trader.detectors.browser_extension import FIREFOX_EXTENSION, Owner, normalize_path

PLUGIN = Path(trader_status.__file__).resolve().parents[2]
FIXTURE = Path(__file__).with_name("fixtures") / "shields_api_payload.json"
TRADER = shields.get("trader")
METAMASK_CHROME = "nkbihfbeogaeaoehlefnkodbefgpgknn"
OWN = "0x" + "ab" * 20
FIREFOX_STORE = "~/.mozilla/firefox/{}/storage/default/moz-extension+++x^usercontextid=4294967295"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    detectors.EXISTING_STORES.reset()
    yield tmp_path
    detectors.EXISTING_STORES.reset()


def _config(monkeypatch, mode="block"):
    """Blackbox's audit/block mode, for the card."""
    monkeypatch.setattr(trader_status, "load_blackbox_config", lambda: BlackboxConfig(mode=mode))


def _mode(monkeypatch, **kwargs):
    chosen = trader_mode.build(**kwargs)
    monkeypatch.setattr(trader_mode, "current", lambda: chosen)
    return chosen


def _vault(home, *parts, browser="google-chrome"):
    folder = home.joinpath(".config", browser, "Default", *parts)
    folder.mkdir(parents=True)
    (folder / "000003.log").write_text("placeholder", encoding="utf-8")


def _section(status: ShieldStatus, title: str) -> StatusSection:
    return next(section for section in status.sections if section.title == title)


def _rows(status: ShieldStatus, title: str) -> dict[str, StatusRow]:
    return {row.text: row for row in _section(status, title).rows}


def _card(active: ShieldMode) -> ShieldStatus:
    return TRADER.status(active)


# ------------------------------------------------------------------ found on this machine (moved scan)


def test_a_metamask_vault_on_this_machine_is_listed_by_browser_profile_and_area(home):
    _vault(home, "Local Extension Settings", METAMASK_CHROME)
    _vault(home, "IndexedDB", f"chrome-extension_{METAMASK_CHROME}_0.indexeddb.leveldb")
    [found] = trader_status.found_wallets()
    assert (found["wallet"], found["id"], found["browser"], found["profile"]) == ("MetaMask", "metamask", "Chrome", "default")
    assert sorted(found["areas"]) == ["backup copy", "vault"]


def test_a_machine_without_a_wallet_lists_none(home, monkeypatch):
    _config(monkeypatch)
    assert trader_status.found_wallets() == []
    [row] = _section(_card(trader_mode.build(enabled=True)), "Found on this machine").rows
    assert (row.icon, row.state, row.text) == ("–", "none", "No wallet found on this machine.")
    assert row.sub == ("Blackbox checks the usual browser and wallet-app folders by name every few minutes; "
                       "it never opens a vault.")


def test_a_firefox_profile_name_is_kept_as_it_is_not_defanged(home, monkeypatch):
    store = normalize_path(FIREFOX_STORE.format("ab12.default-release"))
    monkeypatch.setattr(detectors.EXISTING_STORES, "get", lambda: [(store, Owner("", FIREFOX_EXTENSION))])
    [found] = trader_status.found_wallets()
    assert (found["id"], found["profile"]) == ("any-extension", "ab12.default-release")


def test_found_rows_are_one_per_wallet_in_the_panels_words(home, monkeypatch):
    """Today's panel (index.html renderWalletProtection): one row per WALLET listing its browsers,
    a Firefox store no pack names as "Firefox wallets", and the gate's own protected rule."""
    stores = [(normalize_path(f"~/.config/google-chrome/Default/local extension settings/{METAMASK_CHROME}"),
               Owner("metamask", "MetaMask")),
              (normalize_path(f"~/.config/BraveSoftware/Brave-Browser/Default/indexeddb/chrome-extension_{METAMASK_CHROME}_0.indexeddb.leveldb"),
               Owner("metamask", "MetaMask")),
              (normalize_path(FIREFOX_STORE.format("a.default")), Owner("", FIREFOX_EXTENSION)),
              (normalize_path(FIREFOX_STORE.format("b.work")), Owner("", FIREFOX_EXTENSION)),
              (normalize_path("~/.electrum/wallets/default_wallet"), Owner("electrum", "Electrum"))]
    monkeypatch.setattr(detectors.EXISTING_STORES, "get", lambda: stores)

    _config(monkeypatch, "block")
    rows = _rows(_card(trader_mode.build(enabled=True, wallets=("metamask",))), "Found on this machine")
    metamask = rows["MetaMask · Chrome, Brave"]
    assert (metamask.icon, metamask.state, metamask.logo) == ("✓", "ok", "/shields/trader/packs/metamask/logo.svg")
    assert metamask.sub == "vault, backup copy — protected — blocked if the agent reaches for it"
    firefox = rows["Firefox wallets · Firefox"]
    assert firefox.sub == ("every extension's storage in 2 Firefox profiles — "
                           "protected — blocked if the agent reaches for it")
    electrum = rows["Electrum · Desktop app"]
    assert (electrum.icon, electrum.state, electrum.logo) == ("–", "none", "/shields/trader/packs/electrum/logo.svg")
    assert electrum.sub == "wallet folder — not selected in Settings, so not protected"

    _config(monkeypatch, "audit")
    rows = _rows(_card(trader_mode.build(enabled=True, wallets=("metamask",))), "Found on this machine")
    assert (rows["MetaMask · Chrome, Brave"].icon, rows["MetaMask · Chrome, Brave"].state) == ("~", "watch")
    assert rows["MetaMask · Chrome, Brave"].sub.endswith("— watched — flagged, not blocked (audit mode)")

    rows = _rows(_card(trader_mode.build(enabled=True, wallets=())), "Found on this machine")
    assert rows["Firefox wallets · Firefox"].state == "none"   # pack-less: counted only while some pack is chosen


# ------------------------------------------------------------------ always watching


def test_always_watching_rows_say_todays_rules(home, monkeypatch):
    _config(monkeypatch, "block")
    rows = _rows(_card(trader_mode.build(enabled=True, addresses=(OWN,))), "Always watching")
    assert list(rows) == ["Seed phrases", "Private keys", "Exchange API keys", "Token approvals", "Protected files"]
    assert rows["Seed phrases"].sub == "checker on — 2,048-word list, checksum verified"
    assert rows["Private keys"].sub == "labelled and Solana keys · blocked if sent · 1 own address listed for raw keys"
    assert rows["Exchange API keys"].sub.startswith("Binance · ") and rows["Exchange API keys"].sub.endswith(
        " — only to their own site")
    assert rows["Token approvals"].sub == "known drainer blocked · unlimited approvals flagged"
    assert rows["Protected files"].sub.endswith(" … · file tools and terminal")   # FIX-0103: the terminal too
    assert all((row.icon, row.state) == ("✓", "ok") for row in rows.values())

    rows = _rows(_card(trader_mode.build(enabled=True)), "Always watching")
    assert rows["Private keys"].sub.endswith("list your addresses in Settings to catch raw keys")


# ------------------------------------------------------------------ health rows


def test_a_chosen_pack_that_is_not_supported_now_is_reported(home, monkeypatch):
    _config(monkeypatch)
    broken = Pack(id="phantom", name="Phantom", kind="browser-extension", status="unavailable", order=20,
                  folder=home, reason="manifest too large")
    packs = tuple(broken if pack.id == "phantom" else pack for pack in trader_mode.wallet_packs())
    monkeypatch.setattr(trader_mode, "wallet_packs", lambda: packs)
    active = ShieldMode(True, {"wallets": ("metamask", "phantom", "ghost")})
    rows = _rows(_card(active), "Needs attention")
    assert "phantom: chosen but unavailable — manifest too large" in rows
    assert "ghost: chosen but unavailable — no such pack" in rows
    assert all((row.icon, row.state) == ("!", "warn") for row in rows.values())


def _saved(monkeypatch, **trader):
    """The config entry as a Settings save left it: ``shields.trader`` = *trader*."""
    from plugins.blackbox.kernel import config as kernel_config

    monkeypatch.setattr(kernel_config, "_blackbox_entry", lambda: {"shields": {"trader": trader}})


def _with_extra_supported_pack(monkeypatch, home):
    """This version supports one more wallet than any earlier save could have offered:
    the planned Rabby pack, promoted to supported."""
    import dataclasses

    packs = tuple(dataclasses.replace(pack, status="supported") if pack.id == "rabby" else pack
                  for pack in trader_mode.wallet_packs())
    assert any(pack.id == "rabby" for pack in packs)
    monkeypatch.setattr(trader_mode, "_packs", packs)


#: Saved when only the first five were offered: the six promoted on 2026-10-16 are new to that save.
NEW_SINCE_THE_FIRST_FIVE = "new since you last saved: Rabby, Coinbase Wallet, Trust Wallet, OKX Wallet, Keplr, Solflare"


def _attention(active):
    return list(_rows(_card(active), "Needs attention")) if "Needs attention" in [
        section.title for section in _card(active).sections] else []


def test_wallets_the_operator_left_unticked_are_never_called_new(home, monkeypatch):
    # The trader bench, 2026-10-15: MetaMask + Phantom saved out of the five offered; the card
    # said "new since you last saved: Exodus, Electrum, Solana CLI" for wallets just unticked.
    _config(monkeypatch)
    _saved(monkeypatch, enabled=True, wallets=["metamask", "phantom"], offered=list(trader_mode.supported_wallets()))
    assert _attention(trader_mode.build(enabled=True, wallets=("metamask", "phantom"))) == []


def test_a_wallet_added_after_the_save_is_named(home, monkeypatch):
    _config(monkeypatch)
    _with_extra_supported_pack(monkeypatch, home)
    _saved(monkeypatch, enabled=True, wallets=["metamask"],
           offered=["metamask", "phantom", "exodus", "electrum", "solana-cli"])
    assert _attention(trader_mode.build(enabled=True, wallets=("metamask",))) == [NEW_SINCE_THE_FIRST_FIVE]


def test_a_save_from_before_offered_was_recorded_counts_the_first_five_as_offered(home, monkeypatch):
    _config(monkeypatch)
    _with_extra_supported_pack(monkeypatch, home)
    _saved(monkeypatch, enabled=True, wallets=["metamask", "phantom"])   # no "offered": saved by an older version
    assert _attention(trader_mode.build(enabled=True, wallets=("metamask", "phantom"))) == [NEW_SINCE_THE_FIRST_FIVE]


def test_never_saved_means_every_supported_wallet_and_nothing_needs_attention(home, monkeypatch):
    _config(monkeypatch)
    _with_extra_supported_pack(monkeypatch, home)
    _saved(monkeypatch, enabled=True)   # no wallets list: every supported wallet is chosen
    assert _attention(trader_mode.build(enabled=True)) == []


# ------------------------------------------------------------------ the serving boundary


def test_no_file_under_shields_imports_safe_payloads_or_the_dashboard():
    offenders = []
    for path in (PLUGIN / "shields").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom):
                names = [node.module or ""] + [alias.name for alias in node.names]
                if any("safe_payloads" in name or "dashboard" in name for name in names):
                    offenders.append(f"{path.relative_to(PLUGIN)}:{node.lineno}")
            elif isinstance(node, ast.Import) and any("dashboard" in alias.name for alias in node.names):
                offenders.append(f"{path.relative_to(PLUGIN)}:{node.lineno}")
    assert not offenders


def test_the_route_sanitises_every_text_once(monkeypatch):
    hostile = ShieldStatus("trader", ShieldMode(True), True, (
        StatusSection("Found \x1b[31mhere", "see http://evil.example/x", (StatusRow("✓", "ok", "a‮b", "evil.example", "javascript:alert(1)"),
                                                                  StatusRow("✓", "ok", "x", "", "/shields/trader/packs/metamask/logo.svg"))),))
    monkeypatch.setattr(shields, "statuses", lambda: [hostile])
    calls = []
    real = shields_routes.safe_text
    monkeypatch.setattr(shields_routes, "safe_text", lambda value, limit: calls.append(value) or real(value, limit))
    [card] = shields_routes.statuses_payload()
    section = card["sections"][0]
    assert "\x1b" not in section["title"] and "evil[.]example" in section["help"] and "hxxp" in section["help"]
    assert section["rows"][0]["text"] == "ab" and section["rows"][0]["sub"].startswith("evil[.]example")
    assert section["rows"][0]["logo"] == "" and section["rows"][1]["logo"] == "/shields/trader/packs/metamask/logo.svg"   # a path, not text
    assert card["page"] == "/shields/trader" and card["name"] == TRADER.name   # the shield's own fields, for the page
    strings = ["trader", "Found \x1b[31mhere", "see http://evil.example/x", "✓", "ok", "a‮b", "evil.example",
               "✓", "ok", "x", "", TRADER.name, TRADER.tagline,
               *(kind.identifier for kind in TRADER.finding_kinds if kind.identifier)]
    assert sorted(calls) == sorted(strings)   # each string once, and nothing else


def _client(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from plugins.blackbox.dashboard import server

    monkeypatch.setenv("HOME", str(tmp_path))   # the app's agent discovery must not find the real ~/.hermes
    return TestClient(server.create_app(), base_url="http://127.0.0.1:9700")


def _await_cached(client, path, *, seconds=5.0):
    """The answer once the cache has filled (the first request answers the empty default)."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        answer = client.get(path).json()
        if answer:
            return answer
        time.sleep(0.02)
    raise AssertionError(f"{path} stayed empty")


def test_no_address_appears_anywhere_in_api_shields(home, monkeypatch):
    pytest.importorskip("fastapi")
    _config(monkeypatch)
    _mode(monkeypatch, enabled=True, wallets=("metamask",), addresses=(OWN,))
    _vault(home, "Local Extension Settings", METAMASK_CHROME)
    with _client(monkeypatch, home) as client:
        payload = _await_cached(client, "/api/shields")
    assert payload[0]["shield_id"] == "trader" and "addresses" not in payload[0]["mode"]
    assert "1 own address listed for raw keys" in json.dumps(payload, ensure_ascii=False)
    assert OWN not in json.dumps(payload).lower() and "ab" * 20 not in json.dumps(payload).lower()


def test_two_requests_inside_two_seconds_call_the_producer_once(home, monkeypatch):
    pytest.importorskip("fastapi")
    calls = []
    lock = threading.Lock()

    def producer():
        with lock:
            calls.append(time.monotonic())
        return [{"shield_id": "trader"}]

    monkeypatch.setattr(shields_routes, "statuses_payload", producer)
    with _client(monkeypatch, home) as client:
        first = _await_cached(client, "/api/shields")
        second = client.get("/api/shields").json()
    assert first == second == [{"shield_id": "trader"}]
    assert len(calls) == 1
    assert shields_routes.STATUS_TTL_SECONDS == 2.0


# ------------------------------------------------------------------ the captured payload (the dashboard replay and the bench proof)


def _every_section_setup(home, monkeypatch):
    """Found wallets, every watched rule, and both health rows."""
    _config(monkeypatch, "block")
    stores = [(normalize_path(f"~/.config/google-chrome/Default/local extension settings/{METAMASK_CHROME}"),
               Owner("metamask", "MetaMask")),
              (normalize_path(FIREFOX_STORE.format("a.default")), Owner("", FIREFOX_EXTENSION)),
              (normalize_path("~/.electrum/wallets/default_wallet"), Owner("electrum", "Electrum"))]
    monkeypatch.setattr(detectors.EXISTING_STORES, "get", lambda: stores)
    chosen = ShieldMode(True, {"wallets": ("metamask", "ghost"), "addresses": (OWN,)}, frozenset({"addresses"}))
    monkeypatch.setattr(trader_mode, "current", lambda: chosen)
    # Saved when Settings offered four wallets: the fifth (Solana CLI) is new since that save.
    _saved(monkeypatch, enabled=True, wallets=["metamask", "ghost"], offered=["metamask", "phantom", "exodus", "electrum"])


def test_the_captured_payload_has_every_section_and_no_address(home, monkeypatch):
    _every_section_setup(home, monkeypatch)
    captured = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert captured == shields_routes.statuses_payload()   # regenerate the fixture when the card changes
    titles = [section["title"] for section in captured[0]["sections"]]
    assert titles == ["Found on this machine", "Always watching", "Needs attention"]
    assert all(section["rows"] for section in captured[0]["sections"])
    assert OWN not in FIXTURE.read_text(encoding="utf-8").lower()


def test_an_off_shield_does_not_tick_its_own_checks(home, monkeypatch):
    """2026-11-08 (bb-test-4): with Trader Shield off, Desktop's Shields tab still ticked "Seed phrases
    — checker on" while a seed phrase went out unchecked. Off, its own checks read "not protected";
    protected files are a built-in rule and stay on."""
    _config(monkeypatch, mode="block")
    off = _rows(_card(trader_mode.build(enabled=False)), "Always watching")
    on = _rows(_card(trader_mode.build(enabled=True)), "Always watching")
    for name in ("Seed phrases", "Private keys"):
        assert off[name].state == "none" and "off" in off[name].sub, off[name]
        assert on[name].state == "ok"
    assert off["Protected files"].state == "ok"


@pytest.mark.parametrize("user", ["marc", "operator", "medgeman"])   # "arc", "opera", "edge" inside the name
def test_the_browser_comes_from_the_browser_folder_not_from_words_in_the_users_name(tmp_path, monkeypatch, user):
    """The card guessed the browser by looking for "arc", "opera", "edge"… ANYWHERE in the path, so a
    Chrome vault in a home folder named "marc" was shown as Arc. It is now the browser whose folder
    (browsers.json) the store sits in."""
    home = tmp_path / user
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("BLACKBOX_HOME", str(home / "bb"))
    detectors.EXISTING_STORES.reset()
    _vault(home, "Local Extension Settings", METAMASK_CHROME)
    [found] = trader_status.found_wallets()
    assert found["browser"] == "Chrome"
    assert trader_status.browser_of(str(home / ".config" / "google-chrome" / "Default")) == "Chrome"
    detectors.EXISTING_STORES.reset()
