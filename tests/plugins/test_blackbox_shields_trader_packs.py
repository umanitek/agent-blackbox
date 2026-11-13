"""Trader Shield's wallets and browser roots as data (shields/trader/wallets/, browsers.json).

The two "coming soon" lists are pinned first, against the code they replace, so moving the
wallets into packs cannot quietly change what Settings and the page promise. Then
the data is held to the code it replaced (code -> data): the eleven packs load,
and the ids, names, extension ids, places and browser roots they state equal the values the
old Python tables (detection/wallet_files.py, detection/app_wallets.py, since deleted)
gave on the last run that had both, under Linux, macOS and Windows layouts with
mixed-case input. That a supported pack has earned it (a blocked
``vault`` row names it) is checked with every shield's attack table, in
test_blackbox_trader_shield_attacks.py.
"""

import json

import pytest
from _blackbox_loader import load_blackbox


shields = load_blackbox("shields")
packs_loader = load_blackbox("shields.packs")
trader_mode = load_blackbox("shields.trader.mode")
detectors = load_blackbox("shields.trader.detectors")
app_folder = load_blackbox("shields.trader.detectors.app_folder")
browser_extension = load_blackbox("shields.trader.detectors.browser_extension")

TRADER = shields.get("trader")
PACKS = packs_loader.load_packs(TRADER)
ROOTS, ROOT_HEALTH = packs_loader.load_browser_roots(TRADER)
SUPPORTED = {pack.id: pack for pack in PACKS if pack.status == "supported"}


def test_settings_coming_soon_is_unchanged():
    fields = shields.settings_view()["trader"]["fields"]
    wallets = next(field for field in fields if field["kind"] == "multi-pick")
    planned = [option["name"] for option in wallets["options"] if option["status"] == "planned"]
    assert planned == []   # the last six were promoted to supported on 2026-10-16


def test_page_coming_next_is_unchanged():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    routes = load_blackbox("dashboard.shields_routes")
    app = FastAPI()
    routes.register_pages(app)
    content = TestClient(app).get("/shields/trader/content.json")   # the page's "Coming soon" chips, as served
    assert content.status_code == 200
    assert content.json()["coming"] == ["Bitcoin Core", "More exchanges", "Safari wallets"]


# ------------------------------------------------------------------ what loads


def test_registry_loads_eleven_supported_none_planned_none_unavailable():
    by_status = {status: [pack.id for pack in PACKS if pack.status == status]
                 for status in ("supported", "planned", "unavailable")}
    assert by_status == {
        "supported": ["metamask", "phantom", "exodus", "electrum", "solana-cli",
                      "rabby", "coinbase-wallet", "trust-wallet", "okx-wallet", "keplr", "solflare"],
        "planned": [],
        "unavailable": [],
    }
    assert [pack.order for pack in PACKS][-6:] == [110, 120, 130, 140, 150, 160]


@pytest.mark.parametrize("pack_id", ["solana-cli", "coinbase-wallet", "trust-wallet", "okx-wallet"])
def test_hyphenated_ids_load_by_name(pack_id):
    pack = next(pack for pack in PACKS if pack.id == pack_id)
    assert pack.status in ("supported", "planned") and pack.folder.name == pack_id


def test_browsers_json_states_the_31_roots():
    entries = json.loads((TRADER.folder / "browsers.json").read_text(encoding="utf-8"))
    engines = [entry["engine"] for entry in entries]
    assert len(entries) == 31 and engines.count("firefox") == 7 and engines.count("chromium") == 24


def test_registry_loads_31_browser_roots_none_dropped():
    assert (len(ROOTS), ROOT_HEALTH) == (31, ())


def test_mode_and_settings_read_the_packs():
    assert trader_mode.supported_wallets() == {"metamask": "MetaMask", "phantom": "Phantom", "exodus": "Exodus",
                                               "electrum": "Electrum", "solana-cli": "Solana CLI", "rabby": "Rabby",
                                               "coinbase-wallet": "Coinbase Wallet", "trust-wallet": "Trust Wallet",
                                               "okx-wallet": "OKX Wallet", "keplr": "Keplr", "solflare": "Solflare"}
    assert trader_mode.wallets(trader_mode.build()) == tuple(SUPPORTED)
    wallets = next(field for field in TRADER.settings_fields() if field.kind == "multi-pick")
    assert [(option.id, option.status) for option in wallets.options] == [
        (pack.id, pack.status) for pack in PACKS if pack.status != "unavailable"]


def test_logos_ship_with_their_terms():
    for pack_id in ("metamask", "phantom", "exodus", "electrum", "solana-cli", "rabby", "coinbase-wallet",
                    "trust-wallet", "keplr", "solflare"):
        pack = SUPPORTED[pack_id]
        assert pack.logo is not None and (pack.folder / pack.logo.file).is_file()
        assert (pack.folder / pack.logo.terms).read_text(encoding="utf-8").strip()
        assert shields.pack_logo("trader", pack_id) == pack.folder / "logo.svg"
    assert shields.pack_logo("trader", "okx-wallet") is None   # no official square SVG found (2026-10-16)


# ------------------------------- the same as the old code, recorded on its last green run

#: ``detection.wallet_files.WALLETS``: id -> (name, Chromium ids, Firefox add-on ids).
RECORDED_EXTENSION_WALLETS = {
    "metamask": ("MetaMask", ("nkbihfbeogaeaoehlefnkodbefgpgknn", "ejbalbakoplchlghecdalmeeeajnimhm"),
                 ("webextension@metamask.io",)),
    "phantom": ("Phantom", ("bfnaelmomeimhlpmgjnjophhpkkoljpa",), ("{7c42eea1-b3e4-4be4-a56f-82a5852b12dc}",)),
    # Promoted 2026-10-16, each proven on a real install (Chrome Web Store; Firefox where the publisher ships one).
    "rabby": ("Rabby", ("acmacodkjbdgmoleebolmdjonilkdbch",), ()),
    "coinbase-wallet": ("Coinbase Wallet", ("hnfanknocfeofbddgcijnmhnfnkdnaad",), ()),
    "trust-wallet": ("Trust Wallet", ("egjidjbpglichdcondbcbdnbeeppgdph",), ()),
    "okx-wallet": ("OKX Wallet", ("mcohilncbfahbmgdjkbpemcciiolgcge",), ()),
    "keplr": ("Keplr", ("dmkamcknogkgcdfhhbddcghachkejeap",), ('keplr-extension@keplr.app',)),
    "solflare": ("Solflare", ("bhhhlbepdkbapadjdnnojkbgioiodbic",), ('{6d72262a-b243-4dc6-8f4f-be96c74e0a86}',)),
}
#: ``detection.app_wallets.APP_WALLETS``: id -> (name, places, label).
RECORDED_APP_WALLETS = {
    "exodus": ("Exodus", ("$XDG_CONFIG_HOME/Exodus/exodus.wallet", "~/Library/Application Support/Exodus/exodus.wallet",
                          "%APPDATA%/Exodus/exodus.wallet"), "Desktop app"),
    "electrum": ("Electrum", ("~/.electrum/wallets", "~/.electrum/*/wallets", "%APPDATA%/Electrum/wallets",
                              "%APPDATA%/Electrum/*/wallets", "%LOCALAPPDATA%/Electrum/wallets",
                              "%LOCALAPPDATA%/Electrum/*/wallets"), "Desktop app"),
    "solana-cli": ("Solana CLI", ("$XDG_CONFIG_HOME/solana/*.json", "~/.config/solana/*.json"), "Command line"),
}
RECORDED_SOLANA_CONFIG = "$XDG_CONFIG_HOME/solana/cli/config.yml"
#: ``detection.wallet_files._browser_roots()``, written back as templates (~, $XDG_CONFIG_HOME,
#: %APPDATA%, %LOCALAPPDATA% for the folders it expanded them to).
RECORDED_BROWSER_ROOTS = (
    "$XDG_CONFIG_HOME/BraveSoftware/Brave-Browser*", "$XDG_CONFIG_HOME/chromium", "$XDG_CONFIG_HOME/google-chrome*",
    "$XDG_CONFIG_HOME/microsoft-edge*", "$XDG_CONFIG_HOME/mozilla/firefox/*", "$XDG_CONFIG_HOME/opera",
    "$XDG_CONFIG_HOME/vivaldi",
    "%APPDATA%/Mozilla/Firefox/Profiles/*", "%APPDATA%/Opera Software/Opera*",
    "%LOCALAPPDATA%/BraveSoftware/Brave-Browser*/User Data", "%LOCALAPPDATA%/Chromium/User Data",
    "%LOCALAPPDATA%/Google/Chrome*/User Data", "%LOCALAPPDATA%/Microsoft/Edge*/User Data",
    "%LOCALAPPDATA%/Vivaldi/User Data",
    "~/.mozilla/firefox/*",
    "~/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser*",
    "~/.var/app/com.google.Chrome/config/google-chrome*", "~/.var/app/com.microsoft.Edge/config/microsoft-edge*",
    "~/.var/app/org.chromium.Chromium/config/chromium", "~/.var/app/org.mozilla.firefox/.mozilla/firefox/*",
    "~/.var/app/org.mozilla.firefox/config/mozilla/firefox/*",
    "~/Library/Application Support/Arc/User Data", "~/Library/Application Support/BraveSoftware/Brave-Browser*",
    "~/Library/Application Support/Chromium", "~/Library/Application Support/Firefox/Profiles/*",
    "~/Library/Application Support/Google/Chrome*", "~/Library/Application Support/Microsoft Edge*",
    "~/Library/Application Support/Vivaldi", "~/Library/Application Support/com.operasoftware.Opera*",
    "~/snap/chromium/common/chromium", "~/snap/firefox/common/.mozilla/firefox/*",
)


def test_browser_extension_packs_equal_the_recorded_wallets():
    data = {pack.id: (pack.name, tuple(pack.data["stores"].get("chromium", ())),
                      tuple(pack.data["stores"].get("firefox", ())))
            for pack in SUPPORTED.values() if pack.kind == "browser-extension"}
    assert data == RECORDED_EXTENSION_WALLETS


def test_app_folder_packs_equal_the_recorded_app_wallets():
    data = {pack.id: (pack.name, tuple(pack.data["places"]), pack.data["label"])
            for pack in SUPPORTED.values() if pack.kind in ("desktop-app", "cli-key-file")}
    assert data == RECORDED_APP_WALLETS
    assert SUPPORTED["solana-cli"].data["pointer"] == {
        "config": RECORDED_SOLANA_CONFIG, "key": "keypair_path", "max_bytes": 65536}


#: Three machines, each with mixed-case folder names (matching ignores case on both sides).
LAYOUTS = {
    "linux": {"HOME": "/home/TraDer", "XDG_CONFIG_HOME": "/home/TraDer/.Config",
              "APPDATA": "/home/TraDer/AppData/Roaming", "LOCALAPPDATA": "/home/TraDer/AppData/Local"},
    "linux-default-xdg": {"HOME": "/home/TraDer", "XDG_CONFIG_HOME": None,
                          "APPDATA": None, "LOCALAPPDATA": None},
    "macos": {"HOME": "/Users/TraDer", "XDG_CONFIG_HOME": None, "APPDATA": None, "LOCALAPPDATA": None},
    "windows": {"HOME": "C:/Users/TraDer", "XDG_CONFIG_HOME": None,
                "APPDATA": "C:/Users/TraDer/AppData/Roaming", "LOCALAPPDATA": "C:/Users/TraDer/AppData/Local"},
}


@pytest.fixture(params=sorted(LAYOUTS))
def layout(request, monkeypatch):
    """The environment of one machine layout; the detectors read it from os.environ."""
    for name, value in LAYOUTS[request.param].items():
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    monkeypatch.setattr(app_folder.POINTER_FILES, "get", lambda pack: None)   # no config on this machine
    return LAYOUTS[request.param]


def _expand(template: str, env: dict) -> str:
    """A path template under *env*, with the defaults the old code used for unset variables."""
    home = env["HOME"]
    roots = {"~": home, "$XDG_CONFIG_HOME": env["XDG_CONFIG_HOME"] or f"{home}/.config",
             "%APPDATA%": env["APPDATA"] or f"{home}/AppData/Roaming",
             "%LOCALAPPDATA%": env["LOCALAPPDATA"] or f"{home}/AppData/Local"}
    root, _, rest = template.partition("/")
    return f"{roots[root]}/{rest}"


def _mixed_case(path: str) -> str:
    """*path* with every other letter's case flipped — how an agent might type it."""
    return "".join(char.swapcase() if index % 2 else char for index, char in enumerate(path))


def test_places_match_the_recorded_owner_on_every_layout(layout):
    for pack in SUPPORTED.values():
        if pack.kind not in ("desktop-app", "cli-key-file"):
            continue
        for template in pack.data["places"]:
            if "%" in template and not layout["APPDATA"]:
                continue   # an unset %VAR% stays literal and is never looked for
            inside = _expand(template, layout).replace("*", "Testnet") + ("" if template.endswith(".json") else "/x")
            owner = detectors.app_matcher().owner(browser_extension.normalize_path(_mixed_case(inside)))
            assert owner is not None and owner.wallet == RECORDED_APP_WALLETS[pack.id][0], inside


def test_browser_roots_match_the_recorded_roots_on_every_layout(layout):
    recorded = {_expand(template, layout).lower() for template in RECORDED_BROWSER_ROOTS}
    entries = json.loads((TRADER.folder / "browsers.json").read_text(encoding="utf-8"))
    data = {_mixed_case(_expand(entry["path"], layout)).lower() for entry in entries}
    assert data == recorded


def test_the_shield_uses_the_registrys_one_read_of_its_packs_and_browser_roots():
    """The packs and browsers.json were read two or three times at import (the registry, the
    mode, and the key-store scan under its own cache), so a bad pack's warning was logged more
    than once. The registry reads them once and hands the same objects to the shield."""
    from plugins.blackbox import shields
    from plugins.blackbox.shields.trader import detectors, mode as trader_mode
    loaded = shields._DATA["trader"]
    assert trader_mode.wallet_packs() is loaded.packs and loaded.packs
    assert detectors.browser_roots() is loaded.roots and loaded.roots
