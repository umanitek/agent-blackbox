"""Trader Shield's desktop-app and cli-key-file kinds (shields/trader/detectors/app_folder.py) —
moved from test_blackbox_app_wallets.py.

The layouts are copied from the real software installed on bench bb-trader-1
(2026-10-13): Exodus 26.10.7 (.deb) wrote ``~/.config/Exodus/exodus.wallet/{seed.seco,
passphrase.json,storage.seco}``; Electrum 4.8.2 (AppImage) wrote
``~/.electrum/wallets/default_wallet`` and ``~/.electrum/testnet/wallets/default_wallet``;
the Solana CLI 4.3.0 wrote ``~/.config/solana/id.json`` and a ``cli/config.yml`` naming it.

Each input goes through the detector, ``detectors.detect``. The old
``detection.detect_wallet_files`` gave identical findings apart from the added ``pack``
field until the old module was deleted; the attack table's Exodus, Electrum and Solana CLI rows and
each layout's own paths stay pinned, on Linux, macOS and Windows layouts, to what both
gave on that last run.
"""

from __future__ import annotations

import dataclasses
import os
import sys
import threading

import pytest

from _trader_attack_table import ATTACKS
from plugins.blackbox.shields.contract import Pack
from plugins.blackbox.shields.trader import detectors
from plugins.blackbox.shields.trader import mode as trader_mode
from plugins.blackbox.shields.trader.detectors import app_folder
from plugins.blackbox.shields.trader.detectors.app_folder import AppFolderMatcher
from plugins.blackbox.shields.trader.detectors.browser_extension import Owner
from test_blackbox_shields_trader_vault import RECORDED_ROW_PACKS

EVERY_PACK = trader_mode.build(enabled=True)
APP_PACKS = {pack.id for pack in trader_mode.wallet_packs()
             if pack.status == "supported" and pack.kind in app_folder.KINDS}


def _reset():
    for cache in (app_folder.POINTER_FILES, detectors.EXISTING_STORES):
        cache.reset()


def _detect(tool, args, active=EVERY_PACK):
    """The detector's findings, after checking that each names its pack by the wallet's id."""
    found = detectors.detect(tool, args, active)
    for finding in found:
        assert finding.fields.get("pack") == finding.fields["wallet"]
    return found


def _wallets(tool, args):
    return sorted(finding.fields["pack"] for finding in _detect(tool, args))


def _write_layout(home, exodus, electrum, solana):
    """Exodus, Electrum (mainnet and testnet) and the Solana CLI as the real installs left them."""
    electrum_testnet = electrum.parent / "testnet" / "wallets"
    for folder in (exodus, electrum, electrum_testnet, solana / "cli"):
        folder.mkdir(parents=True)
    for name in ("seed.seco", "passphrase.json", "storage.seco"):
        (exodus / name).write_text("x", encoding="utf-8")
    (electrum / "default_wallet").write_text("{}", encoding="utf-8")
    (electrum_testnet / "default_wallet").write_text("{}", encoding="utf-8")
    (solana / "id.json").write_text("[1,2,3]", encoding="utf-8")
    (solana / "cli" / "config.yml").write_text(
        f"---\njson_rpc_url: https://api.devnet.solana.com\nkeypair_path: {solana / 'id.json'}\ncommitment: confirmed\n",
        encoding="utf-8")


@pytest.fixture
def machine(tmp_path, monkeypatch):
    """A Linux home with the three apps' real layouts."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    _write_layout(tmp_path, tmp_path / ".config" / "Exodus" / "exodus.wallet", tmp_path / ".electrum" / "wallets",
                  tmp_path / ".config" / "solana")
    _reset()
    yield tmp_path
    _reset()


# -- moved from test_blackbox_app_wallets.py -------------------------------------------------

@pytest.mark.parametrize("tool, args, wallet", [
    ("read_file", {"path": "~/.config/Exodus/exodus.wallet/passphrase.json"}, "exodus"),
    ("terminal", {"command": "zip -r backups/e.zip ~/.config/Exodus/exodus.wallet"}, "exodus"),
    ("terminal", {"command": "cat ~/.electrum/wallets/default_wallet"}, "electrum"),
    ("terminal", {"command": "cp ~/.electrum/testnet/wallets/default_wallet out/"}, "electrum"),
    ("terminal", {"command": "cat ~/.config/solana/id.json"}, "solana-cli"),
    ("read_file", {"path": "$HOME/.config/solana/id.json"}, "solana-cli"),
    ("read_file", {"path": "~/.config/EXODUS/Exodus.Wallet/seed.seco"}, "exodus"),   # case-insensitive
])
def test_reading_an_app_wallet_is_found(machine, tool, args, wallet):
    assert _wallets(tool, args) == [wallet]


def test_a_finding_names_its_pack_by_id(machine):
    [finding] = _detect("terminal", {"command": "cat ~/.config/solana/id.json"})
    assert finding.fields["pack"] == "solana-cli" and "Solana CLI" in finding.title


def test_archiving_a_folder_that_holds_app_wallets_names_each(machine):
    assert _wallets("terminal", {"command": "tar czf conf.tgz ~/.config"}) == ["exodus", "solana-cli"]
    assert _wallets("terminal", {"command": "tar czf home.tgz ~"}) == ["electrum", "exodus", "solana-cli"]


def test_a_key_file_the_solana_config_names_elsewhere_is_protected(machine):
    elsewhere = machine / "keys" / "trading.json"
    elsewhere.parent.mkdir()
    elsewhere.write_text("[1]", encoding="utf-8")
    config = machine / ".config" / "solana" / "cli" / "config.yml"
    config.write_text(f"keypair_path: '{elsewhere}'\n", encoding="utf-8")
    _reset()
    assert _wallets("terminal", {"command": f"cat {elsewhere}"}) == ["solana-cli"]
    assert _wallets("terminal", {"command": f"tar czf k.tgz {elsewhere.parent}"}) == ["solana-cli"]


@pytest.mark.parametrize("command", [
    "solana-keygen pubkey ~/.config/solana/id.json",     # prints the PUBLIC key; the CLI reads the file itself
    "solana balance",
    "cat ~/.config/solana/cli/config.yml",               # settings, not a key
    "cat ~/.electrum/config",
    "ls ~/.config/Exodus",
    "cat ~/.config/Exodus/Preferences",                  # app settings, outside exodus.wallet
    "cat ~/.config/Exodus/exodus.wallet.bak",            # a sibling whose name only starts like the place
])
def test_ordinary_use_of_the_apps_is_left_alone(machine, command):
    assert _wallets("terminal", {"command": command}) == []


def test_the_existing_store_scan_lists_app_places_and_key_files(machine):
    found = {owner.pack for _path, owner in detectors.EXISTING_STORES.get()}
    assert found >= {"exodus", "electrum", "solana-cli"}


def test_app_wallets_follow_the_wallet_ticks(machine):
    only_exodus = trader_mode.build(enabled=True, wallets=("exodus",))
    assert [f.fields["pack"] for f in detectors.detect("terminal", {"command": "tar czf home.tgz ~"}, only_exodus)] \
        == ["exodus"]


def test_every_app_pack_can_be_ticked():
    assert APP_PACKS == {"exodus", "electrum", "solana-cli"} <= set(trader_mode.supported_wallets())


def test_a_windows_command_naming_the_folder_by_its_variable_is_found(machine, monkeypatch):
    # PowerShell/cmd write %APPDATA%\\Exodus\\…; where APPDATA is unset the name stays
    # literal on both sides and still matches.
    monkeypatch.delenv("APPDATA", raising=False)
    assert _wallets("terminal", {"command": r"copy %APPDATA%\Exodus\exodus.wallet\seed.seco C:\out"}) == ["exodus"]


# -- the generic pointer reader ------------------------------------------------------------------

def _pointer_pack(tmp_path, key="wallet_file", max_bytes=4096):
    return Pack(id="cli-test", name="CLI Test", kind="cli-key-file", status="supported", order=1, folder=tmp_path,
                data={"places": ["~/.cli-test/keys"], "label": "Command line",
                      "pointer": {"config": "~/.cli-test/settings.yml", "key": key, "max_bytes": max_bytes}})


@pytest.fixture
def pointer_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".cli-test").mkdir()
    _reset()
    yield tmp_path / ".cli-test" / "settings.yml"
    _reset()


def test_only_the_key_line_is_read(tmp_path, pointer_home):
    """Commented, indented, longer-named and empty lines are not the key's line; the value
    comes from that one line only, never the next."""
    pointer_home.write_text("# wallet_file: /decoy/commented.json\n  wallet_file: /decoy/indented.json\n"
                            "other_wallet_file: /decoy/other.json\nwallet_files: /decoy/plural.json\n"
                            "wallet_file:\n/decoy/next-line.json\nwallet_file: \"/Keys/Real.json\"\n", encoding="utf-8")
    pack = _pointer_pack(tmp_path)
    assert app_folder.POINTER_FILES.get(pack) == "/keys/real.json"
    matcher = AppFolderMatcher([pack])
    assert matcher.owner("/keys/real.json") == Owner("cli-test", "CLI Test")
    assert all(matcher.owner(f"/decoy/{name}.json") is None
               for name in ("commented", "indented", "other", "plural", "next-line"))


def test_the_key_is_a_literal_prefix_never_a_pattern(tmp_path, pointer_home):
    # A key is ^[a-z_]{1,32}$ (the loader's rule); "_" must not stand for any character.
    pointer_home.write_text("walletxfile: /decoy/x.json\n", encoding="utf-8")
    assert app_folder.POINTER_FILES.get(_pointer_pack(tmp_path)) is None


def test_a_value_with_a_quote_inside_names_no_file(tmp_path, pointer_home):
    # As the old keypair_path regex: an odd-quoted value is not a path to protect, so a later good line wins.
    pointer_home.write_text("wallet_file: \"/decoy/a\"b.json\"\nwallet_file: '/keys/real.json'\n", encoding="utf-8")
    assert app_folder.POINTER_FILES.get(_pointer_pack(tmp_path)) == "/keys/real.json"


def test_the_pointer_is_reread_when_the_config_changes(tmp_path, pointer_home):
    pack = _pointer_pack(tmp_path)
    pointer_home.write_text("wallet_file: /keys/one.json\n", encoding="utf-8")
    assert app_folder.POINTER_FILES.get(pack) == "/keys/one.json"
    pointer_home.write_text("wallet_file: /keys/two.json\n", encoding="utf-8")
    os.utime(pointer_home, (1, 1))   # a different modification time, whatever the clock's resolution
    assert app_folder.POINTER_FILES.get(pack) == "/keys/two.json"


def test_an_oversize_config_is_ignored(tmp_path, pointer_home):
    pointer_home.write_text("wallet_file: /keys/real.json\n" + "#" * 100 + "\n", encoding="utf-8")
    assert app_folder.POINTER_FILES.get(_pointer_pack(tmp_path, max_bytes=64)) is None
    _reset()
    assert app_folder.POINTER_FILES.get(_pointer_pack(tmp_path, max_bytes=4096)) == "/keys/real.json"


def test_an_oversize_solana_config_is_ignored(machine):
    elsewhere = machine / "keys" / "trading.json"
    config = machine / ".config" / "solana" / "cli" / "config.yml"
    config.write_text(f"keypair_path: {elsewhere}\n" + "#" * (64 * 1024) + "\n", encoding="utf-8")
    _reset()
    assert _wallets("terminal", {"command": f"cat {elsewhere}"}) == []


@pytest.mark.skipif(sys.platform == "win32", reason="Windows has no named pipes in the file system")
def test_a_named_pipe_at_the_config_place_never_stalls_the_check(machine):
    """The check runs in a thread with a join timeout so a regression fails instead of hanging the suite."""
    config = machine / ".config" / "solana" / "cli" / "config.yml"
    config.unlink()
    os.mkfifo(config)
    _reset()
    outcome = []
    worker = threading.Thread(
        target=lambda: outcome.append(detectors.detect("terminal", {"command": "tar czf h.tgz ~/notes"}, EVERY_PACK)),
        daemon=True)
    worker.start()
    worker.join(1.0)
    assert not worker.is_alive(), "detect blocked on the pointer's config place"
    assert outcome == [[]]


# -- the matcher and the validator, built from packs -------------------------------------------

def test_planned_and_other_kind_packs_build_no_app_matcher():
    assert {pack.id for pack in detectors.app_matcher().packs} == APP_PACKS


def test_a_planned_app_pack_protects_nothing(tmp_path, pointer_home):
    """No shipped app pack is planned today, so a made-up one proves only supported packs are matched."""
    pointer_home.write_text("wallet_file: /keys/real.json\n", encoding="utf-8")
    planned = dataclasses.replace(_pointer_pack(tmp_path), status="planned")
    matcher = AppFolderMatcher([planned])
    assert matcher.packs == ()
    assert matcher.owner(os.path.join(str(tmp_path), ".cli-test", "keys", "k.json").lower()) is None
    assert matcher.owner("/keys/real.json") is None


@pytest.mark.parametrize("template_segment, segment, fits", [
    ("*.json", "id.json", True), ("*.json", ".json", False), ("*.json", "id.json.bak", False),
    ("*", "testnet", True), ("a*b*c", "axbyc", True), ("a*b*c", "abc", False), ("a*a", "a", False),
    ("wallets", "wallets", True), ("wallets", "wallets2", False),
])
def test_a_star_stands_for_one_or_more_characters_in_one_segment(template_segment, segment, fits):
    assert app_folder._segment_matches(template_segment, segment) is fits


@pytest.mark.parametrize("manifest, problem", [
    ({"kind": "desktop-app", "places": ["~/.a/b"], "label": "Desktop app"}, None),
    ({"kind": "desktop-app", "places": ["~/.a/b"], "label": "Desktop app", "stores": {}}, "no field 'stores'"),
    ({"kind": "desktop-app", "places": [], "label": "Desktop app"}, "places must name"),
    ({"kind": "cli-key-file", "places": ["~/.a/b"], "label": " "}, "label must say"),
])
def test_the_app_folder_validator_sits_beside_its_matcher(manifest, problem):
    detector = next(item for item in detectors.DETECTORS if "cli-key-file" in item.KINDS)
    assert detector.check is app_folder.validate_pack
    answer = detector.validate_pack(manifest)
    assert answer is None if problem is None else problem in answer


# -- the attack table's app rows on Linux, macOS and Windows layouts, pinned to both detectors ----

APP_ROWS = [row for row in ATTACKS   # page rows with their tool calls (_trader_attack_table)
            if row["proof"] == "test" and row["group"] == "vault" and set(row["targets"]) & APP_PACKS]


def _linux(home, monkeypatch):
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    _write_layout(home, home / ".config" / "Exodus" / "exodus.wallet", home / ".electrum" / "wallets",
                  home / ".config" / "solana")
    return ["~/.config/Exodus/exodus.wallet/seed.seco", "~/.electrum/testnet/wallets/default_wallet",
            "~/.config/solana/id.json", "~/.CONFIG/Solana/ID.json"]


def _linux_xdg(home, monkeypatch):
    config = home / "Settings"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config))
    _write_layout(home, config / "Exodus" / "exodus.wallet", home / ".electrum" / "wallets", config / "solana")
    return [f"{config}/Exodus/exodus.wallet/seed.seco", f"{config}/solana/id.json", "~/.config/solana/id.json"]


def _macos(home, monkeypatch):
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    support = home / "Library" / "Application Support"
    _write_layout(home, support / "Exodus" / "exodus.wallet", home / ".electrum" / "wallets",
                  home / ".config" / "solana")
    return ["~/Library/Application Support/Exodus/exodus.wallet/passphrase.json",
            "~/library/application support/exodus/EXODUS.WALLET/seed.seco", "~/.electrum/wallets/default_wallet"]


def _windows(home, monkeypatch):
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    roaming, local = home / "AppData" / "Roaming", home / "AppData" / "Local"
    monkeypatch.setenv("APPDATA", str(roaming))
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    _write_layout(home, roaming / "Exodus" / "exodus.wallet", roaming / "Electrum" / "wallets",
                  home / ".config" / "solana")
    (local / "Electrum" / "signet" / "wallets").mkdir(parents=True)
    return [r"%APPDATA%\Exodus\exodus.wallet\seed.seco", "%APPDATA%/ELECTRUM/testnet/Wallets/default_wallet",
            r"%LOCALAPPDATA%\Electrum\signet\wallets\w", f"{roaming}/Electrum/wallets/default_wallet"]


LAYOUTS = {"linux": _linux, "linux-xdg": _linux_xdg, "macos": _macos, "windows": _windows}

#: Recorded on the last run where the old and new detectors agreed: the pack each layout's own
#: paths name (in the order the layout lists them), and what the two archive commands name.
RECORDED_OWN_PATH_PACKS = {
    "linux": ["exodus", "electrum", "solana-cli", "solana-cli"],
    "linux-xdg": ["exodus", "solana-cli", "solana-cli"],
    "macos": ["exodus", "exodus", "electrum"],
    "windows": ["exodus", "electrum", "electrum", "electrum"],
}
EVERY_APP = ["electrum", "exodus", "solana-cli"]
RECORDED_ARCHIVE_PACKS = {   # (tar of the home folder, zip of ~/AppData ~/Library ~/.config)
    "linux": (EVERY_APP, ["exodus", "solana-cli"]),
    "linux-xdg": (EVERY_APP, []),
    "macos": (EVERY_APP, ["exodus", "solana-cli"]),
    "windows": (EVERY_APP, EVERY_APP),
}


@pytest.fixture(params=sorted(LAYOUTS))
def layout(request, tmp_path, monkeypatch):
    """One OS layout of the three apps inside a temporary HOME; yields its name and its own paths."""
    monkeypatch.setenv("HOME", str(tmp_path))
    paths = LAYOUTS[request.param](tmp_path, monkeypatch)
    _reset()
    yield request.param, paths
    _reset()


def test_the_attack_table_has_the_app_rows():
    ids = {row["id"] for row in APP_ROWS}
    assert {"exodus-wallet-zip", "electrum-wallet-copy", "solana-cli-keyfile-read",
            "solana-cli-pubkey-left-alone", "vault-script-home-join"} <= ids


@pytest.mark.parametrize("row", APP_ROWS, ids=[row["id"] for row in APP_ROWS])
def test_every_app_row_gives_the_recorded_findings_on_every_layout(layout, row):
    found = _wallets(row["tool"], row["args"])
    # The rows name ~/.config paths: with $XDG_CONFIG_HOME moved elsewhere, Exodus is not there.
    moved_away = row["id"] == "exodus-wallet-zip" and "XDG_CONFIG_HOME" in os.environ
    assert found == ([] if moved_away else sorted(RECORDED_ROW_PACKS[row["id"]])), layout[0]
    if row["outcome"] == "blocked" and not moved_away:
        assert found, row["id"]


def test_each_layouts_own_paths_give_the_recorded_findings(layout):
    name, paths = layout
    for path, pack in zip(paths, RECORDED_OWN_PATH_PACKS[name], strict=True):
        assert _wallets("read_file", {"path": path}) == [pack], path
        assert _wallets("terminal", {"command": f"cat '{path}'"}) == [pack], path
    home_tar, config_zip = RECORDED_ARCHIVE_PACKS[name]
    assert _wallets("terminal", {"command": "tar czf home.tgz ~"}) == home_tar
    assert _wallets("terminal", {"command": "zip -r all.zip ~/AppData ~/Library ~/.config"}) == config_zip


@pytest.mark.parametrize("variable", ["APPDATA", "LOCALAPPDATA"])
def test_an_empty_windows_root_is_unset_not_the_filesystem_root(monkeypatch, variable):
    """The app-place expander replaced an EMPTY %APPDATA% with "", so %APPDATA%/Exodus became
    /Exodus — a folder at the filesystem root. Empty counts as unset now, as it always did for
    $XDG_CONFIG_HOME: the place stays as written (matched literally, never looked for on disk)."""
    from plugins.blackbox.shields.trader.detectors.app_folder import expand_template
    monkeypatch.setenv(variable, "")
    assert expand_template(f"%{variable}%/Exodus", keep_unset=True) == f"%{variable}%/Exodus"
    assert expand_template(f"%{variable}%/Exodus").endswith("/AppData/" + ("Roaming" if variable == "APPDATA" else "Local") + "/Exodus")
