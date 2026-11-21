"""Shields skeleton: the contract records, the registry, and the pack / browser-root loader.

One named test per loader rule (docs: plugins/blackbox/shields/packs.py): template
shapes, reserved ids, logo terms and lint, the file-safety rules (size cap, symlinked
manifest, symlinked logo, FIFO, folder-name case, case twins, duplicate key, nesting
depth), browser-root rules, and that a corrupt pack never takes the registry down.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional

import pytest

from plugins.blackbox import shields
from plugins.blackbox.detection import Finding
from plugins.blackbox.kernel.settings import ShieldSettings
from plugins.blackbox.shields import packs
from plugins.blackbox.shields.contract import (
    AttackRow,
    BrowserRoot,
    Capability,
    EventFact,
    FindingKind,
    Pack,
    PackLogo,
    SessionSummary,
    SettingField,
    SettingOption,
    Shield,
    ShieldEvent,
    ShieldMode,
    ShieldsSnapshot,
    ShieldStatus,
    StatusRow,
    StatusSection,
    TimelineStep,
)
from plugins.blackbox.shields.packs import PackError, check_template

CLEAN_SVG = '<svg xmlns="http://www.w3.org/2000/svg"><use href="#m"/><path d="M0 0h1"/></svg>'


def _needs_stores(manifest: dict[str, Any]) -> Optional[str]:
    return None if manifest.get("stores") else "stores names no extension id"


def _needs_places(manifest: dict[str, Any]) -> Optional[str]:
    return None if manifest.get("places") else "places names no folder"


#: A fake detector table: one detector per kind group, each validating its own block.
DETECTORS = (SimpleNamespace(KINDS=("browser-extension",), validate_pack=_needs_stores),
             SimpleNamespace(KINDS=("desktop-app", "cli-key-file"), validate_pack=_needs_places))

CAPABILITIES = (Capability(id="exchanges", name="Exchanges", note="API keys", claims=("secret:exchange-api-key",)),
                Capability(id="secrets", name="Secrets", note="display only"))

EXTENSION = {"id": "metamask", "name": "MetaMask", "kind": "browser-extension", "status": "supported",
             "order": 10, "verified": "2026-10-13", "source": "store listings",
             "stores": {"chromium": ["nkbihfbeogaeaoehlefnkodbefgpgknn"], "firefox": ["webextension@metamask.io"]}}
DESKTOP = {"id": "electrum", "name": "Electrum", "kind": "desktop-app", "status": "supported", "order": 40,
           "verified": "2026-10-13", "source": "Electrum 4.5", "places": ["~/.electrum/wallets"],
           "label": "Desktop app"}
CLI = {"id": "solana-cli", "name": "Solana CLI", "kind": "cli-key-file", "status": "supported", "order": 50,
       "verified": "2026-10-13", "source": "Solana CLI 4.3.0",
       "places": ["$XDG_CONFIG_HOME/solana/*.json", "~/.config/solana/*.json"],
       "pointer": {"config": "$XDG_CONFIG_HOME/solana/cli/config.yml", "key": "keypair_path", "max_bytes": 65536},
       "label": "Command line"}
PLANNED = {"id": "trust-wallet", "name": "Trust Wallet", "kind": "hardware-companion", "status": "planned",
           "order": 70}

FIREFOX_ROOT = {"browser": "firefox", "engine": "firefox", "os": "linux", "install": "snap",
                "path": "~/snap/firefox/common/.mozilla/firefox/*", "profiles": "self",
                "verified": "2026-10-13", "source": "Firefox 157 snap"}
CHROME_ROOT = {"browser": "chrome", "engine": "chromium", "os": "macos", "install": "native",
               "path": "~/Library/Application Support/Google/Chrome", "profiles": "children",
               "verified": "2026-10-13", "source": "Chrome 141"}


# ---------------------------------------------------------------- helpers


def _shield(folder: Path, *, roots: bool = False, **overrides: Any) -> Shield:
    """A fake shield over *folder* (packs in ``folder/wallets``); every callable is trivial."""
    (folder / "wallets").mkdir(parents=True, exist_ok=True)
    fields: dict[str, Any] = dict(
        id="trader", name="Trader Shield", tagline="Wallets", beta=True,
        mode=lambda: ShieldMode(enabled=True), validate=lambda payload: ShieldSettings("trader", {}, []),
        detect=lambda tool, args, current: [], claims=lambda finding: False, allows=lambda finding, current: True,
        status=lambda current: ShieldStatus("trader", current, False), events=list,
        settings_fields=list, finding_kinds=(), capabilities=CAPABILITIES,
        packs=folder / "wallets", page=folder / "page" / "trader.html", attacks=folder / "attacks.json",
        detectors=DETECTORS, browser_roots=folder / "browsers.json" if roots else None)
    fields.update(overrides)
    return Shield(**fields)


def _pack(shield: Shield, folder: str, manifest: Any, *, file: str = "wallet.json") -> Path:
    """Write *manifest* (an object, or raw text) as ``wallets/<folder>/<file>``."""
    target = shield.packs / folder
    target.mkdir(parents=True, exist_ok=True)
    text = manifest if isinstance(manifest, str) else json.dumps(manifest)
    (target / file).write_text(text, encoding="utf-8")
    return target


def _with_logo(shield: Shield, svg: str = CLEAN_SVG, *, terms: bool = True) -> Path:
    folder = _pack(shield, "metamask", {**EXTENSION, "logo": {"file": "logo.svg", "terms": "NOTICE.md"}})
    (folder / "logo.svg").write_text(svg, encoding="utf-8")
    if terms:
        (folder / "NOTICE.md").write_text("ISC licence", encoding="utf-8")
    return folder


def _by_id(shield: Shield) -> dict[str, Pack]:
    return {pack.id: pack for pack in packs.load_packs(shield)}


def _only(shield: Shield) -> Pack:
    (pack,) = packs.load_packs(shield)
    return pack


def _roots(shield: Shield, entries: Any) -> tuple[tuple[BrowserRoot, ...], tuple[str, ...]]:
    assert shield.browser_roots is not None
    shield.browser_roots.write_text(json.dumps(entries), encoding="utf-8")
    return packs.load_browser_roots(shield)


def _case_insensitive(folder: Path) -> bool:
    (folder / "Probe").mkdir(parents=True)
    return (folder / "probe").exists()


def _case_twins(monkeypatch: pytest.MonkeyPatch, shield: Shield, lower: str, upper: str) -> None:
    """``lower/`` and ``upper/`` side by side: real on a case-sensitive disk, else listed as the disk would."""
    if _case_insensitive(shield.folder / "probe-area"):
        on_disk = packs._folder_names(shield.packs)
        monkeypatch.setattr(packs, "_folder_names", lambda folder: sorted([*on_disk, upper]))
    else:
        (shield.packs / upper).mkdir()
        (shield.packs / upper / "wallet.json").write_text((shield.packs / lower / "wallet.json").read_text())


# ---------------------------------------------------------------- records


def test_records_round_trip_to_json():
    mode = ShieldMode(enabled=True, options={"wallets": ("metamask",), "addresses": ("0xabc",)},
                      personal=frozenset({"addresses"}))
    session = SessionSummary("s1", "hermes", "m", "2026-10-14T00:00:00Z", "", "running", 3)
    records = [
        StatusRow("wallet", "ok", "MetaMask found", "Chrome", "/logo.svg"),
        StatusSection("Found", "help", (StatusRow("i", "ok", "t"),)),
        ShieldStatus("trader", mode, True, (StatusSection("Found", "help"),)),
        TimelineStep("tool", 1.5, "terminal", "cat x", "ok", ("blocked",), ("Vault read",), True),
        ShieldEvent(1.0, "secret:crypto-wallet", "Vault", "critical", "blocked", "terminal", "cat x", "asked",
                    "/logo.svg", "<b>Stopped</b>", session, ("Rotate",), (EventFact("Wallet", "MetaMask", True),),
                    (TimelineStep("tool", 1.0, "terminal", "cat x"),)),
        AttackRow("vault-1", "vault", ("metamask",), "test", "blocked", "Read vault", "cat", "terminal",
                  {"command": "cat x"}, ("tests",)),
        CAPABILITIES[0],
        FindingKind("wallet-drain", "wallet-keys", "T1555.003", identifier="*:crypto-wallet"),
        SettingField("wallets", "multi-pick", "Wallets", "help", (SettingOption("metamask", "MetaMask", "supported"),)),
        Pack("metamask", "MetaMask", "browser-extension", "supported", 10, Path("/x/metamask"),
             {"stores": {"chromium": ["a"]}}, PackLogo("logo.svg", "NOTICE.md"), "2026-10-13", "store"),
        BrowserRoot(**CHROME_ROOT),
        ShieldsSnapshot(),
    ]
    for record in records:
        data = record.as_json()
        assert json.loads(json.dumps(data)) == data, type(record).__name__
    assert ShieldStatus("trader", mode, True).as_json()["mode"] == {"enabled": True, "wallets": ["metamask"]}
    assert mode.as_json(include_personal=True)["addresses"] == ["0xabc"]
    assert records[9].as_json()["folder"] == "/x/metamask"


def test_shield_as_json_holds_its_descriptive_fields_only(tmp_path):
    data = _shield(tmp_path).as_json()
    assert json.loads(json.dumps(data)) == data
    assert set(data) == {"id", "name", "tagline", "beta", "finding_kinds", "capabilities"}


# ---------------------------------------------------------------- manifests


def test_manifests_of_all_three_kinds_are_validated_through_the_detector_table(tmp_path):
    shield = _shield(tmp_path)
    for manifest in (EXTENSION, DESKTOP, CLI, PLANNED):
        _pack(shield, str(manifest["id"]), manifest)
    loaded = packs.load_packs(shield)
    assert [(pack.id, pack.status) for pack in loaded] == [
        ("metamask", "supported"), ("electrum", "supported"), ("solana-cli", "supported"), ("trust-wallet", "planned")]
    assert loaded[2].data["pointer"] == CLI["pointer"]


@pytest.mark.parametrize("manifest, reason", [
    ({**EXTENSION, "stores": {}}, "stores names no extension id"),
    ({**DESKTOP, "places": []}, "places names no folder"),
    ({**CLI, "kind": "hardware-companion"}, "no detector serves kind"),
], ids=["browser-extension", "desktop-app", "unserved-kind"])
def test_a_supported_manifest_is_refused_by_its_detector(tmp_path, manifest, reason):
    shield = _shield(tmp_path)
    _pack(shield, manifest["id"], manifest)
    assert _only(shield).status == "unavailable" and reason in _only(shield).reason


def test_a_planned_pack_needs_no_detector_but_carries_the_common_fields_only(tmp_path):
    shield = _shield(tmp_path, detectors=())
    _pack(shield, "trust-wallet", PLANNED)
    assert _only(shield).status == "planned"
    _pack(shield, "trust-wallet", {**PLANNED, "places": ["~/.trust/keys"]})
    assert _only(shield).reason == "a planned pack carries the common fields only"


@pytest.mark.parametrize("manifest, reason", [
    ({**PLANNED, "status": "beta"}, "status must be one of"),
    ({**PLANNED, "order": "70"}, "order must be an integer"),
    ({**PLANNED, "name": " "}, "name must be non-empty text"),
    ({**PLANNED, "verified": "13/10/2026"}, "verified must be a date"),
    ({key: value for key, value in EXTENSION.items() if key != "verified"}, "says when it was verified"),
    ([PLANNED], "the manifest must be a JSON object"),
], ids=["status", "order", "name", "verified-date", "supported-unverified", "not-an-object"])
def test_common_fields_are_checked(tmp_path, manifest, reason):
    shield = _shield(tmp_path)
    _pack(shield, "trust-wallet" if isinstance(manifest, list) else manifest["id"], manifest)
    assert reason in _only(shield).reason


def test_order_must_be_unique_among_usable_packs(tmp_path):
    shield = _shield(tmp_path)
    _pack(shield, "trust-wallet", PLANNED)
    _pack(shield, "okx-wallet", {**PLANNED, "id": "okx-wallet", "name": "OKX Wallet"})
    _pack(shield, "broken", "{")      # unavailable packs never collide on order
    _pack(shield, "rabby", {**PLANNED, "id": "rabby", "name": "Rabby", "order": 0})
    loaded = _by_id(shield)
    assert {loaded["trust-wallet"].reason, loaded["okx-wallet"].reason} == {"order is used by another pack"}
    assert loaded["rabby"].status == "planned"


# ---------------------------------------------------------------- templates


@pytest.mark.parametrize("template", [
    "~", "~/*", "~/.config", "~/**/wallets", "~/../etc/keys", "/etc/wallets/keys", "~//wallets", "$HOME/.x/y",
    "~/./x/y", "~/.electrum/wallets/", "%APPDATA%\\Electrum\\wallets", "~/*/wallets", "", None,
    "$XDG_CONFIG_HOME", "$XDG_CONFIG_HOME/*", "$XDG_CONFIG_HOME/*chrome", "$XDG_CONFIG_HOME/google-chrome*/Default",
    "~/.config*", "%APPDATA%/Opera*", "%LOCALAPPDATA%/Chromium",
], ids=["home", "home-star", "home-config", "double-star", "dot-dot", "absolute", "empty-segment",
        "unknown-variable", "dot", "trailing-slash", "backslash", "first-folder-wildcard", "empty", "not-text",
        "xdg-config", "xdg-config-star", "xdg-leading-wildcard", "xdg-wildcard-then-deeper",
        "home-one-folder-wildcard", "appdata-one-folder", "localappdata-one-folder"])
def test_forbidden_template_shapes_are_refused(template):
    with pytest.raises(PackError):
        check_template(template)


@pytest.mark.parametrize("template", [
    "~/.electrum/wallets", "$XDG_CONFIG_HOME/solana/*.json", "%APPDATA%/Mozilla/Firefox/Profiles/*",
    "%LOCALAPPDATA%/Google/Chrome/User Data", "~/.mozilla/firefox/*"])
def test_valid_templates_pass(template):
    assert check_template(template) == template


# With the shipped browser roots: $XDG_CONFIG_HOME is ~/.config, already one folder below
# home, so one named folder below it is as narrow as ~/.electrum/wallets.
@pytest.mark.parametrize("template", [
    "$XDG_CONFIG_HOME/chromium", "$XDG_CONFIG_HOME/google-chrome*", "$XDG_CONFIG_HOME/BraveSoftware/Brave-Browser*"])
def test_one_named_folder_below_xdg_config_home_passes(template):
    assert check_template(template) == template


def test_a_forbidden_template_in_a_manifest_makes_the_pack_unavailable(tmp_path):
    shield = _shield(tmp_path)
    _pack(shield, "electrum", {**DESKTOP, "places": ["~/.config"]})
    assert "at least two folders" in _only(shield).reason
    _pack(shield, "electrum", {**DESKTOP, "places": "~/.electrum/wallets"})
    assert _only(shield).reason == "places must be a list of path templates"


@pytest.mark.parametrize("pointer, reason", [
    ({**CLI["pointer"], "key": "keypair.*"}, "pointer.key"),
    ({**CLI["pointer"], "key": "KEYPAIR"}, "pointer.key"),
    ({**CLI["pointer"], "config": "/etc/solana.yml"}, "must start with"),
    ({**CLI["pointer"], "max_bytes": 10 ** 9}, "pointer.max_bytes"),
    ("keypair_path", "pointer must be an object"),
], ids=["regex-key", "upper-key", "absolute-config", "huge-cap", "not-an-object"])
def test_the_pointer_is_plain_data(tmp_path, pointer, reason):
    shield = _shield(tmp_path)
    _pack(shield, "solana-cli", {**CLI, "pointer": pointer})
    assert reason in _only(shield).reason


# ---------------------------------------------------------------- ids


@pytest.mark.parametrize("pack_id", ["any-extension", "all", "none", "exchanges", "secrets"])
def test_reserved_ids_are_refused(tmp_path, pack_id):
    shield = _shield(tmp_path)
    _pack(shield, pack_id, {**PLANNED, "id": pack_id})
    assert _only(shield).reason == f"id {pack_id!r} is reserved"


@pytest.mark.parametrize("pack_id", ["solana-cli", "coinbase-wallet", "trust-wallet", "okx-wallet"])
def test_todays_hyphenated_ids_pass(tmp_path, pack_id):
    shield = _shield(tmp_path)
    _pack(shield, pack_id, {**PLANNED, "id": pack_id})
    assert _only(shield).status == "planned"


@pytest.mark.parametrize("pack_id", ["m", "meta_mask", "x" * 33, 7])
def test_badly_shaped_ids_are_refused(tmp_path, pack_id):
    shield = _shield(tmp_path)
    _pack(shield, "folder", {**PLANNED, "id": pack_id})
    assert "id must be 2-32" in _only(shield).reason


# ---------------------------------------------------------------- logos


def test_a_clean_logo_with_terms_loads_and_is_served_through_the_registry(tmp_path, monkeypatch):
    shield = _shield(tmp_path)
    folder = _with_logo(shield)
    pack = _only(shield)
    assert pack.logo == PackLogo("logo.svg", "NOTICE.md")
    monkeypatch.setitem(shields._registry(), "data", shields._load_all((shield,)))
    assert shields.pack_logo("trader", "metamask") == folder / "logo.svg"
    assert shields.pack_logo("trader", "phantom") is None and shields.pack_logo("other", "metamask") is None


def test_a_logo_without_terms_is_refused(tmp_path):
    shield = _shield(tmp_path)
    _with_logo(shield, terms=False)
    assert _only(shield).reason == "NOTICE.md is missing"
    _pack(shield, "metamask", {**EXTENSION, "logo": {"file": "logo.svg"}})
    assert _only(shield).reason == "a logo names both its file and its terms"


@pytest.mark.parametrize("svg", [
    "<svg><script>fetch('/api/session')</script></svg>", "<svg><foreignObject><p/></foreignObject></svg>",
    '<svg onload="alert(1)"></svg>', '<svg><a href="https://evil.example/">x</a></svg>',
    '<svg><use xlink:href="data:image/svg+xml;base64,AA"/></svg>',
    "<svg/onload=alert(1)></svg>", "<svg><a href=https://evil.example/>x</a></svg>"],
    ids=["script", "foreign-object", "on-attribute", "external-href", "xlink-data-href",
         "slash-on-attribute", "unquoted-external-href"])
def test_a_logo_carrying_refused_markup_is_refused(tmp_path, svg):
    shield = _shield(tmp_path)
    _with_logo(shield, svg)
    assert _only(shield).reason.startswith("the logo carries refused markup")


@pytest.mark.parametrize("svg", [
    '<svg><use href="#glyph"/></svg>', "<svg><use href=#glyph /></svg>",
    '<svg><rect width="1" height="1" fill="none"/></svg>'],
    ids=["quoted-fragment-href", "unquoted-fragment-href", "plain-shapes"])
def test_a_logo_with_only_fragment_links_and_shapes_loads(tmp_path, svg):
    shield = _shield(tmp_path)
    _with_logo(shield, svg)
    assert _only(shield).status == "supported"


def test_an_unavailable_pack_carries_its_reason_and_serves_no_logo(tmp_path, monkeypatch):
    shield = _shield(tmp_path)
    _with_logo(shield, "<svg><script/></svg>")
    pack = _only(shield)
    assert pack.status == "unavailable" and pack.reason and pack.as_json()["reason"] == pack.reason
    monkeypatch.setitem(shields._registry(), "data", shields._load_all((shield,)))
    assert shields.pack_logo("trader", "metamask") is None


# ---------------------------------------------------------------- file safety


def test_an_oversized_manifest_is_refused(tmp_path):
    shield = _shield(tmp_path)
    _pack(shield, "trust-wallet", {**PLANNED, "source": "x" * packs.MANIFEST_MAX_BYTES})
    assert _only(shield).reason.startswith("wallet.json too large")


def test_a_symlinked_manifest_is_refused(tmp_path):
    shield = _shield(tmp_path)
    real = tmp_path / "elsewhere.json"
    real.write_text(json.dumps(PLANNED))
    (shield.packs / "trust-wallet").mkdir()
    (shield.packs / "trust-wallet" / "wallet.json").symlink_to(real)
    assert _only(shield).reason == "wallet.json is a symlink"


def test_a_symlinked_logo_pointing_outside_the_folder_is_refused(tmp_path):
    shield = _shield(tmp_path)
    folder = _with_logo(shield)
    outside = tmp_path / "outside.svg"
    outside.write_text(CLEAN_SVG)
    (folder / "logo.svg").unlink()
    (folder / "logo.svg").symlink_to(outside)
    assert _only(shield).reason == "logo.svg is a symlink"


def test_a_logo_named_outside_the_pack_folder_is_refused(tmp_path):
    shield = _shield(tmp_path)
    folder = _with_logo(shield)
    (folder / "wallet.json").write_text(json.dumps({**EXTENSION, "logo": {"file": "../x.svg", "terms": "NOTICE.md"}}))
    assert _only(shield).reason == "x.svg is outside the shield's folder"


def test_a_symlinked_pack_folder_is_refused(tmp_path):
    shield = _shield(tmp_path)
    real = tmp_path / "real-pack"
    real.mkdir()
    (real / "wallet.json").write_text(json.dumps(PLANNED))
    (shield.packs / "trust-wallet").symlink_to(real, target_is_directory=True)
    assert _only(shield).reason == "trust-wallet is a symlink"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no named pipes on this platform")
def test_a_fifo_named_wallet_json_is_refused_without_blocking(tmp_path):
    shield = _shield(tmp_path)
    (shield.packs / "trust-wallet").mkdir()
    os.mkfifo(shield.packs / "trust-wallet" / "wallet.json")
    assert _only(shield).reason == "wallet.json is not a regular file or folder"


def test_a_metamask_folder_beside_metamask_is_unavailable_because_the_folder_name_must_be_the_id(
        tmp_path, monkeypatch):
    shield = _shield(tmp_path)
    _pack(shield, "metamask", EXTENSION)
    _case_twins(monkeypatch, shield, "metamask", "MetaMask")
    loaded = {pack.folder.name: pack for pack in packs.load_packs(shield)}
    assert loaded["MetaMask"].reason == "folder name must be the id"
    assert loaded["metamask"].status == "unavailable"


def test_two_folders_differing_only_in_case_are_both_refused(tmp_path, monkeypatch):
    shield = _shield(tmp_path)
    _pack(shield, "electrum", DESKTOP)
    _pack(shield, "solana-cli", CLI)
    _case_twins(monkeypatch, shield, "electrum", "Electrum")
    loaded = {pack.folder.name: pack for pack in packs.load_packs(shield)}
    assert loaded["electrum"].reason == "duplicate id ignoring case"
    assert loaded["Electrum"].status == "unavailable"
    assert loaded["solana-cli"].status == "supported"


def test_a_lone_mixed_case_folder_is_unavailable(tmp_path):
    shield = _shield(tmp_path)
    _pack(shield, "MetaMask", EXTENSION)
    assert _only(shield).reason == "folder name must be the id"


def test_a_duplicate_json_key_is_refused(tmp_path):
    shield = _shield(tmp_path)
    _pack(shield, "trust-wallet", '{"id": "trust-wallet", "id": "metamask", "name": "T", "status": "planned", "order": 1}')
    assert "duplicate key 'id'" in _only(shield).reason


def test_nesting_depth_nine_is_refused_and_eight_loads(tmp_path):
    def nested(levels: int) -> dict[str, Any]:
        value: Any = 1
        for _ in range(levels - 2):
            value = [value]
        return {**EXTENSION, "stores": {"chromium": value}}   # manifest + stores + lists

    shield = _shield(tmp_path)
    _pack(shield, "metamask", nested(9))
    assert _only(shield).reason == "wallet.json nests deeper than 8"
    _pack(shield, "metamask", nested(8))
    assert _only(shield).status == "supported"


def test_a_manifest_that_is_not_json_is_unavailable(tmp_path):
    shield = _shield(tmp_path)
    _pack(shield, "trust-wallet", "[" * 60_000)
    assert _only(shield).status == "unavailable"


def test_a_pack_folder_holds_exactly_one_manifest(tmp_path):
    shield = _shield(tmp_path)
    folder = _pack(shield, "trust-wallet", PLANNED)
    (folder / "second.json").write_text("{}")
    assert _only(shield).reason == "a pack folder holds exactly one .json manifest"


# ---------------------------------------------------------------- browser roots


def test_valid_browser_roots_load(tmp_path):
    roots, health = _roots(_shield(tmp_path, roots=True), [FIREFOX_ROOT, CHROME_ROOT])
    assert [root.browser for root in roots] == ["firefox", "chrome"] and health == ()


@pytest.mark.parametrize("key, value", [
    ("engine", "webkit"), ("os", "freebsd"), ("install", "appimage"), ("profiles", "many"),
    ("browser", "Chrome!"), ("verified", "yesterday"), ("source", ""), ("path", "~/*")])
def test_a_browser_root_outside_its_enums_is_dropped_with_a_health_reason(tmp_path, key, value):
    roots, health = _roots(_shield(tmp_path, roots=True), [{**CHROME_ROOT, key: value}, FIREFOX_ROOT])
    assert [root.browser for root in roots] == ["firefox"]
    assert len(health) == 1 and health[0].startswith("browser folder rule unavailable — ")


def test_a_firefox_root_must_end_in_a_star_profile_segment(tmp_path):
    roots, health = _roots(_shield(tmp_path, roots=True), [{**FIREFOX_ROOT, "path": "~/.mozilla/firefox"}])
    assert roots == () and "must end in a * profile folder" in health[0]


def test_a_duplicate_browser_root_path_is_dropped(tmp_path):
    roots, health = _roots(_shield(tmp_path, roots=True), [CHROME_ROOT, {**CHROME_ROOT, "browser": "chromium"}])
    assert [root.browser for root in roots] == ["chrome"] and "duplicate path" in health[0]


def test_an_unreadable_browsers_file_gives_no_roots_and_one_reason(tmp_path):
    shield = _shield(tmp_path, roots=True)
    assert shield.browser_roots is not None
    shield.browser_roots.write_text('{"roots": []}')
    assert packs.load_browser_roots(shield) == ((), ("browser folder rules unavailable — browsers.json must be a list",))
    shield.browser_roots.unlink()
    roots, health = packs.load_browser_roots(shield)
    assert roots == () and health == ("browser folder rules unavailable — browsers.json is missing",)


# ---------------------------------------------------------------- registry


def test_a_corrupt_pack_leaves_the_registry_importable_and_the_other_packs_supported(tmp_path, monkeypatch):
    shield = _shield(tmp_path, roots=True)
    _pack(shield, "metamask", EXTENSION)
    _pack(shield, "electrum", DESKTOP)
    _pack(shield, "exodus", '{"id": "exodus", ')                 # corrupt JSON
    assert shield.browser_roots is not None
    shield.browser_roots.write_text("not json")
    monkeypatch.setattr(packs, "_folder_names", lambda folder: ["electrum", "exodus", "metamask", "vanished"])
    loaded = shields._load_all((shield,))["trader"]               # what the registry runs at import
    states = {pack.id: pack.status for pack in loaded.packs}
    assert states == {"metamask": "supported", "electrum": "supported", "exodus": "unavailable",
                      "vanished": "unavailable"}
    assert loaded.roots == () and len(loaded.health) == 1
    assert [shield.id for shield in importlib.reload(shields).all_shields()] == ["trader", "network-shield"]
    monkeypatch.undo()
    importlib.reload(shields)   # the reload above loaded the patched packs; later tests need the real ones


def test_a_loader_that_raises_leaves_the_shield_with_a_reason(tmp_path, monkeypatch):
    shield = _shield(tmp_path)
    monkeypatch.setattr(packs, "_folder_names", lambda folder: 1 / 0)
    assert packs.load_shield_data(shield).health == ("packs unavailable — could not list the folder (ZeroDivisionError)",)
    monkeypatch.setattr(shields, "load_shield_data", lambda item: 1 / 0)
    assert shields._load_all((shield,))["trader"].health == ("shield data unavailable — ZeroDivisionError",)


def test_importing_the_registry_reads_no_config(monkeypatch):
    import plugins.blackbox
    from plugins.blackbox.kernel import config

    reads: list[str] = []
    monkeypatch.setattr(config, "_blackbox_entry", lambda: reads.append("entry") or {})
    monkeypatch.setattr(plugins.blackbox, "shields", shields)     # restored after the fresh import
    for name in [name for name in sys.modules if name.startswith("plugins.blackbox.shields")]:
        monkeypatch.delitem(sys.modules, name)
    fresh = importlib.import_module("plugins.blackbox.shields")
    assert fresh is not shields and reads == []


def _finding(identifier: str = "secret:crypto-wallet", source: str = "heuristic") -> Finding:
    return Finding(identifier=identifier, category="fileaccess", severity="critical", title="t", source=source)


def test_check_runs_enabled_shields_only_and_makes_every_finding_local_only(tmp_path, monkeypatch):
    on = _shield(tmp_path / "a", detect=lambda tool, args, mode: [_finding()])
    off = _shield(tmp_path / "b", id="off", detect=lambda tool, args, mode: [_finding("x:off")])
    broken = _shield(tmp_path / "c", id="broken", detect=lambda tool, args, mode: 1 / 0)
    active = ShieldsSnapshot(((on, ShieldMode(True)), (off, ShieldMode(False)), (broken, ShieldMode(True))))
    found = shields.check("terminal", {"command": "cat x"}, active)
    assert [(item.identifier, item.source) for item in found] == [("secret:crypto-wallet", "secret")]


def test_allows_gates_only_what_a_shield_claims_and_fails_toward_off(tmp_path):
    mine = {"identifier": "secret:seed-phrase"}
    claiming = _shield(tmp_path / "a", claims=lambda finding: finding is mine,
                       allows=lambda finding, mode: "metamask" in mode.options.get("wallets", ()))
    assert shields.allows({"identifier": "ioc:x"}, ShieldsSnapshot(((claiming, ShieldMode(False)),)))
    assert not shields.allows(mine, ShieldsSnapshot(((claiming, ShieldMode(False)),)))
    assert not shields.allows(mine, ShieldsSnapshot(((claiming, ShieldMode(True)),)))
    assert shields.allows(mine, ShieldsSnapshot(((claiming, ShieldMode(True, {"wallets": ("metamask",)})),)))
    raising = _shield(tmp_path / "b", claims=lambda finding: 1 / 0)
    assert not shields.allows({"identifier": "ioc:x"}, ShieldsSnapshot(((raising, ShieldMode(True)),)))


def test_snapshot_reads_each_mode_once_and_keeps_an_unsupported_choice(tmp_path, monkeypatch):
    calls: list[str] = []
    chosen = ShieldMode(True, {"wallets": ("metamask", "ghost")})
    shield = _shield(tmp_path, mode=lambda: calls.append("read") or chosen)
    broken = _shield(tmp_path / "b", id="broken", mode=lambda: 1 / 0)
    monkeypatch.setitem(shields._registry(), "shields", (shield, broken))
    active = shields.snapshot()
    assert calls == ["read"] and active.mode("trader") == chosen and active.mode("broken") == ShieldMode(False)
    _pack(shield, "metamask", EXTENSION)
    lines = packs.chosen_but_unavailable(packs.load_packs(shield), chosen.options["wallets"])
    assert lines == ("ghost: chosen but unavailable — no such pack",)


def test_the_registry_views_fan_out_to_every_shield(tmp_path, monkeypatch):
    personal = ShieldMode(True, {"addresses": ("0xabc",)}, frozenset({"addresses"}))
    shield = _shield(tmp_path, mode=lambda: personal,
                     settings_fields=lambda: [SettingField("enabled", "toggle", "On")])
    monkeypatch.setitem(shields._registry(), "shields", (shield,))
    assert shields.all_shields() == (shield,) and shields.get("trader") is shield and shields.get("x") is None
    assert shields.settings_validators()[0]({}) == ShieldSettings("trader", {}, [])
    assert shields.settings_view() == {"trader": {"mode": {"enabled": True, "addresses": ["0xabc"]},
                                                  "fields": [SettingField("enabled", "toggle", "On").as_json()]}}
    assert [status.as_json()["mode"] for status in shields.statuses()] == [{"enabled": True}]
    assert shields.events("trader") == [] and shields.events("x") == []


def test_every_shield_opens_its_settings_with_its_engage_switch():
    """Settings draws a shield's first field as its on/off switch and greys out the rest while it
    is off (dashboard/static/shields.js, Blackbox Desktop's Shields page). A shield without one
    (Network Shield before this) shows no switch there, and its other settings can never be edited."""
    for shield in shields.all_shields():
        first = shield.settings_fields()[0]
        assert (first.key, first.kind) == ("enabled", "toggle"), shield.id
        assert first.label.startswith("Engage "), shield.id
