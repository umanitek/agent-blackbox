"""Every registered shield's attack table (``shields/<id>/attacks.json``) stays true.

The page's table and what each row DOES are two files joined by row id: a shield ships the
table (title, how, outcome, targets, evidence); the tool calls live beside this test in
``<id>_shield_attack_scenarios.json`` (``_trader_attack_table``) — attack commands are test
data, and a plugin that ships them reads as an attack to Hermes's install scanner.

A shield's page shows people which attacks are blocked, flagged or left alone. That table is
the single source: every ``proof: "test"`` row is driven here through the REAL pre-execution
hook and must give exactly the outcome the page claims. The setup is DERIVED from the packs,
never typed: every ``supported`` pack is chosen, one store per supported pack is laid out
from its manifest inside a temporary HOME (a Chromium store per browser-extension pack, the
place of a desktop-app pack, a key file plus its pointer config for a cli-key-file pack),
and Blackbox runs in block mode at the table's ``tested_severity`` (the local rules only).
``proof: "bench"`` rows need the verified threat graph or live OSV and are proven on a bench
node (the run is stamped in ``bench_run``). Placeholders are filled with values made at test
time — no secret-shaped literal lives in the repo (LES-022).
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import re
import secrets
import uuid
from collections import Counter
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from _trader_attack_table import ATTACKS, SCENARIO_FIELDS, TABLES
from plugins.blackbox import ruleset as ruleset_mod
from plugins.blackbox import shields
from plugins.blackbox.guard import background as guard_background
from plugins.blackbox.guard import hooks
from plugins.blackbox.guard import reporting as guard_reporting
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.kernel import crypto_secrets, threat_ids
from plugins.blackbox.kernel.crypto_secrets import seed_phrase
from plugins.blackbox.ruleset import Ruleset
from plugins.blackbox.shields.network import mode as network_mode
from plugins.blackbox.shields.network.protect import blocklists as network_blocklists
from plugins.blackbox.shields.trader import detectors, mode as trader_mode

#: blocked / flagged / missed (a gap); allowed = a harmless look-alike that must raise nothing.
OUTCOMES = {"blocked", "flagged", "missed", "allowed"}
#: How far an attack was proven, weakest to strongest (each table's ``evidence_levels``).
EVIDENCE = ("tests", "bench", "real-software", "real-agent")
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
WORDS = seed_phrase.WORDLIST_FILE.read_text(encoding="ascii").split()
#: Where a browser-extension pack's store is laid out (one Chromium profile under the home).
CHROME_PROFILE = (".config", "google-chrome", "Default")
SHIELD_IDS = [shield.id for shield in shields.all_shields()]


def _supported(shield_id: str) -> list:
    return [pack for pack in shields.loaded_packs(shield_id) if pack.status == "supported"]


def _phrase(entropy: bytes) -> str:
    """A checksum-valid BIP-39 phrase, encoded here independently of the code under test."""
    bits = len(entropy) * 8
    checksum_bits = bits // 32
    value = int.from_bytes(entropy, "big") << checksum_bits | hashlib.sha256(entropy).digest()[0] >> (8 - checksum_bits)
    count = (bits + checksum_bits) // 11
    return " ".join(WORDS[(value >> (11 * (count - 1 - i))) & 0x7FF] for i in range(count))


def _base58(data: bytes) -> str:
    number, out = int.from_bytes(data, "big"), ""
    while number:
        number, digit = divmod(number, 58)
        out = BASE58[digit] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def _base58check(payload: bytes) -> str:
    return _base58(payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4])


def _solana_key() -> bytes:
    """A real Solana secret key, made here: Ed25519 seed + its public key."""
    private = Ed25519PrivateKey.generate()
    return private.private_bytes_raw() + private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


# ------------------------------------------------------------- setup from the packs


def _posix_place(templates, home: Path) -> Path:
    """The first ``~`` / ``$XDG_CONFIG_HOME`` template of a pack, expanded under *home*
    (``*`` becomes one plausible name) — where the app keeps its store on Linux."""
    for template in templates:
        for root, base in (("~/", home), ("$XDG_CONFIG_HOME/", home / ".config")):
            if template.startswith(root):
                return base / template[len(root):].replace("*", "id")
    pytest.fail(f"no Linux place among {templates}")


def _materialise(pack, home: Path, key_file_text: str) -> Path:
    """Lay one store of *pack* out under *home*, from its manifest; answers the store."""
    if pack.kind == "dns-blocklist":
        return home   # a public block list keeps nothing in the home folder (its copy: the shield's setup)
    if pack.kind == "browser-extension":
        extension = pack.data["stores"]["chromium"][0]
        profile = home.joinpath(*CHROME_PROFILE)
        store = profile / "Local Extension Settings" / extension
        backup = profile / "IndexedDB" / f"chrome-extension_{extension}_0.indexeddb.leveldb"
        for folder in (store, backup):
            folder.mkdir(parents=True)
            (folder / "000003.log").write_text("vault", encoding="utf-8")
        return store
    if pack.kind == "desktop-app":
        store = _posix_place(pack.data["places"], home)
        store.mkdir(parents=True)
        (store / "default_wallet").write_text("wallet", encoding="utf-8")
        return store
    if pack.kind == "cli-key-file":
        store = _posix_place(pack.data["places"], home)
        store.parent.mkdir(parents=True, exist_ok=True)
        store.write_text(key_file_text, encoding="utf-8")
        pointer = pack.data["pointer"]
        config = _posix_place([pointer["config"]], home)
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(f"{pointer['key']}: {store}\n", encoding="utf-8")
        return store
    pytest.fail(f"supported pack {pack.id} has kind {pack.kind}, which this test cannot lay out")


def _trader_setup(monkeypatch, chosen: tuple[str, ...], values: dict[str, str]) -> None:
    """Trader Shield on for *chosen*, with @KEY@'s address listed as the trader's own."""
    own = trader_mode.build(enabled=True, wallets=chosen,
                            addresses=(crypto_secrets.address_of(bytes.fromhex(values["@HEX@"])),))
    monkeypatch.setattr(trader_mode, "current", lambda: own)


def _network_setup(monkeypatch, chosen: tuple[str, ...], _values: dict[str, str]) -> None:
    """Network Shield on with DNS Shield, one host on the block list, and every supported public list chosen and
    already downloaded (holding one tracker domain). Agent lockdown is off here: a row turns it
    on for itself (``"lockdown": true``, :func:`_scenario_setting`), so the other shields' rows,
    which name real hosts, are judged without it."""
    on = network_mode.build(enabled=True, protections=(network_mode.DNS,), lists=chosen, block=("blocked-by-you-blackbox-test.com",))
    monkeypatch.setattr(network_mode, "current", lambda: on)
    monkeypatch.setattr(network_blocklists, "_memory", {})
    for pack in network_mode.list_packs():
        if pack.id in chosen:
            cached = network_blocklists._cache_path(pack)
            cached.parent.mkdir(parents=True, exist_ok=True)
            cached.write_text("# test copy\nlisted-tracker-blackbox-test.com\n", encoding="utf-8")


SETUPS = {"trader": _trader_setup, "network-shield": _network_setup}


def _shell_path(path: Path, home: Path) -> str:
    """*path* the way a person types it: from ``~``, spaces escaped."""
    return ("~/" + path.relative_to(home).as_posix()).replace(" ", "\\ ")


def _values(home: Path, stores: dict[str, Path], solana: bytes) -> dict[str, str]:
    """Every placeholder the scenarios use, made now (stores named by the scenarios' packs)."""
    seed12, seed24, key = _phrase(os.urandom(16)), _phrase(os.urandom(32)), "0x" + secrets.token_hex(32)
    values = {"@SEED12PLUS@": seed12.replace(" ", "+"), "@SEED12@": seed12, "@SEED24@": seed24, "@KEY@": key,
              "@HEX@": key[2:], "@TXHASH@": secrets.token_hex(32), "@APIKEY@": secrets.token_hex(32),
              "@VAULTFILE@": str(stores["metamask"] / "000003.log"), "@VAULT@": _shell_path(stores["metamask"], home),
              "@PHANTOMFILE@": str(stores["phantom"] / "000003.log"), "@PHANTOM@": _shell_path(stores["phantom"], home),
              "@SOLKEY@": _base58(solana), "@SOLFILE@": "[" + ",".join(str(b) for b in solana) + "]",
              "@SOLSIG@": _base58(random.randbytes(64))}
    # KI-380: more key shapes (Bitcoin WIF / xprv, a Solana key as hex, a key behind 100 decoys).
    values.update({"@WIF@": _base58check(b"\x80\x01" + os.urandom(31) + b"\x01"), "@SOLHEX@": solana.hex(),
                   "@XPRV@": _base58check(bytes.fromhex("0488ade4") + bytes(9) + os.urandom(32) + b"\x00\x01" + os.urandom(31)),
                   "@SOLDECOYS@": " ".join(_base58(random.randbytes(64)) for _ in range(100))})
    # KI-378: the same 12 words spelled to slip past a word matcher.
    values.update({"@SEED12ZW@": "\u200b|".join(seed12.split()), "@SEED12CAMEL@": "".join(w.capitalize() for w in seed12.split())})
    values["@FILLER@"] = "lorem ipsum " * 5000   # KI-376: 60,000 characters of padding
    # One @<PACK>FILE@ per extension store laid out (e.g. @RABBYFILE@), so a new wallet pack's
    # vault row needs no new placeholder here.
    values.update({"@" + re.sub(r"[^A-Z0-9]", "", pack.upper()) + "FILE@": str(store / "000003.log")
                   for pack, store in stores.items() if pack not in ("metamask", "phantom") and store.is_dir()})
    values.update({f"@W{i + 1}@": word for i, word in enumerate(seed12.split())})   # KI-377: one word per item
    return values


def _block_config(severity: str) -> config_mod.BlackboxConfig:
    return config_mod.BlackboxConfig(mode="block", report=False, block_severity=severity)


def _hook_under_test(monkeypatch) -> list:
    """The real hook in block mode at the default tested severity, local rules only, no OSV
    discovery; answers the list its reported findings land in."""
    monkeypatch.setattr(hooks, "_config", lambda: _block_config(shields.DEFAULT_TESTED_SEVERITY))
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: Ruleset())
    monkeypatch.setattr(guard_background, "_spawn_osv_discovery", lambda *a, **k: None)
    findings: list = []
    monkeypatch.setattr(guard_reporting, "_report_and_audit", lambda cfg, event, found, detail: findings.extend(found))
    return findings


@pytest.fixture
def shield(tmp_path, monkeypatch):
    """Every registered shield on for every supported pack, one store per supported pack laid
    out from its manifest in a temporary HOME, block mode; returns a placeholder filler and
    the list the hook's findings land in."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    solana = _solana_key()
    key_file = "[" + ",".join(str(b) for b in solana) + "]"
    stores = {pack.id: _materialise(pack, tmp_path, key_file) for shield_id in SHIELD_IDS for pack in _supported(shield_id)}
    values = _values(tmp_path, stores, solana)
    for shield_id in SHIELD_IDS:
        SETUPS[shield_id](monkeypatch, tuple(pack.id for pack in _supported(shield_id)), values)
    detectors.EXISTING_STORES.reset()   # the hook asks the shield's detectors
    findings = _hook_under_test(monkeypatch)

    def fill(value):
        if isinstance(value, str):
            for marker, real in values.items():
                value = value.replace(marker, real)
            return value
        if isinstance(value, list):
            return [fill(item) for item in value]
        return {k: fill(v) for k, v in value.items()} if isinstance(value, dict) else value

    yield fill, findings
    detectors.EXISTING_STORES.reset()


def _scenario_setting(attack, monkeypatch):
    """Block mode at the row's shield's ``tested_severity``; a row may also list one address in
    the threat graph (``graph``: wallet + trust tier) and lower the block threshold
    (``block_severity``) — e.g. "a community-listed drainer never blocks, even at
    block_severity high" (KI-385)."""
    listed = attack.get("graph")
    if listed:
        rules = {threat_ids.ioc_identifier("wallet", listed["wallet"]): {"source": listed["source"], "severity": "critical"}}
        monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: Ruleset(ioc=rules))
    if attack.get("lockdown"):   # Network Shield's agent lockdown, for this row only
        current = network_mode.current()
        locked = network_mode.build(enabled=True, protections=(*network_mode.protections(current), network_mode.LOCKDOWN),
                                    lists=network_mode.option(current, network_mode.OPT_LISTS),
                                    block=network_mode.option(current, network_mode.OPT_BLOCK))
        monkeypatch.setattr(network_mode, "current", lambda: locked)
    severity = attack.get("block_severity") or TABLES[attack.get("shield", "trader")].table["tested_severity"]
    config = _block_config(severity)
    monkeypatch.setattr(hooks, "_config", lambda: config)


LOCAL = [attack for joined in TABLES.values() for attack in joined.attacks if attack["proof"] == "test"]


@pytest.mark.parametrize("attack", LOCAL, ids=[f"{attack['shield']}-{attack['id']}" for attack in LOCAL])
def test_each_attack_has_the_outcome_the_page_claims(shield, attack, monkeypatch):
    fill, findings = shield
    _scenario_setting(attack, monkeypatch)
    result = hooks.on_pre_tool_call(tool_name=attack["tool"], args=fill(attack["args"]), session_id="matrix")
    outcome = "blocked" if result and result.get("action") == "block" else ("flagged" if findings else "missed")
    expected = "missed" if attack["outcome"] == "allowed" else attack["outcome"]   # allowed: nothing raised, by design
    assert outcome == expected, [f.identifier for f in findings]


def test_every_registered_shield_has_a_table_scenarios_and_a_setup():
    assert set(TABLES) == set(SHIELD_IDS) and set(SETUPS) >= set(SHIELD_IDS)


def test_trader_drives_seventy_rows():
    # The count moves only with a row added or removed: say so in the commit.
    assert sum(1 for attack in ATTACKS if attack["proof"] == "test") == 76   # +6 on 2026-10-16: one vault row per newly supported wallet


# ------------------------------------------------------------------ the table itself


@pytest.mark.parametrize("shield_id", SHIELD_IDS)
def test_the_table_is_well_formed(shield_id):
    table = TABLES[shield_id].table
    groups = {group["id"] for group in table["groups"]}
    ids = [attack["id"] for attack in table["attacks"]]
    assert len(ids) == len(set(ids))
    for attack in TABLES[shield_id].attacks:
        assert attack["group"] in groups and attack["outcome"] in OUTCOMES and attack["proof"] in ("test", "bench")
        assert attack["title"] and attack["how"] and attack["args"]
    assert table.get("bench_run") and table.get("tested_severity")


@pytest.mark.parametrize("shield_id", SHIELD_IDS)
def test_every_row_has_exactly_one_scenario_and_ships_none(shield_id):
    shipped = json.loads(shields.get(shield_id).attacks.read_text(encoding="utf-8"))
    assert set(TABLES[shield_id].scenarios) == {attack["id"] for attack in shipped["attacks"]}
    carried = {attack["id"]: sorted(SCENARIO_FIELDS & set(attack)) for attack in shipped["attacks"]}
    assert {row: fields for row, fields in carried.items() if fields} == {}


@pytest.mark.parametrize("shield_id", SHIELD_IDS)
def test_what_it_was_tested_on_is_composed_never_typed(shield_id):
    shipped = json.loads(shields.get(shield_id).attacks.read_text(encoding="utf-8"))
    assert "systems" not in shipped and "tested_with" not in shipped
    table, supported = TABLES[shield_id].table, _supported(shield_id)
    capabilities = [capability.id for capability in shields.get(shield_id).capabilities]
    assert [system["id"] for system in table["systems"]] == [pack.id for pack in supported] + capabilities
    assert all(pack.name in table["tested_with"] for pack in supported)
    assert table["tested_with"].endswith(f"block mode, block at {table['tested_severity']}")


@pytest.mark.parametrize("shield_id", SHIELD_IDS)
def test_every_gap_says_what_would_close_it(shield_id):
    for attack in TABLES[shield_id].table["attacks"]:
        if attack["outcome"] == "missed":
            assert attack["group"] == "gap" and attack.get("next"), attack["id"]


@pytest.mark.parametrize("shield_id", SHIELD_IDS)
def test_every_target_is_a_supported_pack_or_a_capability(shield_id):
    supported = {pack.id for pack in _supported(shield_id)}
    unsupported = {pack.id for pack in shields.loaded_packs(shield_id)} - supported
    capabilities = {capability.id for capability in shields.get(shield_id).capabilities}
    for attack in TABLES[shield_id].table["attacks"]:
        assert attack["targets"], attack["id"]
        assert not set(attack["targets"]) & unsupported, f"{attack['id']} names a pack that is not supported"
        assert set(attack["targets"]) <= supported | capabilities, attack["id"]


@pytest.mark.parametrize("shield_id", SHIELD_IDS)
def test_every_attack_says_how_it_was_proven(shield_id):
    table = TABLES[shield_id].table
    assert set(table["evidence_levels"]) == set(EVIDENCE)
    for attack in table["attacks"]:
        assert attack["evidence"] and set(attack["evidence"]) <= set(EVIDENCE), attack["id"]
        assert ("tests" in attack["evidence"]) == (attack["proof"] == "test"), attack["id"]   # the suite runs exactly these
        # the full bench run covers every row — except rows added since it, marked until the next run
        assert "bench" in attack["evidence"] or attack.get("bench_pending") is True, attack["id"]


def _blocked_targets(shield_id: str, group: str = "") -> set[str]:
    return {target for attack in TABLES[shield_id].table["attacks"] if attack["outcome"] == "blocked"
            and (not group or attack["group"] == group) for target in attack["targets"]}


@pytest.mark.parametrize("shield_id", SHIELD_IDS)
def test_every_supported_pack_has_earned_it_with_a_blocked_vault_row(shield_id):
    supported = {pack.id for pack in _supported(shield_id)}
    group = TABLES[shield_id].table.get("pack_group", "vault")   # the group whose rows prove a pack (Trader: vault)
    assert supported <= _blocked_targets(shield_id, group), sorted(supported - _blocked_targets(shield_id, group))


@pytest.mark.parametrize("shield_id", SHIELD_IDS)
def test_every_capability_that_claims_findings_has_a_blocked_row(shield_id):
    claiming = {capability.id for capability in shields.get(shield_id).capabilities if capability.claims}
    assert claiming <= _blocked_targets(shield_id), sorted(claiming - _blocked_targets(shield_id))


@pytest.mark.parametrize("shield_id", SHIELD_IDS)
def test_every_system_has_something_proven_against_it(shield_id):
    for system in TABLES[shield_id].table["systems"]:
        assert system["id"] in _blocked_targets(shield_id), system["id"]


# ------------------------------------------------------------------ the page


def _served(path: str):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from plugins.blackbox.dashboard import shields_routes

    app = FastAPI()
    shields_routes.register_pages(app)
    return TestClient(app).get(path)


@pytest.mark.parametrize("shield_id", SHIELD_IDS)
def test_the_page_reads_the_table_it_is_tested_against(shield_id):
    page = _served(f"/shields/{shield_id}").text
    assert 'getJSON("attacks.json")' in page and 'id="systems"' in page and "renderProven(t);" in page
    served = _served(f"/shields/{shield_id}/attacks.json").json()
    hand_written = [row for row in served["attacks"] if not row["id"].startswith(ROOT_ROW_PREFIX)]
    groups = [group for group in served["groups"] if group["id"] != FOLDER_GROUP]
    assert {**served, "attacks": hand_written, "groups": groups} == TABLES[shield_id].table


@pytest.mark.parametrize("shield_id", SHIELD_IDS)
def test_the_page_types_no_count_and_no_address_of_its_own(shield_id):
    page = shields.get(shield_id).page.read_text(encoding="utf-8")
    assert not re.search(r"\d+\s+attacks tested", page)
    assert not re.search(r"""["'](/api/|/trader-shield|/wallets/|/shields/)""", page)   # relative, never mounted


def test_the_trader_page_says_which_agents_it_covers():
    lead = shields.get("trader").page.read_text(encoding="utf-8")
    assert "attached to Blackbox through Hermes" in lead and "OpenClaw are not covered" in lead


# ------------------------------------------- one generated row per browser root
#
# Every rule in the shield's browsers.json owes one row, ``vault-root-<browser>-<os>-<install>``
# (``-2`` … when rules share all three): a store of a supported browser-extension pack laid
# out under that root alone in an empty temporary HOME, the root's parent archived with
# ``tar czf`` through the real hook, blocked. The rows are read from the FILE, not the
# loader, so a rule the loader drops still owes its row and the suite goes red.

ROOT_ROW_PREFIX = "vault-root-"
FOLDER_GROUP = "browser-folders"
TRADER_ROOTS_FILE = shields.get("trader").browser_roots
ROOT_ENTRIES = json.loads(TRADER_ROOTS_FILE.read_text(encoding="utf-8"))
#: Where each template root lands inside the temporary HOME (the variables point there too).
ANCHORS = {"~": (), "$XDG_CONFIG_HOME": (".config",), "%APPDATA%": ("AppData", "Roaming"),
           "%LOCALAPPDATA%": ("AppData", "Local")}
ANCHOR_VARIABLES = {"HOME": "~", "XDG_CONFIG_HOME": "$XDG_CONFIG_HOME", "APPDATA": "%APPDATA%",
                    "LOCALAPPDATA": "%LOCALAPPDATA%"}
#: A whole ``*`` segment is one Firefox profile folder; a ``*`` inside a name (``Chrome*``) matches nothing.
PROFILE_FOLDER = "t3st0001.default-release"


def _root_row_ids(entries: list[dict]) -> list[str]:
    """The row id each browsers.json entry owes, in file order."""
    seen: Counter[str] = Counter()
    ids = []
    for entry in entries:
        key = f"{ROOT_ROW_PREFIX}{entry['browser']}-{entry['os']}-{entry['install']}"
        seen[key] += 1
        ids.append(key if seen[key] == 1 else f"{key}-{seen[key]}")
    return ids


ROOT_ROWS = list(zip(_root_row_ids(ROOT_ENTRIES), ROOT_ENTRIES))


def _root_pack(engine: str):
    """The supported browser-extension pack whose store a root of *engine* is proven with."""
    for pack in _supported("trader"):
        if pack.kind == "browser-extension" and pack.data["stores"].get(engine):
            return pack
    pytest.fail(f"no supported browser-extension pack keeps a {engine} store")


def _expand_root(template: str, home: Path) -> Path:
    anchor, *below = template.split("/")
    return home.joinpath(*ANCHORS[anchor], *(PROFILE_FOLDER if part == "*" else part.replace("*", "") for part in below))


def _lay_out_root_store(entry: dict, home: Path) -> Path:
    """One store of the root's pack under *entry*'s root inside *home*; answers the root."""
    root, pack = _expand_root(entry["path"], home), _root_pack(entry["engine"])
    if entry["engine"] == "chromium":
        profile = root / "Default" if entry["profiles"] == "children" else root
        store = profile / "Local Extension Settings" / pack.data["stores"]["chromium"][0]
    else:   # Firefox: a storage folder named by a per-install UUID, placed by the profile's prefs.js
        folder_id = str(uuid.uuid4())
        store = root / "storage" / "default" / f"moz-extension+++{folder_id}^userContextId=4294967295" / "idb"
        uuids = json.dumps({pack.data["stores"]["firefox"][0]: folder_id})
        root.mkdir(parents=True)
        (root / "prefs.js").write_text(f'user_pref("extensions.webextensions.uuids", {json.dumps(uuids)});\n', encoding="utf-8")
    store.mkdir(parents=True)
    (store / "000003.log").write_text("vault", encoding="utf-8")
    return root


@pytest.fixture
def empty_home(tmp_path, monkeypatch):
    """An empty temporary HOME (``XDG_CONFIG_HOME``, ``APPDATA`` and ``LOCALAPPDATA`` inside
    it), Trader Shield on for every supported pack, the real hook in block mode; answers
    ``(home, findings)``."""
    for variable, anchor in ANCHOR_VARIABLES.items():
        monkeypatch.setenv(variable, str(tmp_path.joinpath(*ANCHORS[anchor])))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    _trader_setup(monkeypatch, tuple(pack.id for pack in _supported("trader")), {"@HEX@": secrets.token_hex(32)})
    detectors.EXISTING_STORES.reset()
    yield tmp_path, _hook_under_test(monkeypatch)
    detectors.EXISTING_STORES.reset()


def _archive_root(entry: dict, home: Path):
    """``tar czf`` of the folder holding *entry*'s root, its store laid out; the hook's answer."""
    root = _lay_out_root_store(entry, home)
    command = f"tar czf backups/browser.tgz {_shell_path(root.parent, home)}"
    return hooks.on_pre_tool_call(tool_name="terminal", args={"command": command}, session_id="matrix")


def test_the_trader_shield_has_thirty_one_browser_roots():
    # The count moves only with a rule added or removed: say so in the commit.
    engines = Counter(entry["engine"] for entry in ROOT_ENTRIES)
    assert len(ROOT_ENTRIES) == 31 and engines == {"firefox": 7, "chromium": 24}
    assert len({row_id for row_id, _ in ROOT_ROWS}) == len(ROOT_ENTRIES)


@pytest.mark.parametrize(("row_id", "entry"), ROOT_ROWS, ids=[row_id for row_id, _ in ROOT_ROWS])
def test_each_browser_root_row_is_blocked(empty_home, row_id, entry):
    home, findings = empty_home
    result = _archive_root(entry, home)
    assert result and result.get("action") == "block", (row_id, [f.identifier for f in findings])
    assert {f.fields.get("pack") for f in findings} == {_root_pack(entry["engine"]).id}


@pytest.mark.parametrize(("row_id", "entry"), ROOT_ROWS, ids=[row_id for row_id, _ in ROOT_ROWS])
def test_a_root_missing_from_the_rules_fails_its_row(empty_home, monkeypatch, row_id, entry):
    """A test copy of the rules without this root: its row is no longer blocked — every root
    is load-bearing, so a layout dropped from browsers.json turns the suite red."""
    home, findings = empty_home
    copy = tuple(root for root in detectors.browser_roots() if root.path != entry["path"])
    assert len(copy) == len(ROOT_ENTRIES) - 1
    monkeypatch.setattr(detectors, "browser_roots", lambda: copy)
    result = _archive_root(entry, home)
    assert not (result and result.get("action") == "block") and not findings, row_id


def test_the_served_table_carries_one_row_per_root_proven_by_the_tests():
    served = _served("/shields/trader/attacks.json").json()
    rows = [row for row in served["attacks"] if row["group"] == FOLDER_GROUP]
    assert [row["id"] for row in rows] == [row_id for row_id, _ in ROOT_ROWS]
    for row, (_, entry) in zip(rows, ROOT_ROWS):
        real = ["real-software"] if "installed on" in entry["source"] else []
        assert row["proof"] == "test" and row["outcome"] == "blocked" and row["evidence"] == ["tests"] + real, row["id"]
        assert row["targets"] == [_root_pack(entry["engine"]).id] and row["title"] and entry["path"] in row["how"]
        assert not SCENARIO_FIELDS & set(row), row["id"]   # what a row does lives in this test only
    assert sum("real-software" in row["evidence"] for row in rows) == 9   # the bench-installed layouts
    group = next(group for group in served["groups"] if group["id"] == FOLDER_GROUP)
    assert group["title"] == "Every browser folder" and group["fold"] is True and group["intro"]


def test_the_page_folds_the_browser_folder_group_from_the_data():
    page = shields.get("trader").page.read_text(encoding="utf-8")
    script = page.rindex("<script>")   # the page's own script, after the markup (the head applies the theme)
    assert page.index('id="attacks"') < script   # the markup the script fills comes first
    wiring = page[script:]
    assert 'g.fold ? ["details", "<summary>", "</summary>"]' in wiring and 't.groups.map(' in wiring   # a group's fold is data
    assert "Every browser folder" not in page and "vault-root-" not in page   # rendered from data, never typed
