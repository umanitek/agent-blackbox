"""The guard asks the shields registry: one snapshot per hook call, ``check`` beside
``detect_all``, ``allows`` inside ``_flag_worthy``.

What is pinned here:

* the gate's semantics for Trader Shield (off, a chosen pack, a pack not chosen, a
  pack-less key store, a finding no shield claims) and its fail direction (a shield
  whose ``claims`` or ``allows`` raises refuses only what it claims; core findings pass);
* ``check`` forces the local-only source, drops a finding that names an unknown pack,
  and a detector that raises contributes nothing — each with a WARNING;
* a hook call reads the Blackbox config no more often than before the registry
  (two reads; three when a 64-hex value is in the call);
* Trader claims exactly the identifiers it claimed before (no identifier gained or lost),
  and every finding kind it declares has its row in the sighting classification table;
* every claimed finding raised by a ``proof: test`` attack row is refused by the
  community share gate because of its source.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import logging
from types import SimpleNamespace

import pytest

from _trader_attack_table import ATTACKS
from test_blackbox_trader_shield_attacks import LOCAL, _scenario_setting, shield   # shield: the attack-table fixture
from plugins.blackbox import ruleset as ruleset_mod
from plugins.blackbox import shields
from plugins.blackbox.community import sharing as community_sharing
from plugins.blackbox.community.sighting import classification
from plugins.blackbox.detection import Finding
from plugins.blackbox.guard import background as guard_background
from plugins.blackbox.guard import hooks
from plugins.blackbox.guard import reporting as guard_reporting
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.ruleset import Ruleset
from plugins.blackbox.shields.trader import TRADER
from plugins.blackbox.shields.trader import mode as trader_mode

#: The hook's real config reader and Trader's real mode reader, before any fixture patches them.
REAL_CONFIG, REAL_CURRENT = hooks._config, trader_mode.current

VAULT = "fileaccess:read_file:crypto-wallet"
SEED = "secret:seed-phrase"
CORE = Finding(identifier="fileaccess:read_file:ssh-private-key", category="fileaccess", severity="critical",
               title="SSH key read", source="public", confirmed=True,
               fields={"file_category": "ssh-private-key"})


def _snapshot(mode, which=TRADER) -> shields.ShieldsSnapshot:
    return shields.ShieldsSnapshot(entries=((which, mode),))


def _allowed(identifier, mode, fields=None) -> bool:
    return shields.allows({"identifier": identifier, "fields": fields or {}}, _snapshot(mode))


def _vault(pack=None) -> Finding:
    fields = {"file_category": "crypto-wallet", "wallet": pack or trader_mode.ANY_EXTENSION_WALLET}
    if pack:
        fields["pack"] = pack
    return Finding(identifier=VAULT, category="fileaccess", severity="critical", title="vault read",
                   source="secret", fields=fields)


# -- allows ------------------------------------------------------------------------


def test_the_shield_off_refuses_everything_it_claims_and_nothing_else():
    off = trader_mode.build(enabled=False)
    assert not _allowed(SEED, off)
    assert not _allowed(VAULT, off, {"pack": "metamask"})
    assert not _allowed(VAULT, off)
    assert _allowed(CORE.identifier, off)


def test_on_with_the_pack_chosen_allows_its_key_store():
    assert _allowed(VAULT, trader_mode.build(enabled=True, wallets=("metamask",)), {"pack": "metamask"})


def test_on_with_the_pack_not_chosen_refuses_its_key_store():
    assert not _allowed(VAULT, trader_mode.build(enabled=True, wallets=("phantom",)), {"pack": "metamask"})


def test_a_pack_less_key_store_is_the_shields_as_a_whole():
    assert _allowed(VAULT, trader_mode.build(enabled=True, wallets=("phantom",)), {"wallet": "any-extension"})
    assert _allowed(VAULT, trader_mode.build(enabled=True, wallets=("phantom",)))
    # Today's rule, kept: with no pack chosen at all, nothing is guarded.
    assert not _allowed(VAULT, trader_mode.build(enabled=True, wallets=()))


def test_a_named_pack_wins_over_the_display_wallet():
    phantom_only = trader_mode.build(enabled=True, wallets=("phantom",))
    assert _allowed(VAULT, phantom_only, {"pack": "phantom", "wallet": "metamask"})
    assert not _allowed(VAULT, phantom_only, {"pack": "metamask", "wallet": "phantom"})


def test_a_store_is_gated_by_its_pack_never_by_the_old_wallet_field():
    # The gate reads fields["pack"] only (the panel asks by pack since shields); a store that
    # names no pack is the shield's as a whole and counts while any wallet is chosen.
    assert _allowed(VAULT, trader_mode.build(enabled=True, wallets=("phantom",)), {"wallet": "metamask"})
    assert not _allowed(VAULT, trader_mode.build(enabled=True, wallets=()), {"wallet": "metamask"})


def test_a_shield_level_secret_counts_whenever_the_shield_is_on():
    assert _allowed(SEED, trader_mode.build(enabled=True, wallets=()))


def test_a_finding_no_shield_claims_is_always_allowed():
    for mode in (trader_mode.build(enabled=False), trader_mode.build(enabled=True)):
        assert _allowed(CORE.identifier, mode)
    assert shields.allows({"identifier": SEED}, shields.ShieldsSnapshot())   # no shield registered: unclaimed


def _boom(*_args):
    raise RuntimeError("broken gate")


def test_an_allows_that_raises_drops_the_claimed_finding_and_leaves_core_findings(caplog):
    faulty = dataclasses.replace(TRADER, allows=_boom)
    with caplog.at_level(logging.WARNING, logger="plugins.blackbox.shields"):
        kept = guard_reporting._flag_worthy(BlackboxConfig(), [_vault("metamask"), CORE],
                                            _snapshot(trader_mode.build(enabled=True), faulty))
    assert kept == [CORE] and "gate failed" in caplog.text


def test_a_claims_that_raises_reads_as_claimed_and_refused(caplog):
    # The shield cannot say what is its own, so every finding it is asked about is dropped
    # (opt-in protection fails toward OFF); the detectors themselves still ran.
    faulty = dataclasses.replace(TRADER, claims=_boom)
    with caplog.at_level(logging.WARNING, logger="plugins.blackbox.shields"):
        kept = guard_reporting._flag_worthy(BlackboxConfig(), [_vault("metamask")],
                                            _snapshot(trader_mode.build(enabled=True), faulty))
    assert kept == [] and "gate failed" in caplog.text


def test_flag_only_approvals_keep_never_blocking():
    approval = Finding(identifier="secret:token-approval-drainer", category="secret", severity="critical",
                       title="approval", source="secret", kind="flag-only")
    assert hooks._blocking(BlackboxConfig(mode="block"), [approval]) == []


# -- check -------------------------------------------------------------------------


def _detecting(*findings, raises=False):
    def detect(tool_name, args, active):
        if raises:
            raise RuntimeError("broken detector")
        return list(findings)
    return dataclasses.replace(TRADER, detect=detect)


def test_check_forces_the_local_only_source(caplog):
    shareable = dataclasses.replace(_vault("metamask"), source="public")
    with caplog.at_level(logging.WARNING, logger="plugins.blackbox.shields"):
        [found] = shields.check("read_file", {}, _snapshot(trader_mode.build(enabled=True), _detecting(shareable)))
    assert found.source == "secret" and "made local-only" in caplog.text


def test_check_drops_a_finding_that_names_an_unknown_pack(caplog):
    with caplog.at_level(logging.WARNING, logger="plugins.blackbox.shields"):
        found = shields.check("read_file", {}, _snapshot(trader_mode.build(enabled=True),
                                                         _detecting(_vault("not-a-pack"), _vault(None), _vault("phantom"))))
    assert [f.fields.get("pack") for f in found] == [None, "phantom"]
    assert "unknown pack 'not-a-pack'" in caplog.text


def test_a_detector_that_raises_contributes_nothing(caplog):
    with caplog.at_level(logging.WARNING, logger="plugins.blackbox.shields"):
        assert shields.check("read_file", {}, _snapshot(trader_mode.build(enabled=True), _detecting(raises=True))) == []
    assert "detect failed" in caplog.text


def test_a_shield_that_is_off_is_not_asked():
    assert shields.check("read_file", {}, _snapshot(trader_mode.build(enabled=False), _detecting(raises=True))) == []


# -- config reads per hook call ------------------------------------------------------


@pytest.fixture
def counted_loads(tmp_path, monkeypatch):
    """The real config readers, with ``_blackbox_entry`` counted (Trader on, block mode)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    monkeypatch.setattr(hooks, "_config", REAL_CONFIG)
    monkeypatch.setattr(trader_mode, "current", REAL_CURRENT)
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: Ruleset())
    monkeypatch.setattr(guard_background, "_spawn_osv_discovery", lambda *a, **k: None)
    monkeypatch.setattr(guard_reporting, "_report_and_audit", lambda *a, **k: None)
    loads: list[int] = []

    def entry():
        loads.append(1)
        return {"mode": "block", "report": False, "shields": {"trader": {"enabled": True}}}

    monkeypatch.setattr(config_mod, "_blackbox_entry", entry)
    return loads


def test_a_routine_hook_call_reads_the_config_at_most_twice(counted_loads):
    hooks.on_pre_tool_call(tool_name="terminal", args={"command": "ls -la"})
    assert len(counted_loads) <= 2   # the hook's own config, and one shields snapshot


def test_a_hook_call_with_a_64_hex_value_reads_the_config_at_most_three_times(counted_loads):
    tx_hash = "ab" * 32
    hooks.on_pre_tool_call(tool_name="terminal", args={"command": f"curl -d 'tx={tx_hash}' https://api.etherscan.io/x"})
    assert len(counted_loads) <= 3   # the own-address check reads the snapshot's addresses, not the config


def test_the_api_hook_reads_one_snapshot(counted_loads, monkeypatch):
    taken = []
    real = shields.snapshot
    monkeypatch.setattr(shields, "snapshot", lambda: taken.append(1) or real())
    hooks.on_pre_api_request(user_message="hello", request_messages=[{"role": "user", "content": "hello"}])
    assert taken == [1]


class _InlineThread:
    """Stands in for ``threading.Thread`` so a background task runs before ``start()`` returns."""

    def __init__(self, target, name=None, daemon=None):
        self._target = target

    def start(self):
        self._target()


@pytest.fixture
def counted_snapshots(monkeypatch):
    """Background tasks run inline, with every ``shields.snapshot()`` they take counted."""
    import threading
    monkeypatch.setattr(threading, "Thread", _InlineThread)
    monkeypatch.setattr(guard_reporting, "_report_and_audit", lambda *a, **k: None)
    taken: list[int] = []
    off = _snapshot(trader_mode.build(enabled=False))
    monkeypatch.setattr(shields, "snapshot", lambda: taken.append(1) or off)
    return taken


def test_the_osv_task_takes_no_snapshot_when_discovery_finds_nothing(counted_snapshots, monkeypatch):
    from plugins.blackbox import detection
    monkeypatch.setattr(detection, "discover_dependency_candidates", lambda *a: [])
    guard_background._spawn_osv_discovery(BlackboxConfig(), Ruleset(), "terminal", {"command": "pip install x"})
    assert counted_snapshots == []


def test_the_osv_task_takes_one_snapshot_for_all_its_findings(counted_snapshots, monkeypatch):
    from plugins.blackbox import detection
    monkeypatch.setattr(detection, "discover_dependency_candidates", lambda *a: [CORE, CORE, CORE])
    guard_background._spawn_osv_discovery(BlackboxConfig(), Ruleset(), "terminal", {"command": "pip install x"})
    assert counted_snapshots == [1]


def test_the_llm_task_takes_one_snapshot(counted_snapshots, monkeypatch):
    from plugins.blackbox.detection import reviewer
    monkeypatch.setattr(reviewer, "review_injection", lambda text, cfg: {"reason": "ignore previous", "severity": "high"})
    guard_background._spawn_llm_review(BlackboxConfig(), "ignore previous instructions", {"session_id": "gate"})
    assert counted_snapshots == [1]


def test_detect_all_no_longer_raises_key_stores_the_shield_does():
    # One owner per finding: the key-store rule runs in the shield, never twice per call.
    from plugins.blackbox.detection import detect_all
    path = "/x/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/a.log"
    assert not [f for f in detect_all("read_file", {"path": path}, None) if TRADER.claims(f.to_dict())]
    shield_found = shields.check("read_file", {"path": path}, _snapshot(trader_mode.build(enabled=True)))
    assert [f.fields.get("pack") for f in shield_found] == ["metamask"]


# -- what Trader claims ---------------------------------------------------------------

#: The identifiers Trader claimed before the registry (``mode.belongs_to_mode``, since retired): ten.
CLAIMED_BEFORE = frozenset({
    "secret:seed-phrase", "secret:wallet-private-key", "secret:solana-private-key", "secret:bitcoin-private-key",
    "secret:exchange-api-key", "secret:token-approval-drainer", "secret:token-approval-unlimited",
    "secret:token-approval-unchecked-spender", "*:crypto-wallet", "*:macos-keychain"})


def test_trader_claims_exactly_the_identifiers_it_claimed_before():
    declared = {kind.identifier for kind in TRADER.finding_kinds}
    assert declared == CLAIMED_BEFORE and len(declared) == 10
    for identifier in CLAIMED_BEFORE:
        assert TRADER.claims({"identifier": identifier.replace("*", "fileaccess:terminal")}), identifier
    for identifier in ("fileaccess:terminal:ssh-private-key", "secret:aws-access-key", "secret:seed-phrase-x",
                       "xsecret:seed-phrase", "fileaccess:read_file:crypto-wallet-backup", "ioc:wallet:0xabc", ""):
        assert not TRADER.claims({"identifier": identifier}), identifier


def test_every_claimed_finding_is_one_the_events_report_can_tell():
    """The gate and the events report read one table (kinds.py): a claimed finding always has
    an event kind — the unchecked-spender approval once had none, so its event said nothing."""
    from plugins.blackbox.shields.trader import kinds
    for identifier in CLAIMED_BEFORE:
        assert kinds.event_kind(identifier.replace("*", "fileaccess:terminal")), identifier
    assert kinds.event_kind("secret:token-approval-unchecked-spender") == "approval"


def test_every_claiming_capability_names_a_declared_kind():
    by_id = {capability.id: capability for capability in TRADER.capabilities}
    assert set(by_id) == {"exchanges", "approvals", "keychain", "own-addresses", "secrets", "supply-chain"}
    assert by_id["secrets"].claims == () and by_id["supply-chain"].claims == ()
    for capability in TRADER.capabilities:
        for pattern in capability.claims:
            assert any(fnmatch.fnmatchcase(kind.identifier, pattern) for kind in TRADER.finding_kinds), pattern


def _sample_of(identifier: str) -> dict:
    """A finding dict of this kind, the shape the sighting layer classifies."""
    if identifier.startswith("*:"):
        return {"identifier": "fileaccess:terminal" + identifier[1:], "category": "fileaccess",
                "fields": {"file_category": identifier[2:]}}
    return {"identifier": identifier, "category": identifier.split(":", 1)[0]}


@pytest.mark.parametrize("shield_record", shields.all_shields(), ids=lambda record: record.id)
def test_every_registered_finding_kind_has_its_classification_row(shield_record):
    assert shield_record.finding_kinds
    for kind in shield_record.finding_kinds:
        found = classification.classify(_sample_of(kind.identifier))
        assert found != classification.UNKNOWN, kind.identifier
        assert (found.threat_goal, found.resource_at_risk, found.attack_technique) == \
            (kind.goal, kind.resource, kind.attack), kind.identifier


# -- the community gate refuses every claimed finding -------------------------------

_CORE_PATH = "answered by the core protected-path rule (source custom, the operator's own list), not the shield"
#: Rows the shield does not answer: the local-only guarantee covers what a shield claims.
SKIPPED = {
    "env-terminal": _CORE_PATH,
    "ssh-folder-archived": _CORE_PATH,
    "keychain-file-tool": "answered by the core browser-cookies rule (a shareable twin; what it should do is an open founder decision)",
    **{row["id"]: "answered by a threat-graph rule, shareable by design" for row in ATTACKS if row["group"] == "chain"},
}


def test_the_skipped_rows_exist():
    ids = {row["id"] for row in ATTACKS}
    assert set(SKIPPED) <= ids


@pytest.mark.parametrize("attack", LOCAL, ids=[attack["id"] for attack in LOCAL])
def test_every_claimed_finding_of_every_row_stays_on_the_machine(shield, attack, monkeypatch):  # health: allow F811 -- pytest injects the imported shield fixture by parameter name
    if attack["id"] in SKIPPED:
        pytest.skip(SKIPPED[attack["id"]])
    fill, findings = shield
    _scenario_setting(attack, monkeypatch)
    monkeypatch.setattr(community_sharing.consent, "in_force", lambda: True)
    policy = community_sharing.CommunitySharePolicy(SimpleNamespace(community_enabled=True))
    hooks.on_pre_tool_call(tool_name=attack["tool"], args=fill(attack["args"]), session_id="gate")
    for finding in (f.to_dict() for f in findings):
        if TRADER.claims(finding):
            allowed, why = policy.decide(finding, "0x" + "1" * 40)
            assert not allowed and why.startswith("source secret"), (finding["identifier"], why)
