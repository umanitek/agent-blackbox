"""What a shield protects cannot leave the machine by a side door.

A shield's own findings are local-only (the registry marks them ``source="secret"``,
and the community gate refuses that source). Sharing is on by default, so three
other routes are pinned here:

* **Twins.** A core rule that matches a resource a shield protects raises its own
  finding, which is shareable. Each twin is found by asking the core file-access rule
  about every tested attack row aimed at a shield capability that claims findings or at
  a supported pack, then driven through the real pre-tool hook. The test pins what
  happens TODAY (the row's outcome, plus a heuristic core finding the community gate
  allows); what a twin should do is an open founder decision, so a change to it must
  come with a change here.
* **The manual report.** ``blackbox report`` accepts closed vocabularies only (the
  file categories, the report types, the indicator types); none may name a shield's
  finding kind, or an operator could hand-report what the shield keeps local.
* **One send path.** Only the reviewed modules may reach ``spawn_community_share`` or
  ``share_knowledge_asset``; a new automatic sender fails here until it is reviewed.
"""

from __future__ import annotations

import ast
import fnmatch
from pathlib import Path
from types import SimpleNamespace

import pytest

from _trader_attack_table import ATTACKS
from test_blackbox_trader_shield_attacks import _scenario_setting, shield   # shield: the attack-table fixture
from plugins.blackbox import detection, shields
from plugins.blackbox.community import sharing as community_sharing
from plugins.blackbox.community.report_cli import report_command
from plugins.blackbox.detection import action_parsing
from plugins.blackbox.guard import hooks
from plugins.blackbox.kernel import threat_ids
from plugins.blackbox.shields.packs import load_packs

PLUGIN_ROOT = Path(shields.__file__).resolve().parent.parent
REPORTER = "0x" + "1" * 40

#: Each registered shield's tested attack rows, with their tool calls. Every registered shield
#: needs an entry (test_every_registered_shield_has_its_attack_rows) so a new shield is reviewed here.
#: Network Shield's is empty on purpose: what it protects is hosts (lockdown, the person's block list,
#: public lists), never files, so the core FILE-access rule this twin check asks cannot twin it; its
#: own findings are local-only like every shield's (registry ``source="secret"``). (E2E recheck
#: 2026-11-21: the missing entry made this whole file fail to collect with KeyError 'network-shield'.)
ATTACK_ROWS = {"trader": ATTACKS, "network-shield": ()}


# -- twins ---------------------------------------------------------------------------


def _protected_targets(shield_record) -> set[str]:
    """The capabilities that claim findings and the supported packs: what the shield protects."""
    capabilities = {capability.id for capability in shield_record.capabilities if capability.claims}
    packs = {pack.id for pack in load_packs(shield_record) if pack.status == "supported"}
    return capabilities | packs


def _twins() -> list[tuple[str, str, str, dict]]:
    """(shield id, protected target, core category, attack row) for every tested row aimed at
    something a shield protects whose path the core file-access rule also matches."""
    found = []
    for shield_record in shields.all_shields():
        targets = _protected_targets(shield_record)
        for row in ATTACK_ROWS[shield_record.id]:
            aimed_at = sorted(targets & set(row["targets"]))
            if row["proof"] != "test" or not aimed_at:   # bench rows run on a node, not here
                continue
            access = detection.file_access_arg(row["tool"], row["args"])
            if access is None:
                continue
            hit = action_parsing.sensitive_path_category(access["path"], row["args"])
            if hit:
                found.extend((shield_record.id, target, hit["category"], row) for target in aimed_at)
    return found


TWINS = _twins()


def test_every_registered_shield_has_its_attack_rows():
    assert {shield_record.id for shield_record in shields.all_shields()} <= set(ATTACK_ROWS)


def test_the_twins_are_the_ones_known_today():
    # A new twin (or one that goes away) changes what leaves the machine: review it, then update this.
    assert {(row["id"], target, category) for _shield, target, category, row in TWINS} == {
        ("keychain-file-tool", "keychain", "browser-cookies"),
    }


@pytest.mark.parametrize("shield_id, target, category, attack", TWINS,
                         ids=[f"{row['id']}-twin-of-{target}-by-core-{category}" for _s, target, category, row in TWINS])
def test_a_twin_route_is_flagged_by_the_core_rule_and_shared(shield, shield_id, target, category, attack, monkeypatch):  # health: allow F811 -- pytest injects the imported shield fixture by parameter name
    fill, findings = shield
    _scenario_setting(attack, monkeypatch)
    monkeypatch.setattr(community_sharing.consent, "in_force", lambda: True)
    policy = community_sharing.CommunitySharePolicy(SimpleNamespace(community_enabled=True))
    shield_record = shields.get(shield_id)

    result = hooks.on_pre_tool_call(tool_name=attack["tool"], args=fill(attack["args"]), session_id="twins")

    outcome = "blocked" if result and result.get("action") == "block" else ("flagged" if findings else "missed")
    assert outcome == attack["outcome"], [finding.identifier for finding in findings]
    found = [finding.to_dict() for finding in findings]
    core = [finding for finding in found if finding.get("fields", {}).get("file_category") == category]
    assert len(core) == 1, [finding["identifier"] for finding in found]
    twin = core[0]
    assert twin["source"] == "heuristic" and not shield_record.claims(twin)
    allowed, why = policy.decide(twin, REPORTER)
    assert allowed, why
    for claimed in (finding for finding in found if shield_record.claims(finding)):
        allowed, why = policy.decide(claimed, REPORTER)
        assert not allowed and why.startswith("source secret"), (claimed["identifier"], why)


# -- the manual report ---------------------------------------------------------------

#: Every closed vocabulary a manual ``blackbox report`` validates against.
MANUAL_REPORT_VOCABULARIES = {
    "file-categories": frozenset(detection.SENSITIVE_PATH_CATEGORIES),
    "report-types": frozenset(report_command._REPORT_REQUIRED_ARGS),
    "indicator-types": frozenset(threat_ids.IOC_TYPES),
}


def _kind_categories(shield_record) -> set[str]:
    """The category each finding kind names: its file category, or the last part of its identifier."""
    return {kind.category or kind.identifier.rsplit(":", 1)[-1] for kind in shield_record.finding_kinds}


@pytest.mark.parametrize("vocabulary", sorted(MANUAL_REPORT_VOCABULARIES))
@pytest.mark.parametrize("shield_record", shields.all_shields(), ids=lambda record: record.id)
def test_no_manual_report_vocabulary_names_a_shield_kind(shield_record, vocabulary):
    categories = _kind_categories(shield_record)
    assert categories and "" not in categories
    words = MANUAL_REPORT_VOCABULARIES[vocabulary]
    assert not [word for word in words for category in categories if fnmatch.fnmatchcase(word, category)]


# -- one send path -------------------------------------------------------------------

SEND_FUNCTIONS = frozenset({"spawn_community_share", "share_knowledge_asset"})
#: The reviewed senders, as paths under plugins/blackbox (a trailing "/" is a whole folder).
REVIEWED_SENDERS = ("guard/reporting.py", "community/sharing.py", "community/share_retry.py",
                    "curate/publishing/", "curate/upkeep/")


def _send_references() -> dict[str, list[int]]:
    """Every module that names a send function in code (a call, or the function handed on
    to be called later), with the lines; definitions and imports are not references."""
    found: dict[str, list[int]] = {}
    for path in sorted(PLUGIN_ROOT.rglob("*.py")):
        module = path.relative_to(PLUGIN_ROOT).as_posix()
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), filename=str(path))):
            name = node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else None
            if name in SEND_FUNCTIONS:
                found.setdefault(module, []).append(node.lineno)
    return found


def _reviewed(module: str) -> bool:
    return any(module == sender or (sender.endswith("/") and module.startswith(sender)) for sender in REVIEWED_SENDERS)


def test_only_the_reviewed_modules_send_to_the_community_graph():
    references = _send_references()
    assert "guard/reporting.py" in references and "community/sharing.py" in references   # the walk sees the senders
    assert {module: lines for module, lines in references.items() if not _reviewed(module)} == {}
