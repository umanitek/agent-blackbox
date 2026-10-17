"""The verified tier serves promoted reports (one-graph flow, ``ruleset/live/promoted.py``).

A community report published to Verified Memory is a verified rule — one that
may block — only when a promotion statement a quorum of the verified
authority's curator keys signed (under the manifest in force on its day)
points at it, and the report reads back from Verified Memory with exactly the
signed digest. Revocations and corrections withdraw it; a read that could not
tell keeps the last promoted rules; rules already in Verified Memory stay.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from _community_rows import Reporter, signed_report_quads
from _one_graph import (NETWORK, SHARED, STORE_URL, VERIFIED, VM_GRAPH, NodeStore, promotion_envelope, shared_report,
                        statement_row, use_store)
from plugins.blackbox import community, detection
from plugins.blackbox.community.statements.curator_statements import CuratorRecord
from plugins.blackbox.community.statements.curator_view import CuratorView
from plugins.blackbox.kernel import signing, threat_ids
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.kernel.signing import key_manifest as km
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement
from plugins.blackbox.ruleset import compiler, curator_tier
from plugins.blackbox.ruleset.live import promoted

CURATOR_A, CURATOR_B, CURATOR_C = (Ed25519PrivateKey.generate() for _ in range(3))
TODAY = "2026-11-20"
CFG = BlackboxConfig(context_graph_id=VM_GRAPH)
EVIL = "dep:npm:evil-pkg@1.0.0"
EDGE, OTHER_EDGE = Reporter("edge-1"), Reporter("edge-2")


def _manifest(version, issued_day, curators):
    pairs = sorted((signing.public_key_hex(key), f"operator-{index}") for index, key in enumerate(curators))
    return km.KeyManifest(environment=NETWORK, graph=VM_GRAPH, chain="", root_epoch=1, version=version,
                          curator_keys=tuple(key for key, _ in pairs), curator_operators=tuple(op for _, op in pairs),
                          threshold=2, promotion_author="0x" + "1" * 40, legacy_assets_hash=km.legacy_assets_hash([]),
                          issued_day=issued_day)


V1 = _manifest(1, "2026-09-01", (CURATOR_A, CURATOR_B))   # in force 09-02 .. 10-31
V2 = _manifest(2, "2026-10-20", (CURATOR_A, CURATOR_C))   # rotates B out; in force from 10-21
NOW_SIGNED = (CURATOR_A, CURATOR_C)


class Node:
    """The node API the reader asks: the promotion statements (None = the read fails) and its status."""

    def __init__(self, statements=()):
        self.statements = None if statements is None else list(statements)

    def query(self, sparql, cg_id=None, view=None, on_error=None, **_kw):
        if "promotesReport" in sparql:
            return on_error if self.statements is None else list(self.statements)
        return on_error

    def status(self, timeout=None):
        return {"networkId": NETWORK, "storeUrl": STORE_URL}


@pytest.fixture
def world(monkeypatch):
    store = NodeStore()
    use_store(monkeypatch, store)
    monkeypatch.setattr(community, "curator_today", lambda: TODAY)
    monkeypatch.setattr(community, "verified_manifest_history", lambda client, graph, environment: (V1, V2))
    return store


def _served(node, view=None, rs=None, prior=None):
    rs = rs or compiler.Ruleset()
    promoted.apply_promoted_reports(rs, node, CFG, view or CuratorView(manifest=V2), prior)
    return rs


def _promoted_store(world, report, *, number=7):
    world.hold(report, layer=VERIFIED, number=number)
    return report


# ------------------------------------------------------------------ served only with a quorum statement


def test_a_promoted_report_is_a_verified_rule_that_blocks(world):
    report = _promoted_store(world, shared_report(EVIL, EDGE, "medium"))
    rs = _served(Node([statement_row(promotion_envelope(report, NOW_SIGNED, sequence=3, day="2026-11-15"))]))
    rule = rs.dependency[threat_ids.dependency_key("npm", "evil-pkg", "1.0.0")]
    assert (rule["source"], rule["kind"], rule["severity"]) == ("public", "malware", "critical")   # the curators' severity
    assert rule["subject"] == rule[promoted.PROMOTED_REPORT] == report.subject
    [finding] = detection.detect_dependency("bash", {"command": "npm install evil-pkg@1.0.0"}, rs)
    assert (finding.confirmed, finding.source, finding.kind) == (True, "public", "malware")


def test_a_report_in_verified_memory_that_no_statement_names_is_never_a_rule(world):
    _promoted_store(world, shared_report(EVIL, EDGE))
    assert not _served(Node([])).dependency


def test_one_curator_signature_is_not_a_promotion(world):
    report = _promoted_store(world, shared_report(EVIL, EDGE))
    assert not _served(Node([statement_row(promotion_envelope(report, (CURATOR_A,), sequence=3, day="2026-11-15"))])).dependency


def test_a_report_still_only_in_shared_memory_is_not_served_until_it_reads_back_verified(world):
    report = shared_report(EVIL, EDGE)
    world.hold(report, layer=SHARED, number=7)
    node = Node([statement_row(promotion_envelope(report, NOW_SIGNED, sequence=3, day="2026-11-15"))])
    assert not _served(node).dependency
    world.hold(report, layer=VERIFIED, number=7)
    assert _served(node).dependency


@pytest.mark.parametrize("severity", ["critical", "high"])
def test_only_the_reviewed_report_is_served_never_another_with_the_same_subject(world, severity):
    """Anyone can sign a report naming the reporter's address (the address is display only) — other
    words, or the very same words: the digest AND the reporter key the curators signed bind the
    statement to the report they reviewed."""
    reviewed = shared_report(EVIL, EDGE)
    impostor = shared_report(EVIL, Reporter(EDGE.address), severity)   # same address, its own key
    assert impostor.subject == reviewed.subject and (impostor.digest == reviewed.digest) is (severity == "high")
    world.hold(impostor, layer=VERIFIED, number=8)
    node = Node([statement_row(promotion_envelope(reviewed, NOW_SIGNED, sequence=3, day="2026-11-15"))])
    assert not _served(node).dependency
    world.hold(reviewed, layer=VERIFIED, number=7)
    assert _served(node).dependency


def test_a_statement_row_showing_another_report_than_it_signed_is_skipped(world):
    report = _promoted_store(world, shared_report(EVIL, EDGE))
    row = statement_row(promotion_envelope(report, NOW_SIGNED, sequence=3, day="2026-11-15"))
    assert not _served(Node([{**row, "report": shared_report(EVIL, OTHER_EDGE).subject}])).dependency


def test_a_rotation_never_unblocks_and_a_retired_key_cannot_promote_after_it(world):
    report = _promoted_store(world, shared_report(EVIL, EDGE))
    before = statement_row(promotion_envelope(report, (CURATOR_A, CURATOR_B), sequence=3, day="2026-10-01"))
    assert _served(Node([before])).dependency                # V1 was in force that day; B is rotated out now
    after = statement_row(promotion_envelope(report, (CURATOR_A, CURATOR_B), sequence=4, day="2026-11-01"))
    assert not _served(Node([after])).dependency             # V2 was in force: B is no curator key
    future = statement_row(promotion_envelope(report, (CURATOR_A, CURATOR_B), sequence=5, day="2027-01-01"))
    assert not _served(Node([future])).dependency            # a later day is judged as of today


def test_the_newest_promotion_of_a_threat_decides(world):
    report = _promoted_store(world, shared_report(EVIL, EDGE))
    rows = [statement_row(promotion_envelope(report, NOW_SIGNED, sequence=5, severity="low", day="2026-11-15")),
            statement_row(promotion_envelope(report, NOW_SIGNED, sequence=3, severity="critical", day="2026-11-10"))]
    [rule] = _served(Node(rows)).dependency.values()
    assert rule["severity"] == "low"


@pytest.mark.parametrize("identifier, table, key", [
    (threat_ids.ioc_identifier("domain", "drainer.example"), "ioc", threat_ids.ioc_identifier("domain", "drainer.example")),
    (threat_ids.skill_version_identifier("totally-safe-helper", "2.1.0"), "skill", None),
    (threat_ids.fileaccess_identifier("read_file", "ssh-private-key"), "fileaccess", None),
])
def test_an_address_a_skill_and_a_file_access_report_become_their_rules(world, identifier, table, key):
    evidence = {"skill": {"skill_name": "totally-safe-helper", "skill_version": "2.1.0", "registry": "clawhub"},
                "fileaccess": {"tool_name": "read_file", "file_category": "ssh-private-key"}}.get(table, {})
    report = _promoted_store(world, shared_report(identifier, EDGE, **evidence))
    rs = _served(Node([statement_row(promotion_envelope(report, NOW_SIGNED, sequence=2, day="2026-11-15"))]))
    rules = getattr(rs, table)
    rule = rules[key] if key else next(rule for rule in rules if rule["identifier"] == identifier)
    assert (rule["source"], rule[promoted.PROMOTED_REPORT]) == ("public", report.subject)
    if table == "ioc":
        assert (rule["iocType"], rule["value"]) == ("domain", "drainer.example")


# ------------------------------------------------------------------ reductions, last-good, the rules already there


def test_a_revoked_threat_and_a_suppressed_report_are_never_served(world):
    report = _promoted_store(world, shared_report(EVIL, EDGE))
    node = Node([statement_row(promotion_envelope(report, NOW_SIGNED, sequence=3, day="2026-11-15"))])
    revocation = CuratorRecord(CuratorStatement.REVOCATION, EVIL, 9, "2026-11-16", (), frozenset())
    assert not _served(node, CuratorView(manifest=V2, verdicts={EVIL: revocation})).dependency
    suppressed = compiler.Ruleset(suppressed_subjects=frozenset({report.subject}))
    assert not _served(node, rs=suppressed).dependency


def test_a_read_that_cannot_tell_keeps_the_last_promoted_rules_but_never_a_revoked_one(world):
    report = _promoted_store(world, shared_report(EVIL, EDGE))
    last = _served(Node([statement_row(promotion_envelope(report, NOW_SIGNED, sequence=3, day="2026-11-15"))]))
    assert _served(Node(None), prior=last).dependency == last.dependency          # the statements read failed
    world.fail = True
    assert _served(Node([statement_row(promotion_envelope(report, NOW_SIGNED, sequence=3, day="2026-11-15"))]),
                   prior=last).dependency == last.dependency                      # the store could not tell
    revocation = CuratorRecord(CuratorStatement.REVOCATION, EVIL, 9, "2026-11-16", (), frozenset())
    assert not _served(Node(None), CuratorView(manifest=V2, verdicts={EVIL: revocation}), prior=last).dependency


def test_without_a_trusted_manifest_no_report_is_promoted(world):
    report = _promoted_store(world, shared_report(EVIL, EDGE))
    node = Node([statement_row(promotion_envelope(report, NOW_SIGNED, sequence=3, day="2026-11-15"))])
    assert not _served(node, CuratorView()).dependency


def test_verified_rules_already_in_verified_memory_stay_and_keep_their_key(world):
    key = threat_ids.dependency_key("npm", "evil-pkg", "1.0.0")
    legacy = {"identifier": EVIL, "source": "public", "kind": "malware", "severity": "high", "subject": "urn:defender:x"}
    report = _promoted_store(world, shared_report(EVIL, EDGE))
    rs = compiler.Ruleset(dependency={key: legacy}, skill=[{"identifier": "skill:old@1.0", "source": "public"}])
    _served(Node([statement_row(promotion_envelope(report, NOW_SIGNED, sequence=3, day="2026-11-15"))]), rs=rs)
    assert rs.dependency[key] is legacy and rs.skill == [{"identifier": "skill:old@1.0", "source": "public"}]


def test_the_curator_tier_withdraws_revocations_then_serves_promotions(world, monkeypatch):
    report = _promoted_store(world, shared_report(EVIL, EDGE))
    other = _promoted_store(world, shared_report("dep:npm:other-pkg@2.0.0", EDGE), number=8)
    node = Node([statement_row(promotion_envelope(report, NOW_SIGNED, sequence=3, day="2026-11-15")),
                 statement_row(promotion_envelope(other, NOW_SIGNED, sequence=1, day="2026-11-15"))])
    revocation = CuratorRecord(CuratorStatement.REVOCATION, EVIL, 9, "2026-11-16", (), frozenset())
    monkeypatch.setattr(community, "read_curator_view", lambda client, config: CuratorView(manifest=V2, verdicts={EVIL: revocation}))
    rs = compiler.Ruleset()
    curator_tier.apply_curator_tier(rs, node, CFG)
    assert [rule["identifier"] for rule in rs.dependency.values()] == ["dep:npm:other-pkg@2.0.0"]
    assert rs.curator_revoked == frozenset({EVIL})
