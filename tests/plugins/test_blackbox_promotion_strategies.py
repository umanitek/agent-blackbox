"""How a promotion reaches Verified Memory (``curate.publishing.strategies``, the one-graph flow).

New promotions take the member-asset way on a node that runs DKG 10.0.25 or
later: the report published as itself (``test_blackbox_one_graph_curator.py``).
An older node takes the curator-asset way, the curators' own verified-rule
asset made from the report, the report as its provenance. A signed promotion
is published the way its own payload says, whichever way the node would
pick; a payload of neither way — the shape promotions had before the report
was their provenance included — is refused with its reason.
"""

from __future__ import annotations

import importlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from _community_rows import Reporter
from _one_graph import NETWORK, VM_GRAPH, promotion_envelope, shared_report
from plugins.blackbox.curate.proposal import Proposal, ProposalState, ProposalStore
from plugins.blackbox.curate.publishing import row_builders as rb
from plugins.blackbox.curate.publishing import strategies
from plugins.blackbox.curate.publishing.errors import VerbError
from plugins.blackbox.kernel import constants, signing, threat_ids
from plugins.blackbox.kernel.signing import key_manifest as km
from plugins.blackbox.kernel.signing import promotion_statement as statement
from test_blackbox_curate import FakeNode, _ctx, _machine

publish_module = importlib.import_module("plugins.blackbox.curate.publishing.publish")

EDGE = Reporter("edge-1")
KEYS = (Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate())
#: The copy, the curator-asset way an older curator node takes.
COPY = strategies.STRATEGIES[strategies.CURATOR_ASSET]
EVIL = "dep:npm:evil-pkg@1.0.0"
IOC = threat_ids.ioc_identifier("domain", "drainer.example")
FILEACCESS = threat_ids.fileaccess_identifier("read_file", "ssh-private-key")


@pytest.fixture
def curators():
    """Two curator keys of different operators: a quorum of the 2-of-2 manifest."""
    a, b = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    manifest = km.KeyManifest(environment=NETWORK, graph=VM_GRAPH, chain="", root_epoch=1, version=1, threshold=2,
                              curator_keys=tuple(sorted(signing.public_key_hex(k) for k in (a, b))),
                              curator_operators=("operator-a", "operator-b"), promotion_author="0x" + "1" * 40,
                              legacy_assets_hash=km.legacy_assets_hash([]))
    return {"a": a, "b": b, "manifest": manifest}


def _signed(payload, sequence=3):
    envelope = signing.sign(KEYS[0], statement_type=statement.PROMOTION_STATEMENT, environment=NETWORK, graph=VM_GRAPH,
                            payload=payload, root_epoch=1, sequence=sequence)
    return signing.cosign(envelope, KEYS[1])


def _report(identifier):
    if identifier.startswith("fileaccess:"):
        return shared_report(identifier, EDGE, category="fileaccess", tool_name="read_file", file_category="ssh-private-key")
    return shared_report(identifier, EDGE)


def _curator_asset_payload(identifier=EVIL, **change):
    payload = COPY.payload(_report(identifier).verified, severity="high", advisory="MAL-2026-1", display_name="")
    return {**payload, **change}


@pytest.mark.parametrize("dkg_version, way", [
    ("10.0.25", strategies.MEMBER_ASSET), ("10.0.26", strategies.MEMBER_ASSET), ("10.1.0", strategies.MEMBER_ASSET),
    ("11.0.0", strategies.MEMBER_ASSET), (" 10.0.25-canary.3", strategies.MEMBER_ASSET),
    ("10.0.24", strategies.CURATOR_ASSET), ("9.9.99", strategies.CURATOR_ASSET), ("0.0.0", strategies.CURATOR_ASSET),
    ("", strategies.CURATOR_ASSET), ("canary", strategies.CURATOR_ASSET),
])
def test_new_promotions_publish_the_report_itself_from_dkg_10_0_25_and_a_copy_before(dkg_version, way):
    """A curator node older than DKG 10.0.25 refuses to publish a member's asset (OriginTrail/dkg#3294); a
    version that does not parse is taken as older: the copy publishes on every release."""
    assert strategies.active(dkg_version) is strategies.STRATEGIES[way]
    assert set(strategies.STRATEGIES) == {strategies.CURATOR_ASSET, strategies.MEMBER_ASSET}
    assert strategies.STRATEGIES[strategies.MEMBER_ASSET].publishes_report and not COPY.publishes_report


@pytest.mark.parametrize("identifier, kind, name", [
    (EVIL, "malware", "evil-pkg@1.0.0 (malicious npm package)"),
    (IOC, "malware", IOC),
    (FILEACCESS, "exfiltration", FILEACCESS),
])
def test_the_curator_asset_payload_is_the_rule_made_from_the_report(identifier, kind, name):
    report = _report(identifier)
    payload = COPY.payload(report.verified, severity=" High", advisory="MAL-2026-1", display_name="")
    assert set(payload) == rb.PAYLOAD_KEYS and "provenance" not in payload
    assert (payload["identifier"], payload["severity"], payload["kind"], payload["name"], payload["advisoryId"]) == (
        identifier, "high", kind, name, "MAL-2026-1")
    assert (payload["report"], payload["reportDigest"], payload["reporterKey"]) == (
        report.subject, report.digest, report.verified.author)   # the report, by subject, digest and reporter key
    named = COPY.payload(report.verified, severity="high", advisory="", display_name="Drainer kit")
    assert named["name"] == "Drainer kit"


def test_the_member_asset_payload_is_the_pointer():
    report = _report(EVIL)
    payload = strategies.STRATEGIES[strategies.MEMBER_ASSET].payload(report.verified, severity="critical",
                                                                     advisory="MAL-2026-1", display_name="ignored")
    assert set(payload) == statement.PAYLOAD_KEYS
    assert statement.parse(_signed(payload)).report == report.subject


def test_a_signed_promotion_is_published_the_way_its_payload_says():
    report = _report(EVIL)
    curator_asset, member_asset = _signed(_curator_asset_payload()), promotion_envelope(report, KEYS, sequence=4)
    assert strategies.strategy_for(curator_asset).name == strategies.CURATOR_ASSET
    assert strategies.strategy_for(member_asset).name == strategies.MEMBER_ASSET
    for envelope in (curator_asset, member_asset):
        ref = strategies.strategy_for(envelope).reference(envelope)
        assert (ref.identifier, ref.report, ref.report_digest, ref.reporter_key) == (
            EVIL, report.subject, report.digest, report.verified.author)
    assert strategies.refusal(curator_asset) == strategies.refusal(member_asset) == ""


@pytest.mark.parametrize("change, why", [
    ({"kind": "vulnerability"}, "promoted as malware only"),
    ({"packageVersion": "2.0.0"}, "do not match its identifier"),
    ({"name": " padded "}, "do not match its identifier"),
    ({"reportDigest": "AB" * 32}, "names no report"),
    ({"report": threat_ids.report_uri("dep:npm:other@1.0.0", EDGE.address)}, "names no report"),
    ({"provenance": "0123456789abcdef"}, "not a well-formed promotion"),   # the earlier shape: an extra key
])
def test_a_payload_of_neither_way_is_refused_with_its_reason(change, why):
    envelope = _signed(_curator_asset_payload(**change))
    assert strategies.strategy_for(envelope) is None
    assert why in strategies.refusal(envelope)
    with pytest.raises(rb.RowBuildError):
        strategies.signed_entry(envelope)


def test_another_statement_type_is_no_promotion():
    revocation = signing.sign(KEYS[0], statement_type="blackbox.revocation", environment=NETWORK, graph=VM_GRAPH,
                              payload=_curator_asset_payload(), root_epoch=1, sequence=1)
    assert strategies.strategy_for(revocation) is None and strategies.strategy_for(None) is None


def test_the_curator_asset_is_the_signed_rule_row_at_the_threat_with_the_keys_evidence():
    envelope = _signed(_curator_asset_payload(), sequence=7)
    proposal = Proposal.new(statement.PROMOTION_STATEMENT, EVIL, envelope, VM_GRAPH, checks={"b": "osv:MAL-2", "a": "advisory:MAL-1"})
    name, quads = COPY.asset(envelope, strategies.evidence_of(proposal))
    assert name == f"threat-{threat_ids.stable_hash(EVIL, 16)}-7"
    assert {q["subject"] for q in quads} == {threat_ids.threat_uri(EVIL)}
    shown = {q["predicate"]: q["object"] for q in quads}
    assert json.loads(shown[constants.SIGNED_STATEMENT_PRED]) == envelope.to_text()
    assert json.loads(shown[constants.SCHEMA_DESCRIPTION_PRED]) == "advisory:MAL-1; osv:MAL-2"
    assert json.loads(json.loads(shown[constants.SOURCE_OBSERVATION_PROVENANCE_JSON_PRED])) == [_report(EVIL).subject]


def test_a_curator_asset_promotion_verified_memory_holds_already_is_not_paid_again(monkeypatch, tmp_path, curators):
    """A retry after a publish whose read-back failed: the asset reads back now, so nothing is published."""
    node = FakeNode()
    report = _report(EVIL)
    envelope = signing.cosign(signing.sign(curators["a"], statement_type=statement.PROMOTION_STATEMENT, environment=NETWORK,
                                           graph=VM_GRAPH, payload=_curator_asset_payload(), root_epoch=1, sequence=2),
                              curators["b"])
    _name, quads = COPY.asset(envelope, "")
    node.vm_published.append((VM_GRAPH, "/earlier", quads))                     # an earlier attempt got it there
    monkeypatch.setattr(publish_module, "checked_promotion",
                        lambda ctx, env: (COPY, report.verified))   # the re-read is tested elsewhere
    proposal = (Proposal.new(statement.PROMOTION_STATEMENT, EVIL, envelope, VM_GRAPH, checks={})
                .transition(ProposalState.PROPOSED).transition(ProposalState.APPROVED))
    _machine(monkeypatch, tmp_path, "B", curators["b"])
    store = ProposalStore()
    store.save(proposal)
    _published, outcome = publish_module.publish(_ctx(node, curators["manifest"]), store, proposal.id, typed_code=None,
                                                 yes=True)
    assert outcome.startswith(f"published to {VM_GRAPH} as threat-") and "already held it" in outcome
    assert [path for _graph, path, _quads in node.vm_published] == ["/earlier"]


def test_an_unacceptable_promotion_is_refused_before_anything_is_written(monkeypatch, tmp_path, curators):
    node = FakeNode()
    payload = _curator_asset_payload(kind="vulnerability")
    envelope = signing.cosign(signing.sign(curators["a"], statement_type=statement.PROMOTION_STATEMENT, environment=NETWORK,
                                           graph=VM_GRAPH, payload=payload, root_epoch=1, sequence=2), curators["b"])
    proposal = (Proposal.new(statement.PROMOTION_STATEMENT, EVIL, envelope, VM_GRAPH, checks={})
                .transition(ProposalState.PROPOSED).transition(ProposalState.APPROVED))
    _machine(monkeypatch, tmp_path, "B", curators["b"])
    store = ProposalStore()
    store.save(proposal)
    with pytest.raises(VerbError, match="promoted as malware only"):
        publish_module.publish(_ctx(node, curators["manifest"]), store, proposal.id, typed_code=None, yes=True)
    assert node.vm_published == [] and node.sealed == []
