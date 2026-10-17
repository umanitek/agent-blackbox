"""What a promotion names, and the member-asset statement's wire format (``kernel.signing.promotion_statement``).

Every promotion names ONE report by subject, digest and reporter key; the
member-asset pointer's payload is a closed schema; on the graph it is a
curator statement the verified reader never compiles into a rule and the
curator view never reads as a verdict; a node's copies of a report are
read back with the asset that holds each; and a shared copy's asset name is
read from the node's record of its author's seal.
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from _community_rows import Reporter
from _one_graph import SHARED, SUB_GRAPH, VERIFIED, VM_GRAPH, asset_graph, promotion_envelope, shared_report
from plugins.blackbox.community.statements import curator_statements
from plugins.blackbox.kernel import constants, signing, threat_ids
from plugins.blackbox.kernel.signing import key_manifest as km
from plugins.blackbox.kernel.signing import promotion_statement as statement
from plugins.blackbox.ruleset.partitions.rows import rows_from_triples

EVIL = "dep:npm:evil-pkg@1.0.0"
KEYS = (Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate())
EDGE = Reporter("0x" + "1" * 40)


@pytest.fixture(scope="module")
def report():
    return shared_report(EVIL, EDGE)


def test_a_promotion_points_at_one_report_by_subject_and_digest(report):
    envelope = promotion_envelope(report, KEYS, sequence=4, severity="high", day="2026-10-16")
    found = statement.parse(envelope)
    assert found == statement.Promotion(identifier=EVIL, report=report.subject, report_digest=report.digest,
                                        reporter_key=EDGE.author, severity="high", day="2026-10-16", sequence=4)
    assert found.reporter == EDGE.address
    assert set(envelope.payload) == statement.PAYLOAD_KEYS   # no copied rule fields, no provenance ids


def test_either_promotion_shape_names_its_report_by_the_same_four_keys(report):
    """``reference`` reads the report a promotion names from the member-asset pointer and from the
    curator-asset rule payload alike (``curate.publishing.strategies``)."""
    ref = statement.reference(promotion_envelope(report, KEYS, sequence=2).payload)
    assert ref == statement.ReportRef(EVIL, report.subject, report.digest, EDGE.author)
    assert isinstance(statement.parse(promotion_envelope(report, KEYS, sequence=2)), statement.ReportRef)
    rule_payload = {**ref.fields(), "severity": "high", "kind": "malware", "ecosystem": "npm", "packageName": "evil-pkg",
                    "packageVersion": "1.0.0", "advisoryId": "", "name": EVIL}
    assert statement.reference(rule_payload) == ref and statement.reference(ref.fields()) == ref
    for broken in ({"reportDigest": "x"}, {"reporterKey": ""}, {"identifier": threat_ids.injection_identifier("x")},
                   {"report": threat_ids.report_uri("dep:npm:other@1.0.0", EDGE.address)}):
        assert statement.reference({**ref.fields(), **broken}) is None and statement.reference_refusal({**ref.fields(), **broken})


@pytest.mark.parametrize("change, why", [
    ({"identifier": threat_ids.injection_identifier("ignore previous")}, "promoted as"),
    ({"identifier": "escalation:shell:sudo"}, "promoted as"),
    ({"identifier": "dep:npm:other@1.0.0"}, "own report of this identifier"),
    ({"report": "urn:guardian:report:0x" + "2" * 40 + ":0123456789abcdef"}, "own report of this identifier"),
    ({"report_digest": "ab" * 31}, "digest is 64 lower-case hex"),
    ({"reporter_key": "AB" * 32}, "reporter key is 64 lower-case hex"),
    ({"severity": "urgent"}, "severity"),
    ({"day": "16.10.2026"}, "YYYY-MM-DD"),
])
def test_a_payload_outside_the_closed_schema_is_refused(report, change, why):
    fields = {"identifier": EVIL, "report": report.subject, "report_digest": report.digest, "reporter_key": EDGE.author,
              "severity": "high", "day": "2026-10-16", **change}
    with pytest.raises(ValueError, match=why):
        statement.promotion_payload(fields.pop("identifier"), **fields)


def test_parse_refuses_another_statement_type_and_an_extra_key(report):
    good = promotion_envelope(report, KEYS, sequence=1)
    revocation = signing.sign(KEYS[0], statement_type="blackbox.revocation", environment=good.environment,
                              graph=good.graph, payload=dict(good.payload), sequence=1)
    extra = signing.sign(KEYS[0], statement_type=good.statement_type, environment=good.environment, graph=good.graph,
                         payload={**good.payload, "provenance": "0123456789abcdef"}, sequence=1)
    assert statement.parse(revocation) is None and statement.parse(extra) is None and statement.parse(None) is None


def test_a_copy_is_the_promoted_report_only_with_its_words_and_its_reporter_key(report):
    """The digest names what was said; another key can sign the same words (naming the same address)."""
    found = statement.parse(promotion_envelope(report, KEYS, sequence=1))
    same_words = shared_report(EVIL, Reporter(EDGE.address))
    assert same_words.digest == report.digest and same_words.verified.author != EDGE.author
    tampered = report.text.replace('"severity":"high"', '"severity":"critical"')
    assert statement.is_the_report(found, report.text)
    assert not statement.is_the_report(found, same_words.text)
    assert not statement.is_the_report(found, tampered) and not statement.is_the_report(found, "not json")


def test_the_statement_asset_is_a_curator_statement_without_an_identifier_triple(report):
    envelope = promotion_envelope(report, KEYS, sequence=7)
    quads = statement.statement_quads(envelope)
    subject = f"urn:guardian:curator:promotion:{threat_ids.stable_hash(EVIL, 24)}:7"
    assert {quad["subject"] for quad in quads} == {subject} == {statement.statement_subject(EVIL, 7)}
    shown = {quad["predicate"]: quad["object"] for quad in quads}
    assert shown[constants.RDF_TYPE] == constants.CURATOR_STATEMENT_TYPE_IRI
    assert shown[statement.PROMOTES_REPORT_PRED] == report.subject            # an IRI the graph can follow
    assert json.loads(shown[constants.SIGNED_STATEMENT_PRED]) == envelope.to_text()
    assert constants.IDENTIFIER_PRED not in shown


def test_neither_the_verified_reader_nor_the_curator_view_reads_the_statement_as_a_rule_or_verdict(report):
    """No g:identifier: the identifier lane compiles nothing from it, and the curator view skips it."""
    envelope = promotion_envelope(report, KEYS, sequence=7)
    quads = statement.statement_quads(envelope)
    assert rows_from_triples("g", [(q["subject"], q["predicate"], q["object"]) for q in quads]) == []
    manifest = km.KeyManifest(environment=envelope.environment, graph=VM_GRAPH, chain="", root_epoch=1, version=1,
                              curator_keys=tuple(sorted(signing.public_key_hex(k) for k in KEYS)),
                              curator_operators=("a", "b"), threshold=2, promotion_author="0x" + "1" * 40,
                              legacy_assets_hash=km.legacy_assets_hash([]))
    row = {"r": statement.statement_subject(EVIL, 7), "identifier": EVIL, "signedStatement": envelope.to_text()}
    assert curator_statements.parse_statement(row, manifest, graph=VM_GRAPH) is None


def test_an_unsigned_or_malformed_statement_is_never_written(report):
    envelope = promotion_envelope(report, KEYS, sequence=1)
    with pytest.raises(ValueError):
        statement.statement_quads(signing.SignedEnvelope(envelope.statement_type, envelope.environment, envelope.graph,
                                                         envelope.schema_version, envelope.payload, ()))
    with pytest.raises(ValueError):
        statement.statement_quads(signing.sign(KEYS[0], statement_type=statement.PROMOTION_STATEMENT,
                                               environment="n", graph=VM_GRAPH, payload={"identifier": EVIL}))


def test_the_statements_query_pages_and_narrows_to_one_identifier():
    every = statement.statements_sparql("")
    about = statement.statements_sparql("urn:x", EVIL)
    assert f"<{statement.PROMOTES_REPORT_PRED}>" in every and "LIMIT 5000" in every and "FILTER" not in every
    assert json.dumps(f"urn:guardian:curator:promotion:{threat_ids.stable_hash(EVIL, 24)}:") in about
    assert 'STR(?r) > "urn:x"' in about


def test_a_report_copy_names_its_asset_layer_and_sub_graph(report):
    shared = asset_graph(EDGE.address, 7, layer=SHARED)
    verified = asset_graph(EDGE.address.upper().replace("0X", "0x"), 9, layer=VERIFIED, sub_graph="")
    for graph_iri, layer, sub_graph, number in ((shared, SHARED, SUB_GRAPH, "7"), (verified, VERIFIED, "", "9")):
        copy = statement.report_copy(VM_GRAPH, {"g": graph_iri, "r": report.subject, "signedStatement": json.dumps(report.text)})
        assert (copy.layer, copy.sub_graph, copy.number, copy.author, copy.text) == (layer, sub_graph, number,
                                                                                     EDGE.address, report.text)
        assert copy.asset_id == f"{EDGE.address}:{number}" and copy.verified is (layer == VERIFIED)
    for foreign in ("did:dkg:context-graph:0xabc/other-graph/_verifiable_memory/0x" + "1" * 40 + "/1",
                    f"did:dkg:context-graph:{VM_GRAPH}/_meta", f"did:dkg:context-graph:{VM_GRAPH}/reports/assertion/x/y",
                    asset_graph("0x" + "2" * 40, 3, layer=SHARED)):          # another node's asset: never the report
        assert statement.report_copy(VM_GRAPH, {"g": foreign, "r": report.subject, "signedStatement": "\"x\""}) is None


def test_the_copies_query_binds_only_report_subjects_in_their_reporters_assets_under_the_graph(report):
    sparql = statement.report_copies_sparql(VM_GRAPH, [report.subject, report.subject, "urn:x> } DROP"], 32)
    assert sparql.count(f"<{report.subject}>") == 1 and "DROP" not in sparql and sparql.endswith("LIMIT 32")
    assert json.dumps(f"did:dkg:context-graph:{VM_GRAPH}/") in sparql
    assert f'(<{report.subject}> "/{EDGE.address}/")' in sparql and "?author" in sparql   # its reporter's assets only
    assert '"/_verifiable_memory/"' not in sparql
    assert '"/_verifiable_memory/"' in statement.report_copies_sparql(VM_GRAPH, [report.subject], 8, verified_only=True)
    assert statement.report_copies_sparql(VM_GRAPH, ["urn:x"], 8) == ""
    assert statement.report_copies_sparql('0xabc/vm"> bad', [report.subject], 8) == ""


def _copy(report, number="7", sub_graph=SUB_GRAPH):
    graph_iri = asset_graph(EDGE.address, int(number), layer=SHARED, sub_graph=sub_graph)
    return statement.report_copy(VM_GRAPH, {"g": graph_iri, "r": report.subject, "signedStatement": json.dumps(report.text)})


def test_a_shared_copys_name_comes_from_the_record_of_its_authors_seal(report):
    """DKG 10.0.25 keeps a member's seal on the curator node in a lifecycle record that spells the author
    checksummed: ``urn:dkg:assertion:<graph>:<sub-graph>:<author>:<name>``, with the asset number."""
    copy = _copy(report)
    checksummed = "0x" + EDGE.address[2:].upper()
    record = f"urn:dkg:assertion:{VM_GRAPH}:{SUB_GRAPH}:{checksummed}:report-ab12-e5"
    row = {"lifecycle": record, "ka": '"7"^^<http://www.w3.org/2001/XMLSchema#integer>', "name": '"report-ab12-e5"'}
    assert statement.sealed_name(VM_GRAPH, copy, row) == "report-ab12-e5"
    for changed in ({"ka": '"8"'},                                                     # another asset of the author
                    {"lifecycle": record.replace(EDGE.address[2:].upper(), "2" * 40)},   # another author
                    {"lifecycle": record.replace(f":{SUB_GRAPH}:", ":drafts:")},         # another sub-graph
                    {"name": '"report-other"'}):                                       # the record names another asset
        assert statement.sealed_name(VM_GRAPH, copy, {**row, **changed}) == ""


def test_the_sealed_names_query_asks_for_kept_seals_of_the_copies_assets_only(report):
    sparql = statement.sealed_names_sparql(VM_GRAPH, [_copy(report), _copy(report, "9")], 16)
    assert sparql.count(json.dumps(f"urn:dkg:assertion:{VM_GRAPH.lower()}:{SUB_GRAPH}:{EDGE.address}:")) == 1
    assert f"GRAPH <did:dkg:context-graph:{VM_GRAPH}/_meta>" in sparql and "swmShareComplete" in sparql
    assert sparql.endswith("LIMIT 16")
    assert statement.sealed_names_sparql(VM_GRAPH, [], 16) == ""
    assert statement.sealed_names_sparql('0xabc/vm"> bad', [_copy(report)], 16) == ""

