"""P2 (trust-and-threat-lab §03.4) — row builders: one Strategy per promotable category.

Every category D3 calls promotable has a builder; every row carries the signed
``blackbox.promotion`` envelope whose payload names the rule and the community
report it was made from (its provenance — the one-graph flow); evidence is
capped at 2 KB; a built row's envelope parses and a 2-key manifest accepts it;
and the verified reader compiles each row back into the rule it was signed as.
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plugins.blackbox.curate import publishing
from plugins.blackbox.curate.publishing import row_builders as rb
from plugins.blackbox.kernel import constants, rdf_terms, signing, threat_ids
from plugins.blackbox.kernel.signing import key_manifest as km
from plugins.blackbox.kernel.signing import promotion_statement as statement
from plugins.blackbox.ruleset import row_adapters
from plugins.blackbox.ruleset.partitions.rows import rows_from_triples

NETWORK = "sandbox-net"
VERIFIED_GRAPH = "0xabc/agent-blackbox-vm"
REPORTER, REPORTER_KEY, DIGEST = "0x" + "e" * 40, "e" * 64, "d" * 64
INJECTION_PATTERN = r"ignore\s+(all\s+)?previous\s+instructions\\n"


def _report(identifier):
    """The community report a promotion of *identifier* was made from (its provenance)."""
    return statement.ReportRef(identifier, threat_ids.report_uri(identifier, REPORTER), DIGEST, REPORTER_KEY)


#: One confirmed entry per promotable category (D3: every listable type is promotable). No report
#: carries an injection's pattern, so the injection entry is made from none.
_IOC, _SKILL = threat_ids.ioc_identifier("domain", "Evil.Example."), threat_ids.skill_version_identifier("totally-safe-helper", "2.1.0")
_FILEACCESS = threat_ids.fileaccess_identifier("read_file", "ssh-private-key")
ENTRIES = {
    "dep": rb.ConfirmedEntry("dep:npm:evil-pkg@1.0.0", "critical", "malware", _report("dep:npm:evil-pkg@1.0.0"),
                             "advisory MAL-2026-1", advisory_id="MAL-2026-1"),
    "ioc": rb.ConfirmedEntry(_IOC, "high", "malware", _report(_IOC), "lab: C2 beacon"),
    "skill": rb.ConfirmedEntry(_SKILL, "high", "malware", _report(_SKILL)),
    "injection": rb.ConfirmedEntry(threat_ids.injection_identifier(INJECTION_PATTERN), "medium", "injection",
                                   pattern=INJECTION_PATTERN),
    "fileaccess": rb.ConfirmedEntry(_FILEACCESS, "high", "exfiltration", _report(_FILEACCESS)),
}


@pytest.fixture(scope="module")
def keys():
    return Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()


@pytest.fixture(scope="module")
def manifest(keys):
    """A 2-of-2 curator manifest for the verified graph."""
    pairs = sorted((signing.public_key_hex(key), f"operator-{i}") for i, key in enumerate(keys))
    return km.KeyManifest(environment=NETWORK, graph=VERIFIED_GRAPH, chain="", root_epoch=1, version=1,
                          curator_keys=tuple(key for key, _ in pairs), curator_operators=tuple(op for _, op in pairs),
                          threshold=2, promotion_author="0x" + "1" * 40, legacy_assets_hash=km.legacy_assets_hash([]))


def _envelope(keys, payload, statement_type=rb.PROMOTION_STATEMENT):
    first = signing.sign(keys[0], statement_type=statement_type, environment=NETWORK, graph=VERIFIED_GRAPH,
                         payload=payload, root_epoch=1, sequence=1)
    return signing.cosign(first, keys[1])


def _built(keys, entry):
    return rb.ROW_BUILDERS[entry.category].quads(entry, _envelope(keys, rb.promotion_payload(entry)))


def _plain(term: str) -> str:
    """A literal term's value (N-Triples escapes match JSON's for these)."""
    return json.loads(term)


def _signed_literal(quads):
    (term,) = [q["object"] for q in quads if q["predicate"] == constants.SIGNED_STATEMENT_PRED]
    return _plain(term)


# ------------------------------------------------------------------ the registry


def test_every_category_d3_calls_promotable_has_a_builder():
    assert set(rb.ROW_BUILDERS) == {"dep", "ioc", "skill", "injection", "fileaccess"} == set(ENTRIES)
    assert all(builder.category == category for category, builder in rb.ROW_BUILDERS.items())
    assert publishing.ROW_BUILDERS is rb.ROW_BUILDERS


def test_the_registry_is_frozen():
    with pytest.raises(TypeError):
        rb.ROW_BUILDERS["escalation"] = rb.ROW_BUILDERS["dep"]  # type: ignore[index]


def test_an_unpromotable_category_is_refused_at_the_entry():
    with pytest.raises(rb.RowBuildError):
        rb.ConfirmedEntry(threat_ids.escalation_identifier("shell", "remote-script-pipe"), "high", "malware")


@pytest.mark.parametrize("field_name,value", [
    ("severity", "urgent"), ("kind", " "), ("kind", "vulnerability"),   # a dependency rule blocks: malware only
    ("report", _report("dep:npm:other@1")),                           # another identifier's report
    ("report", statement.ReportRef("dep:npm:x@1", threat_ids.report_uri("dep:npm:x@1", REPORTER), "ab", REPORTER_KEY)),
    ("report", statement.ReportRef("dep:npm:x@1", "urn:guardian:report:0xr:1", DIGEST, REPORTER_KEY)),
])
def test_an_ill_formed_entry_is_refused(field_name, value):
    fields = {"identifier": "dep:npm:x@1", "severity": "high", "kind": "malware", field_name: value}
    with pytest.raises(rb.RowBuildError):
        rb.ConfirmedEntry(**fields)


# ------------------------------------------------------------------ every row is signed


@pytest.mark.parametrize("category", sorted(ENTRIES))
def test_no_builder_writes_a_row_without_the_signed_statement(keys, category):
    quads = _built(keys, ENTRIES[category])
    subjects = {q["subject"] for q in quads}
    assert subjects == {threat_ids.threat_uri(ENTRIES[category].identifier)}
    assert [q["predicate"] for q in quads].count(constants.SIGNED_STATEMENT_PRED) == 1


@pytest.mark.parametrize("category", sorted(ENTRIES))
def test_the_signed_payload_carries_identifier_kind_severity_version_and_the_report(keys, category):
    entry = ENTRIES[category]
    quads = _built(keys, entry)
    payload = signing.from_text(_signed_literal(quads)).payload
    assert set(payload) == rb.PAYLOAD_KEYS and "provenance" not in payload   # no random provenance ids any more
    assert (payload["identifier"], payload["kind"], payload["severity"]) == (entry.identifier, entry.kind, entry.severity)
    named = entry.report.fields() if entry.report else {"report": "", "reportDigest": "", "reporterKey": ""}
    assert {key: payload[key] for key in ("report", "reportDigest", "reporterKey")} == {
        key: named[key] for key in ("report", "reportDigest", "reporterKey")}
    provenance = next(_plain(q["object"]) for q in quads if q["predicate"] == constants.SOURCE_OBSERVATION_PROVENANCE_JSON_PRED)
    assert json.loads(provenance) == ([entry.report.report] if entry.report else [])   # the report itself, as the corpus writes it


def test_the_payload_names_the_package_and_version_where_the_identifier_has_them():
    dep = rb.promotion_payload(ENTRIES["dep"])
    assert (dep["ecosystem"], dep["packageName"], dep["packageVersion"]) == ("npm", "evil-pkg", "1.0.0")
    skill = rb.promotion_payload(ENTRIES["skill"])
    assert (skill["packageName"], skill["packageVersion"]) == ("totally-safe-helper", "2.1.0")
    assert rb.promotion_payload(ENTRIES["ioc"])["packageVersion"] == ""


@pytest.mark.parametrize("name,version,shape", [
    ("mail@helper", "", "exec-remote"),      # an '@' inside a shape id's name is not a version
    ("@acme/tool", "", "exec-remote"),       # a scoped name with a shape
    ("@acme/tool", "1.2.0", ""),             # a scoped name with a version
])
def test_a_skill_name_holding_an_at_sign_is_read_as_its_identifier_says(keys, name, version, shape):
    """P2 review: an '@' in a skill name must not make the signed payload name a bogus version."""
    identifier = (threat_ids.skill_version_identifier(name, version) if version
                  else threat_ids.skill_shape_identifier(name, shape))
    entry = rb.ConfirmedEntry(identifier, "high", "malware")
    payload = rb.promotion_payload(entry)
    assert (payload["packageName"], payload["packageVersion"]) == ((name, version) if version else ("", ""))
    written = {q["predicate"]: _plain(q["object"]) for q in _built(keys, entry)}
    assert written[constants.SKILL_NAME_PRED] == name
    assert written.get(constants.SKILL_VERSION_PRED, "") == version
    assert written.get(constants.DANGER_SHAPE_PRED, "") == shape


def test_an_unsigned_envelope_is_refused(keys):
    entry = ENTRIES["dep"]
    unsigned = signing.SignedEnvelope(statement_type=rb.PROMOTION_STATEMENT, environment=NETWORK, graph=VERIFIED_GRAPH,
                                      schema_version=1, payload=rb.promotion_payload(entry), signatures=())
    with pytest.raises(rb.RowBuildError):
        rb.ROW_BUILDERS["dep"].quads(entry, unsigned)


def test_an_envelope_of_another_statement_type_is_refused(keys):
    entry = ENTRIES["ioc"]
    with pytest.raises(rb.RowBuildError):
        rb.ROW_BUILDERS["ioc"].quads(entry, _envelope(keys, rb.promotion_payload(entry), "blackbox.confirmation"))


@pytest.mark.parametrize("field_name", rb.SIGNED_RULE_FIELDS)
def test_a_row_never_shows_a_rule_its_signatures_do_not_name(keys, field_name):
    """a real envelope transplanted onto another entry is refused."""
    entry = ENTRIES["dep"]
    payload = {**rb.promotion_payload(entry), field_name: "tampered"}
    with pytest.raises(rb.RowBuildError):
        rb.ROW_BUILDERS["dep"].quads(entry, _envelope(keys, payload))


def test_a_builder_refuses_another_category(keys):
    entry = ENTRIES["ioc"]
    with pytest.raises(rb.RowBuildError):
        rb.ROW_BUILDERS["dep"].quads(entry, _envelope(keys, rb.promotion_payload(entry)))


def test_an_injection_needs_the_pattern_its_hash_names(keys):
    entry = rb.ConfirmedEntry(ENTRIES["injection"].identifier, "medium", "injection", pattern="something else")
    with pytest.raises(rb.RowBuildError):
        rb.ROW_BUILDERS["injection"].quads(entry, _envelope(keys, rb.promotion_payload(entry)))


def test_a_non_canonical_ioc_identifier_is_refused(keys):
    entry = rb.ConfirmedEntry("ioc:domain:Evil.Example.", "high", "malware")
    with pytest.raises(rb.RowBuildError):
        rb.ROW_BUILDERS["ioc"].quads(entry, _envelope(keys, rb.promotion_payload(entry)))


# ------------------------------------------------------------------ evidence cap


def _evidence_of(quads):
    values = [_plain(q["object"]) for q in quads if q["predicate"] == constants.SCHEMA_DESCRIPTION_PRED]
    return values[0] if values else ""


@pytest.mark.parametrize("category", sorted(ENTRIES))
def test_evidence_over_2kb_is_truncated_to_the_typed_cap(keys, category):
    base = ENTRIES[category]
    long_evidence = "é" * 3000   # 6000 UTF-8 bytes; a multi-byte character is never split
    entry = rb.ConfirmedEntry(base.identifier, base.severity, base.kind, base.report, long_evidence, pattern=base.pattern)
    evidence = _evidence_of(_built(keys, entry))
    assert len(evidence.encode("utf-8")) <= rb.EVIDENCE_MAX_BYTES == 2048
    assert evidence.endswith("[truncated]") and evidence.startswith("é" * 100)


def test_evidence_within_the_cap_is_written_whole(keys):
    assert _evidence_of(_built(keys, ENTRIES["ioc"])) == "lab: C2 beacon"
    exact = "x" * rb.EVIDENCE_MAX_BYTES
    entry = rb.ConfirmedEntry(ENTRIES["dep"].identifier, "critical", "malware", ENTRIES["dep"].report, exact)
    assert _evidence_of(_built(keys, entry)) == exact


@pytest.mark.parametrize("category", sorted(ENTRIES))
def test_every_literal_respects_the_store_cap(keys, category):
    rdf_terms.assert_quads_literal_size(_built(keys, ENTRIES[category]))


# ------------------------------------------------------------------ round trip


@pytest.mark.parametrize("category", sorted(ENTRIES))
def test_a_built_rows_envelope_parses_and_a_two_key_manifest_accepts_it(keys, manifest, category):
    envelope = signing.from_text(_signed_literal(_built(keys, ENTRIES[category])))
    assert envelope is not None and envelope.statement_type == rb.PROMOTION_STATEMENT
    assert manifest.has_quorum(envelope, statement_type=rb.PROMOTION_STATEMENT, graph=VERIFIED_GRAPH)


def test_one_signature_is_not_a_quorum(keys, manifest):
    entry = ENTRIES["dep"]
    single = signing.sign(keys[0], statement_type=rb.PROMOTION_STATEMENT, environment=NETWORK, graph=VERIFIED_GRAPH,
                          payload=rb.promotion_payload(entry), root_epoch=1, sequence=1)
    envelope = signing.from_text(_signed_literal(rb.ROW_BUILDERS["dep"].quads(entry, single)))
    assert not manifest.has_quorum(envelope, statement_type=rb.PROMOTION_STATEMENT, graph=VERIFIED_GRAPH)


_READER_CATEGORY = {"dep": "dependency", "ioc": "ioc", "skill": "skill", "injection": "injection", "fileaccess": "fileaccess"}


@pytest.mark.parametrize("category", sorted(ENTRIES))
def test_the_verified_reader_compiles_each_row_into_the_signed_rule(keys, category):
    """The corpus's existing shape: the reader's own row rebuild + adapter yield the rule."""
    entry = ENTRIES[category]
    triples = [(q["subject"], q["predicate"], q["object"]) for q in _built(keys, entry)]
    rules = [rule for row in rows_from_triples(VERIFIED_GRAPH, triples)
             if (rule := row_adapters._row_to_rule(row, "public")) is not None]
    assert rules, category
    assert {(reader_category, rule["identifier"], rule["severity"]) for reader_category, _key, rule in rules} == {
        (_READER_CATEGORY[category], entry.identifier, entry.severity)}
    if category == "injection":
        assert all(rule["pattern_src"] == INJECTION_PATTERN for _c, _k, rule in rules)
    if category == "fileaccess":
        assert all((rule["toolName"], rule["category"]) == ("read_file", "ssh-private-key") for _c, _k, rule in rules)


def test_the_dependency_row_carries_the_locators_the_live_lookup_queries(keys):
    """ruleset/live/lookup._dependency_sparql finds a DependencySignal by dp:package/dp:ecosystem/dp:version."""
    found = {q["predicate"]: _plain(q["object"]) for q in _built(keys, ENTRIES["dep"]) if q["predicate"].startswith("urn:defender:p:")}
    assert found == {"urn:defender:p:package": "evil-pkg", "urn:defender:p:ecosystem": "npm", "urn:defender:p:version": "1.0.0"}


def test_the_ioc_row_carries_the_value_the_live_lookup_queries(keys):
    """ruleset/live/lookup._ioc_sparql finds an IocSignal by dp:value."""
    found = {q["predicate"]: _plain(q["object"]) for q in _built(keys, ENTRIES["ioc"]) if q["predicate"].startswith("urn:defender:p:")}
    assert found == {"urn:defender:p:iocType": "domain", "urn:defender:p:value": "evil.example"}


# ------------------------------------------------------------------ corrections (P5)

#: A legacy corpus row for 8.8.8.8 does not live at threat_uri(identifier) (F-031).
LEGACY_8888 = "urn:defender:signal:94f04f19bc0000000000000000000000"
OWN_8888 = threat_ids.threat_uri("ioc:ip:8.8.8.8")
CORRECTION_ASSET = f"{VERIFIED_GRAPH}/_verifiable_memory/7"


def _correction_envelope(signers, payload):
    first = signing.sign(signers[0], statement_type=rb.CORRECTION_STATEMENT, environment=NETWORK, graph=VERIFIED_GRAPH,
                         payload=payload, root_epoch=1, sequence=4)
    for key in signers[1:]:
        first = signing.cosign(first, key)
    return first


def _reader_rows(quads):
    """The correction lane's binding rows (graph_queries.CORRECTION_PROPERTIES) for *quads*."""
    variable = {constants.RDF_TYPE: "rdfType", constants.DEFENDER_CORRECTION_TARGET_PRED: "targetSubject",
                constants.DEFENDER_CORRECTION_ACTION_PRED: "correctionAction", constants.SIGNED_STATEMENT_PRED: "signedStatement"}
    rows = {}
    for quad in quads:
        if quad["predicate"] in variable:
            value = quad["object"] if quad["object"].startswith("urn:") else _plain(quad["object"])
            rows.setdefault(quad["subject"], {"g": CORRECTION_ASSET})[variable[quad["predicate"]]] = value
    return [(row, "public") for row in rows.values()]


def test_the_correction_payload_holds_the_looked_up_target_subjects():
    payload = rb.correction_payload("ioc:ip:8.8.8.8", [OWN_8888, LEGACY_8888, LEGACY_8888],
                                    reason="public DNS resolver", source="misp-warninglists:public-dns-v4")
    assert payload == {"action": "suppress", "targetSubjects": f"{LEGACY_8888} {OWN_8888}", "identifier": "ioc:ip:8.8.8.8",
                       "reason": "public DNS resolver", "source": "misp-warninglists:public-dns-v4"}
    assert all(isinstance(value, str) for value in payload.values())            # a flat str->str envelope payload


def test_the_rows_target_exactly_the_looked_up_subjects_never_the_identifiers_own_uri(keys):
    """F-031: 8.8.8.8 lives at urn:defender:signal:…; a row aimed at threat_uri(identifier) would miss it."""
    envelope = _correction_envelope(keys, rb.correction_payload("ioc:ip:8.8.8.8", [LEGACY_8888], reason="resolver",
                                                                source="misp"))
    quads = rb.correction_quads(envelope)
    targets = [q["object"] for q in quads if q["predicate"] == constants.DEFENDER_CORRECTION_TARGET_PRED]
    assert targets == [LEGACY_8888] and OWN_8888 not in json.dumps(quads)
    assert {q["object"] for q in quads if q["predicate"] == constants.RDF_TYPE} == {constants.DEFENDER_CORRECTION_TYPE_IRI}
    assert [_signed_literal(quads)] == [envelope.to_text()]                      # every row carries the envelope
    assert not any(q["predicate"] == constants.IDENTIFIER_PRED for q in quads)  # never a g:identifier rule


def test_each_target_gets_its_own_signed_row(keys):
    envelope = _correction_envelope(keys, rb.correction_payload("ioc:ip:8.8.8.8", [LEGACY_8888, OWN_8888],
                                                                reason="resolver", source="misp"))
    quads = rb.correction_quads(envelope)
    by_subject = {}
    for quad in quads:
        by_subject.setdefault(quad["subject"], {})[quad["predicate"]] = quad["object"]
    assert len(by_subject) == 2
    assert {row[constants.DEFENDER_CORRECTION_TARGET_PRED] for row in by_subject.values()} == {LEGACY_8888, OWN_8888}
    assert all(_plain(row[constants.SIGNED_STATEMENT_PRED]) == envelope.to_text() for row in by_subject.values())
    assert all(_plain(row["urn:defender:p:reason"]) == "resolver" for row in by_subject.values())


def test_the_r3_reader_honours_the_built_rows_with_a_curator_and_the_break_glass_key():
    """Round trip: what P5 writes is what ruleset/live/corrections honours — the break-glass key
    counts toward a correction (a reduction, K2), on the signed targets only."""
    from plugins.blackbox.ruleset.live import corrections

    curator_a, curator_b, break_glass = (Ed25519PrivateKey.generate() for _ in range(3))
    operators = {signing.public_key_hex(curator_a): "Umanitek", signing.public_key_hex(curator_b): "Umoja Ark",
                 signing.public_key_hex(break_glass): "Sealed"}
    manifest = km.KeyManifest(environment=NETWORK, graph=VERIFIED_GRAPH, chain="", root_epoch=1, version=1, threshold=2,
                              promotion_author="0x" + "1" * 40, legacy_assets_hash=km.legacy_assets_hash([]),
                              break_glass_key=signing.public_key_hex(break_glass), **km.roster(operators))
    payload = rb.correction_payload("ioc:ip:8.8.8.8", [LEGACY_8888, OWN_8888], reason="resolver", source="misp")
    rows = _reader_rows(rb.correction_quads(_correction_envelope((curator_a, break_glass), payload)))
    assert corrections.signed_suppressions(rows, {CORRECTION_ASSET: manifest}, frozenset()) == {LEGACY_8888, OWN_8888}
    alone = _reader_rows(rb.correction_quads(_correction_envelope((curator_a,), payload)))
    assert corrections.signed_suppressions(alone, {CORRECTION_ASSET: manifest}, frozenset()) == frozenset()


@pytest.mark.parametrize("subjects, reason, source, refused", [
    ([], "r", "s", "1 to 20 subjects"),
    ([f"urn:defender:signal:{n}" for n in range(21)], "r", "s", "1 to 20 subjects"),
    (["urn:x y"], "r", "s", "plain subject IRI"),
    (["urn:x>"], "r", "s", "plain subject IRI"),
    ([LEGACY_8888], " ", "s", "one-line reason"),
    ([LEGACY_8888], "r", "two\nlines", "one-line source"),
    ([LEGACY_8888], "r" * 201, "s", "one-line reason"),
])
def test_a_correction_payload_outside_its_shape_is_refused(subjects, reason, source, refused):
    with pytest.raises(rb.RowBuildError, match=refused):
        rb.correction_payload("ioc:ip:8.8.8.8", subjects, reason=reason, source=source)


def test_correction_rows_need_a_signed_suppress_correction(keys):
    payload = rb.correction_payload("ioc:ip:8.8.8.8", [LEGACY_8888], reason="r", source="s")
    with pytest.raises(rb.RowBuildError, match="signed blackbox.correction"):
        rb.correction_quads(_envelope(keys, payload))                             # a promotion envelope
    with pytest.raises(rb.RowBuildError, match="only a suppress"):
        rb.correction_quads(_correction_envelope(keys, {**payload, "action": "restore"}))
