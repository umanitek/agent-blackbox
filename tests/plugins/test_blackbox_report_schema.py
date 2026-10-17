"""Refine R1 — an unvalidated report cannot be built (community/report_schema.py).

Every field is checked against a closed vocabulary that already exists in the
code, the identifier must equal the one its fields derive, and free text is
refused. Rejects never leave the machine.
"""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timedelta, timezone, UTC

import pytest

from plugins.blackbox.community import report_builder, report_schema
from plugins.blackbox.community.report_schema import ReportValidationError, validate_report
from plugins.blackbox.kernel import constants, threat_ids

SHA = "a" * 64


def _ok(category, identifier, **evidence):
    return validate_report(identifier=identifier, category=category, severity="high", framework="hermes", evidence=evidence)


def _bad(category, identifier, **evidence):
    with pytest.raises(ReportValidationError):
        _ok(category, identifier, **evidence)


# ------------------------------------------------------------ accepted shapes


def test_each_category_accepts_its_valid_shape():
    inj = threat_ids.injection_identifier("ignore previous instructions")
    assert _ok("injection", inj, context="in-fetched-page", owasp_category="llm01").evidence == (
        ("context", "in-fetched-page"), ("owasp_category", "LLM01"))
    _ok("escalation", "escalation:terminal:rm-rf-system-paths", tool_name="terminal", arg_shape="rm-rf-system-paths")
    _ok("dependency", "dep:pypi:evil-pkg@1.0", ecosystem="pypi", package_name="Evil_Pkg", package_version="1.0",
        kind="malware", advisory_id="MAL-2026-1", reason="advisory:MAL-2026-1")
    _ok("fileaccess", "fileaccess:read_file:ssh-private-key", tool_name="read_file", file_category="ssh-private-key")
    _ok("skill", f"skill:artifact:{SHA}:credential-exfil", artifact_hash=SHA, danger_shape="credential-exfil")
    _ok("ioc", threat_ids.ioc_identifier("domain", "evil.example"), ioc_type="domain", ioc_context="in-skill")


# ------------------------------------------------------------- refused shapes


def test_a_vulnerability_report_cannot_be_built():
    _bad("dependency", "dep:npm:x@1", ecosystem="npm", package_name="x", package_version="1", kind="vulnerability")
    _bad("dependency", "dep:npm:x@1", ecosystem="npm", package_name="x", package_version="1")   # kind is mandatory


def test_an_injection_report_without_a_valid_context_is_refused():
    inj = threat_ids.injection_identifier("p")
    _bad("injection", inj)
    _bad("injection", inj, context="https://example.com/page")       # never a source domain (decision 24)


def test_free_text_is_refused():
    inj = threat_ids.injection_identifier("p")
    _bad("injection", inj, context="in-user-prompt", pattern="ignore all previous instructions")
    _bad("dependency", "dep:npm:x@1", ecosystem="npm", package_name="x", package_version="1", kind="malware",
         description="free text")


def test_a_local_skill_is_never_named():
    _bad("skill", f"skill:artifact:{SHA}:obfuscation", artifact_hash=SHA, danger_shape="obfuscation", skill_name="acme-internal")
    _bad("skill", f"skill:artifact:{'z' * 64}:obfuscation", artifact_hash="z" * 64, danger_shape="obfuscation")


def test_values_outside_the_closed_vocabularies_are_refused():
    _bad("escalation", "escalation:terminal:made-up", tool_name="terminal", arg_shape="made-up")
    _bad("fileaccess", "fileaccess:read_file:my-diary", tool_name="read_file", file_category="my-diary")
    _bad("ioc", "ioc:planet:mars", ioc_type="planet")
    _bad("dependency", "dep:go:x@1", ecosystem="go", package_name="x", package_version="1", kind="malware")


def test_the_identifier_must_match_its_fields():
    _bad("escalation", "escalation:terminal:chmod-world-writable", tool_name="terminal", arg_shape="rm-rf-system-paths")
    _bad("dependency", "dep:npm:other@1", ecosystem="npm", package_name="x", package_version="1", kind="malware")
    _bad("injection", "injection:Ignore all previous instructions", context="in-user-prompt")


def test_ioc_identifiers_must_be_canonical_so_lookalikes_cannot_split():
    _bad("ioc", "ioc:domain:EVIL.example", ioc_type="domain", ioc_context="fetched-by-tool")                  # not canonical (case)
    canonical = threat_ids.ioc_identifier("domain", "bücher.example")          # IDN -> punycode
    _ok("ioc", canonical, ioc_type="domain", ioc_context="fetched-by-tool")
    _bad("ioc", "ioc:domain:bücher.example", ioc_type="domain", ioc_context="fetched-by-tool")


def test_control_characters_and_oversized_values_are_refused():
    _bad("fileaccess", "fileaccess:read\x1b_file:ssh-private-key", tool_name="read\x1b_file", file_category="ssh-private-key")
    _bad("dependency", "dep:npm:x@1", ecosystem="npm", package_name="x" * 500, package_version="1", kind="malware")
    _bad("ioc", "ioc:domain:" + "a" * 600 + ".example", ioc_type="domain")


def test_severity_and_framework_are_closed():
    with pytest.raises(ReportValidationError):
        validate_report(identifier="ioc:domain:x.example", category="ioc", severity="apocalyptic",
                        framework="hermes", evidence={"ioc_type": "domain", "ioc_context": "in-skill"})
    with pytest.raises(ReportValidationError):
        validate_report(identifier="ioc:domain:x.example", category="ioc", severity="high",
                        framework="some-bot", evidence={"ioc_type": "domain", "ioc_context": "in-skill"})


def test_a_report_dated_in_the_future_is_refused():
    future = datetime.now(UTC) + timedelta(hours=2)
    with pytest.raises(ReportValidationError):
        report_builder.build_report_quads(identifier="ioc:domain:x.example", category="ioc", severity="high",
                                          reporter_address="0x66bc7cd539d3bb0be39158dd14f27b38342c7e6a", ioc_type="domain", ioc_context="in-skill", ts=future)


def test_the_builder_emits_only_validated_fields():
    quads = report_builder.build_report_quads(identifier="dep:pypi:evil-pkg@1.0", category="dependency",
                                              severity="critical", reporter_address="0x66bc7cd539d3bb0be39158dd14f27b38342c7e6a", ecosystem="PyPI",
                                              package_name="Evil_Pkg", package_version="1.0", kind="malware",
                                              reason="exfil")
    names = {q["object"] for q in quads if q["predicate"] == constants.PACKAGE_NAME_PRED}
    assert names == {'"evil-pkg"'}                                              # canonical, as in the identifier


# ------------------------------------------- plan §04 minimums (R1 completion, LES-023)


def _dep(version="1.0", **kw):
    fields = dict(ecosystem="npm", package_name="x", package_version=version, kind="malware")
    fields.update(kw)
    return f"dep:npm:x@{version}", fields


def test_a_dependency_report_needs_a_closed_reason():
    _bad("dependency", *_dep()[:1], **_dep()[1])                                  # no reason
    _bad("dependency", *_dep()[:1], **_dep(reason="looked sketchy")[1])            # free text
    for reason in ("typosquat", "install-hook", "exfil", "internal-mirror-collision", "advisory:MAL-2026-1"):
        _ok("dependency", *_dep()[:1], **_dep(reason=reason)[1])


def test_an_advisory_reason_must_agree_with_the_advisory_id():
    _bad("dependency", *_dep()[:1], **_dep(reason="advisory:MAL-1", advisory_id="MAL-2")[1])
    record = _ok("dependency", *_dep()[:1], **_dep(reason="advisory:MAL-7")[1])
    assert dict(record.evidence)["advisory_id"] == "MAL-7"


def test_a_whole_package_report_only_for_typosquat_or_mirror_collision():
    _ok("dependency", *_dep("*")[:1], **_dep("*", reason="typosquat")[1])
    _ok("dependency", *_dep("*")[:1], **_dep("*", reason="internal-mirror-collision")[1])
    _bad("dependency", *_dep("*")[:1], **_dep("*", reason="install-hook")[1])
    _bad("dependency", *_dep("*")[:1], **_dep("*", reason="advisory:MAL-1")[1])


def test_an_ioc_report_needs_a_closed_context():
    ident = threat_ids.ioc_identifier("domain", "evil.example")
    _bad("ioc", ident, ioc_type="domain")
    _bad("ioc", ident, ioc_type="domain", ioc_context="https://where-i-saw-it.example")
    for context in constants.IOC_CONTEXTS:
        _ok("ioc", ident, ioc_type="domain", ioc_context=context)


def test_a_named_skill_needs_a_public_registry_and_a_local_one_is_never_named():
    _ok("skill", "skill:evil@1.0", registry="clawhub", skill_name="evil", skill_version="1.0")
    _bad("skill", "skill:evil@1.0", skill_name="evil", skill_version="1.0")                       # no registry
    _bad("skill", "skill:evil@1.0", registry="local", skill_name="evil", skill_version="1.0")     # never local
    _bad("skill", f"skill:artifact:{SHA}:obfuscation", artifact_hash=SHA, danger_shape="obfuscation",
         registry="clawhub")


# ------------------------------------------------------- R1 done-when: "no path"


def test_confusable_package_names_are_refused_not_canonicalised_into_a_real_one():
    """A Cyrillic 'а' (U+0430) in "reаct" must not pass as the ASCII package."""
    lookalike = "reаct"
    _bad("dependency", f"dep:npm:{lookalike}@1.0", **_dep(package_name=lookalike, reason="typosquat")[1])


def test_the_openclaw_bridge_share_path_is_the_r1_signed_community_path():
    """KI-182 (FIX-0044): the bridge shares only R1-schema, SIGNED reports, with the
    community — the verified graph's shared memory, never its Verified Memory
    (one graph since 2026-10-16) — behind the same gates as Python. These
    structural checks keep every piece of the port in place."""
    from pathlib import Path
    src = Path(__file__).resolve().parents[2] / "integrations" / "openclaw" / "src"
    config = (src / "config.ts").read_text(encoding="utf-8")
    index = (src / "index.ts").read_text(encoding="utf-8")
    quads = (src / "quads.ts").read_text(encoding="utf-8")
    assert "effectiveDailyReportLimit(" in config and "dailyReportLimit: 0" not in config   # 0 is never "no cap"
    assert "rt.client.shareReport(rt.cfg.contextGraphId, name, quads)" in index         # the community's shared memory
    assert "sharingConsentInForce(rt.cfg.blackboxHome)" in index                          # R13 gate
    assert "if (!signer) return;" in index                                               # a node that cannot sign does not share
    assert "validateReport(" in quads and "BLACKBOX_SIGNED_STATEMENT_PRED" in quads       # R1 schema + R0b envelope
    assert '"anonymous"' not in quads and 'rt.reporterAddress = "node"' not in index     # LES-003: no fallback identity


# ------------------------------------------------------------------ KI-193: IPv6 is an IOC identifier


def test_ipv6_canonicalises_to_the_compressed_lower_case_form():
    from plugins.blackbox.kernel import threat_ids

    for spelled in ("2001:DB8:0:0:0:0:0:1", "2001:db8::1", "[2001:db8::1]:8443", "2001:db8::1%eth0", "2001:0db8:0000::0001"):
        assert threat_ids.normalize_ioc_value("ip", spelled) == "2001:db8::1", spelled
    assert threat_ids.ioc_value_is_well_formed("ip", "2001:db8::1")
    assert threat_ids.ioc_value_is_well_formed("ip", "::1")


def test_ipv4_identifiers_do_not_move():
    """Changing a canonical form changes graph identifiers — IPv4 stays byte-identical."""
    from plugins.blackbox.kernel import threat_ids

    assert threat_ids.normalize_ioc_value("ip", "203.0.113.7:8080") == "203.0.113.7"
    assert threat_ids.normalize_ioc_value("ip", "203.0.113.7") == "203.0.113.7"


def test_a_malformed_ipv6_is_refused_by_the_grammar_not_repaired():
    from plugins.blackbox.kernel import threat_ids

    for bad in ("2001:db8::zz", "2001:db8:::1", "[2001:db8::1"):
        canonical = threat_ids.normalize_ioc_value("ip", bad)
        assert not threat_ids.ioc_value_is_well_formed("ip", canonical), bad


# ------------------------------- trust-and-threat-lab §03.6 (REP1): common fields, IOC reason, widened formats


IOC_DOMAIN = threat_ids.ioc_identifier("domain", "evil.example")


def test_matched_by_outside_the_vocabulary_is_refused():
    for matched_by in sorted(report_schema.MATCHED_BY):
        assert _ok("ioc", IOC_DOMAIN, ioc_type="domain", ioc_context="in-skill", matched_by=matched_by).matched_by == matched_by
    for bad in ("heuristic", "verified graph", "llm", "VERIFIED-ish"):
        _bad("ioc", IOC_DOMAIN, ioc_type="domain", ioc_context="in-skill", matched_by=bad)


def test_blackbox_version_must_be_a_release_number():
    for version in ("1.1.0", constants.__version__, "1.2.0rc1", "1.2.0+local", "10.0.20"):
        assert _ok("ioc", IOC_DOMAIN, ioc_type="domain", ioc_context="in-skill",
                   blackbox_version=version).blackbox_version == version
    for bad in ("latest", "1", "v1.1.0", "1.1.0 beta", "1.1.0‮", "1." + "1" * 200):
        _bad("ioc", IOC_DOMAIN, ioc_type="domain", ioc_context="in-skill", blackbox_version=bad)


def test_the_common_fields_are_optional_so_older_reports_stay_valid():
    record = _ok("ioc", IOC_DOMAIN, ioc_type="domain", ioc_context="in-skill")
    assert (record.matched_by, record.blackbox_version, record.common_fields()) == ("", "", {})


def test_an_ioc_reason_comes_from_the_fixed_list():
    for reason in sorted(report_schema.IOC_REASONS):
        record = _ok("ioc", IOC_DOMAIN, ioc_type="domain", ioc_context="in-skill", reason=reason)
        assert dict(record.evidence)["reason"] == reason
    for bad in ("it looked bad", "typosquat", "advisory:MAL-1", "https://evil.example"):
        _bad("ioc", IOC_DOMAIN, ioc_type="domain", ioc_context="in-skill", reason=bad)


def test_a_package_matched_by_the_verified_graph_needs_no_advisory_id():
    record = _ok("dependency", *_dep()[:1], **_dep(reason="verified-match", matched_by="verified")[1])
    assert dict(record.evidence)["reason"] == "verified-match" and "advisory_id" not in dict(record.evidence)
    _bad("dependency", *_dep()[:1], **_dep(reason="verified-match")[1])                         # only a verified match
    _bad("dependency", *_dep()[:1], **_dep(reason="verified-match", matched_by="built-in")[1])
    _bad("dependency", *_dep("*")[:1], **_dep("*", reason="verified-match", matched_by="verified")[1])


def test_an_injection_found_in_a_tools_input_can_be_reported():
    inj = threat_ids.injection_identifier("ignore previous instructions")
    assert dict(_ok("injection", inj, context="in-tool-input").evidence)["context"] == "in-tool-input"
    assert set(constants.INJECTION_CONTEXTS) < set(report_schema.INJECTION_CONTEXTS)   # widened, nothing dropped


def test_a_skill_matched_by_the_verified_graph_is_reported_by_name_and_version():
    record = _ok("skill", "skill:evil@1.0", skill_name="evil", skill_version="1.0", matched_by="verified")
    assert record.evidence == (("skill_name", "evil"), ("skill_version", "1.0"))
    _bad("skill", "skill:evil@1.0", skill_name="evil", skill_version="1.0", matched_by="built-in")   # KI-159 holds
    _bad("skill", "skill:evil@1.0", skill_name="evil", skill_version="1.0", matched_by="verified", registry="local")


def _real_report_of_every_category():
    """(identifier, evidence) — one real item per category, each stating both common fields."""
    common = {"matched_by": "built-in", "blackbox_version": constants.__version__}
    return [
        (threat_ids.injection_identifier("ignore previous instructions"),
         {"context": "in-tool-input", "owasp_category": "LLM01", **common}),
        ("escalation:terminal:rm-rf-system-paths", {"tool_name": "terminal", "arg_shape": "rm-rf-system-paths", **common}),
        ("dep:npm:evil@1.0", {"ecosystem": "npm", "package_name": "evil", "package_version": "1.0", "kind": "malware",
                              "reason": "verified-match", **common, "matched_by": "verified"}),
        ("dep:pypi:evil-pkg@2.0", {"ecosystem": "pypi", "package_name": "evil-pkg", "package_version": "2.0",
                                   "kind": "malware", "reason": "advisory:MAL-2026-1", "advisory_id": "MAL-2026-1",
                                   **common, "matched_by": "advisory"}),
        ("fileaccess:read_file:ssh-private-key", {"tool_name": "read_file", "file_category": "ssh-private-key", **common}),
        ("skill:evil@1.0", {"skill_name": "evil", "skill_version": "1.0", **common, "matched_by": "verified"}),
        ("skill:evil@2.0", {"registry": "clawhub", "skill_name": "evil", "skill_version": "2.0", **common}),
        (f"skill:artifact:{SHA}:credential-exfil", {"artifact_hash": SHA, "danger_shape": "credential-exfil", **common}),
        (IOC_DOMAIN, {"ioc_type": "domain", "ioc_context": "fetched-by-tool", "reason": "phishing", **common}),
    ]


def test_writer_to_reader_parity_for_one_real_item_of_every_category():
    """LES-032: the reader re-validates exactly what the writer validated and signed —
    every writer-built report verifies, and the read side carries both common fields."""
    from _community_rows import GRAPH, NETWORK, Reporter, signed_row
    from plugins.blackbox.community import graph_stats
    from plugins.blackbox.community.verification import ReportVerifier, verify_report_rows

    items = _real_report_of_every_category()
    assert {threat_ids.category_for(identifier) for identifier, _ in items} == set(report_schema._VALIDATORS)
    reporter = Reporter("0xparity")
    rows = [signed_row(identifier, reporter, category=threat_ids.category_for(identifier), **evidence)
            for identifier, evidence in items]
    verifier = ReportVerifier(NETWORK, GRAPH)
    reports, dropped = verify_report_rows(rows, verifier)
    assert dropped == 0 and verifier.drops["schema"] == 0
    for (identifier, evidence), report in zip(items, reports):
        fields = dict(report.fields)
        assert report.identifier == identifier
        assert (fields["matchedBy"], fields["blackboxVersion"]) == (evidence["matched_by"], evidence["blackbox_version"])
    board = {t["identifier"]: t for t in graph_stats.most_reported_threats(reports, limit=len(items))}
    assert board["dep:npm:evil@1.0"]["matched_by"] == ["verified"]
    assert board[IOC_DOMAIN]["blackbox_versions"] == [constants.__version__]


def test_the_reader_refuses_a_signed_matched_by_the_writer_would_refuse():
    """A modified client can sign anything: the reader drops a signed report whose
    common field is outside the closed vocabulary, as the writer would refuse to build it."""
    from _community_rows import GRAPH, NETWORK, Reporter, signed_row
    from plugins.blackbox.community.report_signer import REPORT_STATEMENT, ReportSigner
    from plugins.blackbox.community.verification import ReportVerifier

    reporter = Reporter("0xforger")
    row = signed_row(IOC_DOMAIN, reporter, matched_by="verified")
    payload = json.loads(row["signedStatement"])["payload"]
    forged = {**payload, "matched_by": "trust-me"}
    row = {**row, "matchedBy": "trust-me",
           "signedStatement": ReportSigner(private_key=reporter.key, environment=NETWORK, graph=GRAPH).sign(REPORT_STATEMENT, forged)}
    verifier = ReportVerifier(NETWORK, GRAPH)
    assert verifier.verify(row) is None and verifier.drops["schema"] == 1


def test_a_row_showing_another_matched_by_than_it_signed_is_dropped():
    from _community_rows import GRAPH, NETWORK, Reporter, signed_row
    from plugins.blackbox.community.verification import ReportVerifier

    row = signed_row(IOC_DOMAIN, Reporter("0xtamper"), matched_by="built-in")
    assert ReportVerifier(NETWORK, GRAPH).verify(row) is not None
    assert ReportVerifier(NETWORK, GRAPH).verify({**row, "matchedBy": "verified"}) is None


def test_the_builder_writes_the_common_fields_under_their_own_predicates_and_signs_them():
    quads = report_builder.build_report_quads(identifier=IOC_DOMAIN, category="ioc", severity="high",
                                              reporter_address="0x66bc7cd539d3bb0be39158dd14f27b38342c7e6a",
                                              ioc_type="domain", ioc_context="in-skill", reason="scam",
                                              matched_by="advisory", blackbox_version="1.1.0")
    by_predicate = {q["predicate"]: q["object"] for q in quads}
    assert by_predicate[constants.MATCHED_BY_PRED] == '"advisory"'
    assert by_predicate[constants.BLACKBOX_VERSION_PRED] == '"1.1.0"'
    assert by_predicate[constants.REPORT_REASON_PRED] == '"scam"'
    plain = report_builder.build_report_quads(identifier=IOC_DOMAIN, category="ioc", severity="high",
                                              reporter_address="0x66bc7cd539d3bb0be39158dd14f27b38342c7e6a",
                                              ioc_type="domain", ioc_context="in-skill")
    assert not {constants.MATCHED_BY_PRED, constants.BLACKBOX_VERSION_PRED} & {q["predicate"] for q in plain}


def test_the_reader_holds_the_verified_only_gates_against_a_forged_matched_by():
    """REP1 review: the two widened formats that need ``matched_by=verified`` (a
    verified-match dependency, a skill by name + version without a registry) are
    refused on READ when a modified client signs them with any other matched_by —
    the reader runs the writer's gates on the signed payload (LES-032)."""
    from _community_rows import GRAPH, NETWORK, Reporter, signed_row
    from plugins.blackbox.community.report_signer import REPORT_STATEMENT, ReportSigner
    from plugins.blackbox.community.verification import ReportVerifier

    reporter = Reporter("0xdowngrade")
    signer = ReportSigner(private_key=reporter.key, environment=NETWORK, graph=GRAPH)
    rows = [signed_row("dep:npm:evil@1.0", reporter, reason="verified-match", matched_by="verified"),
            signed_row("skill:evil@1.0", reporter, skill_name="evil", skill_version="1.0", matched_by="verified")]
    verifier = ReportVerifier(NETWORK, GRAPH)
    assert all(verifier.verify(row) is not None for row in rows)              # genuine verified matches pass
    for row in rows:
        payload = json.loads(row["signedStatement"])["payload"]
        forged = {**row, "matchedBy": "built-in",
                  "signedStatement": signer.sign(REPORT_STATEMENT, {**payload, "matched_by": "built-in"})}
        assert verifier.verify(forged) is None
    assert verifier.drops["schema"] == 2


def test_verified_prefixed_hash_identifier_is_reportable():
    """KI-354: the verified graph and detection both spell digests ``sha256:<hex>``;
    such a report was refused, so no verified hash match could ever be shared."""
    identifier = "ioc:hash:sha256:d2e1ab10d5a0c16a724aeda8acb46b38f551ade58137969c3bc3c9cdc0a12425"
    assert _ok("ioc", identifier, ioc_type="hash", ioc_context="fetched-by-tool").identifier == identifier
    _bad("ioc", "ioc:hash:sha256:" + "a" * 40, ioc_type="hash", ioc_context="fetched-by-tool")


# --- KI-339: an IPv4-mapped address has one spelling on every Python -------------
# CPython 3.11.7 printed ::ffff:c000:280, 3.11.15 / 3.13+ ::ffff:192.0.2.128, so two
# nodes minted different identifiers for one address. The dotted form is spelt out.


@pytest.mark.parametrize("spelling", ["::ffff:192.0.2.128", "::ffff:c000:280", "::FFFF:C000:0280",
                                       "[::ffff:192.0.2.128]:443", "::ffff:192.0.2.128%eth0"])
def test_every_spelling_of_a_mapped_address_canonicalises_to_the_dotted_form(spelling):
    from plugins.blackbox.kernel import threat_ids
    assert threat_ids.normalize_ioc_value("ip", spelling) == "::ffff:192.0.2.128"


def test_only_the_dotted_mapped_form_is_canonical():
    from plugins.blackbox.kernel import threat_ids
    assert threat_ids.ioc_value_is_well_formed("ip", "::ffff:192.0.2.128")
    assert not threat_ids.ioc_value_is_well_formed("ip", "::ffff:c000:280")


def test_the_spelling_survives_a_python_that_prints_mapped_addresses_in_hex(monkeypatch):
    # LES-043: our text, not the library's str(); fake the 3.11.7 rendering.
    from plugins.blackbox.kernel import threat_ids
    real = ipaddress.IPv6Address.compressed
    def old_python(self):
        return "::ffff:c000:280" if self.ipv4_mapped is not None else real.fget(self)
    monkeypatch.setattr(ipaddress.IPv6Address, "compressed", property(old_python))
    assert threat_ids.normalize_ioc_value("ip", "::ffff:192.0.2.128") == "::ffff:192.0.2.128"
    assert threat_ids.normalize_ioc_value("ip", "2001:db8::1") == "2001:db8::1"
