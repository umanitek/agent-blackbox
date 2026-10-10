"""Refine R1 — an unvalidated report cannot be built (community/report_schema.py).

Every field is checked against a closed vocabulary that already exists in the
code, the identifier must equal the one its fields derive, and free text is
refused. Rejects never leave the machine.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from plugins.blackbox.community import report_builder
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
    future = datetime.now(timezone.utc) + timedelta(hours=2)
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
    """KI-182 (FIX-0044): the bridge shares only R1-schema, SIGNED reports, to the
    COMMUNITY graph, behind the same gates as Python. The switch may be wired
    now; these structural checks keep every piece of the port in place."""
    from pathlib import Path
    src = Path(__file__).resolve().parents[2] / "integrations" / "openclaw" / "src"
    config = (src / "config.ts").read_text(encoding="utf-8")
    index = (src / "index.ts").read_text(encoding="utf-8")
    quads = (src / "quads.ts").read_text(encoding="utf-8")
    assert "effectiveDailyReportLimit(" in config and "dailyReportLimit: 0" not in config   # 0 is never "no cap"
    assert "communityGraphId" in config and "communityGraphPeerId" in config
    assert "rt.client.shareReport(rt.cfg.communityGraphId" in index                      # never the verified graph
    assert "rt.cfg.contextGraphId, name, quads" not in index
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


def test_mapped_ipv6_preserves_shared_hex_identifiers_and_grammar():
    from plugins.blackbox.kernel import threat_ids

    for dotted, canonical in [("::ffff:192.0.2.128", "::ffff:c000:280"),
                              ("::ffff:0.0.0.1", "::ffff:0:1"),
                              ("::ffff:255.255.255.255", "::ffff:ffff:ffff")]:
        assert threat_ids.normalize_ioc_value("ip", dotted) == canonical
        assert threat_ids.normalize_ioc_value("ip", canonical) == canonical
        assert threat_ids.ioc_value_is_well_formed("ip", canonical)
        assert not threat_ids.ioc_value_is_well_formed("ip", dotted)
