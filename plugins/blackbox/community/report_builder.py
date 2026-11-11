"""Report quads: a finding -> the privacy-safe statements shared to the community graph.

One subject per (reporter, threat) — ``urn:guardian:report:{reporter}:{hash}``
— which makes distinct-reporter counting honest by construction. Never carries
prompt or command text; literals are capped by :mod:`..kernel.rdf_terms`.

Usage: ``community.build_report_quads(identifier, severity=..., reporter_address=...)``
· ``community.build_false_positive_quads(identifier, reporter_address=..., reason=...)``
· ``community.build_retraction_quads(identifier, reporter_address=..., signer=...)``.
"""

from __future__ import annotations

from datetime import datetime, UTC
from typing import Optional
from ..kernel import constants
from ..kernel import rdf_terms
from ..kernel import signing, threat_ids
from . import report_schema
from .sighting import vocab as sighting_vocab
from .report_signer import DISPUTE_STATEMENT, REPORT_STATEMENT, RETRACT_STATEMENT, ReportSigner

# ---------------------------------------------------------------------------
# Threat / report quad builders
# ---------------------------------------------------------------------------

#: The evidence a report may carry, per category: (keyword argument, predicate),
#: in emission order. ONE table, so the builder and anything that reads or signs
#: a report's fields agree on what a report holds.
_EVIDENCE_FIELDS: dict[str, tuple[tuple[str, str], ...]] = {
    # R1: never the pattern text — the identifier is its hash; the closed context instead.
    "injection": (("context", constants.INJECTION_CONTEXT_PRED), ("owasp_category", constants.OWASP_CATEGORY_PRED)),
    "escalation": (("tool_name", constants.TOOL_NAME_PRED), ("arg_shape", constants.ARG_SHAPE_PRED)),
    "dependency": (
        ("package_name", constants.PACKAGE_NAME_PRED),
        ("package_version", constants.PACKAGE_VERSION_PRED),
        ("ecosystem", constants.PACKAGE_ECOSYSTEM_PRED),
        ("advisory_id", constants.SCHEMA_IDENTIFIER_PRED),
        # Keep the dependency kind intact in the community report.
        ("kind", constants.KIND_PRED),
        ("reason", constants.REPORT_REASON_PRED),   # R1 (§04): why it is malware
    ),
    "fileaccess": (("tool_name", constants.TOOL_NAME_PRED), ("file_category", constants.CATEGORY_PRED)),
    "skill": (
        ("artifact_hash", constants.SKILL_ARTIFACT_HASH_PRED),   # R1: local skills by hash, never name (KI-159)
        ("registry", constants.SKILL_REGISTRY_PRED),              # R1: a named skill's public registry
        ("skill_name", constants.SKILL_NAME_PRED),
        ("skill_version", constants.SKILL_VERSION_PRED),
        ("danger_shape", constants.DANGER_SHAPE_PRED),
    ),
    # KI-024: without this entry an IOC report carried only the common core and
    # curators' evidence queries bound nothing for it. The value itself already
    # lives IN the identifier (ioc:{type}:{value}); the type travels as its own
    # field so reviewers can filter without parsing.
    "ioc": (("ioc_type", constants.IOC_TYPE_PRED), ("ioc_context", constants.IOC_CONTEXT_PRED),
            ("reason", constants.REPORT_REASON_PRED)),   # §03.6: why the indicator is bad (IOC_REASONS)
}

#: The common fields any category may carry (trust-and-threat-lab §03.6), in
#: emission order after the evidence: (keyword argument, predicate).
_COMMON_FIELDS: tuple[tuple[str, str], ...] = (
    ("matched_by", constants.MATCHED_BY_PRED),
    ("blackbox_version", constants.BLACKBOX_VERSION_PRED),
    *sighting_vocab.SIGHTING_FIELDS,   # threat-profiles §03.2: the sighting and what the threat goes after
)
#: Every key a signed report payload may carry beside the core: what a READER
#: validates; any other key is a newer writer's field it does not know yet.
PAYLOAD_FIELD_KEYS = frozenset({name for table in _EVIDENCE_FIELDS.values() for name, _ in table}
                               | {name for name, _ in _COMMON_FIELDS})


def _day(ts: Optional[datetime]) -> datetime:
    """*ts* (default: now) rounded down to midnight UTC — decision 25: a report
    says WHICH DAY, never the minute, so the timestamp is no activity clock."""
    when = ts or datetime.now(UTC)
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return when.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)


def _evidence(record: report_schema.ReportRecord) -> list[tuple[str, str, str]]:
    """(name, predicate, value) for each field of a VALIDATED record — its
    evidence in the table's emission order, then the common fields it states."""
    values = {**dict(record.evidence), **record.common_fields()}
    table = (*_EVIDENCE_FIELDS.get(record.category, ()), *_COMMON_FIELDS)
    return [(name, predicate, values[name]) for name, predicate in table if name in values]


def _signature_quad(subject: str, signer: ReportSigner, statement_type: str, payload: dict[str, str]) -> rdf_terms.Quad:
    """The quad carrying *subject*'s signed envelope."""
    return rdf_terms.make_quad(subject, constants.SIGNED_STATEMENT_PRED,
                               rdf_terms.literal(signer.sign(statement_type, payload)))


def _integrity_quads(subject: str, signed_text: str) -> list[rdf_terms.Quad]:
    """Who signed and what was signed, beside the envelope (threat-profiles §03.3a):
    the record digest (sha256 of the exact signed bytes — the statement's identity,
    LES-033) and the signer's public key. Readers take both from the envelope
    itself; these quads are for anyone browsing the graph."""
    envelope = signing.from_text(signed_text)
    if envelope is None or not envelope.signatures:
        return []
    return [rdf_terms.make_quad(subject, sighting_vocab.RECORD_DIGEST_PRED,
                                rdf_terms.literal("sha256:" + signing.content_id(envelope))),
            rdf_terms.make_quad(subject, sighting_vocab.SIGNER_KEY_PRED,
                                rdf_terms.literal("ed25519:" + envelope.signatures[0].signer))]


def build_report_quads(
    *,
    identifier: str,
    category: str,
    severity: str,
    reporter_address: str,
    framework: str = "hermes",
    ts: Optional[datetime] = None,
    signer: Optional[ReportSigner] = None,
    **evidence: Optional[str],
) -> list[rdf_terms.Quad]:
    """Build a sighting/report for SWM — only from a VALIDATED record.

    The subject is per-submitter namespaced (:func:`report_uri`). Evidence is
    passed as keyword arguments; what each category may carry, and every
    rule it must meet, is :mod:`.report_schema` (Refine R1) — a bad report
    raises :class:`.report_schema.ReportValidationError` and is never built.
    The common fields ``matched_by`` and ``blackbox_version`` (§03.6) are
    keyword arguments like the evidence and are written and signed with it.
    Timestamps are rounded to the day (decision 25). With a *signer* the
    report carries a signed envelope over its fields (R0b).
    """
    record = report_schema.validate_report(identifier=identifier, category=category, severity=severity,
                                           framework=framework, evidence=evidence, ts=ts)
    identifier, severity = record.identifier, record.severity
    subj = threat_ids.report_uri(identifier, reporter_address)
    threat = threat_ids.threat_uri(identifier)
    day = _day(ts)
    reporter = reporter_address.strip().lower()   # report_uri above refused a blank one
    fields = _evidence(record)
    out: list[rdf_terms.Quad] = [
        rdf_terms.make_quad(subj, constants.RDF_TYPE, rdf_terms.iri(constants.REPORT_TYPE_IRI)),
        rdf_terms.make_quad(subj, constants.REPORTS_THREAT_PRED, rdf_terms.iri(threat)),
        rdf_terms.make_quad(subj, constants.IDENTIFIER_PRED, rdf_terms.literal(identifier)),
        rdf_terms.make_quad(subj, constants.REPORTER_PRED, rdf_terms.literal(reporter)),
        rdf_terms.make_quad(subj, constants.FRAMEWORK_PRED, rdf_terms.literal(framework)),
        rdf_terms.make_quad(subj, constants.SEVERITY_PRED, rdf_terms.literal(severity)),
        rdf_terms.make_quad(subj, constants.SCHEMA_DATE_MODIFIED_PRED, rdf_terms.datetime_literal(day)),
    ]
    out.extend(rdf_terms.make_quad(subj, predicate, rdf_terms.literal(value)) for _, predicate, value in fields)
    if signer is not None:
        payload = {"subject": subj, "identifier": identifier, "category": category, "severity": severity,
                   "reporter": reporter, "framework": framework, "day": day.date().isoformat()}
        payload.update({name: value for name, _, value in fields})
        signed_text = signer.sign(REPORT_STATEMENT, payload)
        out.append(rdf_terms.make_quad(subj, constants.SIGNED_STATEMENT_PRED, rdf_terms.literal(signed_text)))
        out.extend(_integrity_quads(subj, signed_text))
    return out




def build_false_positive_quads(
    *,
    identifier: str,
    reporter_address: str,
    reason: str,
    framework: str = "hermes",
    ts: Optional[datetime] = None,
    signer: Optional[ReportSigner] = None,
) -> list[rdf_terms.Quad]:
    """A dispute signal: "this community threat is wrong" (KI-011, Q8's writer).

    Same per-(reporter, threat) subject discipline as reports — one dispute
    voice per reporter per threat, first write wins — under a ``:fp`` suffix
    so a reporter can hold both a report and a dispute without collision.
    Carries the identifier, reporter, framework, timestamp and a closed
    *reason* (``constants.FALSE_POSITIVE_REASONS``, required — Refine R1;
    validated by :func:`.report_schema.validate_dispute`). No evidence
    payload: curators re-check the original reports. Day-rounded and, with a
    *signer*, signed like a report (``blackbox.dispute``).
    """
    identifier, reason = report_schema.validate_dispute(identifier=identifier, reason=reason)
    return _reporter_statement_quads(identifier=identifier, reporter_address=reporter_address, suffix=":fp",
                                     type_iri=constants.FALSE_POSITIVE_TYPE_IRI, statement_type=DISPUTE_STATEMENT,
                                     framework=framework, ts=ts, signer=signer, reason=reason)


def build_retraction_quads(
    *,
    identifier: str,
    reporter_address: str,
    framework: str = "hermes",
    ts: Optional[datetime] = None,
    signer: Optional[ReportSigner] = None,
) -> list[rdf_terms.Quad]:
    """A retraction: "I withdraw my report of this threat" (Refine R1, RETRACT).

    Subject ``report_uri(identifier, reporter) + ":retract"`` — one per
    (reporter, threat), beside the report and any dispute. Readers honour a
    retraction only when it is signed (``blackbox.retract``) by the SAME key
    that signed the report: it withdraws that signer's voice and nobody
    else's (see :mod:`.retractions`). Day-rounded like every statement. An
    unsigned retraction is built (for symmetry with the other builders) but
    no reader acts on it.
    """
    identifier = report_schema.validate_statement_identifier(identifier)
    return _reporter_statement_quads(identifier=identifier, reporter_address=reporter_address, suffix=":retract",
                                     type_iri=constants.RETRACTION_TYPE_IRI, statement_type=RETRACT_STATEMENT,
                                     framework=framework, ts=ts, signer=signer)


def _reporter_statement_quads(*, identifier: str, reporter_address: str, suffix: str, type_iri: str,
                              statement_type: str, framework: str, ts: Optional[datetime],
                              signer: Optional[ReportSigner], reason: str = "") -> list[rdf_terms.Quad]:
    """A reporter's statement ABOUT a threat (dispute, retraction, …): subject
    ``report_uri(identifier, reporter) + suffix`` — one per (reporter, threat,
    kind) — carrying type, identifier, reporter, framework, day, an optional
    closed *reason*, and with a *signer* the signed envelope. The caller has
    validated *identifier* and *reason*."""
    subj = threat_ids.report_uri(identifier, reporter_address) + suffix
    day = _day(ts)
    reporter = reporter_address.strip().lower()   # report_uri above refused a blank one
    out = [
        rdf_terms.make_quad(subj, constants.RDF_TYPE, rdf_terms.iri(type_iri)),
        rdf_terms.make_quad(subj, constants.IDENTIFIER_PRED, rdf_terms.literal(identifier)),
        rdf_terms.make_quad(subj, constants.REPORTER_PRED, rdf_terms.literal(reporter)),
        rdf_terms.make_quad(subj, constants.FRAMEWORK_PRED, rdf_terms.literal(framework)),
        rdf_terms.make_quad(subj, constants.SCHEMA_DATE_MODIFIED_PRED, rdf_terms.datetime_literal(day)),
    ]
    payload = {"subject": subj, "identifier": identifier, "reporter": reporter,
               "framework": framework, "day": day.date().isoformat()}
    if reason:
        out.append(rdf_terms.make_quad(subj, constants.REPORT_REASON_PRED, rdf_terms.literal(reason)))
        payload["reason"] = reason
    if signer is not None:
        out.append(_signature_quad(subj, signer, statement_type, payload))
    return out
