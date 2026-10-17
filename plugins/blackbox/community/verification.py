"""Verifying community reports — the only door from a raw row to a counted report (R0c).

A community row is untrusted: any node can write any ``g:reporter`` string, and
the DKG's own authorship signals are unchecked on some delivery routes
(KI-067/102/110). So a row is believed only when the signed envelope it carries
(:mod:`..kernel.signing`, written by R0b) verifies AND agrees with what the row
shows:

1. the envelope is a ``blackbox.report`` signed for THIS node's network and
   THIS graph — the verified graph, whose shared memory holds the community's
   reports (no replay from a test network or another graph);
2. the row's subject, identifier, reporter and severity equal the signed ones;
3. the subject is the signed reporter's own (``report_uri(identifier, reporter)``);
4. every evidence field the row shows equals the signed value.

Anything else is dropped. A verified report's AUTHOR is the signer's public key
— counting, dedupe and caps key on it, never on the self-described reporter
string, which stays display-only (LES-014). The signer is checked before any
dedupe (KI-144).

Usage::

    verifier = ReportVerifier(environment=network_id, graph=cfg.context_graph_id)
    reports, dropped = verify_report_rows(raw_rows, verifier)
    rules = aggregate_community_reports(reports, prior_first_seen)
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone, UTC

import logging
from dataclasses import dataclass
from typing import Dict, Any, Iterable, List, Mapping, Optional, Tuple

from ..kernel import constants, signing, threat_ids
from ..kernel.dkg_client import extract_binding
from . import report_builder, report_schema
from .sighting import vocab as sighting_vocab
from .report_signer import REPORT_STATEMENT, STATEMENT_SCHEMA_VERSION

logger = logging.getLogger(__name__)

#: Reader query variable -> the key the signed payload uses for the same field
#: (the builder's keyword names, community.report_builder._EVIDENCE_FIELDS).
EVIDENCE_PAYLOAD_KEYS: Mapping[str, str] = {
    "kind": "kind",
    "iocType": "ioc_type",
    "toolName": "tool_name",
    "argShape": "arg_shape",
    "packageName": "package_name",
    "packageVersion": "package_version",
    "packageEcosystem": "ecosystem",
    "category": "file_category",
    "skillName": "skill_name",
    "dangerShape": "danger_shape",
    "pattern": "pattern",
    "injectionContext": "context",          # Refine R1
    "skillArtifactHash": "artifact_hash",   # Refine R1 (KI-159)
    "skillRegistry": "registry",            # Refine R1 (§04)
    "iocContext": "ioc_context",            # Refine R1 (§04)
    "reportReason": "reason",               # Refine R1 (§04)
    "matchedBy": "matched_by",              # trust-and-threat-lab §03.6 (common field)
    "blackboxVersion": "blackbox_version",  # trust-and-threat-lab §03.6 (common field)
    # threat-profiles §03.2: not in the reader's query — taken from the signed payload.
    **sighting_vocab.SIGHTING_PAYLOAD_VARS,
}

#: The reader query variable that carries the envelope.
SIGNED_STATEMENT_VAR = "signedStatement"


@dataclass(frozen=True)
class VerifiedReport:
    """One community report whose signature checked out.

    ``author`` — the signer's Ed25519 public key (hex): THE identity for
    counting. ``reporter`` — the self-described agent address (display only).
    ``fields`` — evidence as (reader variable, signed value) pairs, sorted.
    ``day`` — the signed UTC day of the report (who reported a threat first,
    and since when a reporter has been reporting, are read from it).
    ``signed`` — the signed statement itself, as text: what is handed on when
    the report must be checked again by someone else (the export bundle).
    """

    subject: str
    identifier: str
    author: str
    reporter: str
    severity: str
    fields: tuple[tuple[str, str], ...] = ()
    framework: str = ""      # the signed framework label (display only)
    day: str = ""
    signed: str = ""


class ReportVerifier:
    """Checks rows for one network (``environment``) and one graph.

    Stateless after construction; safe to share across threads.
    """

    def __init__(self, environment: str, graph: str, today: Optional[str] = None) -> None:
        self._environment = environment
        self._graph = graph
        self._today = today or _utc_today()
        #: R10b: why rows were dropped — "env_mismatch" (signed for another network / graph:
        #: a config mistake), "future_dated" (a modified client), "other" (unsigned / forged).
        #: "schema" — signed and well attributed, but a value the closed report schema refuses today.
        self.drops: dict[str, int] = {"env_mismatch": 0, "future_dated": 0, "schema": 0, "other": 0}

    def verify(self, row: Mapping[str, Any]) -> Optional[VerifiedReport]:
        """The verified report for *row*, or None when it must be dropped."""
        envelope = signing.from_text(extract_binding(row.get(SIGNED_STATEMENT_VAR)))
        author = signing.verify(envelope, statement_type=REPORT_STATEMENT,
                                environment=self._environment, graph=self._graph)
        if author is None or envelope is None:
            mismatch = envelope is not None and (envelope.environment, envelope.graph) != (self._environment, self._graph)
            self.drops["env_mismatch" if mismatch else "other"] += 1
            return None
        payload = envelope.payload
        if payload.get("day", "") > _tomorrow(self._today):
            self.drops["future_dated"] += 1
            return None
        identifier = payload.get("identifier", "")
        reporter = payload.get("reporter", "")
        severity = payload.get("severity", "")
        if not identifier or not threat_ids.is_agent_address(reporter):
            return None                                             # KI-196: free text is not a reporter
        if payload.get("subject") != threat_ids.report_uri(identifier, reporter):
            return None
        shown = (
            extract_binding(row.get("r")),
            extract_binding(row.get("identifier")).strip(),
            extract_binding(row.get("reporter")).strip().lower(),
            constants.normalize_severity(extract_binding(row.get("severity"))),
        )
        if shown != (payload["subject"], identifier, reporter, severity):
            return None
        fields = _agreed_evidence(row, payload)
        if fields is None:
            return None
        if not _meets_the_schema(identifier, severity, payload, newer=envelope.schema_version > STATEMENT_SCHEMA_VERSION):
            self.drops["schema"] += 1
            return None
        return VerifiedReport(subject=payload["subject"], identifier=identifier, author=author,
                              reporter=reporter, severity=severity, fields=fields,
                              framework=payload.get("framework", ""), day=str(payload.get("day", "")),
                              signed=extract_binding(row.get(SIGNED_STATEMENT_VAR)))

    def verify_signed(self, text: str) -> Optional[VerifiedReport]:
        """The verified report for one signed report TEXT on its own — an
        export bundle holds the text, not a graph row. The row is rebuilt from
        what the signature covers, then checked exactly like a row that was read."""
        envelope = signing.from_text(text)
        payload = envelope.payload if envelope is not None else {}
        return self.verify({"r": payload.get("subject", ""), "identifier": payload.get("identifier", ""),
                            "reporter": payload.get("reporter", ""), "severity": payload.get("severity", ""),
                            SIGNED_STATEMENT_VAR: text})


def _utc_today() -> str:
    return datetime.now(UTC).date().isoformat()


def _tomorrow(today: str) -> str:
    """Rows dated after tomorrow (UTC) are future-dated: a day of clock skew is allowed."""
    try:
        return (date.fromisoformat(today) + timedelta(days=1)).isoformat()
    except ValueError:
        return today


def _meets_the_schema(identifier: str, severity: str, payload: Mapping[str, str], *, newer: bool = False) -> bool:
    """True when the SIGNED report would be built by today's writer. A signature
    proves who said it, not that it fits the closed schema: a modified client,
    or a row written before a rule existed, can carry a value outside the
    closed vocabularies (a free-text context, a vulnerability dependency, a
    locally named skill). Readers refuse those exactly as the writer would."""
    # EVERY signed field beside the core is evidence: a field the schema does
    # not know for this category is refused, exactly as the writer refuses it.
    # One exception (threat-profiles R5): a statement signed under a NEWER
    # schema than this reader's may carry fields added since — those are set
    # aside unread (never shown, never counted), so a release that adds report
    # fields does not make its reports vanish from the readers before it.
    evidence = {key: value for key, value in payload.items() if key not in report_schema.REPORT_CORE_KEYS
                and (not newer or key in report_builder.PAYLOAD_FIELD_KEYS)}
    try:
        report_schema.validate_report(identifier=identifier, category=threat_ids.category_for(identifier),
                                      severity=severity, framework=payload.get("framework") or "hermes",
                                      evidence=evidence)
    except report_schema.ReportValidationError:
        return False
    return True


def _agreed_evidence(row: Mapping[str, Any], payload: Mapping[str, str]) -> Optional[tuple[tuple[str, str], ...]]:
    """Evidence taken from the SIGNED payload; None when the row shows a
    value the signature does not (a tampered or forged row). A field the row
    omits is fine — the signed value is used."""
    fields: list[tuple[str, str]] = []
    for var, key in EVIDENCE_PAYLOAD_KEYS.items():
        signed = payload.get(key, "")
        shown = extract_binding(row.get(var))
        if shown and shown != signed:
            return None
        if signed:
            fields.append((var, signed))
    return tuple(sorted(fields))


def unique_by_subject(found: list[Any]) -> list[Any]:
    """One statement per subject, first seen kept (KI-207).

    An epoch copy — the same statement re-shared under a NEW asset name to
    outlive expiry (R5) — carries the same subject and sits beside the
    original on peers until the original expires (bench 2026-10-02). Counting
    both would double a reporter's statements against the per-author cap and
    the daily budget; they are one statement, so every reader folds them here
    before anything is counted.
    """
    seen = set()
    unique = []
    for item in found:
        if item.subject in seen:
            continue
        seen.add(item.subject)
        unique.append(item)
    if len(unique) < len(found):
        logger.debug("blackbox: %d duplicate statement copy(ies) folded by subject", len(found) - len(unique))
    return unique


def verify_report_rows(rows: Iterable[Mapping[str, Any]], verifier: ReportVerifier) -> tuple[list[VerifiedReport], int]:
    """(verified reports, number of rows dropped). Logs the drop count —
    a sudden jump is the visible sign of forged or unsigned traffic."""
    reports: list[VerifiedReport] = []
    dropped = 0
    for row in rows:
        report = verifier.verify(row)
        if report is None:
            dropped += 1
        else:
            reports.append(report)
    if dropped:
        logger.info("blackbox: community read dropped %d unsigned or unverifiable report row(s)", dropped)
    return unique_by_subject(reports), dropped

