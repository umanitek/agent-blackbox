"""Disputes (``g:FalsePositive``) — the reader the plugin never had (Refine R2, KI-092).

Since R1 a reporter can dispute a community threat with a closed reason
(``blackbox report --false-positive ID --reason R``), but nothing read the
statement back: a safeguard without a caller (LES-004). This module reads and
VERIFIES disputes: signed ``blackbox.dispute`` for this network and graph, the
subject is the signer's own ``…:fp`` subject, the reason is in the closed set,
and every shown field matches what was signed.

A dispute NEVER changes enforcement by itself (plan §03): it tags a threat
DISPUTED and, in R3, counts toward decay only when its author is counted.

Usage (from the reader)::

    rows = page_community_rows(client, cfg, disputes.disputes_sparql)
    found = disputes.verified_disputes(rows, environment, graph)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional

from ...kernel import constants, sparql_text, threat_ids
from ...kernel.dkg_client import extract_binding
from ..report_signer import DISPUTE_STATEMENT

from ..verification import shown_as_signed, signed_by, verified_rows

logger = logging.getLogger(__name__)

_PAGE_SIZE = 5000


@dataclass(frozen=True)
class VerifiedDispute:
    """One verified dispute: ``subject`` (the dispute's own), ``identifier``
    (the disputed threat), ``author`` (the signer key — the identity),
    ``reporter`` (the claimed address, display only), ``reason`` (closed),
    ``day`` (the signed UTC day, display only)."""

    subject: str
    identifier: str
    author: str
    reporter: str
    reason: str
    day: str


def disputes_sparql(after: str) -> str:
    """One page of FalsePositive rows after the subject cursor *after*."""
    cursor = sparql_text.cursor_filter(after)
    return f"""
{sparql_text.GUARDIAN_PREFIX}
SELECT ?r ?identifier ?reporter ?reportReason ?signedStatement WHERE {{
  ?r a g:FalsePositive ;
     g:identifier ?identifier ;
     g:reporter ?reporter .
  OPTIONAL {{ ?r g:reportReason ?reportReason }}
  OPTIONAL {{ ?r g:signedStatement ?signedStatement }}
  {cursor}
}} ORDER BY STR(?r) LIMIT {_PAGE_SIZE}
"""


def _verified(row: Mapping[str, Any], environment: str, graph: str) -> Optional[VerifiedDispute]:
    signed = signed_by(row, DISPUTE_STATEMENT, environment, graph)
    if signed is None:
        return None
    author, payload = signed
    identifier, reporter, reason = payload.get("identifier", ""), payload.get("reporter", ""), payload.get("reason", "")
    if not identifier or not threat_ids.is_agent_address(reporter) or reason not in constants.FALSE_POSITIVE_REASONS:
        return None
    subject = threat_ids.dispute_subject(identifier, reporter)
    shown = {"r": subject, "identifier": identifier, "reporter": reporter}
    if extract_binding(row.get("reportReason")).strip():   # a row may omit it; the signed one counts
        shown["reportReason"] = reason
    if payload.get("subject") != subject or not shown_as_signed(row, shown):
        return None
    return VerifiedDispute(subject=subject, identifier=identifier, author=author, reporter=reporter,
                           reason=reason, day=payload.get("day", ""))


def verified_disputes(rows: Iterable[Mapping[str, Any]], environment: str, graph: str) -> list[VerifiedDispute]:
    """Every dispute row that verifies; the rest are dropped and counted in the log."""
    return verified_rows(rows, lambda row: _verified(row, environment, graph), "dispute")[0]
