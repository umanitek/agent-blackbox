"""Retractions — a reporter withdrawing its own report (Refine R1, lifecycle RETRACT).

A retraction is a ``g:Retraction`` statement signed ``blackbox.retract`` by
the SAME reporter key that signed the report (``blackbox report --retract``).
Readers honour it unconditionally, with no hold, cap or delay: a statement
that REDUCES enforcement must always get through (LES-016). Its reach is
exactly its signer's own voice. A verified retraction removes every report
that signer made about that identifier, and nobody else's, so a retraction
can never silence other reporters (LES-014: identity is the signature, never
a payload field). Unsigned or unverifiable retraction rows are ignored.

A retraction is final for that (reporter, threat) pair: the report's asset
name is fixed, so the same report cannot be re-sent afterwards.

Usage (from the reader)::

    rows = page_community_rows(client, cfg, retractions.retractions_sparql)
    found = retractions.verified_retractions(rows, environment, graph)       # List[VerifiedRetraction]
    withdrawn, _ = tombstones.applicable_withdrawals(found, reports, first_seen, now)
    reports = retractions.apply_retractions(reports, withdrawn)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional

from ...kernel import sparql_text, threat_ids
from ..report_signer import RETRACT_STATEMENT
from ..verification import VerifiedReport, shown_as_signed, signed_by, verified_rows


logger = logging.getLogger(__name__)

#: One withdrawn voice: (signer key, threat identifier).
Withdrawal = tuple[str, str]


@dataclass(frozen=True)
class VerifiedRetraction:
    """One verified retraction: its ``author`` (signer key), the
    ``identifier`` it withdraws, its own ``subject``, and for display the
    claimed ``reporter`` address and signed ``day``."""

    author: str
    identifier: str
    subject: str
    reporter: str = ""
    day: str = ""

#: Rows per page (retractions are rare; the pager's row ceiling still applies).
_PAGE_SIZE = 5000


def retractions_sparql(after: str) -> str:
    """One page of Retraction rows after the subject cursor *after*."""
    cursor = f"FILTER(STR(?r) > {sparql_text.sparql_string_literal(after)})" if after else ""
    return f"""
PREFIX g: <http://umanitek.ai/ontology/guardian/>
SELECT ?r ?identifier ?reporter ?signedStatement WHERE {{
  ?r a g:Retraction ;
     g:identifier ?identifier ;
     g:reporter ?reporter .
  OPTIONAL {{ ?r g:signedStatement ?signedStatement }}
  {cursor}
}} ORDER BY STR(?r) LIMIT {_PAGE_SIZE}
"""


def _verified_withdrawal(row: Mapping[str, Any], environment: str, graph: str) -> Optional[VerifiedRetraction]:
    """The retraction in *row* when it is signed for this network and graph
    and its shown fields match what was signed; else None."""
    signed = signed_by(row, RETRACT_STATEMENT, environment, graph)
    if signed is None:
        return None
    author, payload = signed
    identifier, reporter = payload.get("identifier", ""), payload.get("reporter", "")
    if not identifier or not threat_ids.is_agent_address(reporter):
        return None
    subject = threat_ids.retraction_subject(identifier, reporter)
    if payload.get("subject") != subject or not shown_as_signed(
            row, {"r": subject, "identifier": identifier, "reporter": reporter}):
        return None
    return VerifiedRetraction(author=author, identifier=identifier, subject=subject, reporter=reporter,
                              day=payload.get("day", ""))


def verified_retractions(rows: Iterable[Mapping[str, Any]], environment: str, graph: str) -> list[VerifiedRetraction]:
    """Every retraction row that verifies; the rest are dropped and counted in the log."""
    return verified_rows(rows, lambda row: _verified_withdrawal(row, environment, graph), "retraction")[0]


def apply_retractions(reports: Iterable[VerifiedReport], withdrawn: frozenset[Withdrawal]) -> list[VerifiedReport]:
    """*reports* without those their own signer withdrew."""
    return [report for report in reports if (report.author, report.identifier) not in withdrawn]
