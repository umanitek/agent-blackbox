"""Promoted community reports as verified rules (the one-graph flow, ``kernel.signing.promotion_statement``).

The verified authority promotes ONE community report at a time: the report
itself is published from the verified graph's shared memory to Verified
Memory (its reporter's own asset), and beside it the curators publish a
promotion statement that points at it — the report's subject and the digest
of its signed envelope. A reader serves a promoted report as a verified rule,
one that may block, only when:

* a promotion statement in the verified graph is signed by a quorum of the
  verified authority's curator keys under the key manifest in force on its
  signed day (never later than today) — the day decides, as a promoted row's
  day decides its tier, so a key rotation never turns a promoted report back
  into a report;
* the report it points at reads back from Verified Memory in this node's own
  store as EXACTLY that report — its digest, signed by the named reporter key —
  and verifies for this network (``community.ReportVerifier``, the community
  reader's check);
* its identifier is not revoked and no correction suppressed its subject.

A report in Verified Memory that no such statement names is never served. The
rule is built from the REPORT's signed payload by the row adapter the
verified lanes use, with the curators' severity, and carries
:data:`PROMOTED_REPORT` (the report's subject). The newest statement whose
report reads back decides an identifier. Revocations and corrections act on
it as on any verified rule; the kill list and the most-restrictive-wins
combination are untouched.

Fail-open with last-good: a read that could not tell keeps the previous
generation's promoted rules (minus what is revoked or suppressed now), never
"no promoted rules".

Usage (``ruleset.curator_tier``, after revocations are dropped)::

    promoted.apply_promoted_reports(rs, client, config, view, prior)
"""

from __future__ import annotations

import logging
from typing import Any, Iterable, Iterator, Mapping, Optional

from ... import community
from ...kernel import constants, signing
from ...kernel.config import BlackboxConfig
from ...kernel.dkg_client import DkgClient, DkgError, extract_binding
from ...kernel.signing import promotion_statement as statement
from ...kernel.sparql_text import page_rows
from ...kernel.store import StoreClient, loopback_store_url
from .. import row_adapters

logger = logging.getLogger(__name__)

#: The field a rule built from a promoted report carries: the report's subject.
PROMOTED_REPORT = "promotedReport"
#: Report subjects per store query (VALUES-bound: index lookups), and copies read per report.
SUBJECTS_PER_QUERY, COPIES_PER_REPORT = 200, 16
#: A signed report's payload key → the verified lanes' column the row adapter reads
#: (``graph_queries._SELECT_COLUMNS``; an IOC's type rides in ``category``, as ``dp:iocType`` does).
_ROW_COLUMNS: Mapping[str, str] = {
    "kind": "kind", "package_name": "packageName", "package_version": "packageVersion",
    "ecosystem": "packageEcosystem", "advisory_id": "advisoryId", "tool_name": "toolName",
    "file_category": "category", "ioc_type": "category", "skill_name": "skillName",
    "skill_version": "skillVersion", "danger_shape": "dangerShape",
}
#: Promoted rules by table: the compiled dicts are keyed, the lists are not.
_KEYED, _LISTED = ("dependency", "ioc"), ("skill", "fileaccess")


def apply_promoted_reports(rs: Any, client: DkgClient, config: BlackboxConfig, view: Any, prior: Any = None) -> int:
    """Replace *rs*'s promoted rules with the ones the verified graph promotes
    now (*prior*'s when the read could not tell). Returns how many are served."""
    rules = promoted_rules(client, config.context_graph_id, view)
    if rules is None:
        logger.info("blackbox: promoted reports could not be read this refresh; the last ones stay")
        rules = list(_promoted_in(prior)) if prior is not None else list(_promoted_in(rs))
    suppressed = rs.suppressed_subjects | (rs.verified_scope.suppressed_subjects if rs.verified_scope else frozenset())
    revoked = frozenset(view.revoked)
    _drop_promoted(rs)
    served = 0
    for category, key, rule in rules:
        if rule["identifier"] not in revoked and rule[PROMOTED_REPORT] not in suppressed:
            served += _install(rs, category, key, rule)
    rs._graph_entries_cache.clear()
    return served


def promoted_rules(client: DkgClient, graph: str, view: Any) -> Optional[list[tuple[str, str, dict[str, Any]]]]:
    """``(category, key, rule)`` for every report the verified graph promotes
    (see the module doc); None when a read could not tell."""
    if view.manifest is None:
        return None if view.unavailable else []
    environment = view.manifest.environment
    rows = page_rows(client, graph, constants.VIEW_VERIFIABLE_MEMORY, statement.statements_sparql)
    history = community.verified_manifest_history(client, graph, environment) if rows else ()
    if rows is None or history is None:
        return None
    promotions = _quorum_promotions(rows, history, graph, community.curator_today())
    copies = _verified_copies(client, graph, {found.report for found in promotions})
    if copies is None:
        return None
    served: dict[str, tuple[str, str, dict[str, Any]]] = {}
    for found in sorted(promotions, key=lambda found: found.sequence, reverse=True):
        if found.identifier not in served:
            rule = _rule(found, copies.get(found.report, ()), environment)
            if rule is not None:
                served[found.identifier] = rule
    return list(served.values())


def _quorum_promotions(rows: Iterable[Mapping[str, Any]], history: Any, graph: str,
                       today: str) -> list[statement.Promotion]:
    """The promotions *rows* hold that a quorum signed under the manifest in force
    on their day; a row whose shown subject or report disagrees with the signed
    one is skipped."""
    found = []
    for row in rows:
        envelope = signing.from_text(extract_binding(row.get("signedStatement")))
        promotion = statement.parse(envelope)
        if promotion is None or (extract_binding(row.get("r")), extract_binding(row.get("report"))) != (
                statement.statement_subject(promotion.identifier, promotion.sequence), promotion.report):
            continue
        manifest = community.manifest_on_day(history, min(promotion.day, today))
        if manifest is not None and manifest.has_quorum(envelope, statement_type=statement.PROMOTION_STATEMENT, graph=graph):
            found.append(promotion)
    return found


def _verified_copies(client: DkgClient, graph: str, subjects: set[str]) -> Optional[dict[str, list[statement.ReportCopy]]]:
    """Report subject → its copies in Verified Memory, from this node's own store;
    None when the store could not be asked or could not tell."""
    if not subjects:
        return {}
    try:
        url = loopback_store_url(client.status(timeout=5.0))
    except DkgError:
        return None
    if not url:
        return None
    store, ordered, copies = StoreClient(url), sorted(subjects), {}
    for start in range(0, len(ordered), SUBJECTS_PER_QUERY):
        chunk = ordered[start:start + SUBJECTS_PER_QUERY]
        answer = store.select(statement.report_copies_sparql(graph, chunk, COPIES_PER_REPORT * len(chunk),
                                                             verified_only=True))
        if not answer.known:
            return None
        for row in answer.rows or []:
            copy = statement.report_copy(graph, row)
            if copy is not None and copy.verified:
                copies.setdefault(copy.subject, []).append(copy)
    return copies


def _rule(found: statement.Promotion, copies: Iterable[statement.ReportCopy],
          environment: str) -> Optional[tuple[str, str, dict[str, Any]]]:
    """The verified rule of the report *found* points at — from the copy that
    is exactly that report and verifies — or None when no copy does."""
    for copy in copies:
        envelope = signing.from_text(copy.text)
        if envelope is None or envelope.environment != environment or not statement.is_the_report(found, copy.text):
            continue
        report = community.ReportVerifier(environment, envelope.graph).verify_signed(copy.text)
        if report is None or (report.subject, report.identifier) != (found.report, found.identifier):
            continue
        row = {"threat": report.subject, "identifier": report.identifier, "severity": found.severity,
               "name": report.identifier}
        row.update({column: envelope.payload[key] for key, column in _ROW_COLUMNS.items() if envelope.payload.get(key)})
        mapped = row_adapters._row_to_rule(row, "public")
        if mapped is not None:
            category, key, rule = mapped
            return category, key, {**rule, PROMOTED_REPORT: report.subject}
    return None


def _install(rs: Any, category: str, key: str, rule: dict[str, Any]) -> int:
    """Put *rule* in its table unless a verified rule already holds its key (1 = served)."""
    if category in _KEYED:
        table = getattr(rs, category)
        if (table.get(key) or {}).get("source") == "public":
            return 0
        table[key] = rule
        return 1
    if category not in _LISTED:
        return 0
    rules = getattr(rs, category)
    if any(held.get("identifier") == rule["identifier"] and held.get("source") == "public" for held in rules):
        return 0
    setattr(rs, category, [held for held in rules if held.get("identifier") != rule["identifier"]] + [rule])
    return 1


def _promoted_in(rs: Any) -> Iterator[tuple[str, str, dict[str, Any]]]:
    """The promoted rules *rs* serves, as ``(category, key, rule)``."""
    for category in _KEYED:
        yield from ((category, key, rule) for key, rule in getattr(rs, category).items() if PROMOTED_REPORT in rule)
    for category in _LISTED:
        yield from ((category, rule["identifier"], rule) for rule in getattr(rs, category) if PROMOTED_REPORT in rule)


def _drop_promoted(rs: Any) -> None:
    for category in _KEYED:
        setattr(rs, category, {key: rule for key, rule in getattr(rs, category).items() if PROMOTED_REPORT not in rule})
    for category in _LISTED:
        setattr(rs, category, [rule for rule in getattr(rs, category) if PROMOTED_REPORT not in rule])
