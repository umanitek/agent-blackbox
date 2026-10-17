"""Promotion — a community report enters the verified tier (Refine R6, the one-graph flow).

Edge nodes share signed reports into the verified graph's shared memory,
sub-graph ``reports``. The curators review ONE report and promote it: two
curator keys sign a promotion whose payload names that report — its subject,
digest and reporter key (``kernel.signing.promotion_statement``) — and the
publish step writes it to Verified Memory the way the payload says
(``publishing.strategies``; by default, on DKG 10.0.25, the reporter's own
asset published as it is, the curators' statement beside it). Nothing stays
curator-private: the report is the provenance. Once promoted, the promotion is permanent in Verified Memory
and names its reporter (agent address and reporter key) — the project's
accepted trade-off.

* :func:`choose_report` — which of an identifier's reports a promotion names;
* :func:`report_reference` — what a promotion of that report names;
* :func:`checked_report` — what every signer and the publisher run before
  acting on a promotion (KI-195): the report re-read on THIS node, its digest,
  reporter key and scope checked;
* :func:`report_copies` — where this node holds a report (asset, layer), read
  from the node's own store;
* :func:`sealed_names` — the asset name of each shared copy whose author's
  seal this node keeps (what the curator publishes a member's asset by).

Scope: dependency (kind ``malware`` only — R6: a vulnerability never
blocks), IOC, skill and file-access reports, exactly as reported — a
whole-package report (``@*``, a typosquat or mirror collision) promotes every
version, and the checklist asks for its reason. An injection report carries
the hash of its pattern, never the pattern, so it cannot be promoted.

Usage::

    report = promotion.choose_report(read.reports, "dep:npm:x@1.0.0")
    ref = promotion.report_reference(report)           # what the payload names (publishing.strategies signs it)
    report = promotion.checked_report(ctx, ref)        # every later key and the publisher, before acting
"""

from __future__ import annotations

from typing import Any, Iterable, Optional, Sequence

from .. import community
from ..kernel import constants, signing
from ..kernel.dkg_client import DkgClient, DkgError
from ..kernel.signing import promotion_statement as statement
from ..kernel.store import StoreClient, loopback_store_url
from .context import CurateContext

#: Copies of one report a lookup reads at most (keep-alive copies, a shared and a verified one).
_COPIES_PER_REPORT = 32


class PromotionError(ValueError):
    """A promotion outside the promotable scope, or one this node cannot check."""


def choose_report(reports: Iterable[community.VerifiedReport], identifier: str,
                  subject: str = "") -> community.VerifiedReport:
    """The report a promotion of *identifier* points at: the one with
    *subject* when given, else the EARLIEST report (its signed day, then its
    subject) — the first reporter is the one the verified rule names. Raises
    :class:`PromotionError` when there is none."""
    candidates = [report for report in reports if report.identifier == identifier and (not subject or report.subject == subject)]
    if not candidates:
        where = f" with subject {subject}" if subject else ""
        raise PromotionError(f"no verified community report of {identifier}{where}: a promotion points at a report")
    return min(candidates, key=lambda report: (report.day or "9999-12-31", report.subject))


def report_reference(report: community.VerifiedReport) -> statement.ReportRef:
    """What a promotion of *report* names: its identifier, subject, the digest
    of its signed envelope and its reporter key. Raises :class:`PromotionError`
    for a report outside the promotable scope."""
    check_scope(report)
    envelope = signing.from_text(report.signed)
    ref = statement.reference({"identifier": report.identifier, "report": report.subject,
                               "reportDigest": signing.content_id(envelope) if envelope else "",
                               "reporterKey": report.author})
    if envelope is None or ref is None:
        raise PromotionError(f"the report {report.subject} cannot be named by a promotion "
                             "(no signed statement, or not its reporter's own report of its identifier)")
    return ref


def check_scope(report: community.VerifiedReport) -> None:
    """Refuse a report no promotion may point at (see the module doc)."""
    if not report.identifier.startswith(statement.PROMOTABLE_PREFIXES):
        raise PromotionError(f"a report is promoted as {statement.PROMOTABLE_PREFIXES} only: {report.identifier} "
                             "is not (an injection report carries no pattern)")
    if report.identifier.startswith("dep:") and dict(report.fields).get("kind") != constants.KIND_MALWARE:
        raise PromotionError("R6 promotes malware dependencies only: this report's signed kind is not malware")


def checked_report(ctx: CurateContext, ref: Optional[statement.ReportRef]) -> community.VerifiedReport:
    """The report a promotion names (*ref*, from its payload), re-read and
    checked on THIS node — what every curator key and the publisher run
    before acting on it (KI-195: the first signer's client may have been
    modified, and a person approving sees only the summary). The report must
    be held here, in shared or Verified Memory, with exactly the signed
    digest, signed by the named reporter key for this network, and the
    identifier the promotion names. Raises :class:`PromotionError`."""
    if ref is None:
        raise PromotionError("the payload is not a well-formed promotion of a report")
    copies = report_copies(ctx.client, ctx.verified_graph, [ref.report])
    if copies is None:
        raise PromotionError("this node's store could not be read: the report cannot be checked (try again)")
    report = verified_copy(ctx, ref, copies)
    if report is None:
        raise PromotionError(f"this node does not hold the report {ref.report} with the signed digest "
                             "and reporter key: nothing is signed or published until it does")
    check_scope(report)
    return report


def verified_copy(ctx: CurateContext, ref: statement.ReportRef,
                  copies: Iterable[statement.ReportCopy]) -> Optional[community.VerifiedReport]:
    """The report among *copies* that IS the one *ref* names — its digest,
    signed by its reporter key (:func:`statement.is_the_report`) for this
    network and the one graph — reporting the promoted identifier; None when
    no copy is."""
    for copy in copies:
        envelope = signing.from_text(copy.text)
        if envelope is None or envelope.graph != ctx.verified_graph or not statement.is_the_report(ref, copy.text):
            continue
        report = community.ReportVerifier(ctx.environment, ctx.verified_graph).verify_signed(copy.text)
        if report is not None and (report.subject, report.identifier) == (ref.report, ref.identifier):
            return report
    return None


def report_copies(client: DkgClient, graph: str, subjects: Iterable[str]) -> Optional[list[statement.ReportCopy]]:
    """Every copy of the reports *subjects* this node holds in *graph* — shared
    or verified, each in an asset its own reporter authored — read from the
    node's own store; None when the store could not be asked or could not tell."""
    wanted = sorted(set(subjects))
    sparql = statement.report_copies_sparql(graph, wanted, _COPIES_PER_REPORT * max(1, len(wanted)))
    if not sparql:
        return []
    rows = _store_rows(client, sparql)
    return None if rows is None else [copy for row in rows if (copy := statement.report_copy(graph, row)) is not None]


def sealed_names(client: DkgClient, graph: str,
                 copies: Sequence[statement.ReportCopy]) -> Optional[dict[tuple[str, str], str]]:
    """``{(sub-graph, asset id): asset name}`` for each shared copy in *copies*
    whose author's seal this node keeps — on the graph's curator node DKG
    10.0.25 keeps a member's seal from the share, with the asset's name — read
    from the node's own store; None when the store could not be asked or
    could not tell."""
    shared = [copy for copy in copies if not copy.verified]
    sparql = statement.sealed_names_sparql(graph, shared, _COPIES_PER_REPORT * max(1, len(shared)))
    if not sparql:
        return {}
    rows = _store_rows(client, sparql)
    if rows is None:
        return None
    return {(copy.sub_graph, copy.asset_id): name for copy in shared for row in rows
            if (name := statement.sealed_name(graph, copy, row))}


def _store_rows(client: DkgClient, sparql: str) -> Optional[list[Any]]:
    """The rows of one SELECT on the node's own store; None when the store
    could not be asked or could not tell."""
    try:
        url = loopback_store_url(client.status(timeout=5.0))
    except DkgError:
        return None
    answer = StoreClient(url).select(sparql) if url else None
    if answer is None or not answer.known:
        return None
    return list(answer.rows or [])
