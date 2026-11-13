"""The evidence dossier and the promotion checklist (Refine R6, plan §09).

A dossier gathers what the curator may look at — never a verdict: the threat's
local stage and reporters, independent advisories (OSV), the curator's
current verdict, counted disputes, this week's heat, and prior decisions —
each with its source and when it was fetched. The CHECKLIST (≤3 items) is
what a curator confirms before signing: (1) TRUTH — a blockable kind needs
independent, non-community evidence; (2) SCOPE ≤ EVIDENCE — exact versions,
``*`` only for typosquat / mirror collision / registry takeover; (3) not on
the allowlist (no allowlist is published yet — recorded as not checked).

Pattern: Builder (:class:`DossierBuilder`) for the dossier; pure
:func:`checklist`.

Usage::

    dossier = (DossierBuilder(identifier).community(rule).advisories(osv.lookup)
               .community_confirmation(confirmed).history(prior).build())
    print("\n".join(render(dossier)))
    items = checklist(identifier, kind="malware", evidence="advisory:MAL-2026-1", reason="advisory:MAL-2026-1")
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Optional

from .. import community
from ..kernel import threat_ids
from .queue import BLOCKABLE_PREFIXES

#: Evidence a curator may cite for item 1: an advisory id, a registry action
#: (URL), or a reproduction (sha256 of the artifact the curator ran) — the same
#: closed format a community confirmation signs.
_EVIDENCE = community.EVIDENCE_REFERENCE
#: The only reasons a whole-package (*) rule may carry (plan §09 checklist item 2).
WHOLE_PACKAGE_REASONS = ("typosquat", "internal-mirror-collision", "registry-takeover")


@dataclass(frozen=True)
class Source:
    """One thing the dossier looked at: where, when (epoch), what it said."""

    name: str
    fetched_at: float
    summary: str


@dataclass(frozen=True)
class Dossier:
    identifier: str
    sources: tuple[Source, ...] = ()
    notes: tuple[str, ...] = field(default=())


@dataclass(frozen=True)
class CommunityConfirmation:
    """The community curators' confirmation of a threat, as a curator of
    ANOTHER authority sees it: the signed ``day``, the ``evidence`` reference
    they checked, how many ``curators`` signed, how many ``reporters`` stand
    behind it (None when not known) and where this was read from (``source``)."""

    day: str
    evidence: str
    curators: int
    reporters: Optional[int]
    source: str


class DossierBuilder:
    """Collects sources for one threat; ``build()`` freezes them. No verdicts."""

    def __init__(self, identifier: str, clock: Callable[[], float] = time.time) -> None:
        self._identifier = identifier
        self._clock = clock
        self._sources: list[Source] = []

    def _add(self, name: str, summary: str) -> DossierBuilder:
        self._sources.append(Source(name=name, fetched_at=self._clock(), summary=summary[:400]))
        return self

    def community(self, rule: Optional[Mapping[str, Any]]) -> DossierBuilder:
        if rule is None:
            return self._add("community graph", "no community reports compiled for this threat")
        return self._add("community graph", f"stage {rule.get('stage')} ({rule.get('enforcement')}) — "
                         f"{rule.get('stageReason')}; {rule.get('reporterCount')} verified signer(s)")

    def advisories(self, lookup: Callable[[str, str, str], Optional[Mapping[str, str]]]) -> DossierBuilder:
        """OSV, for a dependency threat: the advisory and whether it is malware."""
        parts = threat_ids.parse_dependency_identifier(self._identifier)
        if parts is None:
            return self
        ecosystem, name, version = parts
        try:
            hit = lookup(ecosystem, name, version)
        except Exception as exc:  # the dossier records the failure, never hides it
            return self._add("OSV", f"lookup failed: {exc}")
        if not hit:
            return self._add("OSV", "no advisory for this exact version")
        return self._add("OSV", f"{hit.get('advisory_id')} ({hit.get('kind')}, severity {hit.get('severity')})")

    def curator(self, verdict: Optional[str], dispute_weight: int) -> DossierBuilder:
        self._add("curator statements", f"current verdict: {verdict or 'none'}")
        return self._add("disputes", f"{dispute_weight} counted author(s) dispute it")

    def community_confirmation(self, confirmed: Optional[CommunityConfirmation]) -> DossierBuilder:
        """The community curators' confirmation and the evidence they checked —
        evidence for this curator's own item 1, never a verdict to adopt."""
        if confirmed is None:
            return self._add("community curators", "no confirmation with evidence")
        behind = "" if confirmed.reporters is None else f", {confirmed.reporters} signed report(s) attached"
        return self._add("community curators", f"confirmed {confirmed.day} by {confirmed.curators} curator key(s); evidence they "
                         f"checked: {confirmed.evidence}{behind} — check it yourself (from {confirmed.source})")

    def allowlist(self, verdict: Any) -> DossierBuilder:
        """R9: what the allowlist / warninglist says (checklist item 3, now automatic)."""
        tag = f" (confusable-of:{verdict.confusable_of})" if getattr(verdict, "confusable_of", "") else ""
        return self._add("allowlist", f"{verdict.verdict.value}{tag}: {verdict.reason}")

    def heat(self, estimate: Optional[Any]) -> DossierBuilder:
        if estimate is None:
            return self._add("sighting digests", "no counted digest names it this week")
        return self._add("sighting digests", f"seen by ~{estimate.agents} agents in {estimate.week} ({estimate.digests} digests)")

    def history(self, proposals: Iterable[Any]) -> DossierBuilder:
        rows = [f"{p.kind} {p.state.value} ({time.strftime('%Y-%m-%d', time.gmtime(p.created))})" for p in proposals]
        return self._add("prior decisions", "; ".join(rows) if rows else "none")

    def build(self) -> Dossier:
        return Dossier(identifier=self._identifier, sources=tuple(self._sources))


def render(dossier: Dossier) -> list[str]:
    """Plain lines for the terminal (sources and times; no verdict)."""
    lines = [f"Dossier for {dossier.identifier}"]
    for source in dossier.sources:
        when = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(source.fetched_at))
        lines.append(f"  {source.name:<20} {when}  {source.summary}")
    return lines


@dataclass(frozen=True)
class CheckItem:
    """One checklist item: ``item`` (1-3), ``title``, ``ok``, ``note``."""

    item: int
    title: str
    ok: bool
    note: str


def checklist(identifier: str, *, kind: str, evidence: str, reason: str) -> tuple[CheckItem, ...]:
    """The ≤3-item promotion checklist for one threat (plan §09). Blockable
    kinds fail item 1 without independent evidence; a whole-package scope
    fails item 2 without a scope reason; item 3 is recorded as not checked."""
    blockable = identifier.startswith(BLOCKABLE_PREFIXES) and kind == "malware"
    cited = bool(_EVIDENCE.fullmatch(evidence.strip())) if evidence else False
    truth = CheckItem(1, "TRUTH — independent non-community evidence", cited or not blockable,
                      "cited" if cited else ("not needed for a flag-only kind" if not blockable
                                             else "missing: cite advisory:<id>, registry-action:<url> or reproduced:<sha256>"))
    whole = identifier.startswith("dep:") and identifier.endswith("@*")
    scoped = not whole or reason in WHOLE_PACKAGE_REASONS
    scope = CheckItem(2, "SCOPE ≤ EVIDENCE — exact versions", scoped,
                      "exact version" if not whole else (f"whole package: {reason}" if scoped
                                                          else f"a whole-package rule needs a reason in {WHOLE_PACKAGE_REASONS}"))
    allow = CheckItem(3, "ALLOWLIST / WARNINGLIST", True, "not checked: no allowlist is published yet (R8)")
    return (truth, scope, allow)


def passes(items: Iterable[CheckItem]) -> bool:
    return all(item.ok for item in items)
