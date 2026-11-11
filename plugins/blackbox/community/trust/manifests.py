"""Which key manifest a reader acts on (reader policy, Refine R7b).

The manifest FORMAT is :mod:`...kernel.signing.key_manifest`; this module is
what a reader does with the manifests it finds in a graph: keep only those a
trusted root signed for this network and graph (a root pinned for another
epoch may only conflict, never be acted on), skip one still inside its
time-lock (unless it only narrows the list in force), prefer a dated one,
and freeze from the lowest order two root-signed manifests disagree on — but
never below the order this reader already acted on (its sticky order, D31).

Usage::

    manifests = trusted_manifests(rows, environment, graph, roots)
    manifest = effective_manifest(manifests, today, stored.effective_order,
                                  sticky_hash=stored.effective_hash)   # None = no curator statement counts
    conflict = manifests_conflict(manifests, stored.effective_order)    # SECURITY: frozen
    ignored = ignored_conflict(manifests, stored.effective_order)       # SECURITY: ignored, alarmed
    frozen_at = freeze_order(manifests, stored.effective_order)         # the store keeps its rows
    sticky = sticky_after(manifests, today, stored.effective_order, stored.effective_hash)  # store it
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional

from ...kernel import signing, sparql_text
from ...kernel.dkg_client import extract_binding
from ...kernel.signing import key_manifest
from ...kernel.signing import RootPins
from ..statements import curator_statements
from . import ordered_policy


def key_manifests_sparql(after: str) -> str:
    """One page of key-manifest rows after the subject cursor *after*."""
    cursor = sparql_text.cursor_filter(after)
    return f"""
{sparql_text.GUARDIAN_PREFIX}
SELECT ?r ?signedStatement WHERE {{
  ?r a g:KeyManifest ;
     g:signedStatement ?signedStatement .
  {cursor}
}} ORDER BY STR(?r) LIMIT 500
"""


#: A trusted manifest as readers receive it: a verdict (it may be freeze-only),
#: or a bare manifest (a full candidate — tests and stored copies).
TrustedManifest = key_manifest.ManifestVerdict | key_manifest.KeyManifest


def _verdict(item: TrustedManifest) -> key_manifest.ManifestVerdict:
    return item if isinstance(item, key_manifest.ManifestVerdict) else key_manifest.ManifestVerdict(item)


def newest_trusted_manifest(rows: Iterable[Mapping[str, Any]], environment: str, graph: str,
                            roots: RootPins) -> Optional[key_manifest.KeyManifest]:
    """The newest manifest (by root epoch, version) a root signed at its own epoch."""
    if not roots:
        return None
    return key_manifest.newest(v.manifest for v in trusted_manifests(rows, environment, graph, roots) if not v.freeze_only)


def trusted_manifests(rows: Iterable[Mapping[str, Any]], environment: str, graph: str,
                      roots: RootPins) -> list[key_manifest.ManifestVerdict]:
    """The verdict on every manifest in *rows* a trusted root signed for this
    environment and graph — including freeze-only ones (a pinned root at
    another epoch), which may conflict but never be acted on."""
    verdicts = []
    for row in rows:
        envelope = signing.from_text(extract_binding(row.get(curator_statements.SIGNED_STATEMENT_VAR)))
        verdict = key_manifest.verify_manifest(envelope, environment=environment, graph=graph, roots=roots)
        if verdict is not None:
            verdicts.append(verdict)
    return verdicts


Order = ordered_policy.Order


def _ordered(verdict: key_manifest.ManifestVerdict) -> ordered_policy.Ordered:
    return ordered_policy.Ordered(verdict.manifest.order, verdict.manifest.content_hash(), verdict.freeze_only)


def conflict_orders(manifests: Iterable[TrustedManifest]) -> set[Order]:
    """The orders at which trusted manifests conflict (:func:`.ordered_policy.conflict_orders`:
    two contents at one order, pending ones included, or any freeze-only verdict — K1, D30)."""
    return ordered_policy.conflict_orders(_ordered(_verdict(item)) for item in manifests)


def effective_manifest(manifests: Iterable[TrustedManifest], today: str, sticky_order: Optional[Order] = None, *,
                       sticky_hash: str = "") -> Optional[key_manifest.KeyManifest]:
    """The manifest readers act on (R7b; D30/D31 — "a freeze holds"):

    * never one inside its time-lock — unless it :meth:`~KeyManifest.narrows`
      the list in force and comes after it: a removal-only list acts at once;
    * an undated manifest only when no dated one exists;
    * a conflict (:func:`conflict_orders`) at order O skips O and every order
      ABOVE it, so one counter-list stops a flood of conflicting versions;
    * *sticky_order* / *sticky_hash* — the manifest this reader already acted on
      after its time-lock passed (:attr:`.trust_store.StoredTrust.effective_order`).
      A conflict at or below it never moves the reader (:func:`ignored_conflict`
      raises the alarm); at the sticky order the content with *sticky_hash* is
      kept. Without a hash an ambiguous sticky order is skipped, never guessed.

    A fresh install (no sticky order) during a freeze takes the newest
    unconflicted order below the lowest conflict — the accepted residual."""
    return _in_force_and_effective(manifests, today, sticky_order, sticky_hash)[1]


def _in_force_and_effective(manifests: Iterable[TrustedManifest], today: str, sticky_order: Optional[Order],
                            sticky_hash: str) -> tuple[Optional[key_manifest.KeyManifest], Optional[key_manifest.KeyManifest]]:
    """(the newest usable list past its time-lock, the list acted on) — the second
    is the first advanced through any narrowing lists (:func:`effective_manifest`)."""
    verdicts = [_verdict(item) for item in manifests]
    conflicts = ordered_policy.conflict_orders(map(_ordered, verdicts))
    usable_manifests = [v.manifest for v in verdicts if not v.freeze_only and ordered_policy.usable(
        _ordered(v), conflicts=conflicts, sticky_order=sticky_order, sticky_hash=sticky_hash)]
    in_force = [m for m in usable_manifests if key_manifest.manifest_clock(m, today)[0] != "pending"]
    dated = [m for m in in_force if m.issued_day]
    current = key_manifest.newest(dated or in_force)
    return current, _narrowed(current, [m for m in usable_manifests if m not in in_force])


def _narrowed(current: Optional[key_manifest.KeyManifest],
              pending: list[key_manifest.KeyManifest]) -> Optional[key_manifest.KeyManifest]:
    """*current* advanced through every pending list that narrows it and comes
    after it (``narrows()`` ignores the order, so the order is checked here).
    Each step may narrow the one before it — one key per list."""
    if current is None:
        return None
    for candidate in sorted(pending, key=lambda m: m.order):
        if candidate.order > current.order and candidate.narrows(current):
            current = candidate
    return current


def sticky_after(manifests: Iterable[TrustedManifest], today: str, previous: Optional[Order],
                 previous_hash: str = "") -> tuple[Optional[Order], str]:
    """(order, content hash) to store after this read: the newest list acted on
    whose time-lock has passed. An early-effective narrowing list is not sticky
    until its own time-lock passes (the challenge window) — the in-force list it
    narrowed is. Same arguments as :func:`effective_manifest`; the sticky
    order never goes down (otherwise the *previous* pair is returned)."""
    manifest = _in_force_and_effective(manifests, today, previous, previous_hash)[0]
    if manifest is None or (previous is not None and manifest.order <= previous):
        return previous, previous_hash
    return manifest.order, manifest.content_hash()


def freeze_order(manifests: Iterable[TrustedManifest], sticky_order: Optional[Order] = None) -> Optional[Order]:
    """The lowest conflict above *sticky_order* — the order this reader is frozen
    at (None: not frozen). The trust store keeps its rows (with the sticky
    list's), so a flood of conflicting higher versions cannot push the freeze out."""
    return ordered_policy.freeze_order((_ordered(_verdict(item)) for item in manifests), sticky_order)


def manifests_conflict(manifests: Iterable[TrustedManifest], sticky_order: Optional[Order] = None) -> bool:
    """R10b SECURITY: a conflict that FREEZES this reader — two trusted manifests
    with one (root epoch, version) but different content, or a freeze-only one,
    above *sticky_order* (all of them without one)."""
    return ordered_policy.freeze_order((_ordered(_verdict(item)) for item in manifests), sticky_order) is not None


def ignored_conflict(manifests: Iterable[TrustedManifest], sticky_order: Optional[Order]) -> bool:
    """T1 SECURITY: a conflict at or below the sticky order — ignored (it cannot
    move this reader), but someone with a root key is signing old orders."""
    return ordered_policy.ignored_conflict((_ordered(_verdict(item)) for item in manifests), sticky_order)
