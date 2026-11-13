"""The verified authority's manifest HISTORY, and which list was in force on a day (trust-and-threat-lab §03.4, F-050).

A verified row's tier is decided ONCE, against the root-signed key manifest in
force on the row's confirmed day — never against the current list, or a
routine rotation would turn every row signed by a key rotated out into
flag-only. Every manifest is durable in verifiable memory, so a reader holds
the whole history; each one is bounded by ``issued_day`` + 60 days.

Which manifest was in force on a day is the reader policy of :mod:`.manifests`
(time-lock, narrowing lists, conflicts freeze) evaluated AS OF that day, minus
any list already stale then. No sticky order applies: the question is about
the past, not about what this reader acted on.

Usage (the verified scope, once per refresh that has undecided assets)::

    history = verified_manifest_history(client, verified_graph, environment)   # None = could not read
    manifest = manifest_on_day(history, "2026-11-02")                          # None = no list in force
    tier = BLOCK if manifest and manifest.has_quorum(envelope, statement_type="blackbox.promotion",
                                                      graph=verified_graph) else FLAG
"""

from __future__ import annotations

from typing import Any, Optional, Sequence

from ...kernel import constants
from ...kernel.signing import key_manifest
from ...kernel.signing import RootPins
from ...kernel.sparql_text import page_rows
from . import manifests


def verified_manifest_history(client: Any, graph: str, environment: str) -> Optional[tuple[key_manifest.ManifestVerdict, ...]]:
    """Every manifest a pinned root signed for *environment* and the verified
    *graph*, freeze-only verdicts included (they can still conflict); () when
    no root is pinned for *environment*; None when the read failed (LES-011:
    could not tell — the caller decides nothing)."""
    roots = RootPins.for_environment(environment) if environment else RootPins()
    if not roots or not graph:
        return ()
    rows = page_rows(client, graph, constants.VIEW_VERIFIABLE_MEMORY, manifests.key_manifests_sparql)
    if rows is None:
        return None
    return tuple(manifests.trusted_manifests(rows, environment, graph, roots))


def manifest_on_day(history: Sequence[manifests.TrustedManifest], day: str) -> Optional[key_manifest.KeyManifest]:
    """The manifest in force on *day* (``YYYY-MM-DD``): the reader policy as of
    that day (:func:`.manifests.effective_manifest`) over the lists issued by
    then — a later narrowing list never reaches back — unless that list was
    already stale then (issued + 60 days) or ANY list in the history conflicts
    with it at its order (a root signed two contents for it: trust neither).
    None = no list was in force."""
    issued_by_then = [item for item in history if _manifest(item).issued_day <= day]   # undated ("") always
    manifest = manifests.effective_manifest(issued_by_then, day)
    if manifest is None or key_manifest.manifest_clock(manifest, day)[0] == "stale":
        return None
    if manifest.order in manifests.conflict_orders(history):
        return None
    return manifest


def _manifest(item: manifests.TrustedManifest) -> key_manifest.KeyManifest:
    return item.manifest if isinstance(item, key_manifest.ManifestVerdict) else item
