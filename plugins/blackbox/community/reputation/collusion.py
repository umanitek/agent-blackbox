"""Cluster collapse and the collusion DETECTOR (R4, plan §05 COLLUSION).

Two established reporters that are really one actor must count once:
keys that share a transport peer id collapse, and keys whose report sets
over the last :data:`OVERLAP_WINDOW_DAYS` overlap almost entirely (Jaccard ≥
:data:`OVERLAP_JACCARD` over at least :data:`OVERLAP_MIN_SHARED` shared
threats) collapse too — a staggered ring that files the same threats in
turn is one cluster however many wallets it uses. The co-report graph is a
DETECTOR only, never a weight source (at ≤ 50 reporters a ring controls
exactly the links a trust-propagation scheme would mix over).

Pure: ``collapse`` returns the cluster id per key; ``rings`` names groups for
the curator's review. The curator publishes a collapse through the
counted-author list (established keys sharing a cluster carry the same
``org``), so every reader applies it (``community.stages.clusters_for``).

Usage::

    clusters = collapse(reports_by_key, peer_id_by_key={"k1": "12D3…", "k2": "12D3…"})
    rings(reports_by_key)      # [frozenset({...}), ...] groups worth a curator's look
"""

from __future__ import annotations

from typing import AbstractSet, Mapping, Optional

OVERLAP_WINDOW_DAYS = 90
OVERLAP_JACCARD = 0.8
OVERLAP_MIN_SHARED = 3


def jaccard(a: AbstractSet[str], b: AbstractSet[str]) -> float:
    union = len(a | b)
    return len(a & b) / union if union else 0.0


def _overlapping(reports_a: AbstractSet[str], reports_b: AbstractSet[str]) -> bool:
    return len(reports_a & reports_b) >= OVERLAP_MIN_SHARED and jaccard(reports_a, reports_b) >= OVERLAP_JACCARD


def collapse(reports_by_key: Mapping[str, AbstractSet[str]],
             peer_id_by_key: Optional[Mapping[str, str]] = None) -> dict[str, str]:
    """``{key: cluster id}`` — the smallest key of each group. *reports_by_key*
    holds each key's threat identifiers inside the overlap window (the caller
    windows them); *peer_id_by_key* the transport peer id where known.
    Union-find over the two collapse rules."""
    parent: dict[str, str] = {key: key for key in reports_by_key}

    def find(key: str) -> str:
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    by_peer: dict[str, str] = {}
    for key, peer in (peer_id_by_key or {}).items():
        if key in parent and peer:
            if peer in by_peer:
                union(key, by_peer[peer])
            by_peer.setdefault(peer, key)
    keys = sorted(reports_by_key)
    for i, a in enumerate(keys):
        for b in keys[i + 1:]:
            if _overlapping(reports_by_key[a], reports_by_key[b]):
                union(a, b)
    return {key: find(key) for key in keys}


def rings(reports_by_key: Mapping[str, AbstractSet[str]],
          peer_id_by_key: Optional[Mapping[str, str]] = None) -> list[frozenset[str]]:
    """Groups of two or more keys that collapse together — for the curator's
    eyes, never a weight."""
    groups: dict[str, set] = {}
    for key, cluster in collapse(reports_by_key, peer_id_by_key).items():
        groups.setdefault(cluster, set()).add(key)
    return sorted((frozenset(g) for g in groups.values() if len(g) > 1), key=lambda g: min(g))
