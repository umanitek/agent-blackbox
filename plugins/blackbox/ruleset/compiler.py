"""The compiled ruleset and how rows become one.

:class:`Ruleset` holds the O(1) lookup dicts detection matches against
(dependency, ioc, injection, escalation, fileaccess, skill) plus the
community display tier. :func:`build_from_rows` compiles verified rows (via
:mod:`.row_adapters`) and :func:`verified_identifiers` answers the legacy proof check.

Usage: ``rs = build_from_rows(rows, cfg)``; detection reads ``rs.dependency`` etc.
"""

from __future__ import annotations

import copy
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Sequence, Tuple
from ..kernel import constants, threat_ids
from . import anchors
from ..kernel.dkg_client import DkgClient, extract_binding
from . import graph_queries
from . import row_adapters
from . import live

logger = logging.getLogger(__name__)

def _fetch_proofs(client: DkgClient, cg_id: str) -> dict[str, dict[str, Any]]:
    """Legacy proofs from the VM view: subject -> {root, members}. Fail-open
    to {} — no proofs simply means no community row can be promoted."""
    try:
        rows = client.query(graph_queries._PROOFS_SPARQL, cg_id, view=constants.VIEW_VERIFIABLE_MEMORY, on_error=None)
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: proof query failed: %s", exc)
        return {}
    proofs: dict[str, dict[str, Any]] = {}
    for row in rows or []:
        subj = extract_binding(row.get("proof"))
        root = extract_binding(row.get("root"))
        member = extract_binding(row.get("member"))
        if not (subj and root and member):
            continue
        entry = proofs.setdefault(subj, {"root": root, "members": set()})
        if entry["root"] == root:
            entry["members"].add(member)
    return proofs


def verified_identifiers(community_rows: list[dict[str, Any]], proofs: dict[str, dict[str, Any]]) -> set:
    """Identifiers of SWM threat rows covered by a matching VM proof.

    A proof verifies only when EVERY member is present locally and the batch
    root recomputed over their anchor hashes equals the published root — a
    tampered or missing row invalidates its whole batch, never silently
    passes. Verified identifiers earn the blockable ``public`` tier.
    """
    candidates: list[dict[str, str]] = []
    for row in community_rows:
        # Hash only threat-subject rows: reports (urn:guardian:report:*) share
        # the identifier and would shadow the threat row's hash.
        if not extract_binding(row.get("threat")).startswith("urn:guardian:threat:"):
            continue
        candidates.append({k: extract_binding(row.get(k)) for k in anchors.ANCHOR_FIELDS})
    if not candidates or not proofs:
        return set()
    hashes = anchors.anchor_hashes_from_rows(candidates)
    ok: set = set()
    for entry in proofs.values():
        members = entry["members"]
        if not members or not members.issubset(hashes.keys()):
            continue
        root = anchors.anchor_root((ident, hashes[ident]) for ident in members)
        if root == entry["root"]:
            ok |= members
    return ok


def _copy_community_stats(entry: dict[str, Any], rule: dict[str, Any]) -> None:
    """Copy a community rule's corroboration stats onto a graph entry (the UI's
    reporter count and recency — this node's observations, KI-012)."""
    entry["reporterCount"] = int(rule.get("reporterCount") or 0)
    entry["firstSeen"] = rule.get("firstSeen")
    entry["lastSeen"] = rule.get("lastSeen")
    for key in ("stage", "stageReason", "stageSource", "enforcement", "disputed",   # Refine R3
                "networkLive", "keptSince"):                                       # Refine R5
        if rule.get(key):
            entry[key] = rule[key]


#: The rule tables of a :class:`Ruleset` — what :meth:`Ruleset.derive` gives a copy of its own.
_TABLES = ("injection", "escalation", "dependency", "fileaccess", "skill", "ioc", "graph_threats", "community", "kill_list")


@dataclass
class Ruleset(live.LiveAnswering):
    """Compiled detection rules. See :mod:`detection` for how each is used.

    What a generation ANSWERS at check time — live lookups, verified subsets, the
    dashboard's live page — comes from :class:`live.LiveAnswering` (a mixin over
    ``verified_scope`` and the compiled dicts; compiler.py sits at its size alarm).
    """

    injection: list[dict[str, Any]] = field(default_factory=list)
    escalation: list[dict[str, Any]] = field(default_factory=list)
    dependency: dict[str, dict[str, Any]] = field(default_factory=dict)
    fileaccess: list[dict[str, Any]] = field(default_factory=list)
    skill: list[dict[str, Any]] = field(default_factory=list)
    # IOC rules keyed by full identifier (``ioc:{type}:{value}``) for O(1) lookup.
    ioc: dict[str, dict[str, Any]] = field(default_factory=dict)
    graph_threats: list[dict[str, Any]] = field(default_factory=list)
    #: Community tier (B5): aggregated reports keyed by identifier LITERAL —
    #: the corroboration/display store ({identifier: rule-dict with
    #: reporterCount/firstSeen/lastSeen/...}). Matchable subsets are also
    #: materialized into ``dependency``/``ioc``; community rules can only
    #: ever flag (confirmed stays False downstream).
    community: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: True when the curator fleet-wide pause flag suppressed community
    #: ingest this refresh (KI-036) — surfaced in status/dashboard.
    community_paused: bool = False
    #: The community pulse fingerprint the graph had when this community tier
    #: was applied (KI-208): a process that starts later compares its first
    #: probe against it instead of baselining blind, so reports that arrived
    #: while no process was beating are applied on the first beat.
    community_fingerprint: str = ""
    #: KI-262: when this node's community read FIRST came back with no reports
    #: while the tier still held some (epoch seconds; 0 = not in that state).
    #: The tier is cleared only once that has lasted ``EMPTY_READ_WITNESS_SECONDS``.
    community_empty_since: float = 0.0
    #: R14: the curators' kill list in force (killlist.KillList.as_cache()); {} = none.
    #: Written only after a list passed its signatures and gates — else last-good stays.
    kill_list: dict[str, Any] = field(default_factory=dict)
    #: R14: why the newest kill list was refused ("" = none) — the SECURITY alarm reads it.
    kill_list_refused: str = ""
    #: R7b: "" | "STALE since <day>" | "PENDING until <day>" — the curator manifest's clock as of the last refresh.
    curator_manifest_state: str = ""
    #: The trusted manifest's legacy pin ("" = no trusted manifest; None = the curator read could not
    #: tell) — the live scope checks the shipped legacy asset list against it (trust-and-threat-lab R1).
    curator_legacy_assets_hash: Optional[str] = None
    #: When this generation was compiled (epoch seconds; 0 = never). Shown as "last sync" and
    #: used for ages and staleness — never moved for scheduling (that is ``refresh_due_at``).
    synced_at: float = 0.0
    #: When this generation asks for its next refresh (epoch seconds); 0 = one full interval
    #: after ``synced_at``. Set earlier while the graph is still arriving or came back empty (KI-288).
    refresh_due_at: float = 0.0
    context_graph_id: str = ""
    #: DKG-lookup: what a live verified lookup may believe this generation (the
    #: confirmed owner-pinned assets, suppressions, revocations, aliases, store
    #: endpoint). ``None`` until the first refresh that built one.
    verified_scope: Optional[live.VerifiedScope] = None
    #: Identifiers the curator revoked as of this generation (Refine R2); the
    #: scope carries them so a live lookup withdraws the same rules the compile did.
    curator_revoked: frozenset[str] = frozenset()
    #: Subjects a public CorrectionSignal suppressed in THIS compile (not persisted:
    #: the scope keeps its own copy) — what the live scope withdraws too.
    suppressed_subjects: frozenset[str] = frozenset()
    _graph_entries_cache: dict[str, list[dict[str, Any]]] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )

    def derive(self) -> Ruleset:
        """A copy to change and then publish (copy-on-write).

        The generation in memory is read by every hook thread, so nothing edits it: a
        step that adds or withdraws rules between refreshes works on ``derive()`` and
        installs the result (``_memory.store``). The copy has its own tables — changing
        them never shows in this generation — and shares the rule dicts inside, which
        are replaced, never edited. Usage::

            rs = refresh_cycle.peek(config).derive()
            community_tier.reapply_community_tier(rs, client, config)
            disk_cache._write_cache(rs); refresh_cycle._memory.store(rs)
        """
        derived = copy.copy(self)   # every attribute, the read-state flags set after a refresh included
        for table in _TABLES:
            held = getattr(self, table)
            setattr(derived, table, type(held)(held))
        derived._graph_entries_cache = {}
        return derived

    def refresh_due(self, interval: float) -> float:
        """Epoch seconds when this generation should be refreshed: its own early
        schedule (``refresh_due_at``) if it set one, else *interval* after it was
        compiled. Every scheduler (hooks, dashboard worker) asks this one method."""
        due = self.synced_at + interval
        return min(due, self.refresh_due_at) if self.refresh_due_at else due

    def live_counts(self) -> dict[str, int]:
        """Verified rules held in the live tiers (``dependency``, ``ioc``), from the
        scope's aggregate counts (its per-ecosystem breakdown is not included); {}
        when this generation has no scope."""
        counts = self.verified_scope.verified_counts if self.verified_scope is not None else {}
        return {tier: int(counts[tier]) for tier in ("dependency", "ioc") if tier in counts}

    def counts(self) -> dict[str, int]:
        """Rules per category: the compiled lists / dicts plus the live tiers'
        verified counts (a compiled dict holds community-materialised rules once a
        scope exists, so the two never count the same rule twice)."""
        live_counts = self.live_counts()
        return {
            "injection": len(self.injection),
            "escalation": len(self.escalation),
            "dependency": len(self.dependency) + live_counts.get("dependency", 0),
            "fileaccess": len(self.fileaccess),
            "skill": len(self.skill),
            "ioc": len(self.ioc) + live_counts.get("ioc", 0),
            "community": len(self.community),
        }

    def iter_rules(self):
        """Yield ``(category, rule)`` for every rule across all categories, so
        callers (e.g. the dashboard) can filter/count by ``rule["source"]``
        straight from the synced cache instead of re-querying the node."""
        for r in self.injection:
            yield "injection", r
        for r in self.escalation:
            yield "escalation", r
        for r in self.dependency.values():
            yield "dependency", r
        for r in self.fileaccess:
            yield "fileaccess", r
        for r in self.skill:
            yield "skill", r
        for r in self.ioc.values():
            yield "ioc", r

    def drop_identifiers(self, identifiers: Iterable[str]) -> int:
        """Remove every rule whose identifier is in *identifiers* (Refine R2:
        a curator revocation withdraws a verified rule). Returns how many
        rules were removed."""
        gone = set(identifiers)
        if not gone:
            return 0
        before = sum(1 for _ in self.iter_rules())
        for name in ("injection", "escalation", "fileaccess", "skill", "graph_threats"):
            setattr(self, name, [r for r in getattr(self, name) if r.get("identifier") not in gone])
        self.dependency = {k: r for k, r in self.dependency.items() if r.get("identifier") not in gone}
        self.ioc = {k: r for k, r in self.ioc.items() if r.get("identifier", k) not in gone}
        self._graph_entries_cache.clear()
        return before - sum(1 for _ in self.iter_rules())

    def source_count(self, source: str) -> int:
        """How many rules are tagged with *source* (``public`` | ``community``);
        public includes the live tiers' verified counts."""
        compiled = sum(1 for _cat, r in self.iter_rules() if r.get("source") == source)
        return compiled + (sum(self.live_counts().values()) if source == "public" else 0)

    def graph_entries(self, source: str) -> list[dict[str, Any]]:
        cached = self._graph_entries_cache.get(source)
        if cached is not None:
            return cached
        entries = [item for item in self.graph_threats if item.get("source") == source]
        seen = {item.get("identifier") for item in entries}
        for category, rule in self.iter_rules():
            identifier = rule.get("identifier")
            if rule.get("source") != source or identifier in seen:
                continue
            seen.add(identifier)
            entry = {
                "identifier": identifier,
                "category": category,
                "severity": str(rule.get("severity") or "info").lower(),
                "name": rule.get("name") or "",
                "subject": rule.get("subject") or "",
                "source": source,
            }
            # Matchable community rules (ioc/dependency) are materialized into
            # the lookup dicts WITHOUT their corroboration stats; take those
            # from the community store, or the UI shows 0 reporters for every
            # IOC — including ones reported by several distinct nodes.
            stats = self.community.get(identifier) if source == "community" else None
            if stats is not None:
                _copy_community_stats(entry, stats)
            entries.append(entry)
        if source == "community":
            # The community STORE holds every aggregated report (including
            # display-only categories that never materialize into lookup
            # dicts) with reporter counts + recency for the UI (KI-037).
            for identifier, rule in self.community.items():
                if identifier in seen:
                    continue
                seen.add(identifier)
                entry = {
                    "identifier": identifier,
                    "category": rule.get("category") or threat_ids.category_for(identifier),
                    "severity": str(rule.get("severity") or "info").lower(),
                    "name": rule.get("name") or identifier,
                    "subject": "",
                    "source": "community",
                }
                _copy_community_stats(entry, rule)
                entries.append(entry)
        self._graph_entries_cache[source] = entries
        return entries

    def graph_count(self, source: str) -> int:
        """Graph threats of *source*: the compiled entries plus, for public, the live tiers."""
        return len(self.graph_entries(source)) + (sum(self.live_counts().values()) if source == "public" else 0)

    def verified_rule_count(self) -> int:
        """THE number of verified rules this node holds (:meth:`graph_count` of ``public``).
        Not ``counts()`` minus its ``community`` key: the compiled dependency / ioc dicts also
        hold community-materialised rules, which only ever flag."""
        return self.graph_count("public")


def suppressed_subjects(tagged_rows: Iterable[tuple], pin: live.CorrectionPin = live.NO_PIN) -> frozenset[str]:
    """Subjects the PUBLIC CorrectionSignal rows suppress (``(row, source)`` pairs):
    a curated correction withdraws the threat it targets from every tier. Once
    *pin* holds the legacy pin, only a quorum-signed correction counts, on the
    targets its signed payload names (:func:`.live.signed_suppressions`, R3)."""
    return live.signed_suppressions(tagged_rows, *pin)


def build_from_rows(rows: list[dict[str, Any]], source: str = "public", pin: live.CorrectionPin = live.NO_PIN) -> Ruleset:
    """Build a :class:`Ruleset` from ``(rows, source)`` pairs or plain rows.

    *rows* may be a flat list of binding rows (all tagged *source*) or a list
    of ``(row, source)`` tuples as produced by :func:`refresh`. Precedence is
    identifier-first-wins with public beating community, so a community row can
    never shadow (or escalate/downgrade) a curated public rule.
    """
    rs = Ruleset(synced_at=time.time())
    inj_seen: set = set()
    esc_seen: set = set()
    fa_seen: set = set()
    skill_seen: set = set()
    graph_seen: set = set()
    tagged_rows = [item if isinstance(item, tuple) else (item, source) for item in rows]
    rs.suppressed_subjects = suppressed_subjects(tagged_rows, pin)

    for row, row_source in tagged_rows:
        if extract_binding(row.get("threat")) in rs.suppressed_subjects:
            continue
        graph_entry = row_adapters._row_to_graph_entry(row, row_source)
        if graph_entry:
            graph_key = (row_source, graph_entry["identifier"])
            if graph_key not in graph_seen:
                graph_seen.add(graph_key)
                rs.graph_threats.append(graph_entry)
        mapped = row_adapters._row_to_rule(row, row_source)
        if not mapped:
            continue
        category, key, rule = mapped
        if category == "injection":
            if key not in inj_seen:
                inj_seen.add(key)
                rs.injection.append(rule)
        elif category == "escalation":
            if key not in esc_seen:
                esc_seen.add(key)
                rs.escalation.append(rule)
        elif category == "fileaccess":
            if key not in fa_seen:
                fa_seen.add(key)
                rs.fileaccess.append(rule)
        elif category == "skill":
            if key not in skill_seen:
                skill_seen.add(key)
                rs.skill.append(rule)
        elif category == "ioc":
            _keep_public_first(rs.ioc, key, rule)
        else:
            _keep_public_first(rs.dependency, key, rule)
    return rs


def _keep_public_first(table: dict[str, dict[str, Any]], key: str, rule: dict[str, Any]) -> None:
    """Store *rule* under *key* unless one is already there — public (curated)
    rules always win over community rows, so only a community rule is replaced."""
    existing = table.get(key)
    if existing is None or (existing.get("source") == "community" and rule.get("source") == "public"):
        table[key] = rule
