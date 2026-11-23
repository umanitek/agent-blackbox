"""A dependency file's packages, judged by the SAME ruleset lookup a named install uses (KI-595).

:func:`listed_packages` asks the ruleset for every package of a :class:`~.model.DependencyGraph`
— the exact version (every spelling of it) and the whole-package ``@*`` rule, as
``detectors._dependency_candidates`` does for ``npm install x@1`` — in chunks of
:data:`LOOKUP_CHUNK` candidates (the live lookup reads at most 4,000 values per question).
:func:`findings_for` turns the hits into :class:`~..finding.Finding` rows of the usual
``dependency`` category, so the tiers are today's: a verified match is confirmed (blockable), a
community one flags. Each names the package, its version, the file and the chain the lockfile
gives ("express → body-parser → bad-pkg@1.2.3"). Past :data:`MAX_LISTED` matches the rest are
summarised on the last row, never listed by the thousand.

The answer for one parsed file and one ruleset generation is kept :data:`VERDICT_TTL_SECONDS`
(the parsed graph object changes whenever the file's content does), so an agent repeating an
install pays a dictionary lookup, not a store query.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Optional

from ...kernel import threat_ids
from .. import osv
from ..detectors import _dependency_candidates, dependency_rules
from ..finding import Finding, _rule_source, rule_subject
from .model import CHAIN_ARROW, DependencyGraph, Package

#: Candidates per ruleset question (the live lookup caps one question at 4,000 values).
LOOKUP_CHUNK = 1000
#: Matches listed one by one; the rest are counted on the last listed row.
MAX_LISTED = 10
#: How long one file's answer is reused for the same ruleset generation.
VERDICT_TTL_SECONDS = 60.0
_VERDICT_ENTRIES = 32
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass(frozen=True)
class Hit:
    """One package of a file that a rule lists: the graph node, the matched rule key and the rule."""

    node: str
    key: str
    rule: dict[str, Any]


def _candidate(package: Package) -> dict[str, str]:
    """The named-install shape ``_dependency_candidates`` reads; a range has no version to key on."""
    return {"ecosystem": package.ecosystem, "name": package.name, "version": package.version if package.exact else ""}


def _ask(ruleset: Any, graph: DependencyGraph) -> list[Hit]:
    per_node = {node: _dependency_candidates(_candidate(package)) for node, package in graph.nodes.items()}
    candidates = list(dict.fromkeys(c for wanted in per_node.values() for c in wanted))
    rules: dict[str, dict[str, Any]] = {}
    for start in range(0, len(candidates), LOOKUP_CHUNK):
        rules.update(dependency_rules(ruleset, candidates[start:start + LOOKUP_CHUNK]))
    hits: list[Hit] = []
    seen: set[str] = set()
    for node, wanted in per_node.items():
        key = next((k for k in (threat_ids.dependency_key(*c) for c in wanted) if k in rules), None)
        if key is not None and key not in seen:
            seen.add(key)
            hits.append(Hit(node, key, rules[key]))
    return sorted(hits, key=lambda hit: (_rule_source(hit.rule) != "public",
                                         _SEVERITY_ORDER.get(str(hit.rule.get("severity", "high")), 4)))


class _Verdicts:
    """Recent answers keyed by (parsed graph, ruleset) object identity; the objects are held, so an id is never reused."""

    def __init__(self) -> None:
        self._entries: OrderedDict[tuple[int, int], tuple[DependencyGraph, Any, float, list[Hit]]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, graph: DependencyGraph, ruleset: Any) -> Optional[list[Hit]]:
        with self._lock:
            entry = self._entries.get((id(graph), id(ruleset)))
        if entry is None or entry[0] is not graph or entry[1] is not ruleset:
            return None
        return entry[3] if time.monotonic() - entry[2] < VERDICT_TTL_SECONDS else None

    def put(self, graph: DependencyGraph, ruleset: Any, hits: list[Hit]) -> None:
        with self._lock:
            self._entries[(id(graph), id(ruleset))] = (graph, ruleset, time.monotonic(), hits)
            while len(self._entries) > _VERDICT_ENTRIES:
                self._entries.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


VERDICTS = _Verdicts()


def listed_packages(ruleset: Any, graph: DependencyGraph, only: Optional[set[str]] = None) -> list[Hit]:
    """The packages of *graph* a rule lists, verified first then by severity. *only*: judge just
    these nodes (the after-install and write checks judge what was added); not cached then."""
    if only is not None:
        subset = DependencyGraph(source=graph.source, nodes={n: graph.nodes[n] for n in only if n in graph.nodes})
        return _ask(ruleset, subset)
    cached = VERDICTS.get(graph, ruleset)
    if cached is not None:
        return cached
    hits = _ask(ruleset, graph)
    VERDICTS.put(graph, ruleset, hits)
    return hits


def findings_for(tool_name: str, graph: DependencyGraph, hits: list[Hit], *, title_prefix: str = "",
                 advice: str = "", landed: bool = False) -> list[Finding]:
    """Up to :data:`MAX_LISTED` findings for *hits* in *graph* (the last counts the rest).

    *landed*: the package is already installed (the after-install check) — a verified one is
    raised to ``critical`` so the person's alert says so, and *advice* names the removal."""
    listed = hits[:MAX_LISTED]
    chains = graph.chains(hit.node for hit in listed)
    out: list[Finding] = []
    for index, hit in enumerate(listed):
        package = graph.nodes[hit.node]
        chain = chains.get(hit.node, package.label)
        more = len(hits) - len(listed) if index == len(listed) - 1 else 0
        top = graph.nodes[hit.node].name if CHAIN_ARROW not in chain else chain.split(CHAIN_ARROW)[0]
        through = f" (it came in through {top})" if top != package.name else ""
        out.append(_finding(tool_name, graph.source, package, chain, hit, title_prefix, more, landed,
                            advice.replace("{top}", top).replace("{through}", through)))
    return out


def _finding(tool_name: str, source_file: str, package: Package, chain: str, hit: Hit, title_prefix: str,
             more: int, landed: bool, advice: str) -> Finding:
    rule = hit.rule
    tier = _rule_source(rule)
    name = threat_ids.canonical_package_name(package.ecosystem, package.name)
    label = package.label if package.exact else f"{package.name} ({package.version or 'any version'})"
    via = f" via {chain}" if CHAIN_ARROW in chain else ""
    title = f"{title_prefix}{rule.get('name') or 'Listed package'}: {label} in {source_file}{via}"
    if more:
        title += f" (and {more} more listed package{'s' if more != 1 else ''} in {source_file})"
    severity = "critical" if landed and tier == "public" else rule.get("severity", "high")
    return Finding(
        identifier=rule.get("identifier") or f"dep:{hit.key}", category="dependency", severity=severity,
        title=title, tool_name=tool_name or "", matched=hit.key,
        evidence=f"{package.ecosystem}:{label} in {source_file}{via}"
        + (f" ({rule.get('advisoryId')})" if rule.get("advisoryId") else ""),
        confirmed=tier == "public", source=tier, rule_subject=rule_subject(rule), kind=rule.get("kind"), advice=advice,
        fields={"ecosystem": package.ecosystem, "package_name": name, "package_version": hit.key.rsplit("@", 1)[1],
                "advisory_id": rule.get("advisoryId"), "kind": rule.get("kind"),
                "reason": osv.advisory_reason(rule.get("advisoryId")), "dependency_file": source_file,
                "dependency_path": chain, **({"more_listed": more} if more else {}),
                **({"answered_by": rule["answered_by"]} if rule.get("answered_by") else {})},
    )
