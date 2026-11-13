"""Read the graph's ``sandbox`` lane: the test statements every member has shared there.

This is the only reader of the sandbox lane. Nothing it returns reaches the
rules, the community tier or any flag: those readers query the ``reports`` lane
by name (``kernel/dkg_client.query``), so a sandbox statement is invisible to
them by construction.

The query is bounded by construction (LES-013/040): it names the record kind
(``g:ThreatReport``), reads four small fields and carries a LIMIT.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from typing import Any, Optional

from ..kernel import constants, identity
from ..kernel.config import BlackboxConfig
from ..kernel.dkg_client import DkgClient, DkgError, extract_binding

logger = logging.getLogger(__name__)

LANE_ROW_LIMIT = 4000   # property rows read per refresh (a report is ~20); the lane expires after the 30-day TTL
#: Fields a statement carries that are proof material, not something to show (long, opaque).
_HIDDEN_FIELDS = frozenset({"signedStatement", "signature", "signatureScheme", "signerKey", "signedBy"})
_FIELD_MAX_CHARS = 300

# Every property of every report in the lane, so the sandbox view shows exactly what a
# member submitted. Bounded by construction (LES-013): one record kind, a LIMIT, small fields.
_LANE_SPARQL = f"""
PREFIX g: <{constants.BLACKBOX_ONTOLOGY}>
SELECT ?r ?p ?o WHERE {{
  ?r a g:ThreatReport ;
     ?p ?o .
}} ORDER BY DESC(?r) LIMIT {LANE_ROW_LIMIT}
"""


@dataclass(frozen=True)
class LaneEntry:
    """One test statement in the sandbox lane. ``mine`` marks this node's own.

    ``reporter`` is the address the statement names; the sandbox lane only
    proves connectivity, so it is shown, never counted or trusted.
    """

    identifier: str
    reporter: str
    severity: str
    mine: bool
    #: every other field the statement carries (category, kind, package, tool, outcome…), as text
    fields: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class LaneView:
    """The sandbox lane as the dashboard shows it. ``readable`` False = the node did not answer."""

    graph: str
    readable: bool
    entries: tuple[LaneEntry, ...]

    @property
    def agents(self) -> int:
        """Distinct reporters heard on the lane, this node included."""
        return len({entry.reporter.lower() for entry in self.entries})

    def to_dict(self) -> dict[str, Any]:
        return {"graph": self.graph, "readable": self.readable, "agents": self.agents,
                "entries": [asdict(entry) for entry in self.entries]}


def read_lane(cfg: BlackboxConfig, client: Optional[DkgClient] = None) -> LaneView:
    """Ask the local node for the sandbox lane of the community graph. Fail-open."""
    graph = cfg.context_graph_id
    try:
        client = client or DkgClient.for_config(cfg)
        failed = object()
        rows = client.query(_LANE_SPARQL, graph, view=constants.VIEW_SHARED_WORKING_MEMORY,
                            on_error=failed, sub_graph=constants.SANDBOX_SUB_GRAPH)
        if rows is failed:
            return LaneView(graph, False, ())
        own = (identity.reporter_address(client) or "").lower()
    except (DkgError, OSError, ValueError) as exc:   # the node is down or busy: say so, never guess
        logger.debug("blackbox: sandbox lane unreadable: %s", exc)
        return LaneView(graph, False, ())
    return LaneView(graph, True, entries_from_rows(rows, own))


def _field_key(predicate: str) -> tuple[str, str]:
    """Pure: ``(local name, field key)`` for a predicate IRI.

    Blackbox's own ontology keeps the bare local name (``identifier``, ``reporter``);
    any other vocabulary is prefixed with its host (``schema:identifier``). Why: a
    package report carries BOTH ``guardian:identifier`` (the threat, ``dep:npm:…``)
    and ``schema:identifier`` (the advisory, ``MAL-…``); folding by local name let
    whichever row came first name the threat (bench, 2026-10-21)."""
    local = predicate.rstrip("/").rsplit("/", 1)[-1].rsplit("#", 1)[-1]
    if predicate.startswith(constants.BLACKBOX_ONTOLOGY) or not local:
        return local, local
    host = predicate.split("//", 1)[-1].split("/", 1)[0].removeprefix("www.").split(".")[0]
    return local, f"{host}:{local}"


def entries_from_rows(rows: list[dict[str, Any]], own: str) -> tuple[LaneEntry, ...]:
    """Pure: fold ``?r ?p ?o`` rows into one :class:`LaneEntry` per report, newest first.
    A report without an identifier or reporter is skipped (not a usable statement)."""
    reports: dict[str, dict[str, str]] = {}
    for row in rows:
        subject = extract_binding(row.get("r"))
        local, key = _field_key(extract_binding(row.get("p")))
        value = extract_binding(row.get("o"))
        if subject and key and local not in _HIDDEN_FIELDS and len(value) <= _FIELD_MAX_CHARS:
            reports.setdefault(subject, {}).setdefault(key, value)
    entries = []
    for fields in reports.values():
        identifier, reporter = fields.pop("identifier", ""), fields.pop("reporter", "")
        if not identifier or not reporter:
            continue
        severity = fields.pop("severity", "")
        fields.pop("w3:type", None)
        entries.append(LaneEntry(identifier=identifier, reporter=reporter, severity=severity,
                                 mine=bool(own) and reporter.lower() == own, fields=tuple(sorted(fields.items()))))
    return tuple(entries)
