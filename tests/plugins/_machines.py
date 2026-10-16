"""Test harness: several machines over ONE shared in-memory network (Community Curation C12).

A single-node test is not evidence for behaviour that only exists between
nodes (LES-015). This harness runs a reporter, curators and a reader as
separate machines — each with its own ``BLACKBOX_HOME`` and its own node
client — over one shared graph store and one message bus, so a test can assert
that what machine A did is OBSERVED on machine B.

* :class:`Network` — the shared state: knowledge assets per (graph, memory
  view), and private messages per peer. Nothing here is trusted: any machine
  can share anything into any graph, exactly like the open community graph.
* :class:`Node` — one machine's node client (the methods the product calls on
  ``DkgClient``). Its ``query`` answers the product's own SPARQL the way a
  triple store would: rows are built from the stored quads, and it honours the
  type pattern, ``VALUES`` lists, an exact signed-statement literal, the
  subject cursor and the fingerprint aggregate.
* :class:`Machine` — a name, a home directory and a node; ``with machine:``
  points ``BLACKBOX_HOME`` at its home for the duration.

Usage::

    net = Network()
    a, b = Machine(net, tmp_path, monkeypatch, "A"), Machine(net, tmp_path, monkeypatch, "B")
    with a:
        ...run product code with a.node as the client...
    with b:
        ...assert what b.node now reads...
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from _community_rows import GRAPH, NETWORK, signed_report_quads
from datetime import UTC

SWM = "shared-working-memory"
VM = "verifiable-memory"
_TYPES = ("ThreatReport", "Retraction", "FalsePositive", "SightingDigest", "CuratorStatement", "KeyManifest")
_RDF_TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
_STRING = r'"((?:[^"\\]|\\.)*)"'


def _local(iri: str) -> str:
    return iri.rstrip(">").rsplit("/", 1)[-1].rsplit("#", 1)[-1]


class Network:
    """The shared store: ``assets[(graph, view)][(author, name)] = quads`` and ``inbox[peer] = [message]``."""

    def __init__(self, network_id: str = NETWORK) -> None:
        self.network_id = network_id
        self.assets: dict[tuple[str, str], dict[tuple[str, str], list[dict[str, str]]]] = {}
        self.inbox: dict[str, list[dict[str, Any]]] = {}
        self.clock = 1_000

    def put(self, graph: str, view: str, author: str, name: str, quads: list[dict[str, str]]) -> bool:
        """Store one asset; False when this author already holds one under that name (never rewritten)."""
        store = self.assets.setdefault((graph, view), {})
        if (author, name) in store:
            return False
        store[(author, name)] = [dict(q) for q in quads]
        return True

    def forget(self, graph: str, view: str = SWM) -> None:
        """Shared memory forgot everything in *graph* (expiry)."""
        self.assets.pop((graph, view), None)

    def rows(self, graph: str, view: str, type_name: Optional[str]) -> list[dict[str, str]]:
        """One row per (asset, subject): ``r`` plus every plain-literal property by its local name."""
        out = []
        for quads in self.assets.get((graph, view), {}).values():
            by_subject: dict[str, dict[str, str]] = {}
            types: dict[str, str] = {}
            for quad in quads:
                subject, predicate, obj = quad["subject"], quad["predicate"], quad["object"]
                if predicate == _RDF_TYPE:
                    types[subject] = _local(obj)
                elif obj.startswith('"') and obj.endswith('"'):
                    by_subject.setdefault(subject, {})[_local(predicate)] = json.loads(obj)
            for subject, fields in by_subject.items():
                if type_name is None or types.get(subject) == type_name:
                    out.append({"r": subject, **fields})
        return out


class Node:
    """One machine's node client over the shared :class:`Network`."""

    def __init__(self, network: Network, name: str, address: str) -> None:
        self.network, self.name, self.address = network, name, address
        self.sealed: dict[str, tuple[str, list[dict[str, str]]]] = {}
        self.queries: list[tuple[str, str]] = []
        self.offline = False          # every query fails
        self.refuse_shares = False    # a share is refused (a new subscriber, or a full node)

    # -- identity ------------------------------------------------------------
    def status(self) -> dict[str, Any]:
        return {"networkId": self.network.network_id, "peerId": self.name}

    def agent_identity(self) -> dict[str, Any]:
        return {"agentAddress": self.address}

    def context_graphs(self) -> list[dict[str, Any]]:
        graphs = {graph for graph, _ in self.network.assets}
        return [{"id": graph, "subscribed": True, "synced": True, "accessPolicy": "public"} for graph in graphs]

    # -- writes --------------------------------------------------------------
    def share_knowledge_asset(self, cg: str, name: str, quads: list[dict[str, str]], **kw: Any) -> dict[str, Any]:
        if self.refuse_shares:
            raise RuntimeError("share refused")
        fresh = self.network.put(cg, SWM, self.name, name, quads)
        return {"state": "succeeded"} if fresh else {"idempotent": True}

    def write_private_knowledge_asset(self, cg: str, name: str, quads: list[dict[str, str]]) -> dict[str, Any]:
        self.sealed[name] = (cg, [dict(q) for q in quads])
        return {"name": name}

    def share_finalized_knowledge_asset(self, cg: str, name: str, sub_graph: str = "") -> dict[str, Any]:
        """The full share a Verified Memory publish needs first (KI-351): nothing to store here."""
        return {"state": "succeeded"}

    def request(self, method: str, path: str, body: Optional[dict[str, Any]] = None, timeout: Any = None) -> dict[str, Any]:
        if path.endswith("/vm/publish"):
            name = path.split("/knowledge-assets/", 1)[1].rsplit("/vm/publish", 1)[0]
            graph, quads = self.sealed[name]
            self.network.put(graph, VM, self.name, name, quads)
            return {"status": "confirmed"}
        if path == "/api/chat":
            self.network.clock += 1
            inbox = self.network.inbox.setdefault(str(body["to"]), [])
            inbox.append({"id": len(inbox) + 1, "ts": self.network.clock, "peer": self.name, "text": body["text"]})
            return {"delivered": True}
        if path.startswith("/api/messages"):
            since_id = int((re.search(r"sinceId=(\d+)", path) or [0, 0])[1])
            return {"messages": [m for m in self.network.inbox.get(self.name, []) if m["id"] > since_id]}
        raise AssertionError(f"unexpected request {method} {path}")

    # -- reads ---------------------------------------------------------------
    def query(self, sparql: str, cg_id: str, view: Optional[str] = VM, on_error: Any = None, **kw: Any) -> Any:
        self.queries.append((cg_id, sparql))
        if self.offline:
            return on_error
        view = view or VM
        if "GROUP BY ?t" in sparql:                                   # the pulse fingerprint
            rows = []
            for kind in _TYPES:
                found = self.network.rows(cg_id, view, kind)
                if found and f"g:{kind}" in sparql:
                    rows.append({"t": f"http://umanitek.ai/ontology/guardian/{kind}", "n": str(len({r["r"] for r in found})),
                                 "last": max(r["r"] for r in found)})
            return rows
        kind = next((k for k in _TYPES if f"g:{k}" in sparql or f"guardian/{k}>" in sparql), None)
        rows = self.network.rows(cg_id, view, kind)
        if "COUNT(" in sparql:
            return [{"n": str(len({r["r"] for r in rows}))}]
        if "VALUES ?identifier" in sparql:
            wanted = set(json.loads(f'"{m}"') for m in re.findall(_STRING, sparql.split("VALUES ?identifier", 1)[1].split("}", 1)[0]))
            rows = [r for r in rows if r.get("identifier") in wanted]
        if "VALUES ?r" in sparql:
            subjects = set(re.findall(r"<([^>]+)>", sparql.split("VALUES ?r", 1)[1].split("}", 1)[0]))
            rows = [r for r in rows if r["r"] in subjects]
        exact = re.search(r"signedStatement>\s+" + _STRING, sparql)
        if exact:                                                     # the read-back after a publish
            rows = [r for r in rows if r.get("signedStatement") == json.loads(f'"{exact.group(1)}"')]
        cursor = re.search(r"FILTER\(STR\(\?r\) > " + _STRING + r"\)", sparql)
        if cursor:
            rows = [r for r in rows if r["r"] > json.loads(f'"{cursor.group(1)}"')]
        return sorted(rows, key=lambda r: r["r"])


class Machine:
    """One machine: ``with machine:`` runs product code against its own home."""

    def __init__(self, network: Network, tmp_path: Path, monkeypatch: Any, name: str, address: str = "") -> None:
        self.name = name
        self.home = tmp_path / name
        (self.home / "curate").mkdir(parents=True, exist_ok=True)
        self.node = Node(network, name, address or "0x" + (name.encode().hex() * 40)[:40])
        self._monkeypatch = monkeypatch

    def __enter__(self) -> Machine:
        self._monkeypatch.setenv("BLACKBOX_HOME", str(self.home))
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def share_report(node: Node, identifier: str, reporter: Any, *, graph: str = GRAPH, day: Optional[str] = None,
                 **evidence: str) -> None:
    """Put one signed report of *identifier* by *reporter* into *graph* through
    *node*, dated *day* (``YYYY-MM-DD``; today when omitted) — built by the
    product's own report writer."""
    from datetime import datetime, timezone
    ts = datetime.fromisoformat(day).replace(tzinfo=UTC) if day else None
    quads = signed_report_quads(identifier, reporter, graph=graph, ts=ts, **evidence)
    node.share_knowledge_asset(graph, f"report-{abs(hash((identifier, reporter.address))):x}", quads)
