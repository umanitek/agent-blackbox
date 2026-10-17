"""Test helper: the one-graph flow's pieces (a report promoted as itself).

* :func:`shared_report` — a report as an edge node shares it into the verified
  graph's sub-graph ``reports``, built and signed by the real writer, with the
  verified record the community reader would hand the curators.
* :class:`NodeStore` — the node's own triple store as the report-copies query
  sees it (``kernel.signing.promotion_statement``): per-asset graphs holding
  report subjects with their signed text, and the lifecycle records of the
  shared assets whose author's seal the node keeps (with the asset's name).
  Patch it in with :func:`use_store`.
* :func:`promotion_envelope` — the curators' promotion statement for a report.

Usage::

    report = shared_report("dep:npm:evil@1.0.0", Reporter("edge-1"))
    store = NodeStore()
    store.hold(report, layer=VERIFIED, number=7)          # Verified Memory holds it
    use_store(monkeypatch, store)
    envelope = promotion_envelope(report, (key_a, key_b), sequence=3)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Iterable, Optional

from _community_rows import Reporter, signed_report_quads
from plugins.blackbox import community
from plugins.blackbox.kernel import constants, signing
from plugins.blackbox.kernel.signing import promotion_statement as statement
from plugins.blackbox.kernel.store import StoreAnswer

NETWORK = "sandbox-net"
VM_GRAPH = "0xabc/agent-blackbox-vm"
STORE_URL = "http://127.0.0.1:7878/query"
SUB_GRAPH = "reports"
SHARED, VERIFIED = statement.SHARED_LAYER, statement.VERIFIED_LAYER
TODAY = datetime.now(UTC).date().isoformat()


@dataclass(frozen=True)
class SharedReport:
    """One shared report: its quads, subject, signed text, envelope and digest,
    the reporter's agent address, and the verified record the reader makes of it."""

    identifier: str
    reporter: Reporter
    quads: tuple
    subject: str
    text: str
    envelope: signing.SignedEnvelope
    digest: str
    verified: community.VerifiedReport


def shared_report(identifier: str, reporter: Reporter, severity: str = "high", *, graph: str = VM_GRAPH,
                  network: str = NETWORK, **evidence: str) -> SharedReport:
    """*identifier* reported by *reporter*, signed for *graph* (the verified graph, one-graph flow)."""
    quads = tuple(signed_report_quads(identifier, reporter, severity, environment=network, graph=graph, **evidence))
    text = next(json.loads(q["object"]) for q in quads if q["predicate"] == constants.SIGNED_STATEMENT_PRED)
    envelope = signing.from_text(text)
    verified = community.ReportVerifier(network, graph).verify_signed(text)
    assert verified is not None, "the helper built a report the real reader refuses"
    return SharedReport(identifier, reporter, quads, quads[0]["subject"], text, envelope, signing.content_id(envelope),
                        verified)


def promotion_envelope(report: SharedReport, keys: Iterable, *, sequence: int, severity: str = "critical",
                       day: str = TODAY, graph: str = VM_GRAPH, network: str = NETWORK, digest: str = "",
                       reporter_key: str = "", root_epoch: int = 1) -> signing.SignedEnvelope:
    """The curators' promotion of *report*, signed by every key in *keys* (in order)."""
    payload = statement.promotion_payload(report.identifier, report=report.subject,
                                          report_digest=digest or report.digest,
                                          reporter_key=reporter_key or report.verified.author, severity=severity, day=day)
    keys = list(keys)
    envelope = signing.sign(keys[0], statement_type=statement.PROMOTION_STATEMENT, environment=network, graph=graph,
                            payload=payload, root_epoch=root_epoch, sequence=sequence)
    for key in keys[1:]:
        envelope = signing.cosign(envelope, key)
    return envelope


class NodeStore:
    """A node's own store as the report-copies query reads it. ``fail`` — every
    select is could-not-tell; ``selects`` — the queries asked."""

    def __init__(self) -> None:
        self.graphs: dict[str, dict[str, str]] = {}
        #: lifecycle record IRI -> (asset number, asset name), kept with the author's seal
        self.seals: dict[str, tuple[str, str]] = {}
        self.fail = False
        self.selects: list[str] = []

    def hold(self, report: SharedReport, *, layer: str, number: int, author: str = "", sub_graph: str = SUB_GRAPH,
             graph: str = VM_GRAPH, text: str = "") -> str:
        """Put one copy of *report* (its own signed text unless *text*) in an asset graph; returns that graph's IRI."""
        asset = asset_graph(author or report.reporter.address, number, layer=layer, sub_graph=sub_graph, graph=graph)
        self.graphs.setdefault(asset, {})[report.subject] = text or report.text
        return asset

    def seal(self, author: str, number: int, name: str, *, sub_graph: str = SUB_GRAPH, graph: str = VM_GRAPH) -> str:
        """Record that this node keeps the seal of *author*'s asset *number*, named *name* (as DKG 10.0.25's
        curator node does for a member's share: OriginTrail/dkg#3307); the record spells the author checksummed."""
        lifecycle = f"urn:dkg:assertion:{graph}:" + (f"{sub_graph}:" if sub_graph else "") + f"0x{author[2:].upper()}:{name}"
        self.seals[lifecycle] = (str(number), name)
        return lifecycle

    def drop(self, asset: str) -> None:
        self.graphs.pop(asset, None)

    def select(self, sparql: str, *, timeout: Optional[float] = None) -> StoreAnswer:
        self.selects.append(sparql)
        if self.fail:
            return StoreAnswer(None, "timeout")
        if "swmShareComplete" in sparql:   # the sealed-names query: lifecycle records by how they begin
            starts = re.findall(r'"([^"]*)"', re.search(r"VALUES \?start \{(.*?)\}", sparql).group(1))
            return StoreAnswer([{"lifecycle": lifecycle, "ka": f'"{number}"^^<http://www.w3.org/2001/XMLSchema#integer>',
                                 "name": json.dumps(name)}
                                for lifecycle, (number, name) in sorted(self.seals.items())
                                if any(lifecycle.lower().startswith(start) for start in starts)])
        values = re.search(r"VALUES \(\?r \?author\) \{(.*?)\} GRAPH", sparql)
        prefix = re.search(r'STRSTARTS\(STR\(\?g\), "([^"]*)"\)', sparql)
        subjects = set(re.findall(r"<([^>]+)>", values.group(1))) if values else set()
        verified_only = f'"/{VERIFIED}/"' in sparql
        rows = [{"g": asset, "r": subject, "signedStatement": json.dumps(text)}
                for asset, held in sorted(self.graphs.items()) if prefix and asset.startswith(prefix.group(1))
                and (not verified_only or f"/{VERIFIED}/" in asset)
                for subject, text in sorted(held.items()) if subject in subjects]
        return StoreAnswer(rows)


def asset_graph(author: str, number: int, *, layer: str, sub_graph: str = SUB_GRAPH, graph: str = VM_GRAPH) -> str:
    """A per-asset graph IRI (OT-RFC-46): ``did:dkg:context-graph:<graph>[/<sub>]/<layer>/<author>/<number>``."""
    base = f"did:dkg:context-graph:{graph}" + (f"/{sub_graph}" if sub_graph else "")
    return f"{base}/{layer}/{author.lower()}/{number}"


def use_store(monkeypatch, store: NodeStore) -> None:
    """Every reader of the node's own store (the curator's and the verified reader's) reads *store*."""
    from plugins.blackbox.curate import promotion
    from plugins.blackbox.ruleset.live import promoted
    for module in (promotion, promoted):
        monkeypatch.setattr(module, "StoreClient", lambda url, **_kw: store)


def statement_row(envelope: signing.SignedEnvelope) -> dict[str, str]:
    """One promotion statement as the reader's statements query returns it."""
    found = statement.parse(envelope)
    return {"r": statement.statement_subject(found.identifier, found.sequence), "report": found.report,
            "signedStatement": json.dumps(envelope.to_text())}
