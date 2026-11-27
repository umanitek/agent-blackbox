"""The small verified tiers are read whole, across every asset at once (review 2026-11-26, findings 3, 9, 10).

* Finding 3: the paged sub-select of a lane over ``GRAPH ?g`` must page the
  subjects of ALL assets together. With the LIMIT inside each named graph, a
  page took the first N subjects of EVERY asset and the cursor then jumped past
  the subjects of the assets it had not finished (asset A = a1 a2 a3, asset
  B = z1 z2, page size 2: a3 was never read).
* Finding 9: a lane that stops at the row ceiling without an empty page is
  not complete — the read could not tell, so it is None (keep last-good).
* Finding 10: one subject may come back as several rows (a correction naming
  two ``dp:targetSubject``); de-duplication keeps every row of the confirmed
  assets and drops only a root-graph copy of a subject already read.

Proved against a real SPARQL engine (rdflib), not a fake that ignores the query.
"""

from __future__ import annotations

import pytest

pytest.importorskip("rdflib", reason="rdflib runs the lanes' real SPARQL; CI installs it (blackbox-ci.yml)")
from rdflib import Dataset, Literal, URIRef

from plugins.blackbox.kernel import constants, sparql_text
from plugins.blackbox.ruleset import fetching

CG = "0x" + "a" * 40 + "/blackbox-threats"
VM = f"did:dkg:context-graph:{CG}/_verifiable_memory/"
ASSET_A, ASSET_B = f"{VM}1", f"{VM}2"
DEFENDER = "urn:defender:"
DP = "urn:defender:p:"
RDF_TYPE = URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type")


class _RdflibNode:
    """A node whose query API is a real SPARQL engine over named graphs (no status: the pager asks it directly)."""

    def __init__(self) -> None:
        self.dataset = Dataset()
        self.queries = 0

    def add(self, graph: str, subject: str, predicate: str, value) -> None:
        obj = value if isinstance(value, (URIRef, Literal)) else Literal(value)
        self.dataset.graph(URIRef(graph)).add((URIRef(subject), URIRef(predicate) if predicate != "a" else RDF_TYPE, obj))

    def query(self, sparql, _cg, *, view=None, on_error=None, **_):
        self.queries += 1
        return [{str(key): str(value) for key, value in row.asdict().items()} for row in self.dataset.query(sparql)]


def _injection(node: _RdflibNode, graph: str, name: str) -> str:
    subject = f"urn:defender:threat:{name}"
    node.add(graph, subject, "a", URIRef(f"{DEFENDER}InjectionSignal"))
    node.add(graph, subject, f"{DP}pattern", f"ignore {name}")
    return subject


def _listing(*graphs: str) -> fetching.PartitionListing:
    return fetching.PartitionListing(graphs=frozenset(graphs), confirmed=tuple(sorted(graphs)))


def _injection_subjects(rows) -> list[str]:
    return sorted({row["threat"] for row in rows if row.get("rdfType", "").endswith("InjectionSignal")})


def test_a_page_spans_every_asset_so_no_subject_is_skipped(monkeypatch):
    monkeypatch.setattr(fetching, "_PAGE_SIZE", 2)
    node = _RdflibNode()
    wanted = [_injection(node, ASSET_A, name) for name in ("a1", "a2", "a3")]
    wanted += [_injection(node, ASSET_B, name) for name in ("z1", "z2")]
    rows = fetching._verified_small_tier_rows(node, CG, VM, _listing(ASSET_A, ASSET_B))
    assert rows is not None
    assert _injection_subjects(rows) == sorted(wanted)            # a3 used to be lost
    assert {row["g"] for row in rows} == {ASSET_A, ASSET_B}


def test_a_subject_in_two_assets_comes_back_from_both(monkeypatch):
    monkeypatch.setattr(fetching, "_PAGE_SIZE", 1)
    node = _RdflibNode()
    shared = _injection(node, ASSET_A, "m1")
    _injection(node, ASSET_B, "m1")
    _injection(node, ASSET_B, "m2")
    rows = fetching._verified_small_tier_rows(node, CG, VM, _listing(ASSET_A, ASSET_B))
    assert {(row["threat"], row["g"]) for row in rows if row["threat"] == shared} == {(shared, ASSET_A), (shared, ASSET_B)}


def test_a_lane_cut_at_the_row_ceiling_could_not_tell(monkeypatch):
    monkeypatch.setattr(fetching, "_PAGE_SIZE", 1)
    monkeypatch.setattr(sparql_text, "MAX_ROWS", 2)
    node = _RdflibNode()
    for name in ("a1", "a2", "a3"):
        _injection(node, ASSET_A, name)
    assert fetching._verified_small_tier_rows(node, CG, VM, _listing(ASSET_A)) is None


def test_every_row_of_a_multi_valued_correction_is_kept():
    correction = "urn:defender:correction:1"
    rows = [{"threat": correction, "targetSubject": "urn:x:one", "g": ASSET_A},
            {"threat": correction, "targetSubject": "urn:x:two", "g": ASSET_A}]
    root_copy = [{"threat": correction, "targetSubject": "urn:x:three"}]
    kept = fetching._dedupe_threat_rows(rows, root_copy)
    assert [row["targetSubject"] for row in kept] == ["urn:x:one", "urn:x:two"]   # the root copy is the one dropped


def test_a_correction_with_two_targets_suppresses_both(monkeypatch):
    from plugins.blackbox.ruleset import compiler
    monkeypatch.setattr(fetching, "_PAGE_SIZE", 5)
    node = _RdflibNode()
    correction = "urn:defender:correction:1"
    node.add(ASSET_A, correction, "a", URIRef(constants.DEFENDER_CORRECTION_TYPE_IRI))
    node.add(ASSET_A, correction, f"{DP}action", constants.DEFENDER_CORRECTION_SUPPRESS)
    node.add(ASSET_A, correction, f"{DP}targetSubject", "urn:defender:threat:one")
    node.add(ASSET_A, correction, f"{DP}targetSubject", "urn:defender:threat:two")
    rows = fetching._dedupe_threat_rows(fetching._verified_small_tier_rows(node, CG, VM, _listing(ASSET_A)), [])
    built = compiler.build_from_rows([(row, "public") for row in rows])
    assert built.suppressed_subjects == {"urn:defender:threat:one", "urn:defender:threat:two"}
