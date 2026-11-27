"""The opt-in fallback index holds whole assets and answers with today's scope (review 2026-11-26, finding 6).

(a) an answer re-checks the scope's suppressed subjects — a correction that
    arrived after the asset was indexed withdraws its threat from the index too;
(b) an asset counts as indexed only when every triple it holds was read: a
    daemon that caps its reply at 1,000 rows (KI-052) used to leave a short
    first page that passed for the whole asset;
(c) a rule key held by two assets is kept once per asset: the second asset no
    longer overwrites the first, so the rule survives the first leaving scope.
"""

from __future__ import annotations

import re

from plugins.blackbox.ruleset import live

TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
DP = "urn:defender:p:"
CG = "0x" + "a" * 40 + "/vm"
VM = f"did:dkg:context-graph:{CG}/_verifiable_memory/"
ASSET_A, ASSET_B = f"{VM}1", f"{VM}2"
DAEMON_CAP = 1000


def _dependency(subject: str, package: str, severity: str = "critical") -> list[tuple[str, str, str]]:
    return [(subject, TYPE, "urn:defender:DependencySignal"), (subject, f"{DP}package", f'"{package}"'),
            (subject, f"{DP}ecosystem", '"npm"'), (subject, f"{DP}version", '"1.0.0"'),
            (subject, f"{DP}severity", f'"{severity}"')]


class _CappingNode:
    """Serves each asset's triples by subject cursor, at most DAEMON_CAP rows a reply, and its triple COUNT."""

    def __init__(self, graphs) -> None:
        self.graphs = {graph: sorted(triples) for graph, triples in graphs.items()}

    def query(self, sparql, _cg, view=None, on_error=None, **_):
        triples = self.graphs.get(re.search(r"GRAPH <([^>]+)>", sparql).group(1), [])
        if "COUNT(" in sparql:
            return [{"n": str(len(triples))}]
        cursor = re.search(r'STR\(\?threat\) > "([^"]+)"', sparql)
        after = cursor.group(1) if cursor else ""
        return [{"threat": s, "p": p, "o": o} for s, p, o in triples if s > after][:DAEMON_CAP]


def _scope(graphs, **fields):
    return live.VerifiedScope(store_url="http://127.0.0.1:7878/query", assertion_graphs=frozenset(graphs),
                              fallback=live.FALLBACK_INDEX, **fields)


def test_an_asset_larger_than_one_capped_reply_is_read_whole(tmp_path):
    triples = [t for n in range(300) for t in _dependency(f"urn:defender:signal:{n:04d}", f"pkg-{n:04d}")]
    assert len(triples) > DAEMON_CAP
    index = live.FallbackIndex(_scope({ASSET_A}), tmp_path / "idx.sqlite")
    assert index.index_missing_assets(_CappingNode({ASSET_A: triples}), CG) == 1 and index.complete()
    assert index.dependencies([("npm", "pkg-0299", "1.0.0")]).outcome == live.HIT   # past the first 1,000 rows


def test_a_subject_suppressed_after_indexing_is_not_answered(tmp_path):
    path = tmp_path / "idx.sqlite"
    live.FallbackIndex(_scope({ASSET_A}), path).index_missing_assets(
        _CappingNode({ASSET_A: _dependency("urn:defender:signal:evil", "evil-pkg")}), CG)
    later = live.FallbackIndex(_scope({ASSET_A}, suppressed_subjects=frozenset({"urn:defender:signal:evil"})), path)
    assert later.dependencies([("npm", "evil-pkg", "1.0.0")]).rules == {}


def test_a_rule_in_two_assets_survives_the_first_leaving_scope(tmp_path):
    path = tmp_path / "idx.sqlite"
    node = _CappingNode({ASSET_A: _dependency("urn:defender:signal:a", "evil-pkg", "high"),
                         ASSET_B: _dependency("urn:defender:signal:b", "evil-pkg", "critical")})
    live.FallbackIndex(_scope({ASSET_A, ASSET_B}), path).index_missing_assets(node, CG)
    only_a = live.FallbackIndex(_scope({ASSET_A}), path).dependencies([("npm", "evil-pkg", "1.0.0")])
    assert only_a.rules["npm:evil-pkg@1.0.0"]["severity"] == "high"     # the second asset overwrote it before
