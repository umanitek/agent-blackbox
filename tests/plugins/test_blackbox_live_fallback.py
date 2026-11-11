"""The opt-in on-disk fallback (DKG-lookup B9): off by default, answers only after
the store could not, never "clean" from a partial index."""

from __future__ import annotations

import pytest

from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.kernel.store import StoreAnswer, StoreClient
from plugins.blackbox.ruleset import compiler, live
from plugins.blackbox.ruleset.live import fallback_index
from test_blackbox_live_lookup import CG, GRAPHS, PART_A, PART_B, SCOPE, FakeStore


class _Node:
    """A fake DKG node serving one asset's triples per GRAPH <…> read."""

    def __init__(self, graphs, *, refuse=frozenset()):
        self.graphs, self.refuse, self.reads = graphs, refuse, []

    def query(self, sparql, cg, view=None, on_error=None, **kw):
        import re
        graph = re.search(r"GRAPH <([^>]+)>", sparql).group(1)
        self.reads.append(graph)
        if graph in self.refuse:
            return on_error
        return [{"threat": s, "p": p, "o": o} for s, p, o in self.graphs.get(graph, [])]


INDEXED = live.VerifiedScope(**{**SCOPE.__dict__, "fallback": live.FALLBACK_INDEX})


class _Failing(StoreClient):
    def __init__(self):
        super().__init__("http://127.0.0.1:7878/query")

    def select(self, sparql, *, timeout=None):
        return StoreAnswer(None, "timeout")


def test_the_fallback_is_off_unless_the_operator_writes_index(monkeypatch):
    assert config_mod.BlackboxConfig().verified_lookup_fallback == "off"
    assert config_mod._fallback_mode("index") == "index"
    assert config_mod._fallback_mode("INDEX ") == "index"
    assert config_mod._fallback_mode("yes") == "off" and config_mod._fallback_mode(None) == "off"
    assert live.FallbackIndex.for_scope(SCOPE) is None
    assert compiler.Ruleset(verified_scope=SCOPE).live_lookup().fallback is None


def test_the_refresh_indexes_each_asset_in_scope_once(tmp_path):
    node = _Node(GRAPHS)
    index = live.FallbackIndex(INDEXED, tmp_path / "idx.sqlite")
    assert index.index_missing_assets(node, CG) == 2
    assert sorted(node.reads) == sorted([PART_A, PART_B])            # foreign / tentative graphs never read
    assert index.index_missing_assets(node, CG) == 0 and index.complete()
    hit = index.dependencies([("npm", "wallet-security-checker", "2.0.3")])
    assert hit.outcome == live.HIT and hit.rules["npm:wallet-security-checker@2.0.3"]["severity"] == "critical"
    assert index.dependencies([("npm", "suppressed-pkg", "1.0.0")]).rules == {}      # suppressed at build
    assert index.dependencies([("npm", "revoked-pkg", "*")]).rules == {}             # revoked at answer time
    assert index.ioc_values(["203.0.113.9"]).rules["ioc:ip:203.0.113.9"]["severity"] == "medium"
    assert index.dependencies([("npm", "react", "18.3.1")]).outcome == live.CLEAN    # complete index: absence is clean


def test_a_partial_index_answers_hits_but_never_clean(tmp_path):
    node = _Node(GRAPHS, refuse={PART_A})            # assets are indexed in sorted order; A sorts last
    index = live.FallbackIndex(INDEXED, tmp_path / "idx.sqlite")
    assert index.index_missing_assets(node, CG) == 1 and not index.complete()
    assert index.ioc_values(["203.0.113.9"]).outcome == live.HIT                        # from the indexed asset
    assert index.dependencies([("npm", "wallet-security-checker", "2.0.3")]).outcome == live.COULD_NOT_TELL
    assert index.dependencies([("npm", "react", "18.3.1")]).outcome == live.COULD_NOT_TELL


def test_the_budget_defers_assets_to_the_next_refresh(tmp_path):
    index = live.FallbackIndex(INDEXED, tmp_path / "idx.sqlite")
    assert index.index_missing_assets(_Node(GRAPHS), CG, budget_seconds=0) == 0


def test_the_lookup_falls_back_only_after_the_store_could_not_answer(tmp_path, monkeypatch):
    from plugins.blackbox.ruleset.live import lookup as live_lookup
    monkeypatch.setattr(live_lookup, "RETRY_AFTER_SECONDS", 0.0)   # this test is about fallback order, not the breaker
    index = live.FallbackIndex(INDEXED, tmp_path / "idx.sqlite")
    index.index_missing_assets(_Node(GRAPHS), CG)
    health = live.LookupHealth(tmp_path / "state.json")
    lookup = live.VerifiedLookup(INDEXED, _Failing(), health=health, fallback=index)
    answer = lookup.dependencies([("npm", "wallet-security-checker", "2.0.3")])
    assert answer.outcome == live.HIT and answer.reason == "fallback index"
    assert lookup.iocs(["ioc:ip:203.0.113.9"]).outcome == live.HIT
    assert lookup.dependencies([("npm", "react", "18.3.1")]).outcome == live.CLEAN
    assert health.read().degraded                                   # the store's failure is still the alarm
    healthy = live.VerifiedLookup(INDEXED, FakeStore(GRAPHS), health=health, fallback=index)
    assert healthy.dependencies([("npm", "react", "18.3.1")]).reason == ""   # the store answered: no fallback


def test_maintain_is_a_no_op_when_off_and_indexes_when_on(tmp_path, monkeypatch):
    monkeypatch.setattr(fallback_index, "index_path", lambda: tmp_path / "idx.sqlite")
    node = _Node(GRAPHS)
    assert live.maintain_fallback_index(SCOPE, node, CG) == 0 and node.reads == []
    assert live.maintain_fallback_index(INDEXED, node, CG) == 2
    assert (tmp_path / "idx.sqlite").exists()
    assert compiler.Ruleset(verified_scope=INDEXED).live_lookup().fallback is not None


def test_the_scope_carries_the_switch_through_the_cache():
    import json
    scope = live.VerifiedScope.from_json(json.loads(json.dumps(INDEXED.to_json())))
    assert scope.fallback == live.FALLBACK_INDEX and live.VerifiedScope.from_json({}).fallback == live.FALLBACK_OFF


@pytest.mark.parametrize("value", ["index", "off"])
def test_refresh_scope_records_the_mode(value):
    scope = live.refresh_scope(type("N", (), {"status": lambda self, timeout=None: {"storeUrl": "http://127.0.0.1:7878/query"}})(),
                               CG, previous=None, confirmed=[PART_A], suppressed=set(), revoked=set(),
                               store=FakeStore({}), fallback=value)
    assert scope.fallback == value


def test_sqlite_is_opened_only_when_the_store_could_not_tell_and_closed_after(tmp_path, monkeypatch):
    """A generation's lookup is built per tool call, and it opened the fallback index (connect +
    schema) every time — two connections per call, never closed, even while the store answered.
    The lookup now holds an on-demand proxy: SQLite opens only for a could-not-tell answer."""
    from plugins.blackbox.ruleset.live import lookup as live_lookup
    monkeypatch.setattr(live_lookup, "RETRY_AFTER_SECONDS", 0.0)
    monkeypatch.setattr(fallback_index, "index_path", lambda: tmp_path / "idx.sqlite")
    live.FallbackIndex(INDEXED).index_missing_assets(_Node(GRAPHS), CG)
    opened, closed = [], []
    real_init, real_close = live.FallbackIndex.__init__, live.FallbackIndex.close
    monkeypatch.setattr(live.FallbackIndex, "__init__", lambda self, *a, **k: opened.append(1) or real_init(self, *a, **k))
    monkeypatch.setattr(live.FallbackIndex, "close", lambda self: closed.append(1) or real_close(self))
    proxy = fallback_index.OnDemandIndex.for_scope(INDEXED)
    health = live.LookupHealth(tmp_path / "state.json")

    answering = live.VerifiedLookup(INDEXED, FakeStore(GRAPHS), health=health, fallback=proxy)
    answering.dependencies([("npm", "react", "18.3.1")])
    assert opened == []                                            # the store answered: no SQLite

    failing = live.VerifiedLookup(INDEXED, _Failing(), health=health, fallback=proxy)
    assert failing.dependencies([("npm", "wallet-security-checker", "2.0.3")]).outcome == live.HIT
    assert opened == [1] and closed == [1]
    assert fallback_index.OnDemandIndex.for_scope(SCOPE) is None   # fallback off (the default): nothing
    assert INDEXED.ready   # a generation's lookup holds the proxy, never an open index
    assert isinstance(compiler.Ruleset(verified_scope=INDEXED).live_lookup().fallback, fallback_index.OnDemandIndex)


def test_a_graph_name_that_cannot_be_an_iri_never_reaches_a_query():
    """Three readers wrote store-sourced graph names into queries as <{graph}> with no check;
    they now go through the kernel's sparql_iri and an unsafe name is left out."""
    from plugins.blackbox.ruleset.live import asset_facts

    hostile = "urn:x> } ; DROP { <urn:y"
    asked = []

    class Client:
        def query(self, sparql, *_a, **_k):
            asked.append(sparql)
            return []

    assert fallback_index._read_asset(Client(), CG, hostile) is None and asked == []
    assert asset_facts._values(["urn:graph:a", hostile]) == "<urn:graph:a>"
