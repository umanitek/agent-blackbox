"""Network Shield's verified lists: every malicious domain and IP of the verified graph, read with
the live lookup's scope (plugins/blackbox/ruleset/live/network_lists.py).

The contract: only confirmed in-scope assets count; curator corrections and revocations take a row
out; both indicator kinds count (IocSignal, active SourceObservation); each asset is read once and
kept; a store failure stops the read (the rest wait) and a partial list says so; a page never
waits for a build.
"""

from __future__ import annotations

import threading
from types import SimpleNamespace

from plugins.blackbox.ruleset.live import network_lists as nl
from plugins.blackbox.ruleset.live.scope import VerifiedScope

CG = "0x37b1fdfd134e2b17583bcbdd3034f91504cd9c70/agent-blackbox-vm"
VM = f"did:dkg:context-graph:{CG}/_verifiable_memory/"
A1, A2, A3 = VM + "asset-1", VM + "asset-2", VM + "asset-3"


def _scope(graphs=(A1, A2), **overrides):
    values = dict(context_graph_id=CG, store_url="http://127.0.0.1:7879", assertion_graphs=frozenset(graphs))
    values.update(overrides)
    return VerifiedScope(**values)


def _row(graph, subject, ioc_type, value):
    return {"g": {"value": graph}, "t": {"value": subject}, "type": {"value": ioc_type}, "value": {"value": value}}


class _Store:
    """Answers each per-asset query with that asset's rows; after *fail_after* queries, fails."""

    def __init__(self, rows, fail_after=None):
        self.rows, self.fail_after, self.queries = rows, fail_after, []

    def select(self, sparql, timeout=None):
        self.queries.append(sparql)
        if self.fail_after is not None and len(self.queries) > self.fail_after:
            return SimpleNamespace(known=False, rows=None, reason="down")
        assert "IocSignal" in sparql and "SourceObservation" in sparql and '"active"' in sparql
        found = [r for r, _kind in self.rows if f"GRAPH <{r['g']['value']}>" in sparql]
        return SimpleNamespace(known=True, rows=found, reason="")


ROWS = [
    (_row(A1, "urn:t:1", "domain", "Evil.Example."), "IocSignal"),
    (_row(A1, "urn:t:2", "ip", "45.130.148.102"), "IocSignal"),
    (_row(A2, "urn:t:3", "domain", "phish.example.net"), "SourceObservation"),
    (_row(A2, "urn:t:4", "domain", "corrected.example"), "IocSignal"),
    (_row(A2, "urn:t:5", "ip", "203.0.113.9"), "IocSignal"),
    (_row(A3, "urn:t:6", "domain", "tentative.example"), "IocSignal"),
]


def test_scope_corrections_and_revocations_apply_and_both_kinds_count():
    assets = nl.read_assets(_Store(ROWS), [A1, A2, A3], {})
    scope = _scope(suppressed_subjects=frozenset({"urn:t:4"}), revoked_identifiers=frozenset({"ioc:ip:203.0.113.9"}))
    found = nl.indicators_from(assets, scope)
    assert found.domains == frozenset({"evil.example", "phish.example.net"})   # A3 is not in scope
    assert found.ips == frozenset({"45.130.148.102"})
    assert found.complete and found.read == 2


def test_assets_already_read_are_never_read_again():
    store = _Store(ROWS)
    known = nl.read_assets(store, [A1], {})
    asked = len(store.queries)
    again = nl.read_assets(store, [A1, A2], known)
    assert set(again) == {A1, A2} and all(f"<{A1}>" not in q for q in store.queries[asked:])


def test_a_store_failure_stops_the_read_and_the_list_says_it_is_partial():
    assets = nl.read_assets(_Store(ROWS, fail_after=1), [A1, A2], {})
    assert set(assets) == {A1}
    found = nl.indicators_from(assets, _scope())
    assert found.complete is False and found.read == 1 and "evil.example" in found.domains


def test_a_page_never_waits_and_the_plan_gets_the_built_list():
    nl.forget()
    gate = threading.Event()

    class _Slow(_Store):
        def select(self, sparql, timeout=None):
            gate.wait(5)
            return super().select(sparql, timeout)

    assert nl.network_indicators(_scope(), store_factory=lambda _url: _Slow(ROWS), wait=False) is None
    gate.set()
    found = nl.network_indicators(_scope(), store_factory=lambda _url: _Store(ROWS), wait=True)
    assert found is not None and "evil.example" in found.domains
    assert nl.network_indicators(_scope(), wait=False) is found   # complete for this scope: cached
    nl.forget()


def test_assets_the_facts_count_no_indicators_in_are_not_read():
    nl.forget()
    store = _Store(ROWS)
    facts = {A1: SimpleNamespace(counts={"ioc": 2}), A2: SimpleNamespace(counts={"ioc": 0})}
    scope = _scope(asset_facts=facts)
    found = nl.network_indicators(scope, store_factory=lambda _url: store, wait=True)
    assert found.complete and all(f"<{A2}>" not in q for q in store.queries)
    nl.forget()


def test_no_scope_is_none():
    assert nl.network_indicators(None) is None
    assert nl.network_indicators(_scope(graphs=())) is None


def test_graph_reachable_asks_the_store_once_per_window_and_says_down_when_it_does_not_answer():
    """E2E recheck 2026-11-21: "can the graph be read now?" is separate from the lists kept in memory."""
    asked = []

    class Store:
        def __init__(self, url, answers):
            self.answers = answers

        def select(self, sparql):
            asked.append(sparql)
            return SimpleNamespace(known=self.answers)

    nl._reachable.update(url=None, at=0.0, value=None)
    scope = _scope()
    assert nl.graph_reachable(scope, store_factory=lambda url: Store(url, False), now=100.0) is False
    assert nl.graph_reachable(scope, store_factory=lambda url: Store(url, True), now=105.0) is False, "cached"
    assert nl.graph_reachable(scope, store_factory=lambda url: Store(url, True), now=111.0) is True
    assert len(asked) == 2 and "?s ?p ?o" not in asked[0]
    assert nl.graph_reachable(None) is None



def test_the_per_asset_cache_keeps_a_row_in_a_few_bytes_beside_the_lists_own_names():
    """KI-675 (Linux round L2): with the whole graph synced (1,158,241 domains, 28,216 IPs) the
    dashboard was 1.06 GB; the per-asset cache alone held ~240 MB as (subject, type, value) tuples.
    A row now costs its digest, its kind and one slot — its name is the very string the lists hold."""
    import gc
    import tracemalloc
    count = 20_000
    rows = [(_row(A1, f"urn:defender:signal:{index:024x}", "domain", f"host-{index}.example-{index % 7}.xyz"), "IocSignal")
            for index in range(count)]
    gc.collect()
    tracemalloc.start()
    assets = nl.read_assets(_Store(rows), [A1], {})
    found = nl.indicators_from(assets, _scope(graphs=(A1,)))
    gc.collect()
    with_cache, _ = tracemalloc.get_traced_memory()
    del assets
    gc.collect()
    lists_only, _ = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert len(found.domains) == count
    per_row = (with_cache - lists_only) / count
    assert per_row < 40, f"the cache costs {per_row:.0f} bytes a row (the old tuples cost ~200)"


def test_a_correction_still_finds_its_subject_through_the_compact_cache():
    assets = nl.read_assets(_Store(ROWS), [A1, A2], {})
    corrected = nl.indicators_from(assets, _scope(suppressed_subjects=frozenset({"urn:t:1", "urn:t:5"})))
    assert "evil.example" not in corrected.domains and "203.0.113.9" not in corrected.ips
    assert "phish.example.net" in corrected.domains and "45.130.148.102" in corrected.ips
