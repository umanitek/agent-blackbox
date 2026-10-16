"""Live verified lookups (DKG-lookup B2/B3): the scope decides what counts, the
store's triples go through the compiler's own builders, and a store that could
not answer is never read as "clean"."""

from __future__ import annotations

import json
import re
from typing import Dict, List, Optional

import pytest

from plugins.blackbox.kernel.store import StoreAnswer, StoreClient
from plugins.blackbox.ruleset import compiler, disk_cache, live
from plugins.blackbox.ruleset.live import lookup as live_lookup

TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
DP = "urn:defender:p:"
BP = "urn:blackbox:p:"
SCHEMA = "http://schema.org/"
CG = "0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox-vm"
VM = f"did:dkg:context-graph:{CG}/_verifiable_memory/0x37b1fdfd134e2b17583bcbdd3034f91504cd9c70/"
PART_A, PART_B = f"{VM}212", f"{VM}17"
FOREIGN = "did:dkg:context-graph:0xD96E82064ce8A7fA25ba0d9Ca8319fF87A2272fd/community-curation-1003"


def _dep(subject, pkg, ver, eco="npm", severity="critical", kind="malware"):
    return [
        (subject, TYPE, "urn:defender:DependencySignal"),
        (subject, f"{DP}package", f'"{pkg}"'), (subject, f"{DP}ecosystem", f'"{eco}"'),
        (subject, f"{DP}version", f'"{ver}"'), (subject, f"{DP}severity", f'"{severity}"'),
        (subject, f"{DP}kind", f'"{kind}"'), (subject, f"{SCHEMA}name", f'"{pkg}@{ver}"'),
    ]


def _ioc(subject, value, ioc_type="domain", severity="high"):
    return [
        (subject, TYPE, "urn:defender:IocSignal"), (subject, f"{DP}value", f'"{value}"'),
        (subject, f"{DP}iocType", f'"{ioc_type}"'), (subject, f"{DP}severity", f'"{severity}"'),
    ]


def _observation(subject, value, canonical_type="ip", lifecycle="active"):
    return [
        (subject, TYPE, "urn:blackbox:SourceObservation"), (subject, f"{BP}normalizedValue", f'"{value}"'),
        (subject, f"{BP}canonicalType", f'"{canonical_type}"'), (subject, f"{BP}lifecycleStatus", f'"{lifecycle}"'),
        (subject, f"{BP}provenanceJson", json.dumps(json.dumps({"severity": "medium"}))),
    ]


class FakeStore(StoreClient):
    """A store holding named-graph triples; answers the lookup's VALUES queries
    by matching literals, so the SPARQL shape itself is exercised a little."""

    def __init__(self, graphs: dict[str, list[tuple]], *, fail: Optional[str] = None) -> None:
        super().__init__("http://127.0.0.1:7878/query")
        self.graphs = graphs
        self.fail = fail
        self.queries: list[str] = []

    def select(self, sparql: str, *, timeout=None) -> StoreAnswer:
        self.queries.append(sparql)
        if self.fail:
            return StoreAnswer(None, self.fail)
        wanted = set(re.findall(r'"((?:[^"\\]|\\.)*)"', sparql.split("GRAPH", 1)[0]))
        rows = []
        for graph, triples in self.graphs.items():
            subjects = {s for s, p, o in triples
                        if p in (f"{DP}package", f"{DP}value", f"{BP}normalizedValue") and o.strip('"') in wanted}
            for s, p, o in triples:
                if s in subjects:
                    rows.append({"g": graph, "t": s, "p": p, "o": o})
        return StoreAnswer(rows)


GRAPHS = {
    PART_A: _dep("urn:defender:signal:a1", "wallet-security-checker", "2.0.3")
            + _dep("urn:defender:signal:a2", "AVNjs", "*", severity="high")
            + _ioc("urn:defender:signal:a3", "loader.example"),
    PART_B: _observation("urn:defender:signal:b1", "203.0.113.9")
            + _dep("urn:defender:signal:b2", "suppressed-pkg", "1.0.0")
            + _dep("urn:defender:signal:b3", "revoked-pkg", "*"),
    FOREIGN: _dep("urn:guardian:threat:x", "react", "18.3.1") + _ioc("urn:guardian:threat:y", "google.com"),
    f"{VM}999-tentative": _dep("urn:defender:signal:t1", "lodash", "4.17.21"),
}

SCOPE = live.VerifiedScope(
    context_graph_id=CG, store_url="http://127.0.0.1:7878/query",
    assertion_graphs=frozenset({PART_A, PART_B}),
    suppressed_subjects=frozenset({"urn:defender:signal:b2"}),
    revoked_identifiers=frozenset({"dep:npm:revoked-pkg@*"}),
    package_aliases={"npm:avnjs": ("AVNjs",)},
    built_at=1.0,
)


@pytest.fixture
def store():
    return FakeStore(GRAPHS)


def test_a_dependency_hit_is_the_rule_the_compiler_would_have_built(store):
    answer = live.VerifiedLookup(SCOPE, store).dependencies([("npm", "wallet-security-checker", "2.0.3")])
    rule = answer.rules["npm:wallet-security-checker@2.0.3"]
    assert answer.outcome == live.HIT and answer.known
    assert (rule["identifier"], rule["severity"], rule["kind"], rule["source"]) == (
        "dep:npm:wallet-security-checker@2.0.3", "critical", "malware", "public")
    # byte-identical to a compile of the same triples
    from plugins.blackbox.ruleset.partitions import rows_from_triples
    compiled = compiler.build_from_rows(rows_from_triples(PART_A, GRAPHS[PART_A]))
    assert compiled.dependency["npm:wallet-security-checker@2.0.3"] == rule


def test_a_mixed_case_stored_name_is_found_through_its_alias(store):
    answer = live.VerifiedLookup(SCOPE, store).dependencies([("npm", "avnjs", "*")])
    assert "npm:avnjs@*" in answer.rules
    assert '"AVNjs"' in store.queries[0] and '"avnjs"' in store.queries[0]


def test_the_untrusted_name_enters_the_query_only_as_an_escaped_literal(store):
    hostile = 'x" } } UNION { ?t ?p ?o } #'
    live.VerifiedLookup(SCOPE, store).dependencies([("npm", hostile, "1.0")])
    query = store.queries[0]
    assert '"x\\" } } union { ?t ?p ?o } #"' in query.lower()
    assert query.count("GRAPH") == 1


def test_rows_from_a_graph_outside_the_scope_never_become_public_rules(store):
    lookup = live.VerifiedLookup(SCOPE, store)
    assert lookup.dependencies([("npm", "react", "18.3.1")]).outcome == live.CLEAN
    assert lookup.dependencies([("npm", "lodash", "4.17.21")]).outcome == live.CLEAN   # tentative asset
    assert lookup.iocs(["ioc:domain:google.com"]).rules == {}


def test_suppressed_subjects_and_revoked_identifiers_are_withdrawn(store):
    lookup = live.VerifiedLookup(SCOPE, store)
    assert lookup.dependencies([("npm", "suppressed-pkg", "1.0.0")]).rules == {}
    assert lookup.dependencies([("npm", "revoked-pkg", "*")]).rules == {}


def test_ioc_hits_cover_signals_and_active_observations(store):
    answer = live.VerifiedLookup(SCOPE, store).iocs(
        ["ioc:domain:loader.example", "ioc:ip:203.0.113.9", "ioc:domain:clean.example"])
    assert set(answer.rules) == {"ioc:domain:loader.example", "ioc:ip:203.0.113.9"}
    assert answer.rules["ioc:ip:203.0.113.9"]["severity"] == "medium"   # from the observation's provenance


# KI-387: an EVM address stored checksummed must still match the lower-case id detection uses.
# The vector is EIP-55's own (eips.ethereum.org/EIPS/eip-55).
CHECKSUMMED = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"


@pytest.mark.parametrize("stored", [CHECKSUMMED, CHECKSUMMED.lower()])
def test_a_wallet_is_found_whichever_spelling_the_store_holds(stored):
    store = FakeStore({PART_A: _ioc("urn:defender:signal:w1", stored, ioc_type="wallet")})
    wanted = f"ioc:wallet:{CHECKSUMMED.lower()}"
    answer = live.VerifiedLookup(SCOPE, store).iocs([wanted])
    assert set(answer.rules) == {wanted} and answer.rules[wanted]["identifier"] == wanted
    assert f'"{CHECKSUMMED}"' in store.queries[0] and f'"{CHECKSUMMED.lower()}"' in store.queries[0]
    assert "LCASE" not in store.queries[0].upper()   # exact VALUES, never a scan of the shared store (LES-040)


def test_a_mixed_case_wallet_row_compiles_to_the_lower_case_id():
    from plugins.blackbox.ruleset.partitions import rows_from_triples
    compiled = compiler.build_from_rows(rows_from_triples(PART_A, _ioc("urn:defender:signal:w1", CHECKSUMMED, ioc_type="wallet")))
    assert set(compiled.ioc) == {f"ioc:wallet:{CHECKSUMMED.lower()}"}


def test_only_the_first_evm_addresses_get_a_second_spelling(store):
    identifiers = [f"ioc:wallet:0x{i:040x}" for i in range(live_lookup.CHECKSUM_SPELLINGS + 10)]
    assert len(live_lookup._stored_spellings(identifiers)) <= len(identifiers) + live_lookup.CHECKSUM_SPELLINGS
    assert live_lookup._stored_spellings(["ioc:domain:a.example", "ioc:wallet:0x" + "1" * 40]) == ["a.example", "0x" + "1" * 40]


def test_a_store_failure_is_could_not_tell_not_clean():
    answer = live.VerifiedLookup(SCOPE, FakeStore(GRAPHS, fail="timeout")).dependencies([("npm", "react", "1.0")])
    assert answer.outcome == live.COULD_NOT_TELL and not answer.known and answer.reason == "timeout"


def test_a_scope_that_is_not_ready_is_could_not_tell(store):
    answer = live.VerifiedLookup(live.VerifiedScope(), store).iocs(["ioc:domain:loader.example"])
    assert answer.outcome == live.COULD_NOT_TELL and store.queries == []


def test_no_candidates_is_clean_without_asking_the_store(store):
    assert live.VerifiedLookup(SCOPE, store).dependencies([]).outcome == live.CLEAN and store.queries == []


def test_values_are_chunked_and_capped(store):
    identifiers = [f"ioc:domain:h{i}.example" for i in range(live_lookup.MAX_VALUES + 50)]
    live.VerifiedLookup(SCOPE, store).iocs(identifiers)
    assert len(store.queries) == live_lookup.MAX_VALUES // live_lookup.CHUNK
    assert all(query.count("LIMIT") == 1 for query in store.queries)


# ------------------------------------------------------------------ the scope


def test_the_scope_survives_the_ruleset_cache_round_trip():
    rs = compiler.Ruleset(context_graph_id=CG, verified_scope=SCOPE, curator_revoked=frozenset({"dep:npm:revoked-pkg@*"}))
    back = disk_cache._deserialize(json.loads(json.dumps(disk_cache._serialize(rs))))
    assert back.verified_scope == SCOPE and back.curator_revoked == rs.curator_revoked
    assert back.live_lookup() is not None


def test_a_generation_without_a_scope_has_no_live_lookup():
    rs = compiler.Ruleset(context_graph_id=CG)
    assert rs.live_lookup() is None
    rs.verified_scope = live.VerifiedScope(store_url="http://127.0.0.1:7878/query")   # no assets yet
    assert rs.live_lookup() is None


class _Node:
    def __init__(self, status):
        self._status = status

    def status(self, timeout=None):
        if isinstance(self._status, Exception):
            raise self._status
        return self._status


def test_refresh_scope_keeps_previous_parts_it_could_not_read():
    from plugins.blackbox.kernel.dkg_client import DkgError
    failing = FakeStore({}, fail="timeout")
    scope = live.refresh_scope(_Node(DkgError("down")), CG, previous=SCOPE, confirmed=None, suppressed=None,
                               revoked=set(), store=failing)
    assert scope.store_url == SCOPE.store_url and scope.assertion_graphs == SCOPE.assertion_graphs
    assert scope.suppressed_subjects == SCOPE.suppressed_subjects
    assert scope.package_aliases == SCOPE.package_aliases
    assert scope.revoked_identifiers == frozenset()   # a reduction always applies


def test_refresh_scope_refuses_a_store_that_is_not_on_this_machine():
    scope = live.refresh_scope(_Node({"storeUrl": "http://10.116.0.6:7878/query"}), CG, previous=None,
                               confirmed=[PART_A], suppressed=set(), revoked=set(), store=FakeStore({}))
    assert scope.store_url == "" and not scope.ready


# ------------------------------------------------------- the refresh cycle builds it


def test_scope_for_generation_uses_the_nodes_partition_listing(monkeypatch):
    from plugins.blackbox.ruleset import fetching
    from plugins.blackbox.ruleset.live import scope as scope_mod
    monkeypatch.setattr(scope_mod.fetching, "confirmed_partitions",
                        lambda client, cg: fetching.PartitionListing(frozenset({PART_A, PART_B}), (PART_A, PART_B)))
    monkeypatch.setattr(scope_mod, "read_new_asset_facts", lambda store, wanted, known: {})
    scope = live.scope_for_generation(_Node({"storeUrl": "http://127.0.0.1:7878/query"}), CG,
                                      previous=None, suppressed=set(), revoked=set())
    assert scope is not None and scope.ready and scope.assertion_graphs == {PART_A, PART_B}


def test_scope_for_generation_keeps_the_previous_scope_when_the_listing_fails(monkeypatch):
    from plugins.blackbox.ruleset.live import scope as scope_mod
    monkeypatch.setattr(scope_mod.fetching, "confirmed_partitions", lambda client, cg: None)
    monkeypatch.setattr(scope_mod, "read_new_asset_facts", lambda store, wanted, known: dict(known))
    scope = live.scope_for_generation(_Node({"storeUrl": "http://127.0.0.1:7878/query"}), CG,
                                      previous=SCOPE, suppressed=None, revoked=SCOPE.revoked_identifiers)
    assert scope is not None and scope.assertion_graphs == SCOPE.assertion_graphs


def test_a_refresh_writes_a_ready_scope_into_the_cache_on_both_paths(monkeypatch, tmp_path):
    """A fresh compile and a kept last-good generation both carry the scope."""
    from plugins.blackbox.kernel import constants
    from plugins.blackbox.kernel.config import BlackboxConfig
    from plugins.blackbox.ruleset import fetching, refresh_cycle
    from plugins.blackbox.ruleset.live import scope as scope_mod
    monkeypatch.setattr(constants, "blackbox_home", lambda: tmp_path)
    monkeypatch.setattr(refresh_cycle, "_memory", refresh_cycle._new_memory())
    monkeypatch.setattr(scope_mod, "read_new_asset_facts", lambda store, wanted, known: {})
    listing = [fetching.PartitionListing(frozenset({PART_A}), (PART_A,))]
    monkeypatch.setattr(scope_mod.fetching, "confirmed_partitions", lambda client, cg: listing[0])
    from plugins.blackbox.ruleset.partitions import rows_from_triples
    public_rows = [rows_from_triples(PART_A, _dep("urn:defender:signal:a1", "evil-pkg", "1.0.0"))]
    monkeypatch.setattr(refresh_cycle.fetching, "fetch_tier", lambda client, cg, view, **kw: public_rows[0])
    monkeypatch.setattr(refresh_cycle.curator_tier, "apply_curator_tier", lambda rs, client, cfg: 0)

    class Client:
        def status(self, timeout=None):
            return {"storeUrl": "http://127.0.0.1:7878/query"}

        def query(self, sparql, cg_id, view=None, on_error=None, **kwargs):
            return on_error   # the community's shared memory is read too (one graph); it fails open

    cfg = BlackboxConfig(context_graph_id=CG)
    rs = refresh_cycle.refresh(cfg, Client(), force_query=True)
    assert rs.verified_scope is not None and rs.verified_scope.assertion_graphs == {PART_A}
    assert disk_cache._read_cache().verified_scope == rs.verified_scope

    # the node now confirms a second asset but answers the read empty: last-good is kept, scope grows
    listing[0] = fetching.PartitionListing(frozenset({PART_A, PART_B}), (PART_A, PART_B))
    public_rows[0] = []
    kept = refresh_cycle.refresh(cfg, Client())
    assert "npm:evil-pkg@1.0.0" in kept.dependency
    assert kept.verified_scope.assertion_graphs == {PART_A, PART_B}


def test_scope_for_generation_reuses_the_listing_the_refresh_already_read(monkeypatch):
    from plugins.blackbox.ruleset import fetching
    from plugins.blackbox.ruleset.live import scope as scope_mod
    monkeypatch.setattr(scope_mod.fetching, "confirmed_partitions",
                        lambda client, cg: pytest.fail("the _meta listing must not be read twice per refresh"))
    monkeypatch.setattr(scope_mod, "read_new_asset_facts", lambda store, wanted, known: {})
    listing = fetching.PartitionListing(frozenset({PART_A}), (PART_A,))
    scope = live.scope_for_generation(_Node({"storeUrl": "http://127.0.0.1:7878/query"}), CG, previous=None,
                                      suppressed=set(), revoked=set(), listing=listing)
    assert scope is not None and scope.assertion_graphs == {PART_A}


# ------------------------------------------------------- verified counts travel in the scope (B6)


def test_ruleset_counts_add_the_live_tiers_to_the_compiled_rules():
    scope = live.VerifiedScope(store_url="http://127.0.0.1:7878/query", assertion_graphs=frozenset({PART_A}),
                               verified_counts={"dependency": 252_860, "ioc": 303_765})
    rs = compiler.Ruleset(
        verified_scope=scope,
        injection=[{"identifier": "injection:1", "source": "public", "pattern": None}],
        dependency={"npm:community-pkg@*": {"identifier": "dep:npm:community-pkg@*", "source": "community"}},
    )
    counts = rs.counts()
    assert (counts["dependency"], counts["ioc"], counts["injection"]) == (252_861, 303_765, 1)
    assert rs.source_count("public") == 1 + 252_860 + 303_765
    assert rs.source_count("community") == 1
    assert rs.graph_count("public") == 1 + 252_860 + 303_765
    back = disk_cache._deserialize(json.loads(json.dumps(disk_cache._serialize(rs))))
    assert back.verified_scope.verified_counts == scope.verified_counts
    assert compiler.Ruleset().counts()["dependency"] == 0 and compiler.Ruleset().live_counts() == {}


# ------------------------------------------------------- per-asset facts (read once per asset)


class FactStore(FakeStore):
    """Answers the per-asset fact queries from fixed rows keyed by query kind; counts the queries."""

    def __init__(self, rows):
        super().__init__({})
        self.rows = rows

    def select(self, sparql, *, timeout=None):
        self.queries.append(sparql)
        if "?pkg" in sparql:
            kind = "aliases"
        elif "?eco (COUNT" in sparql:
            kind = "ecosystem"
        else:
            kind = next(k for k in ("DependencySignal", "IocSignal", "SourceObservation") if k in sparql)
        bound = set(re.findall(r"<(did:dkg:[^>]+)>", sparql.split("GRAPH ?g")[0]))
        return StoreAnswer([row for row in self.rows.get(kind, []) if row["g"] in bound])


FACT_ROWS = {
    "DependencySignal": [{"g": PART_A, "n": '"3"'}, {"g": PART_B, "n": '"2"'}, {"g": FOREIGN, "n": '"99"'}],
    "IocSignal": [{"g": PART_A, "n": '"5"'}],
    "SourceObservation": [{"g": PART_B, "n": '"4"^^<http://www.w3.org/2001/XMLSchema#integer>'}],
    "ecosystem": [{"g": PART_A, "eco": '"npm"', "n": '"3"'}, {"g": PART_B, "eco": '"pypi"', "n": '"2"'}],
    "aliases": [{"g": PART_A, "eco": '"npm"', "pkg": '"AVNjs"'}, {"g": PART_B, "eco": '"pypi"', "pkg": '"Foo_Bar"'},
                {"g": FOREIGN, "eco": '"npm"', "pkg": '"Outside"'}],
}


def test_refresh_scope_reads_each_assets_facts_bound_to_its_graph(monkeypatch):
    from plugins.blackbox.ruleset.live import asset_facts
    monkeypatch.setattr(asset_facts, "PAUSE_SECONDS", 0)
    store = FactStore(FACT_ROWS)
    scope = live.refresh_scope(_Node({"storeUrl": "http://127.0.0.1:7878/query"}), CG, previous=None,
                               confirmed=[PART_A, PART_B], suppressed={"urn:defender:signal:b2"},
                               revoked={"dep:npm:revoked-pkg@*"}, store=store)
    assert scope.ready and scope.verified_counts == {"dependency": 5, "ioc": 9, "dependency:npm": 3, "dependency:pypi": 2}
    assert scope.package_aliases == {"npm:avnjs": ("AVNjs",), "pypi:foo-bar": ("Foo_Bar",)}
    assert scope.spellings("npm", "AVNJS") == ("avnjs", "AVNjs")
    assert all("VALUES ?g" in q for q in store.queries) and len(store.queries) == 5
    assert set(scope.asset_facts) == {PART_A, PART_B}


def test_known_assets_are_never_read_again_and_new_ones_are(monkeypatch):
    from plugins.blackbox.ruleset.live import asset_facts
    monkeypatch.setattr(asset_facts, "PAUSE_SECONDS", 0)
    node = _Node({"storeUrl": "http://127.0.0.1:7878/query"})
    first = live.refresh_scope(node, CG, previous=None, confirmed=[PART_A], suppressed=set(), revoked=set(),
                               store=FactStore(FACT_ROWS))
    quiet = FactStore(FACT_ROWS)
    again = live.refresh_scope(node, CG, previous=first, confirmed=[PART_A], suppressed=set(), revoked=set(), store=quiet)
    assert quiet.queries == [] and again.verified_counts == first.verified_counts
    grown = FactStore(FACT_ROWS)
    both = live.refresh_scope(node, CG, previous=again, confirmed=[PART_A, PART_B], suppressed=set(), revoked=set(), store=grown)
    assert grown.queries and all(PART_A not in q for q in grown.queries)          # only the new asset is read
    assert both.verified_counts["dependency"] == 5


def test_a_failed_read_keeps_known_facts_and_retries_the_rest_later(monkeypatch):
    from plugins.blackbox.ruleset.live import asset_facts
    monkeypatch.setattr(asset_facts, "PAUSE_SECONDS", 0)
    node = _Node({"storeUrl": "http://127.0.0.1:7878/query"})
    first = live.refresh_scope(node, CG, previous=None, confirmed=[PART_A], suppressed=set(), revoked=set(),
                               store=FactStore(FACT_ROWS))
    failing = FakeStore({}, fail="timeout")
    later = live.refresh_scope(node, CG, previous=first, confirmed=[PART_A, PART_B], suppressed=set(), revoked=set(),
                               store=failing)
    assert set(later.asset_facts) == {PART_A} and later.verified_counts == first.verified_counts
    assert live.VerifiedScope.from_json(json.loads(json.dumps(later.to_json()))).asset_facts == later.asset_facts


def test_an_asset_no_longer_confirmed_drops_out_of_the_totals(monkeypatch):
    from plugins.blackbox.ruleset.live import asset_facts
    monkeypatch.setattr(asset_facts, "PAUSE_SECONDS", 0)
    node = _Node({"storeUrl": "http://127.0.0.1:7878/query"})
    both = live.refresh_scope(node, CG, previous=None, confirmed=[PART_A, PART_B], suppressed=set(), revoked=set(),
                              store=FactStore(FACT_ROWS))
    one = live.refresh_scope(node, CG, previous=both, confirmed=[PART_A], suppressed=set(), revoked=set(),
                             store=FactStore(FACT_ROWS))
    assert one.verified_counts["dependency"] == 3 and set(one.asset_facts) == {PART_A}
