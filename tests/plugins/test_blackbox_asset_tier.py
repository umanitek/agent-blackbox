"""Asset tiers and the shipped legacy asset list (trust-and-threat-lab R1, §03.4).

An asset in the legacy list — only once the list's hash equals the trusted
manifest's pin — is tiered BLOCK; an undecided tier (None) never caps a rule, so
an upgrade or a refused list never turns the known corpus flag-only (F-055); a
FLAG-tier asset's rules are capped at flag on the hot path (one dict lookup).
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

import pytest

from plugins.blackbox.kernel import health
from plugins.blackbox.kernel.store import StoreAnswer, StoreClient
from plugins.blackbox.ruleset import anchors, compiler, curator_tier
from plugins.blackbox.ruleset.live import asset_facts, lookup, scope as scope_mod
from plugins.blackbox.ruleset.live.asset_facts import AssetFacts, AssetTier

CG = "0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox-vm"
DATA = f"did:dkg:context-graph:{CG}"
VM = f"{DATA}/_verifiable_memory/0x37b1fdfd134e2b17583bcbdd3034f91504cd9c70/"
PART_A, PART_B = f"{VM}212", f"{VM}17"
UAL_A, UAL_B = "did:dkg:base:8453/0x37b1fdfd134e2b17583bcbdd3034f91504cd9c70/212", \
    "did:dkg:base:8453/0x37b1fdfd134e2b17583bcbdd3034f91504cd9c70/17"
UALS = {PART_A: UAL_A, PART_B: UAL_B}
TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
DP = "urn:defender:p:"


class _Node:
    def status(self, timeout=None):
        return {"storeUrl": "http://127.0.0.1:7878/query"}


class TierStore(StoreClient):
    """Answers the fact counts with nothing and the ``_meta`` UAL query from :data:`UALS`; records queries."""

    def __init__(self, fail_uals: bool = False) -> None:
        super().__init__("http://127.0.0.1:7878/query")
        self.queries = []
        self.fail_uals = fail_uals

    def ual_queries(self):
        return [query for query in self.queries if "kaUal" in query]

    def select(self, sparql, *, timeout=None):
        self.queries.append(sparql)
        if "kaUal" not in sparql:
            return StoreAnswer([])
        if self.fail_uals:
            return StoreAnswer(None, "timeout")
        pairs = re.findall(r"\(<([^>]+)> <([^>]+)>\)", sparql)
        assert pairs and all(meta == f"{DATA}/_meta" for _graph, meta in pairs)   # bound to each asset's _meta
        return StoreAnswer([{"g": graph, "ual": UALS[graph]} for graph, _meta in pairs if graph in UALS])


@pytest.fixture(autouse=True)
def _no_pause(monkeypatch):
    monkeypatch.setattr(asset_facts, "PAUSE_SECONDS", 0)


def _list_file(tmp_path: Path, uals) -> Path:
    path = tmp_path / "legacy_assets.txt"
    path.write_text("# header comment\n\n" + "".join(f"{ual}\n" for ual in uals), encoding="utf-8")
    return path


def _refresh(monkeypatch, path: Path, pin, *, previous=None, confirmed=(PART_A, PART_B), store=None):
    monkeypatch.setattr(anchors, "LEGACY_ASSETS_FILE", path)
    return scope_mod.refresh_scope(_Node(), CG, previous=previous, confirmed=list(confirmed), suppressed=set(),
                                   revoked=set(), store=store or TierStore(), legacy_assets_hash=pin)


# ------------------------------------------------------------------ the list file


def test_the_shipped_list_file_loads_empty_and_matches_the_empty_pin():
    assert anchors.LEGACY_ASSETS_FILE.name == "legacy_assets.txt" and anchors.LEGACY_ASSETS_FILE.parent.name == "ruleset"
    assert anchors.load_legacy_assets() == frozenset()                       # ships EMPTY until OPS3 fills it
    empty_pin = anchors.legacy_list_hash(())
    assert anchors.verified_legacy_assets(empty_pin) == anchors.LegacyAssets(uals=frozenset())


def test_the_list_hash_is_the_manifest_hash_and_ignores_order_comments_and_blanks(tmp_path):
    from plugins.blackbox.kernel.signing import key_manifest
    path = _list_file(tmp_path, [UAL_B, UAL_A, UAL_A])
    assert anchors.load_legacy_assets(path) == {UAL_A, UAL_B}
    assert anchors.legacy_list_hash([UAL_A, UAL_B]) == key_manifest.legacy_assets_hash([UAL_B, UAL_A])
    assert anchors.verified_legacy_assets(key_manifest.legacy_assets_hash([UAL_A, UAL_B]), path).uals == {UAL_A, UAL_B}


def test_no_trusted_manifest_means_the_list_is_not_used_and_nothing_is_wrong(tmp_path):
    assert anchors.verified_legacy_assets("", _list_file(tmp_path, [UAL_A])) == anchors.LegacyAssets()


def test_an_altered_or_missing_list_is_refused(tmp_path):
    pin = anchors.legacy_list_hash([UAL_A])
    altered = anchors.verified_legacy_assets(pin, _list_file(tmp_path, [UAL_A, UAL_B]))
    assert altered.uals is None and "does not match" in altered.refused
    missing = anchors.verified_legacy_assets(pin, tmp_path / "absent.txt")
    assert missing.uals is None and "could not be read" in missing.refused


# ------------------------------------------------------------------ the tier on the facts


def test_a_legacy_asset_is_tiered_block_and_an_unlisted_one_stays_undecided(monkeypatch, tmp_path):
    store = TierStore()
    scope = _refresh(monkeypatch, _list_file(tmp_path, [UAL_A]), anchors.legacy_list_hash([UAL_A]), store=store)
    assert scope.tier_of(PART_A) is AssetTier.BLOCK and scope.tier_of(PART_B) is None
    assert scope.asset_facts[PART_B].ual == UAL_B and scope.legacy_refused == ""
    assert len(store.ual_queries()) == 1                                     # both assets, one VALUES-bound query
    again = TierStore()
    _refresh(monkeypatch, _list_file(tmp_path, [UAL_A]), anchors.legacy_list_hash([UAL_A]), previous=scope, store=again)
    assert again.queries == []                                               # known UALs and facts are never re-read


def test_a_pre_upgrade_record_yields_no_tier_and_is_read_again(monkeypatch, tmp_path):
    record = {"counts": {"dependency": 3}, "aliases": {}}                     # written before tiers existed
    fact = AssetFacts.from_json(record)
    assert fact.tier is None and fact.ual == "" and fact.counts == {"dependency": 3}
    assert AssetFacts.from_json({**record, "tier": "bogus"}).tier is None   # an unknown tier is undecided, never FLAG
    previous = scope_mod.VerifiedScope.from_json({"store_url": "http://127.0.0.1:7878/query",
                                                  "assertion_graphs": [PART_A], "asset_facts": {PART_A: record}})
    assert previous.tier_of(PART_A) is None
    store = TierStore()
    scope = _refresh(monkeypatch, _list_file(tmp_path, [UAL_A]), anchors.legacy_list_hash([UAL_A]),
                     previous=previous, confirmed=[PART_A], store=store)
    assert store.ual_queries() and scope.tier_of(PART_A) is AssetTier.BLOCK  # re-read, then decided
    assert scope.asset_facts[PART_A].counts == {"dependency": 3}              # the facts themselves are not re-read
    assert not [query for query in store.queries if "COUNT" in query]


def test_tier_and_ual_survive_the_ruleset_cache_round_trip(monkeypatch, tmp_path):
    scope = _refresh(monkeypatch, _list_file(tmp_path, [UAL_A]), anchors.legacy_list_hash([UAL_A]))
    back = scope_mod.VerifiedScope.from_json(json.loads(json.dumps(scope.to_json())))
    assert back.asset_facts == scope.asset_facts and back.tier_of(PART_A) is AssetTier.BLOCK


def test_an_altered_list_keeps_the_last_good_tiers_and_raises_the_alarm(monkeypatch, tmp_path):
    good = _refresh(monkeypatch, _list_file(tmp_path, [UAL_A]), anchors.legacy_list_hash([UAL_A]), confirmed=[PART_A])
    assert good.tier_of(PART_A) is AssetTier.BLOCK
    store = TierStore()
    altered = _refresh(monkeypatch, _list_file(tmp_path, [UAL_A, UAL_B]), anchors.legacy_list_hash([UAL_A]),
                       previous=good, store=store)
    assert altered.tier_of(PART_A) is AssetTier.BLOCK                         # last-good kept
    assert altered.tier_of(PART_B) is None                                   # never flag-only: undecided
    assert store.ual_queries() == [] and "does not match" in altered.legacy_refused
    items = health.operator_health(health.HealthInputs(node_reachable=True, ruleset_age_s=1.0, sync_interval_s=60.0,
                                                       rule_count=5, legacy_list_refused=altered.legacy_refused))
    assert [item.klass for item in items if "legacy asset list" in item.message] == [health.HealthClass.SECURITY]
    rs = compiler.Ruleset(synced_at=time.time(), verified_scope=altered)
    gathered = health.gather(None, rs, True, None, {}, time.time())
    assert gathered.legacy_list_refused == altered.legacy_refused


def test_a_curator_read_that_could_not_tell_keeps_the_last_verdict(monkeypatch, tmp_path):
    refused = _refresh(monkeypatch, _list_file(tmp_path, [UAL_B]), anchors.legacy_list_hash([UAL_A]))
    assert refused.legacy_refused
    unknown = _refresh(monkeypatch, _list_file(tmp_path, [UAL_B]), None, previous=refused)
    assert unknown.legacy_refused == refused.legacy_refused                  # None = could not tell (LES-011)
    unpinned = _refresh(monkeypatch, _list_file(tmp_path, [UAL_B]), "", previous=refused)
    assert unpinned.legacy_refused == "" and unpinned.tier_of(PART_A) is None


def test_a_failed_ual_read_decides_nothing_and_is_retried(monkeypatch, tmp_path):
    pin = anchors.legacy_list_hash([UAL_A])
    failed = _refresh(monkeypatch, _list_file(tmp_path, [UAL_A]), pin, store=TierStore(fail_uals=True))
    assert failed.tier_of(PART_A) is None and failed.asset_facts[PART_A].ual == ""
    retried = _refresh(monkeypatch, _list_file(tmp_path, [UAL_A]), pin, previous=failed)
    assert retried.tier_of(PART_A) is AssetTier.BLOCK


def test_an_empty_verified_list_reads_no_uals(monkeypatch, tmp_path):
    store = TierStore()
    scope = _refresh(monkeypatch, _list_file(tmp_path, []), anchors.legacy_list_hash(()), store=store)
    assert store.ual_queries() == [] and scope.tier_of(PART_A) is None and scope.legacy_refused == ""


def test_the_curator_overlay_hands_the_manifest_pin_to_the_scope(monkeypatch):
    import plugins.blackbox.community.statements.curator_view as cv
    from plugins.blackbox.kernel.config import BlackboxConfig
    cfg = BlackboxConfig(context_graph_id=CG)
    for view, expected in ((cv.CuratorView(), ""), (cv.CuratorView(unavailable=True), None)):
        monkeypatch.setattr(curator_tier.community, "read_curator_view", lambda client, config, view=view: view)
        rs = compiler.Ruleset()
        curator_tier.apply_curator_tier(rs, object(), cfg)
        assert rs.curator_legacy_assets_hash == expected


# ------------------------------------------------------------------ the hot path


def _dep(subject, pkg, ver="1.0.0"):
    return [(subject, TYPE, "urn:defender:DependencySignal"), (subject, f"{DP}package", f'"{pkg}"'),
            (subject, f"{DP}ecosystem", '"npm"'), (subject, f"{DP}version", f'"{ver}"'),
            (subject, f"{DP}severity", '"critical"'), (subject, f"{DP}kind", '"malware"')]


def _rows(graph, triples):
    return [{"g": graph, "t": s, "p": p, "o": o} for s, p, o in triples]


def _scope(tiers):
    return scope_mod.VerifiedScope(store_url="http://127.0.0.1:7878/query", assertion_graphs=frozenset(tiers),
                                   asset_facts={graph: AssetFacts(tier=tier) for graph, tier in tiers.items()})


def test_a_flag_tier_assets_rules_are_capped_at_flag_and_the_others_unchanged():
    scope = _scope({PART_A: AssetTier.FLAG, PART_B: AssetTier.BLOCK, f"{VM}9": None})
    rows = _rows(PART_A, _dep("urn:s:a", "flagged-pkg")) + _rows(PART_B, _dep("urn:s:b", "blocked-pkg")) \
        + _rows(f"{VM}9", _dep("urn:s:c", "undecided-pkg"))
    rules = lookup.VerifiedLookup(scope, StoreClient("http://127.0.0.1:7878/query"))._rules_from(rows, "dependency")
    by_package = {key.split(":", 1)[1].split("@", 1)[0]: rule for key, rule in rules.items()}   # "npm:name@1.0.0"
    assert set(by_package) == {"flagged-pkg", "blocked-pkg", "undecided-pkg"}
    assert by_package["flagged-pkg"]["source"] == scope_mod.FLAG_ONLY_SOURCE
    assert by_package["flagged-pkg"]["asset_tier"] == "flag"
    assert by_package["blocked-pkg"]["source"] == "public" and by_package["undecided-pkg"]["source"] == "public"
    from plugins.blackbox.detection.finding import _rule_source
    assert _rule_source(by_package["flagged-pkg"]) != "public"               # a finding from it is never confirmed


def test_the_tier_read_adds_no_measurable_hot_path_cost(monkeypatch):
    """The tier read is one dict lookup: p95 of _rules_from with tiers vs with the cap
    switched off (the pre-R1 path) stays within noise."""
    graphs = {f"{VM}{index}": AssetTier.BLOCK for index in range(600)}
    scope = _scope(graphs)
    rows = [row for index, graph in enumerate(graphs) if index % 30 == 0
            for row in _rows(graph, _dep(f"urn:s:{index}", f"pkg-{index}"))]
    verified = lookup.VerifiedLookup(scope, StoreClient("http://127.0.0.1:7878/query"))

    def p95() -> float:
        samples = []
        for _ in range(200):
            start = time.perf_counter()
            verified._rules_from(rows, "dependency")
            samples.append(time.perf_counter() - start)
        return sorted(samples)[int(len(samples) * 0.95)]

    with_tiers = p95()
    monkeypatch.setattr(scope_mod.VerifiedScope, "as_tier_allows", lambda self, graph, category, key, rule: rule)
    without = p95()
    assert with_tiers <= without * 1.5 + 0.0005, (with_tiers, without)


# ------------------------------------------------------------------ review additions (verify R1)


def test_no_trusted_manifest_issues_no_ual_query_and_leaves_every_tier_undecided(monkeypatch, tmp_path):
    """Acceptance 4: pin "" (mainnet today) — even with a populated list file on disk,
    the refresh reads no UAL and decides no tier; enforcement is unchanged."""
    store = TierStore()
    scope = _refresh(monkeypatch, _list_file(tmp_path, [UAL_A, UAL_B]), "", store=store)
    assert store.ual_queries() == []
    assert scope.tier_of(PART_A) is None and scope.tier_of(PART_B) is None and scope.legacy_refused == ""
    assert all(fact.tier is None and fact.ual == "" for fact in scope.asset_facts.values())


def test_a_decided_tier_is_never_changed_and_never_re_read(monkeypatch):
    facts = {PART_A: AssetFacts(tier=AssetTier.FLAG), PART_B: AssetFacts(ual=UAL_B)}
    store = TierStore()
    tiered = asset_facts.tier_assets(store, facts, legacy=frozenset({UAL_A, UAL_B}))
    assert tiered[PART_A].tier is AssetTier.FLAG                             # decided: the list does not override it
    assert tiered[PART_B].tier is AssetTier.BLOCK                            # known UAL in the list: decided, no read
    assert store.ual_queries() == []


def test_an_exhausted_budget_reads_no_uals_and_decides_nothing(monkeypatch):
    store = TierStore()
    tiered = asset_facts.tier_assets(store, {PART_A: AssetFacts()}, legacy=frozenset({UAL_A}), budget_seconds=0)
    assert store.ual_queries() == [] and tiered[PART_A].tier is None and tiered[PART_A].ual == ""


def test_the_curator_overlay_hands_a_trusted_manifests_pin_to_the_scope(monkeypatch):
    import types
    import plugins.blackbox.community.statements.curator_view as cv
    from plugins.blackbox.kernel.config import BlackboxConfig
    pin = anchors.legacy_list_hash([UAL_A])
    view = cv.CuratorView(manifest=types.SimpleNamespace(legacy_assets_hash=pin))
    monkeypatch.setattr(curator_tier.community, "read_curator_view", lambda client, config: view)
    monkeypatch.setattr(curator_tier, "_apply_kill_list", lambda *args: None)
    rs = compiler.Ruleset()
    curator_tier.apply_curator_tier(rs, object(), BlackboxConfig(context_graph_id=CG))
    assert rs.curator_legacy_assets_hash == pin


def test_the_opt_in_fallback_index_applies_the_same_flag_cap(tmp_path):
    from plugins.blackbox.ruleset.live import fallback_index
    scope = _scope({PART_A: AssetTier.FLAG, PART_B: AssetTier.BLOCK})
    index = fallback_index.FallbackIndex(scope, tmp_path / "fallback.sqlite")
    try:
        for graph, key in ((PART_A, "ioc-a"), (PART_B, "ioc-b")):
            index._db.execute("INSERT INTO ioc (key, graph, rule, value) VALUES (?, ?, ?, ?)",
                              (key, graph, json.dumps({"identifier": key, "source": "public"}), key))
        answer = index.iocs(["ioc-a", "ioc-b"])
    finally:
        index.close()
    assert answer.rules["ioc-a"]["source"] == scope_mod.FLAG_ONLY_SOURCE and answer.rules["ioc-a"]["asset_tier"] == "flag"
    assert answer.rules["ioc-b"]["source"] == "public" and "asset_tier" not in answer.rules["ioc-b"]


# ================================================================== R2: the tier from the signed envelope
#
# After the pin, an asset outside the legacy list is BLOCK only when its rows carry
# a promotion envelope that the manifest in force ON THE ASSET'S DAY accepts; the
# rule is served from the signed payload; a row showing a rule its signature does
# not name (a transplanted envelope) is never served, flags its asset and
# raises the alarm input. Rows are written by the real row builders (P2).

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plugins.blackbox.community.trust import manifest_history
from plugins.blackbox.curate.publishing import row_builders as rb
from plugins.blackbox.kernel import constants, signing, threat_ids
from plugins.blackbox.kernel.signing import key_manifest as km
from plugins.blackbox.kernel.signing import promotion_statement
from plugins.blackbox.ruleset import graph_queries
from plugins.blackbox.ruleset.live import envelope_tier
from plugins.blackbox.ruleset.live.asset_facts import SignedRule

NETWORK = "sandbox-net"
CURATOR_A, CURATOR_B, CURATOR_C = (Ed25519PrivateKey.generate() for _ in range(3))


def _report(identifier):
    """The community report a promotion of *identifier* was made from (its provenance, the one-graph flow)."""
    return promotion_statement.ReportRef(identifier, threat_ids.report_uri(identifier, "0x" + "e" * 40), "d" * 64, "e" * 64)


EVIL = rb.ConfirmedEntry("dep:npm:evil-pkg@1.0.0", "critical", "malware", _report("dep:npm:evil-pkg@1.0.0"),
                         "advisory MAL-2026-1")
EVIL_IOC = rb.ConfirmedEntry(threat_ids.ioc_identifier("domain", "evil.example"), "high", "malware",
                             _report(threat_ids.ioc_identifier("domain", "evil.example")))
PART_C = f"{VM}300"
UAL_C = "did:dkg:base:8453/0x37b1fdfd134e2b17583bcbdd3034f91504cd9c70/300"
TODAY = "2026-11-20"


def _key_manifest(version, issued_day, curators):
    pairs = sorted((signing.public_key_hex(key), f"operator-{index}") for index, key in enumerate(curators))
    return km.KeyManifest(environment=NETWORK, graph=CG, chain="", root_epoch=1, version=version,
                          curator_keys=tuple(key for key, _ in pairs), curator_operators=tuple(op for _, op in pairs),
                          threshold=2, promotion_author="0x" + "1" * 40, legacy_assets_hash=km.legacy_assets_hash([]),
                          issued_day=issued_day)


V1 = _key_manifest(1, "2026-09-01", (CURATOR_A, CURATOR_B))                 # in force 09-02 .. 10-31
V2 = _key_manifest(2, "2026-10-20", (CURATOR_A, CURATOR_C))                 # rotates B out; in force from 10-21
HISTORY = (V1, V2)


def _envelope(entry, signers=(CURATOR_A, CURATOR_B), payload=None):
    statement = signing.sign(signers[0], statement_type=rb.PROMOTION_STATEMENT, environment=NETWORK, graph=CG,
                             payload=payload or rb.promotion_payload(entry), root_epoch=1, sequence=1)
    for key in signers[1:]:
        statement = signing.cosign(statement, key)
    return statement


def _promoted(entry, signers=(CURATOR_A, CURATOR_B)):
    """(subject, predicate, object) triples of a promoted row, exactly as the row builder writes them."""
    return [(q["subject"], q["predicate"], q["object"])
            for q in rb.ROW_BUILDERS[entry.category].quads(entry, _envelope(entry, signers))]


def _edited(triples, replacements):
    """*triples* with each (predicate → new literal value) swapped: an unsigned edit by the wallet holder."""
    return [(s, p, rdf_quoted(replacements[p]) if p in replacements else o) for s, p, o in triples]


def rdf_quoted(value):
    return json.dumps(value)


class SignedStore(StoreClient):
    """A node store holding *assets* (graph → triples): answers the ``_meta`` read
    (UAL + publishedAt from *meta*) and the signed-rows lane; records queries."""

    def __init__(self, assets, meta, *, fail_signed=False):
        super().__init__("http://127.0.0.1:7878/query")
        self.assets, self.meta, self.fail_signed, self.queries = assets, meta, fail_signed, []

    def signed_queries(self):
        return [query for query in self.queries if "signedStatement" in query]

    def select(self, sparql, *, timeout=None):
        self.queries.append(sparql)
        if "kaUal" in sparql:
            graphs = [graph for graph, _meta in re.findall(r"\(<([^>]+)> <([^>]+)>\)", sparql)]
            return StoreAnswer([{"g": g, "ual": self.meta[g][0], "at": f'"{self.meta[g][1]}T09:15:00Z"'}
                                for g in graphs if g in self.meta])
        if "signedStatement" in sparql:
            if self.fail_signed:
                return StoreAnswer(None, "timeout")
            graphs = re.findall(r"<([^>]+)>", sparql.split("VALUES ?g {", 1)[1].split("}", 1)[0])
            signed = {(g, s) for g in graphs for s, p, _o in self.assets.get(g, ()) if p == constants.SIGNED_STATEMENT_PRED}
            return StoreAnswer([{"g": g, "t": s, "p": p, "o": o} for g in graphs for s, p, o in self.assets.get(g, ())
                                if (g, s) in signed])
        return StoreAnswer([])


def _decide(assets, days, history=HISTORY, store=None):
    facts = {graph: AssetFacts(ual=f"ual:{graph}", day=days.get(graph, "")) for graph in assets}
    store = store or SignedStore(assets, {})
    decided = envelope_tier.decide_by_envelope(
        store, facts, manifest_for_day=lambda day: manifest_history.manifest_on_day(history, day),
        verified_graph=CG, today=TODAY)
    return decided, store


def _served(decided, graph, triples, category="dependency"):
    scope = scope_mod.VerifiedScope(store_url="http://127.0.0.1:7878/query", assertion_graphs=frozenset(decided),
                                    asset_facts=decided)
    return lookup.VerifiedLookup(scope, StoreClient("http://127.0.0.1:7878/query"))._rules_from(_rows(graph, triples), category)


# ------------------------------------------------------------------ acceptance 1: the tier


def test_a_quorum_envelope_tiers_the_asset_block_and_serves_its_rule():
    triples = _promoted(EVIL)
    decided, store = _decide({PART_A: triples}, {PART_A: "2026-09-10"})
    assert decided[PART_A].tier is AssetTier.BLOCK
    assert decided[PART_A].signed == {triples[0][0]: SignedRule.from_payload(rb.promotion_payload(EVIL))}
    assert len(store.signed_queries()) == 1
    rules = _served(decided, PART_A, triples)
    assert set(rules) == {"npm:evil-pkg@1.0.0"} and rules["npm:evil-pkg@1.0.0"]["source"] == "public"


def test_a_row_signed_before_the_report_was_its_provenance_is_served_the_same():
    """Legacy verified rules need no re-publish: a row whose envelope carries the payload promotions
    signed before the one-graph flow (random provenance ids, no report) is decided and served the same."""
    legacy = {**{key: value for key, value in rb.promotion_payload(EVIL).items()
                 if key not in ("report", "reportDigest", "reporterKey")}, "provenance": "0123456789abcdef"}
    triples = [(q["subject"], q["predicate"], q["object"])
               for q in rb.ROW_BUILDERS["dep"].quads(EVIL, _envelope(EVIL, payload=legacy))]
    decided, _store = _decide({PART_A: triples}, {PART_A: "2026-09-10"})
    assert decided[PART_A].tier is AssetTier.BLOCK
    assert decided[PART_A].signed == {triples[0][0]: SignedRule.from_payload(legacy)}
    assert set(_served(decided, PART_A, triples)) == {"npm:evil-pkg@1.0.0"}


def test_an_unsigned_or_under_signed_post_pin_row_tiers_its_asset_flag():
    unsigned = [t for t in _promoted(EVIL) if t[1] != constants.SIGNED_STATEMENT_PRED]
    one_key = _promoted(EVIL, signers=(CURATOR_A,))
    foreign = _promoted(EVIL, signers=(CURATOR_C, Ed25519PrivateKey.generate()))
    decided, _store = _decide({PART_A: unsigned, PART_B: one_key, PART_C: foreign},
                              {PART_A: "2026-09-10", PART_B: "2026-09-10", PART_C: "2026-09-10"})
    assert [decided[graph].tier for graph in (PART_A, PART_B, PART_C)] == [AssetTier.FLAG] * 3
    for graph, triples in ((PART_A, unsigned), (PART_B, one_key)):
        (rule,) = _served(decided, graph, triples).values()
        assert rule["source"] == scope_mod.FLAG_ONLY_SOURCE and rule["asset_tier"] == "flag"


def test_the_manifest_in_force_on_the_assets_day_decides():
    """A+B signed: BLOCK on a day V1 was in force, FLAG on a day V2 (B rotated out) was."""
    triples = _promoted(EVIL)
    decided, _store = _decide({PART_A: triples, PART_B: triples}, {PART_A: "2026-09-10", PART_B: "2026-10-25"})
    assert decided[PART_A].tier is AssetTier.BLOCK and decided[PART_B].tier is AssetTier.FLAG
    after_rotation, _store = _decide({PART_A: _promoted(EVIL, signers=(CURATOR_A, CURATOR_C))}, {PART_A: "2026-10-25"})
    assert after_rotation[PART_A].tier is AssetTier.BLOCK


def test_a_later_rotation_never_re_tiers_a_decided_asset(monkeypatch, tmp_path):
    triples = _promoted(EVIL)
    store = SignedStore({PART_A: triples}, {PART_A: (UAL_A, "2026-09-10")})
    monkeypatch.setattr(scope_mod.community, "verified_manifest_history", lambda client, graph, env: (V1,))
    pin = anchors.legacy_list_hash(())
    first = _refresh(monkeypatch, _list_file(tmp_path, []), pin, confirmed=[PART_A], store=store)
    assert first.tier_of(PART_A) is AssetTier.BLOCK
    monkeypatch.setattr(scope_mod.community, "verified_manifest_history", lambda client, graph, env: HISTORY)
    again = SignedStore({PART_A: triples}, {PART_A: (UAL_A, "2026-09-10")})
    later = _refresh(monkeypatch, _list_file(tmp_path, []), pin, previous=first, confirmed=[PART_A], store=again)
    assert later.tier_of(PART_A) is AssetTier.BLOCK and again.queries == []   # decided once; zero recurring cost
    back = scope_mod.VerifiedScope.from_json(json.loads(json.dumps(later.to_json())))
    assert back.asset_facts == later.asset_facts                               # carried in the facts


def test_the_day_is_first_sight_when_the_node_gives_none_and_never_later_than_today():
    triples = _promoted(EVIL)
    decided, _store = _decide({PART_A: triples, PART_B: triples}, {PART_A: "", PART_B: "2027-01-01"},
                              history=(_key_manifest(3, "2026-11-01", (CURATOR_A, CURATOR_B)),))
    assert decided[PART_A].tier is AssetTier.BLOCK and decided[PART_B].tier is AssetTier.BLOCK   # judged on TODAY


@pytest.mark.usefixtures("time_lock_one_day")
def test_no_list_in_force_on_the_day_tiers_flag():
    decided, _store = _decide({PART_A: _promoted(EVIL), PART_B: _promoted(EVIL)},
                              {PART_A: "2026-09-01", PART_B: "2026-11-05"}, history=(V1,))
    assert decided[PART_A].tier is AssetTier.FLAG                              # inside V1's time-lock
    assert decided[PART_B].tier is AssetTier.FLAG                              # V1 stale after 10-31


# ------------------------------------------------------------------ acceptance 1: the transplant


def test_a_transplanted_envelope_on_a_legitimate_package_flags_the_asset_and_raises_the_alarm():
    """The wallet copies evil-pkg's valid envelope onto a row that LOCATES react@18.2.0."""
    react = {constants.PACKAGE_NAME_PRED: "react", constants.PACKAGE_VERSION_PRED: "18.2.0",
             f"{DP}package": "react", f"{DP}version": "18.2.0"}
    transplanted = _edited(_promoted(EVIL), react)
    renamed = _edited(transplanted, {constants.IDENTIFIER_PRED: "dep:npm:react@18.2.0"})
    decided, _store = _decide({PART_A: transplanted, PART_B: renamed}, {PART_A: "2026-09-10", PART_B: "2026-09-10"})
    subject = transplanted[0][0]
    for graph, triples in ((PART_A, transplanted), (PART_B, renamed)):
        assert decided[graph].tier is AssetTier.FLAG and decided[graph].ignored == {subject}
        assert _served(decided, graph, triples) == {}                          # not even a flag on react
    scope = scope_mod.VerifiedScope(asset_facts=decided)
    assert scope.refused_envelope_rows == tuple(sorted((f"{PART_A} {subject}", f"{PART_B} {subject}")))


def test_an_ioc_envelope_re_aimed_at_another_value_is_never_served():
    moved = _edited(_promoted(EVIL_IOC), {f"{DP}value": "github.com"})
    decided, _store = _decide({PART_A: moved}, {PART_A: "2026-09-10"})
    assert decided[PART_A].tier is AssetTier.FLAG and decided[PART_A].ignored
    assert _served(decided, PART_A, moved, "ioc") == {}


def test_a_genuine_ioc_row_agrees_with_its_signature():
    triples = _promoted(EVIL_IOC)
    decided, _store = _decide({PART_A: triples}, {PART_A: "2026-09-10"})
    assert decided[PART_A].tier is AssetTier.BLOCK
    assert set(_served(decided, PART_A, triples, "ioc")) == {EVIL_IOC.identifier}


def test_every_promotable_category_written_by_its_builder_agrees_with_its_signature():
    entries = [EVIL, EVIL_IOC,
               rb.ConfirmedEntry(threat_ids.skill_version_identifier("totally-safe-helper", "2.1.0"), "high", "malware"),
               rb.ConfirmedEntry(threat_ids.fileaccess_identifier("read_file", "ssh-private-key"), "high", "exfiltration")]
    for entry in entries:
        decided, _store = _decide({PART_A: _promoted(entry)}, {PART_A: "2026-09-10"})
        assert decided[PART_A].tier is AssetTier.BLOCK, entry.identifier


# ------------------------------------------------------------------ acceptance 1: the rule comes from the payload


def test_a_block_rows_identifier_kind_severity_and_version_come_from_the_signed_payload():
    """The wallet edits the row's unsigned severity and kind: the served rule still says what was signed."""
    edited = _edited(_promoted(EVIL), {constants.SEVERITY_PRED: "low", constants.KIND_PRED: "pup",
                                       f"{DP}severity": "low", f"{DP}kind": "pup"})
    decided, _store = _decide({PART_A: edited}, {PART_A: "2026-09-10"})
    assert decided[PART_A].tier is AssetTier.BLOCK                             # the locators still name the signed rule
    (rule,) = _served(decided, PART_A, edited).values()
    assert (rule["identifier"], rule["severity"], rule["kind"], rule["packageVersion"]) == \
        ("dep:npm:evil-pkg@1.0.0", "critical", "malware", "1.0.0")


def test_an_unsigned_row_beside_signed_ones_is_capped_at_flag():
    stray = _dep("urn:s:stray", "stray-pkg")
    triples = _promoted(EVIL) + stray
    decided, _store = _decide({PART_A: triples}, {PART_A: "2026-09-10"})
    assert decided[PART_A].tier is AssetTier.BLOCK
    rules = _served(decided, PART_A, triples)
    assert rules["npm:stray-pkg@1.0.0"]["source"] == scope_mod.FLAG_ONLY_SOURCE
    assert rules["npm:evil-pkg@1.0.0"]["source"] == "public"


def test_the_hot_path_drops_a_rule_that_disagrees_with_its_recorded_signature():
    signed = SignedRule.from_payload(rb.promotion_payload(EVIL))
    scope = scope_mod.VerifiedScope(asset_facts={PART_A: AssetFacts(tier=AssetTier.BLOCK, signed={"urn:s:x": signed})})
    rule = {"identifier": EVIL.identifier, "subject": "urn:s:x", "severity": "low", "source": "public"}
    assert scope.as_tier_allows(PART_A, "dependency", "npm:react@18.2.0", rule) is None
    assert scope.as_tier_allows(PART_A, "dependency", "npm:evil-pkg@1.0.0", rule)["severity"] == "critical"


# ------------------------------------------------------------------ could not tell, budget, batching


def test_without_a_manifest_history_nothing_is_decided_by_envelope(monkeypatch, tmp_path):
    store = SignedStore({PART_A: _promoted(EVIL)}, {PART_A: (UAL_A, "2026-09-10")})
    for history in (None, ()):
        monkeypatch.setattr(scope_mod.community, "verified_manifest_history", lambda c, g, e, h=history: h)
        scope = _refresh(monkeypatch, _list_file(tmp_path, []), anchors.legacy_list_hash(()), confirmed=[PART_A],
                         store=store)
        assert scope.tier_of(PART_A) is None and store.signed_queries() == []


def test_a_failed_signed_read_decides_nothing_and_is_retried():
    store = SignedStore({PART_A: _promoted(EVIL)}, {}, fail_signed=True)
    decided, _store = _decide({PART_A: _promoted(EVIL)}, {PART_A: "2026-09-10"}, store=store)
    assert decided[PART_A].tier is None
    retried, _store = _decide({PART_A: _promoted(EVIL)}, {PART_A: "2026-09-10"})
    assert retried[PART_A].tier is AssetTier.BLOCK


def test_an_answer_at_the_row_limit_decides_nothing(monkeypatch):
    monkeypatch.setattr(envelope_tier, "ROW_LIMIT", 3)
    decided, _store = _decide({PART_A: _promoted(EVIL)}, {PART_A: "2026-09-10"})
    assert decided[PART_A].tier is None


def test_an_asset_whose_meta_was_not_read_is_never_decided_by_envelope():
    store = SignedStore({PART_A: _promoted(EVIL)}, {})
    decided = envelope_tier.decide_by_envelope(store, {PART_A: AssetFacts()}, manifest_for_day=lambda day: V1,
                                               verified_graph=CG, today=TODAY)
    assert decided[PART_A].tier is None and store.queries == []               # legacy membership unknown


def test_a_legacy_asset_is_block_without_reading_envelopes(monkeypatch, tmp_path):
    store = SignedStore({PART_A: []}, {PART_A: (UAL_A, "2026-09-10")})
    monkeypatch.setattr(scope_mod.community, "verified_manifest_history", lambda client, graph, env: HISTORY)
    scope = _refresh(monkeypatch, _list_file(tmp_path, [UAL_A]), anchors.legacy_list_hash([UAL_A]),
                     confirmed=[PART_A], store=store)
    assert scope.tier_of(PART_A) is AssetTier.BLOCK and store.signed_queries() == []
    assert scope.asset_facts[PART_A].day == "2026-09-10"


def test_the_signed_read_is_one_values_bound_query_per_batch_with_a_pause(monkeypatch):
    """LES-040: the extra read rides the facts lane — 20 assets per query, a pause after each."""
    pauses = []
    monkeypatch.setattr(envelope_tier.time, "sleep", pauses.append)
    assets = {f"{VM}{index}": _promoted(EVIL) for index in range(45)}
    decided, store = _decide(assets, {graph: "2026-09-10" for graph in assets})
    assert len(store.signed_queries()) == 3 == len(pauses)
    assert all(query.count("<did:dkg:") <= asset_facts.BATCH for query in store.signed_queries())
    assert all("LIMIT" in query and "GRAPH ?g" in query for query in store.signed_queries())
    assert {fact.tier for fact in decided.values()} == {AssetTier.BLOCK}


def test_an_exhausted_budget_decides_nothing():
    store = SignedStore({PART_A: _promoted(EVIL)}, {})
    decided = envelope_tier.decide_by_envelope(store, {PART_A: AssetFacts(ual=UAL_A)}, manifest_for_day=lambda day: V1,
                                               verified_graph=CG, today=TODAY, budget_seconds=0)
    assert decided[PART_A].tier is None and store.queries == []


def test_the_signed_rows_query_refuses_unsafe_graph_iris():
    assert graph_queries.signed_rows_sparql(["urn:x> } DROP ALL {"], 10) == ""
    assert f"<{constants.SIGNED_STATEMENT_PRED}>" in graph_queries.signed_rows_sparql([PART_A], 10)


def test_signed_facts_survive_the_cache_round_trip():
    fact = AssetFacts(ual=UAL_A, tier=AssetTier.FLAG, day="2026-09-10", ignored=frozenset({"urn:s:x"}))
    block = AssetFacts(tier=AssetTier.BLOCK, signed={"urn:s:y": SignedRule.from_payload(rb.promotion_payload(EVIL))})
    for item in (fact, block):
        assert AssetFacts.from_json(json.loads(json.dumps(item.to_json()))) == item


# ------------------------------------------------------------------ which manifest was in force (community/trust)


@pytest.mark.usefixtures("time_lock_one_day")
def test_manifest_on_day_follows_the_reader_policy_as_of_that_day():
    assert manifest_history.manifest_on_day(HISTORY, "2026-09-10") == V1
    assert manifest_history.manifest_on_day(HISTORY, "2026-10-20") == V1      # V2 still in its time-lock
    assert manifest_history.manifest_on_day(HISTORY, "2026-10-25") == V2
    assert manifest_history.manifest_on_day(HISTORY, "2026-09-01") is None    # nothing in force yet
    assert manifest_history.manifest_on_day((V1,), "2026-11-01") is None      # stale (issued + 60 d)


def test_a_later_narrowing_list_never_reaches_back_and_a_conflict_trusts_neither():
    narrowed = _key_manifest(2, "2026-10-01", (CURATOR_A, CURATOR_B, CURATOR_C))
    wide = _key_manifest(1, "2026-09-01", (CURATOR_A, CURATOR_B, CURATOR_C))
    narrow = km.KeyManifest(**{**narrowed.__dict__, "curator_keys": wide.curator_keys[:2],
                               "curator_operators": wide.curator_operators[:2]})
    assert narrow.narrows(wide)
    assert manifest_history.manifest_on_day((wide, narrow), "2026-09-10") == wide   # issued later: not yet
    assert manifest_history.manifest_on_day((wide, narrow), "2026-10-01") == narrow  # narrowing acts at once
    rival = _key_manifest(1, "2026-09-01", (CURATOR_A, CURATOR_C))
    assert manifest_history.manifest_on_day((V1, rival), "2026-09-10") is None


def test_the_history_read_needs_a_pinned_root_and_reports_could_not_tell(monkeypatch):
    from plugins.blackbox.community.trust import manifest_history as mh
    assert mh.verified_manifest_history(object(), CG, "") == ()
    monkeypatch.setattr(mh.RootPins, "for_environment", classmethod(lambda cls, env: cls.unbound(("ab" * 32,))))
    monkeypatch.setattr(mh, "page_rows", lambda *args: None)
    assert mh.verified_manifest_history(object(), CG, NETWORK) is None


# ================================================================== R5: a successor graph's cut-off
#
# Once readers follow a root-signed graph migration, the configured graph keeps its
# legacy assets and the assets dated BEFORE from_day (each with its own tier); every
# later asset there is out of scope entirely — not even flag — and new assets come
# only from the successor graph, whose envelopes must name the successor.

from plugins.blackbox.community import ActiveGraph
from plugins.blackbox.kernel.signing.graph_migration import GraphMigration
from plugins.blackbox.ruleset import fetching

SUCCESSOR = "0x" + "2" * 40 + "/agent-blackbox-vm"
SUCCESSOR_VM = graph_queries.verifiable_memory_prefix(SUCCESSOR) + "0x" + "2" * 40 + "/"
PART_S = f"{SUCCESSOR_VM}5"
UAL_S = "did:dkg:base:8453/0x" + "2" * 40 + "/5"
PART_D = f"{VM}400"
UAL_D = "did:dkg:base:8453/0x37b1fdfd134e2b17583bcbdd3034f91504cd9c70/400"
CUT_DAY = "2026-10-24"
MIGRATION = GraphMigration(environment=NETWORK, from_graph=CG, to_graph=SUCCESSOR, from_day=CUT_DAY,
                           issued_day="2026-10-20", root_epoch=1, sequence=1)
EVIL_S = rb.ConfirmedEntry("dep:npm:evil-next@2.0.0", "critical", "malware", _report("dep:npm:evil-next@2.0.0"))


def _promoted_in(entry, graph, signers=(CURATOR_A, CURATOR_C)):
    """A promoted row whose envelope names *graph* (signed after V2's rotation: A + C)."""
    statement = signing.sign(signers[0], statement_type=rb.PROMOTION_STATEMENT, environment=NETWORK, graph=graph,
                             payload=rb.promotion_payload(entry), root_epoch=1, sequence=1)
    for key in signers[1:]:
        statement = signing.cosign(statement, key)
    return [(q["subject"], q["predicate"], q["object"]) for q in rb.ROW_BUILDERS[entry.category].quads(entry, statement)]


#: PART_A signed before the cut; PART_B signed (validly!) after it; PART_C a legacy asset
#: the node dates after the cut; PART_D unsigned after the cut; PART_S the successor's.
CUT_ASSETS = {PART_A: _promoted(EVIL), PART_B: _promoted(EVIL, signers=(CURATOR_A, CURATOR_C)), PART_C: [],
              PART_D: _dep("urn:s:late", "late-pkg"), PART_S: _promoted_in(EVIL_S, SUCCESSOR)}
CUT_META = {PART_A: (UAL_A, "2026-09-10"), PART_B: (UAL_B, "2026-10-25"), PART_C: (UAL_C, "2026-10-26"),
            PART_D: (UAL_D, CUT_DAY), PART_S: (UAL_S, "2026-10-25")}


def _cut_refresh(monkeypatch, tmp_path, *, migration=MIGRATION, assets=None, meta=None, previous=None,
                 confirmed=(PART_A, PART_B, PART_C, PART_D), successor=(PART_S,), store=None):
    monkeypatch.setattr(scope_mod.community, "verified_manifest_history", lambda client, graph, env: HISTORY)
    monkeypatch.setattr(scope_mod.community, "curator_today", lambda: TODAY)
    monkeypatch.setattr(anchors, "LEGACY_ASSETS_FILE", _list_file(tmp_path, [UAL_C]))
    store = store or SignedStore(assets or CUT_ASSETS, meta if meta is not None else CUT_META)
    scope = scope_mod.refresh_scope(
        _Node(), CG, previous=previous, confirmed=None if confirmed is None else list(confirmed), suppressed=set(),
        revoked=set(), store=store, legacy_assets_hash=anchors.legacy_list_hash([UAL_C]), migration=migration,
        successor_confirmed=None if successor is None else list(successor))
    return scope, store


def _rules(scope, graph, triples=None):
    triples = CUT_ASSETS[graph] if triples is None else triples
    return lookup.VerifiedLookup(scope, StoreClient("http://127.0.0.1:7878/query"))._rules_from(
        _rows(graph, triples), "dependency")


def test_with_a_successor_an_old_graph_row_dated_from_the_cut_yields_no_rule_at_all(monkeypatch, tmp_path):
    scope, _store = _cut_refresh(monkeypatch, tmp_path)
    assert scope.assertion_graphs == {PART_A, PART_C, PART_S}
    assert _rules(scope, PART_B) == {}                                          # validly signed, but after the cut
    assert _rules(scope, PART_D) == {}                                          # dated ON from_day: not even a flag
    assert scope.tier_of(PART_B) is None and scope.asset_facts[PART_B].day == "2026-10-25"   # never decided
    assert scope.asset_facts[PART_B].ual == UAL_B                               # facts carried: never read again


def test_with_a_successor_a_pre_cut_signed_row_keeps_its_tier_and_legacy_stays(monkeypatch, tmp_path):
    scope, _store = _cut_refresh(monkeypatch, tmp_path)
    assert scope.tier_of(PART_A) is AssetTier.BLOCK
    (rule,) = _rules(scope, PART_A).values()
    assert rule["source"] == "public" and rule["identifier"] == EVIL.identifier
    assert scope.tier_of(PART_C) is AssetTier.BLOCK                             # legacy: in scope whatever its day
    stray = _dep("urn:s:early", "early-pkg")
    unsigned_before = {PART_A: stray}
    early, _store = _cut_refresh(monkeypatch, tmp_path, assets=unsigned_before, confirmed=[PART_A], successor=())
    (flagged,) = _rules(early, PART_A, stray).values()
    assert early.tier_of(PART_A) is AssetTier.FLAG and flagged["source"] == scope_mod.FLAG_ONLY_SOURCE


def test_with_a_successor_its_rows_are_read_and_tiered_against_the_successor_graph(monkeypatch, tmp_path):
    scope, store = _cut_refresh(monkeypatch, tmp_path)
    assert scope.tier_of(PART_S) is AssetTier.BLOCK
    (rule,) = _rules(scope, PART_S).values()
    assert rule["source"] == "public" and rule["identifier"] == EVIL_S.identifier
    assert any(PART_S in query for query in store.signed_queries())
    # An envelope naming the OLD graph does not promote a successor row (graph binding).
    rebound = {PART_S: _promoted(EVIL_S, signers=(CURATOR_A, CURATOR_C))}
    wrong, _store = _cut_refresh(monkeypatch, tmp_path, assets=rebound, confirmed=(), successor=[PART_S])
    assert wrong.tier_of(PART_S) is AssetTier.FLAG


def test_without_a_successor_the_same_graph_is_scoped_exactly_as_before(monkeypatch, tmp_path):
    scope, _store = _cut_refresh(monkeypatch, tmp_path, migration=None, successor=None)
    assert scope.assertion_graphs == {PART_A, PART_B, PART_C, PART_D}           # no cut, no successor read
    assert scope.tier_of(PART_B) is AssetTier.BLOCK and _rules(scope, PART_B)
    assert scope.tier_of(PART_D) is AssetTier.FLAG


def test_an_old_asset_with_no_known_day_is_out_of_scope_until_one_is_read(monkeypatch, tmp_path):
    undated = {**CUT_META, PART_A: (UAL_A, "")}
    scope, _store = _cut_refresh(monkeypatch, tmp_path, meta=undated)
    assert PART_A not in scope.assertion_graphs                                 # could not tell is never "before"
    failed, _store = _cut_refresh(monkeypatch, tmp_path, store=TierStore(fail_uals=True), confirmed=[PART_A],
                                  successor=())
    assert failed.assertion_graphs == frozenset()                                # _meta unreadable: nothing believed
    retried, _store = _cut_refresh(monkeypatch, tmp_path, previous=failed, confirmed=[PART_A], successor=())
    assert retried.assertion_graphs == {PART_A} and retried.tier_of(PART_A) is AssetTier.BLOCK


def test_unreadable_listings_keep_the_last_scope_and_the_cut_without_re_reading(monkeypatch, tmp_path):
    first, _store = _cut_refresh(monkeypatch, tmp_path)
    again = SignedStore(CUT_ASSETS, CUT_META)
    kept, _store = _cut_refresh(monkeypatch, tmp_path, previous=first, confirmed=None, successor=None, store=again)
    assert kept.assertion_graphs == first.assertion_graphs and again.queries == []
    back = scope_mod.VerifiedScope.from_json(json.loads(json.dumps(kept.to_json())))
    assert back.assertion_graphs == kept.assertion_graphs and back.asset_facts == kept.asset_facts


def test_scope_for_generation_reads_the_successor_listing_only_when_one_is_in_effect(monkeypatch):
    listed, handed = [], {}
    listings = {CG: fetching.PartitionListing(frozenset({PART_A}), (PART_A,)),
                SUCCESSOR: fetching.PartitionListing(frozenset({PART_S}), (PART_S,))}
    monkeypatch.setattr(scope_mod.fetching, "confirmed_partitions",
                        lambda client, graph: listed.append(graph) or listings[graph])
    monkeypatch.setattr(scope_mod, "refresh_scope", lambda client, graph, **kwargs: handed.update(kwargs) or "scope")
    for active, expected_reads, successor_assets in ((ActiveGraph(CG), [CG], None),
                                                     (ActiveGraph(CG, MIGRATION), [CG, SUCCESSOR], [PART_S])):
        listed.clear()
        monkeypatch.setattr(scope_mod.community, "active_verified_graph", lambda client, cfg, a=active: a)
        assert scope_mod.scope_for_generation(_Node(), CG, previous=None, suppressed=set(), revoked=set()) == "scope"
        assert listed == expected_reads
        assert handed["migration"] == active.migration and handed["successor_confirmed"] == (
            tuple(successor_assets) if successor_assets else None)
