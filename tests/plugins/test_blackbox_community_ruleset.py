"""B5 contract: the community read path — aggregation, precedence, never-block.

* Aggregation math keys on the identifier LITERAL (KI-027): distinct
  reporters counted honestly, severity = max, dup reporters collapse.
* Public rules always beat community rows for the same key.
* THE INVARIANT: a community-sourced rule can never block, even critical
  in block mode (structural: confirmed stays False).
* KI-004: no community string ever reaches the compiled scan lists.
* KI-001: community rules survive the serialize→deserialize round trip.
* KI-010: bounded ingest keeps the corroborated head and logs the drop.
* KI-029: sparql_string_literal neutralizes hostile identifiers.
* KI-036: the curator pause flag suppresses ingest and marks the ruleset.
"""

from __future__ import annotations

import pytest

from plugins.blackbox import detection
from plugins.blackbox.community import aggregation as community_aggregation
from plugins.blackbox.community import reader as community_reader
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.community import CommunityRule, VerifiedReport, aggregate_community_reports
from plugins.blackbox.kernel.constants import normalize_severity

from _community_rows import NETWORK, Reporter, signed_row
from plugins.blackbox.kernel.sparql_text import sparql_string_literal
from plugins.blackbox.ruleset import Ruleset
from plugins.blackbox.ruleset.disk_cache import _deserialize, _serialize
from plugins.blackbox.ruleset.community_tier import apply_community_tier as _apply_community_tier
from plugins.blackbox.ruleset.community_tier import materialize_community_rules as _materialize_community_rules


DEV_GRAPH = "0x51E5dE758A45c8b64048E29918421F0bdD6D5d5C/agent-blackbox-community-dev"
CFG = BlackboxConfig(report=True, context_graph_id=DEV_GRAPH)


def _report(identifier, author, severity="high", reporter=None, **fields):
    """A report that already passed verification (R0c): *author* is the signer key."""
    return VerifiedReport(
        subject=f"urn:guardian:report:{reporter or author}:{abs(hash(identifier)) % 10**8:08x}",
        identifier=identifier, author=author, reporter=reporter or author,
        severity=normalize_severity(severity), fields=tuple(sorted(fields.items())),
    )


# ---------------------------------------------------------------------------
# Aggregation math (KI-027: identifier literal is the key)
# ---------------------------------------------------------------------------


def test_three_reporters_count_three():
    rows = [_report("dep:npm:evil@1", f"0xr{i}") for i in range(3)]
    rules = aggregate_community_reports(rows, {})
    assert len(rules) == 1
    assert rules[0].reporter_count == 3


def test_same_signer_twice_counts_once():
    rows = [_report("dep:npm:evil@1", "key-1"), _report("dep:npm:evil@1", "key-1")]
    rules = aggregate_community_reports(rows, {})
    assert rules[0].reporter_count == 1


def test_one_signer_under_many_reporter_strings_counts_once():
    """KI-067/110: the reporter field is self-described — counting keys on the signer."""
    rows = [_report("dep:npm:evil@1", "key-1", reporter=f"0xfake{i}") for i in range(10)]
    assert aggregate_community_reports(rows, {})[0].reporter_count == 1


def test_two_signers_count_two():
    rows = [_report("dep:npm:evil@1", "key-1"), _report("dep:npm:evil@1", "key-2")]
    assert aggregate_community_reports(rows, {})[0].reporter_count == 2


def test_severity_is_max_across_reporters():
    rows = [
        _report("dep:npm:evil@1", "0x54fd580f81be3e09ae45a05c507295d1c3635f0a", severity="medium"),
        _report("dep:npm:evil@1", "0xfe26576731c057e0ef78f7a21e8b8b9cceed6bdb", severity="critical"),
        _report("dep:npm:evil@1", "0x7299e99649371fb11035cac1d7574b29487a151e", severity="low"),
    ]
    assert aggregate_community_reports(rows, {})[0].severity == "critical"


def test_identifier_literals_stay_distinct_even_when_slugs_collide():
    """KI-027: these two collapse to the same slugged URN; the literal must not."""
    a = "ioc:url:https://evil.example/x?a=1"
    b = "ioc:url:https://evil.example/x/a/1"
    rules = aggregate_community_reports(
        [_report(a, "0x54fd580f81be3e09ae45a05c507295d1c3635f0a"), _report(b, "0xfe26576731c057e0ef78f7a21e8b8b9cceed6bdb")], {}
    )
    assert len(rules) == 2


def test_first_seen_carries_over_from_prior_cache():
    """KI-012: first_seen is OUR observation history, not reporter-supplied."""
    rules = aggregate_community_reports(
        [_report("dep:npm:evil@1", "0x54fd580f81be3e09ae45a05c507295d1c3635f0a")], {"dep:npm:evil@1": 1000.0}
    )
    assert rules[0].first_seen == 1000.0


def test_bounded_ingest_keeps_corroborated_head(monkeypatch):
    monkeypatch.setattr(community_aggregation, "_COMMUNITY_MAX_RULES", 3)
    rows = []
    for i in range(6):
        for r in range(i + 1):  # identifier i has i+1 reporters
            rows.append(_report(f"dep:npm:pkg{i}@1", f"0xr{r}"))
    rules = aggregate_community_reports(rows, {})
    assert len(rules) == 3
    assert [r.reporter_count for r in rules] == [6, 5, 4]  # the head, not the tail


# ---------------------------------------------------------------------------
# The Adapter boundary (KI-004): display-only, clamped, never compiled
# ---------------------------------------------------------------------------


def test_as_rule_clamps_hostile_fields():
    hostile = "A" * 10_000
    rule = CommunityRule(
        identifier="dep:npm:evil@1", category="dep", severity="high",
        reporter_count=2, first_seen=1.0, last_seen=2.0,
        fields=(("pattern", hostile),),
    ).as_rule()
    assert len(rule["pattern"]) <= 256
    assert isinstance(rule["pattern"], str)  # plain display text, never compiled


def test_community_injection_reports_never_enter_the_scan_list():
    rs = Ruleset()
    rs.community = {
        "injection:deadbeef": {
            "identifier": "injection:deadbeef",
            "severity": "critical",
            "source": "community",
            "reporterCount": 5,
            "pattern": "(a+)+$",  # catastrophic-backtracking bait
        }
    }
    _materialize_community_rules(rs)
    assert rs.injection == []  # KI-004: nothing to compile, nothing to scan


def test_materialize_dependency_and_ioc_only():
    rs = Ruleset()
    rs.community = {
        "dep:npm:evil@1.0.0": {
            "identifier": "dep:npm:evil@1.0.0", "severity": "high",
            "source": "community", "reporterCount": 2,
        },
        "ioc:domain:evil.example": {
            "identifier": "ioc:domain:evil.example", "severity": "high",
            "source": "community", "reporterCount": 3, "iocType": "domain",
        },
        "escalation:shell:remote-script-pipe": {
            "identifier": "escalation:shell:remote-script-pipe", "severity": "high",
            "source": "community", "reporterCount": 1,
        },
    }
    _materialize_community_rules(rs)
    assert "npm:evil@1.0.0" in rs.dependency
    assert "ioc:domain:evil.example" in rs.ioc
    assert rs.escalation == []  # display/corroboration only in v1


def test_public_beats_community_for_same_key():
    rs = Ruleset()
    rs.dependency["npm:evil@1.0.0"] = {"identifier": "dep:npm:evil@1.0.0", "source": "public"}
    rs.community = {
        "dep:npm:evil@1.0.0": {
            "identifier": "dep:npm:evil@1.0.0", "severity": "low",
            "source": "community", "reporterCount": 9,
        }
    }
    _materialize_community_rules(rs)
    assert rs.dependency["npm:evil@1.0.0"]["source"] == "public"


# ---------------------------------------------------------------------------
# THE INVARIANT: community can never block
# ---------------------------------------------------------------------------


def test_community_rule_can_never_block_even_critical_in_block_mode():
    rs = Ruleset()
    rs.community = {
        "ioc:domain:evil.example": {
            "identifier": "ioc:domain:evil.example", "severity": "critical",
            "source": "community", "reporterCount": 50, "iocType": "domain",
        }
    }
    _materialize_community_rules(rs)
    findings = detection.detect_ioc("browser", {"url": "https://evil.example/x"}, rs)
    assert findings, "community IOC rule must still FLAG"
    cfg = BlackboxConfig(mode="block", block_severity="critical")
    for f in findings:
        assert f.source == "community"
        assert f.confirmed is False
        # the hooks blocking filter requires confirmed OR source in (custom, secret)
        would_block = (
            (f.confirmed or f.source in ("custom", "secret"))
            and f.category != "ioc"
            and cfg.meets_block_threshold(f.severity)
        )
        assert would_block is False


# ---------------------------------------------------------------------------
# Cache round trip (KI-001)
# ---------------------------------------------------------------------------


def test_community_rules_survive_cache_round_trip():
    rs = Ruleset()
    rs.community = {
        "dep:npm:evil@1.0.0": {
            "identifier": "dep:npm:evil@1.0.0", "severity": "high",
            "source": "community", "reporterCount": 2, "firstSeen": 111.0,
        }
    }
    _materialize_community_rules(rs)
    restored = _deserialize(_serialize(rs))
    assert restored.community == rs.community
    assert "npm:evil@1.0.0" in restored.dependency
    assert restored.dependency["npm:evil@1.0.0"]["source"] == "community"


def test_public_only_scan_lists_after_round_trip():
    rs = Ruleset()
    rs.injection = [
        {"identifier": "injection:aaa", "source": "public", "pattern_src": "safe", "pattern": None},
        {"identifier": "injection:bbb", "source": "community", "pattern_src": "(a+)+$", "pattern": None},
    ]
    restored = _deserialize(_serialize(rs))
    assert [r["identifier"] for r in restored.injection] == ["injection:aaa"]


# ---------------------------------------------------------------------------
# Fetch / pause / fail-open
# ---------------------------------------------------------------------------


class FakeClient:
    def __init__(self, report_rows=None, paused=False, fail=False):
        self._rows = report_rows if report_rows is not None else []
        self._paused = paused
        self._fail = fail
        self.subscribed = []
        self.network = NETWORK
        self.graphs = []          # what context_graphs() reports (membership probe)

    def status(self):
        return {"networkId": self.network}

    def context_graphs(self):
        return self.graphs

    def subscribe_context_graph(self, cg_id, include_shared_memory=False):
        self.subscribed.append((cg_id, include_shared_memory))
        return {}

    def query(self, sparql, cg_id, view=None, on_error=None, **kw):
        if "community:pause" in sparql:
            return [{"v": "true"}] if self._paused else []
        if self._fail:
            return on_error
        served, self._rows = self._rows, []  # one page, then empty
        return served


def test_apply_community_tier_populates_store_and_subscribes(monkeypatch):
    rs = Ruleset()
    client = FakeClient(report_rows=[signed_row("ioc:domain:evil.example", Reporter("0x54fd580f81be3e09ae45a05c507295d1c3635f0a"), ioc_type="domain")])
    _apply_community_tier(rs, client, CFG)
    assert "ioc:domain:evil.example" in rs.community
    assert rs.community["ioc:domain:evil.example"]["reporterCount"] == 1
    assert (DEV_GRAPH, True) in client.subscribed  # KI-034 refresh-path subscribe


def test_pause_flag_suppresses_ingest(monkeypatch):
    rs = Ruleset()
    client = FakeClient(report_rows=[signed_row("dep:npm:evil@1", Reporter("0x54fd580f81be3e09ae45a05c507295d1c3635f0a"))], paused=True)
    _apply_community_tier(rs, client, CFG)
    assert rs.community == {}
    assert rs.community_paused is True


def test_fetch_failure_keeps_last_good(monkeypatch):
    prior = Ruleset()
    prior.community = {
        "dep:npm:old@1": {"identifier": "dep:npm:old@1", "severity": "high",
                          "source": "community", "reporterCount": 4, "firstSeen": 5.0}
    }
    rs = Ruleset()
    _apply_community_tier(rs, FakeClient(fail=True), CFG, prior)
    assert rs.community == prior.community


def _prior_with(identifier="ioc:domain:old.example"):
    prior = Ruleset()
    prior.community = {identifier: {"identifier": identifier, "severity": "high",
                                    "source": "community", "reporterCount": 2, "firstSeen": 5.0}}
    return prior


def test_empty_read_without_membership_proof_keeps_last_good():
    """R0 tri-state (inverts the old 'empty graph degrades to zero rules'):
    an empty answer is not proof of an empty graph — keep last-good."""
    prior = _prior_with()
    rs = Ruleset()
    _apply_community_tier(rs, FakeClient(report_rows=[]), CFG, prior)
    assert rs.community == prior.community


def test_empty_read_with_a_synced_subscription_is_authorised_empty():
    client = FakeClient(report_rows=[])
    client.graphs = [{"id": DEV_GRAPH, "subscribed": True, "synced": True}]
    prior = _prior_with()
    prior.community_empty_since = 1.0    # the emptiness is old news (KI-262: one empty read alone is not believed)
    rs = Ruleset()
    _apply_community_tier(rs, client, CFG, prior)
    assert rs.community == {}
    assert rs.community_paused is False


def test_subscribed_but_still_syncing_is_not_proof_of_empty():
    client = FakeClient(report_rows=[])
    client.graphs = [{"id": DEV_GRAPH, "subscribed": True, "synced": False}]
    prior = _prior_with()
    rs = Ruleset()
    _apply_community_tier(rs, client, CFG, prior)
    assert rs.community == prior.community


class _PagedClient(FakeClient):
    """Serves the community report pages in order; a page that is an
    Exception fails (the client then returns the caller's on_error)."""

    def __init__(self, pages):
        super().__init__()
        self._pages = list(pages)

    def query(self, sparql, cg_id, view=None, on_error=None, **kw):
        if "community:pause" in sparql:
            return []
        page = self._pages.pop(0) if self._pages else []
        return on_error if isinstance(page, Exception) else page


def test_a_failed_second_page_makes_the_whole_read_unavailable(monkeypatch):
    monkeypatch.setattr(community_reader, "_COMMUNITY_PAGE_SIZE", 1)
    page1 = [signed_row("ioc:domain:one.example", Reporter("0x54fd580f81be3e09ae45a05c507295d1c3635f0a"))]
    prior = _prior_with()
    rs = Ruleset()
    _apply_community_tier(rs, _PagedClient([page1, RuntimeError("page 2 down")]), CFG, prior)
    assert rs.community == prior.community          # never the partial page


def test_read_states_are_tagged():
    from plugins.blackbox.community import ReadState, read_verified_reports
    rows_client = FakeClient(report_rows=[signed_row("ioc:domain:x.example", Reporter("0x54fd580f81be3e09ae45a05c507295d1c3635f0a"))])
    assert read_verified_reports(rows_client, CFG).state is ReadState.ROWS
    unknown_network = FakeClient(report_rows=[signed_row("ioc:domain:x.example", Reporter("0x54fd580f81be3e09ae45a05c507295d1c3635f0a"))])
    unknown_network.network = ""
    read = read_verified_reports(unknown_network, CFG)
    assert read.state is ReadState.UNAVAILABLE and "network id" in read.reason
    assert read_verified_reports(FakeClient(), BlackboxConfig(context_graph_id="")).state is ReadState.AUTHORISED_EMPTY


def test_reapply_on_a_reused_ruleset_replaces_stale_community_entries():
    """The community tier refreshes even when the verified tier is reused."""
    from plugins.blackbox.ruleset.community_tier import reapply_community_tier
    rs = _prior_with("ioc:domain:stale.example")
    _materialize_community_rules(rs)
    assert "ioc:domain:stale.example" in rs.ioc
    client = FakeClient(report_rows=[signed_row("ioc:domain:fresh.example", Reporter("0x54fd580f81be3e09ae45a05c507295d1c3635f0a"))])
    reapply_community_tier(rs, client, CFG)
    assert "ioc:domain:stale.example" not in rs.ioc and "ioc:domain:stale.example" not in rs.community
    # Refine R3 / decision 15: ONE report from an UNLISTED author is MONITOR-only — it lives in the
    # community store with its stage, and never materializes into the matchable lookups.
    fresh = rs.community["ioc:domain:fresh.example"]
    assert (fresh["stage"], fresh["enforcement"]) == ("reported", "monitor")
    assert "ioc:domain:fresh.example" not in rs.ioc


# ---------------------------------------------------------------------------
# R0c: only verified reports count (KI-067/102/110/144)
# ---------------------------------------------------------------------------


def _tier(rows, network=NETWORK, prior=None):
    rs = Ruleset()
    client = FakeClient(report_rows=rows)
    client.network = network
    _apply_community_tier(rs, client, CFG, prior)
    return rs.community


def test_unsigned_row_is_not_counted():
    row = signed_row("ioc:domain:evil.example", Reporter("0x54fd580f81be3e09ae45a05c507295d1c3635f0a"))
    del row["signedStatement"]
    assert _tier([row]) == {}


def test_forged_reporter_field_is_dropped():
    row = signed_row("ioc:domain:evil.example", Reporter("0x54fd580f81be3e09ae45a05c507295d1c3635f0a"))
    row["reporter"] = "0x772e97e2f594637e81f9316c5d3abbdf3ea487e7"
    assert _tier([row]) == {}


def test_tampered_evidence_is_dropped():
    row = signed_row("dep:npm:evil@1.0.0", Reporter("0x54fd580f81be3e09ae45a05c507295d1c3635f0a"), package_name="evil", package_version="1.0.0", ecosystem="npm")
    row["packageVersion"] = "2.0.0"
    assert _tier([row]) == {}


def test_signature_from_another_network_is_dropped():
    row = signed_row("ioc:domain:evil.example", Reporter("0x54fd580f81be3e09ae45a05c507295d1c3635f0a"), environment="some-test-network")
    assert _tier([row]) == {}


def test_signature_for_another_graph_is_dropped():
    row = signed_row("ioc:domain:evil.example", Reporter("0x54fd580f81be3e09ae45a05c507295d1c3635f0a"), graph="0xabc/other-graph")
    assert _tier([row]) == {}


def test_one_key_posing_as_ten_addresses_counts_once():
    """THE KI-067 attack: one node, ten reporter identities, one key."""
    key = Reporter("0xfc617e77d2fed5b59012c371e63c37a5f48c2363").key
    rows = [signed_row("ioc:domain:evil.example", Reporter(f"0xpose{i}", key)) for i in range(10)]
    assert _tier(rows)["ioc:domain:evil.example"]["reporterCount"] == 1


def test_two_real_reporters_count_two():
    rows = [signed_row("ioc:domain:evil.example", Reporter("0x54fd580f81be3e09ae45a05c507295d1c3635f0a")), signed_row("ioc:domain:evil.example", Reporter("0xfe26576731c057e0ef78f7a21e8b8b9cceed6bdb"))]
    assert _tier(rows)["ioc:domain:evil.example"]["reporterCount"] == 2


def test_unknown_network_keeps_last_good():
    prior = Ruleset()
    prior.community = {"ioc:domain:old.example": {"identifier": "ioc:domain:old.example", "severity": "high",
                                                  "source": "community", "reporterCount": 2, "firstSeen": 5.0}}
    assert _tier([signed_row("ioc:domain:evil.example", Reporter("0x54fd580f81be3e09ae45a05c507295d1c3635f0a"))], network="", prior=prior) == prior.community


def test_no_community_graph_configured_is_a_noop():
    rs = Ruleset()
    _apply_community_tier(rs, FakeClient(), BlackboxConfig())
    assert rs.community == {}


# ---------------------------------------------------------------------------
# SPARQL escaping (KI-029)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "hostile",
    [
        'x" } UNION { ?s ?p ?o } FILTER("',
        "line\nbreak",
        "back\\slash",
        'quote"quote',
        "tab\there",
    ],
)
def test_sparql_string_literal_neutralizes_hostile_input(hostile):
    lit = sparql_string_literal(hostile)
    assert lit.startswith('"') and lit.endswith('"')
    body = lit[1:-1]
    # no raw quote/newline can terminate the literal early
    assert '"' not in body.replace('\\"', "")
    assert "\n" not in body and "\r" not in body


def test_graph_entries_carry_reporter_stats_for_materialized_community_iocs():
    """Regression: matchable community IOCs are listed via the ioc lookup dict,
    which lacks corroboration stats, so the dashboard showed 0 reporters for an
    IOC reported by two distinct nodes. Checked after the cache round trip the
    dashboard actually reads."""
    rs = Ruleset()
    rs.community = {
        "ioc:ip:203.0.113.66": {
            "identifier": "ioc:ip:203.0.113.66", "severity": "critical",
            "source": "community", "reporterCount": 2, "iocType": "ip",
            "firstSeen": 100.0, "lastSeen": 200.0,
        },
    }
    _materialize_community_rules(rs)
    served = _deserialize(_serialize(rs))

    entry = next(
        item for item in served.graph_entries("community")
        if item["identifier"] == "ioc:ip:203.0.113.66"
    )

    assert entry["reporterCount"] == 2
    assert entry["lastSeen"] == 200.0


# ---------------------------------------------------------------------------
# Flood resistance (Refine R0, KI-100/111)
# ---------------------------------------------------------------------------


def test_a_flood_of_fresh_singletons_keeps_older_honest_threats(monkeypatch):
    """The plan's test: 6,000 fresh single-author identifiers must not evict
    10 older honest ones from the compile cap."""
    honest = [_report(f"ioc:domain:honest-{i}.example", f"honest-key-{i}") for i in range(10)]
    flood = [_report(f"ioc:domain:flood-{i}.example", "flood-key") for i in range(6000)]
    history = {r.identifier: 100.0 for r in honest}          # this node saw them long ago
    rules = aggregate_community_reports(flood + honest, history)
    kept = {r.identifier for r in rules}
    assert all(r.identifier in kept for r in honest)
    assert len(rules) <= community_aggregation._COMMUNITY_MAX_RULES


def test_one_signer_is_capped_and_keeps_its_oldest_reports(monkeypatch):
    monkeypatch.setattr(community_aggregation, "MAX_REPORTS_PER_AUTHOR", 3)
    reports = [_report(f"ioc:domain:k{i}.example", "one-key") for i in range(6)]
    history = {"ioc:domain:k5.example": 1.0, "ioc:domain:k4.example": 2.0}   # the oldest-known two
    kept = {r.identifier for r in aggregate_community_reports(reports, history)}
    assert len(kept) == 3
    assert {"ioc:domain:k5.example", "ioc:domain:k4.example"} <= kept


def test_ties_go_to_the_oldest_observation(monkeypatch):
    monkeypatch.setattr(community_aggregation, "_COMMUNITY_MAX_RULES", 1)
    old = _report("ioc:domain:old.example", "k1")
    new = _report("ioc:domain:new.example", "k2")
    rules = aggregate_community_reports([new, old], {"ioc:domain:old.example": 5.0})
    assert [r.identifier for r in rules] == ["ioc:domain:old.example"]


def test_aggregated_rules_carry_the_canonical_category_name():
    """KI-197: the community store names categories as the schema and the UI do (`dependency`, never `dep`)."""
    from _community_rows import GRAPH, NETWORK, Reporter, signed_row
    from plugins.blackbox.community.verification import ReportVerifier, verify_report_rows
    reports, _ = verify_report_rows([signed_row("dep:npm:x@1", Reporter("0xf79e09c14d5c229b89c4ac719117cf2bd56fe5f1")), signed_row("ioc:ip:203.0.113.7", Reporter("0x680964861de62daa6c399f0d8887109f83e17cff"))],
                                    ReportVerifier(NETWORK, GRAPH))
    assert sorted(r.category for r in aggregate_community_reports(reports, {})) == ["dependency", "ioc"]
