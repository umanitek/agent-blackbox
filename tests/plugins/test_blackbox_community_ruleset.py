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

from plugins.blackbox import detection, ruleset as rs_mod
from plugins.blackbox.config import BlackboxConfig
from plugins.blackbox.ruleset import (
    CommunityRule,
    Ruleset,
    _aggregate_community_reports,
    _apply_community_tier,
    _deserialize,
    _materialize_community_rules,
    _serialize,
    sparql_string_literal,
)


DEV_GRAPH = "0x51E5dE758A45c8b64048E29918421F0bdD6D5d5C/agent-blackbox-community-dev"
CFG = BlackboxConfig(report=True, community_graph_id=DEV_GRAPH)


def _report_row(identifier, reporter, severity="high", **extra):
    row = {
        "r": f"urn:guardian:report:{reporter}:{abs(hash(identifier)) % 10**8:08x}",
        "identifier": identifier,
        "reporter": reporter,
        "severity": severity,
    }
    row.update(extra)
    return row


# ---------------------------------------------------------------------------
# Aggregation math (KI-027: identifier literal is the key)
# ---------------------------------------------------------------------------


def test_three_reporters_count_three():
    rows = [_report_row("dep:npm:evil@1", f"0xr{i}") for i in range(3)]
    rules = _aggregate_community_reports(rows, {})
    assert len(rules) == 1
    assert rules[0].reporter_count == 3


def test_same_reporter_twice_counts_once():
    rows = [_report_row("dep:npm:evil@1", "0xr1"), _report_row("dep:npm:evil@1", "0xR1")]
    rules = _aggregate_community_reports(rows, {})
    assert rules[0].reporter_count == 1  # case-normalized address


def test_severity_is_max_across_reporters():
    rows = [
        _report_row("dep:npm:evil@1", "0xr1", severity="medium"),
        _report_row("dep:npm:evil@1", "0xr2", severity="critical"),
        _report_row("dep:npm:evil@1", "0xr3", severity="low"),
    ]
    assert _aggregate_community_reports(rows, {})[0].severity == "critical"


def test_identifier_literals_stay_distinct_even_when_slugs_collide():
    """KI-027: these two collapse to the same slugged URN; the literal must not."""
    a = "ioc:url:https://evil.example/x?a=1"
    b = "ioc:url:https://evil.example/x/a/1"
    rules = _aggregate_community_reports(
        [_report_row(a, "0xr1"), _report_row(b, "0xr2")], {}
    )
    assert len(rules) == 2


def test_first_seen_carries_over_from_prior_cache():
    """KI-012: first_seen is OUR observation history, not reporter-supplied."""
    rules = _aggregate_community_reports(
        [_report_row("dep:npm:evil@1", "0xr1")], {"dep:npm:evil@1": 1000.0}
    )
    assert rules[0].first_seen == 1000.0


def test_bounded_ingest_keeps_corroborated_head(monkeypatch):
    monkeypatch.setattr(rs_mod, "_COMMUNITY_MAX_RULES", 3)
    rows = []
    for i in range(6):
        for r in range(i + 1):  # identifier i has i+1 reporters
            rows.append(_report_row(f"dep:npm:pkg{i}@1", f"0xr{r}"))
    rules = _aggregate_community_reports(rows, {})
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
    monkeypatch.setattr(rs_mod, "_latest_cached_ruleset", lambda cg: None)
    rs = Ruleset()
    client = FakeClient(report_rows=[_report_row("ioc:domain:evil.example", "0xr1", iocType="domain")])
    _apply_community_tier(rs, client, CFG)
    assert "ioc:domain:evil.example" in rs.community
    assert rs.community["ioc:domain:evil.example"]["reporterCount"] == 1
    assert (DEV_GRAPH, True) in client.subscribed  # KI-034 refresh-path subscribe


def test_pause_flag_suppresses_ingest(monkeypatch):
    monkeypatch.setattr(rs_mod, "_latest_cached_ruleset", lambda cg: None)
    rs = Ruleset()
    client = FakeClient(report_rows=[_report_row("dep:npm:evil@1", "0xr1")], paused=True)
    _apply_community_tier(rs, client, CFG)
    assert rs.community == {}
    assert rs.community_paused is True


def test_fetch_failure_keeps_last_good(monkeypatch):
    prior = Ruleset()
    prior.community = {
        "dep:npm:old@1": {"identifier": "dep:npm:old@1", "severity": "high",
                          "source": "community", "reporterCount": 4, "firstSeen": 5.0}
    }
    monkeypatch.setattr(rs_mod, "_latest_cached_ruleset", lambda cg: prior)
    rs = Ruleset()
    _apply_community_tier(rs, FakeClient(fail=True), CFG)
    assert rs.community == prior.community


def test_empty_graph_degrades_to_zero_rules(monkeypatch):
    monkeypatch.setattr(rs_mod, "_latest_cached_ruleset", lambda cg: None)
    rs = Ruleset()
    _apply_community_tier(rs, FakeClient(report_rows=[]), CFG)
    assert rs.community == {}
    assert rs.community_paused is False


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
