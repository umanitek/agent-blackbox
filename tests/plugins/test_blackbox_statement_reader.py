"""Refine R2 — readers honour reporter statements before counting.

Disputes are finally read and verified (KI-092) but never change enforcement.
One per-author budget covers every statement type, counted per READER-observed
day, with this node's first read as an exempt baseline. Tombstones for
reports this reader has not seen are bounded (lifetime + 7 days, 100 per
author), so a tombstone storm stays bounded.
"""

from __future__ import annotations

import json

import pytest
from _community_rows import GRAPH, NETWORK, Reporter, signed_dispute_row, signed_retraction_row, signed_row

from plugins.blackbox.community import ReadState, aggregate_community_reports, read_verified_reports
from plugins.blackbox.community.statements import author_budget, tombstones
from plugins.blackbox.community.statements.lifetimes import lifetime_days
from plugins.blackbox.community.statements.retractions import VerifiedRetraction
from plugins.blackbox.community.verification import VerifiedReport
from plugins.blackbox.kernel.config import BlackboxConfig

CFG = BlackboxConfig(report=True, context_graph_id=GRAPH)
THREAT = "ioc:domain:evil.example"
DAY = 86_400


class _Graph:
    """Serves reports, retractions and disputes to the matching query (one page each)."""

    def __init__(self, reports=(), retractions=(), disputes=(), fail_disputes=False):
        self.rows = {"report": list(reports), "retraction": list(retractions), "dispute": list(disputes)}
        self.fail_disputes = fail_disputes

    def status(self):
        return {"networkId": NETWORK}

    def context_graphs(self):
        return []

    def query(self, sparql, cg_id, view=None, on_error=None, **kw):
        kind = "retraction" if "g:Retraction" in sparql else "dispute" if "g:FalsePositive" in sparql else "report"
        if kind == "dispute" and self.fail_disputes:
            return on_error
        served, self.rows[kind] = self.rows[kind], []
        return served


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))


# ------------------------------------------------------------------ disputes (KI-092)


def test_a_verified_dispute_is_read_with_its_reason():
    reporter, disputer = Reporter("0x54fd580f81be3e09ae45a05c507295d1c3635f0a"), Reporter("0xe74717e44e0a3c5af04e9e62c04a7b444a448f62")
    read = read_verified_reports(_Graph([signed_row(THREAT, reporter)],
                                        disputes=[signed_dispute_row(THREAT, disputer, reason="fixed")]), CFG)
    assert [(d.identifier, d.author, d.reason) for d in read.disputes] == [(THREAT, disputer.author, "fixed")]


@pytest.mark.parametrize("tamper", ["unsigned", "other-network", "shown-reason"])
def test_an_unverifiable_dispute_is_ignored(tamper):
    disputer = Reporter("0xe74717e44e0a3c5af04e9e62c04a7b444a448f62")
    row = signed_dispute_row(THREAT, disputer, environment="other" if tamper == "other-network" else NETWORK)
    if tamper == "unsigned":
        row.pop("signedStatement")
    if tamper == "shown-reason":
        row["reportReason"] = "tolerable"   # the signed reason was "wrong"
    read = read_verified_reports(_Graph([signed_row(THREAT, Reporter("0x54fd580f81be3e09ae45a05c507295d1c3635f0a"))], disputes=[row]), CFG)
    assert read.disputes == ()


def test_a_dispute_never_changes_enforcement():
    reporters = [Reporter(f"0xr{i}") for i in range(3)]
    reports = [signed_row(THREAT, r) for r in reporters]
    without = read_verified_reports(_Graph(reports), CFG)
    with_disputes = read_verified_reports(_Graph(reports, disputes=[signed_dispute_row(THREAT, Reporter(f"0xd{i}"))
                                                                    for i in range(5)]), CFG)
    assert len(with_disputes.disputes) == 5
    rules = lambda read: [rule.as_rule() for rule in aggregate_community_reports(read.reports, {})]
    strip = lambda rows: [{k: v for k, v in r.items() if k not in ("firstSeen", "lastSeen")} for r in rows]
    assert strip(rules(with_disputes)) == strip(rules(without))


def test_a_failed_dispute_page_makes_the_read_unavailable():
    read = read_verified_reports(_Graph([signed_row(THREAT, Reporter("0x54fd580f81be3e09ae45a05c507295d1c3635f0a"))], fail_disputes=True), CFG)
    assert read.state is ReadState.UNAVAILABLE


# ------------------------------------------------------------------ the per-author budget


def _statements(author, n, prefix="s"):
    return [author_budget.Statement(author, f"{prefix}{i}") for i in range(n)]


class _Clock:
    def __init__(self, at):
        self.at = at

    def __call__(self):
        return self.at


def test_the_first_read_is_an_exempt_baseline(tmp_path):
    store = author_budget.FirstSeenStore(tmp_path / "seen.json", clock=_Clock(10 * DAY))
    result = author_budget.AuthorBudget(store, per_day=5).admit(_statements("a", 30))
    assert len(result.admitted) == 30 and result.held_back == 0


def test_after_the_baseline_an_author_gets_its_daily_budget_per_reader_day(tmp_path):
    clock = _Clock(10 * DAY)
    store = author_budget.FirstSeenStore(tmp_path / "seen.json", clock=clock)
    budget = author_budget.AuthorBudget(store, per_day=5)
    budget.admit(_statements("a", 1, "base"))                         # baseline
    clock.at = 11 * DAY + 60
    flood = _statements("a", 1, "base") + _statements("a", 12) + _statements("b", 3, "honest")
    result = budget.admit(flood)
    assert result.held_back == 7
    assert {s.subject for s in _statements("b", 3, "honest")} <= result.admitted   # one flooder never costs another
    clock.at = 12 * DAY + 60                                          # a new reader-day: the held-back ones are...
    assert budget.admit(flood).held_back == 7                        # ...still dated day 11 — first seen, not resent


def test_the_store_keeps_only_the_latest_read_and_survives_garbage(tmp_path):
    path = tmp_path / "seen.json"
    store = author_budget.FirstSeenStore(path, clock=_Clock(DAY))
    store.observe(["x", "y"])
    first_seen, _ = store.observe(["y"])
    assert len(json.loads(path.read_text(encoding="utf-8"))["seen"]) == 1 and first_seen["y"] == DAY
    path.write_text("{not json", encoding="utf-8")
    _, baseline = author_budget.FirstSeenStore(path, clock=_Clock(5 * DAY)).observe(["z"])
    assert baseline == 5 * DAY                                        # unreadable = a fresh baseline


def test_the_reader_holds_back_a_flood_after_the_baseline():
    flooder = Reporter("0x9489f322ab5d949bca01102253e8597795d2be9e")
    base = signed_row("ioc:domain:base.example", flooder)
    read_verified_reports(_Graph([base]), CFG)                        # baseline read
    from plugins.blackbox.community.statements.author_budget import MAX_STATEMENTS_PER_AUTHOR_PER_DAY as budget
    flood = [signed_row(f"ioc:domain:f{i}.example", flooder) for i in range(budget + 10)]
    read = read_verified_reports(_Graph([base, *flood]), CFG)
    assert read.held_back == 10 and len(read.reports) == budget + 1


# ------------------------------------------------------------------ pending tombstones


def _report(identifier, author="a"):
    return VerifiedReport(subject=f"r:{identifier}", identifier=identifier, author=author, reporter="0x1cb7a2e9afbed1e81860f3dd4e4e3b795be5b95a", severity="high")


def _retraction(identifier, author="a"):
    return VerifiedRetraction(author=author, identifier=identifier, subject=f"t:{author}:{identifier}")


def test_a_retraction_for_a_present_report_applies():
    applicable, pending = tombstones.applicable_withdrawals([_retraction(THREAT)], [_report(THREAT)], {}, 0.0)
    assert applicable == {("a", THREAT)} and pending == 0


def test_a_tombstone_storm_stays_bounded():
    storm = [_retraction(f"ioc:domain:x{i}.example") for i in range(10_000)]
    first_seen = {r.subject: float(i) for i, r in enumerate(storm)}
    applicable, pending = tombstones.applicable_withdrawals(storm, [], first_seen, 10_000.0)
    assert pending == tombstones.MAX_PENDING_PER_AUTHOR == len(applicable)
    assert ("a", "ioc:domain:x9999.example") in applicable           # the newest are kept


def test_an_old_tombstone_for_an_unseen_report_is_forgotten():
    old = _retraction("ioc:ip:203.0.113.7")
    expires = (lifetime_days("ioc:ip:203.0.113.7") + 7) * DAY
    _, kept = tombstones.applicable_withdrawals([old], [], {old.subject: 0.0}, expires - 1)
    _, forgotten = tombstones.applicable_withdrawals([old], [], {old.subject: 0.0}, expires + 1)
    assert (kept, forgotten) == (1, 0)


def test_lifetimes_follow_the_plan_table():
    assert [lifetime_days(i) for i in ("ioc:ip:1.2.3.4", "ioc:url:x", "ioc:domain:x", "ioc:wallet:0x1",
                                        "dep:npm:x@1", "escalation:t:s", "injection:abc", "skill:x@1", "ioc:hash:aa")] == [
        47, 47, 300, 460, 460, 460, 300, 300, 300]
