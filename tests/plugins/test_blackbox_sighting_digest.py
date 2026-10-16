"""Refine R2b — the seen-again counter: a weekly sighting digest per reporter.

Repeats inside the report cooldown still count in the local tally; only
VERIFIED-tier matches enter it; buckets have the plan's edges; the digest
carries no time finer than the ISO week; readers keep one digest per author
per week (first observed) and count unlisted authors as zero; the heat
estimate is the sum of bucket midpoints over counted authors.
"""

from __future__ import annotations

import json
from datetime import date, datetime, timezone, UTC

import pytest
from _community_rows import GRAPH, NETWORK, Reporter, signed_row

from plugins.blackbox import audit
from plugins.blackbox.community import digest, read_verified_reports
from plugins.blackbox.community.report_signer import ReportSigner
from plugins.blackbox.community.statements import curator_view as cv
from plugins.blackbox.community.statements import digests as digest_reader
from plugins.blackbox.guard import reporting
from plugins.blackbox.kernel import signing
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.detection import Finding

CFG = BlackboxConfig(report=True, context_graph_id=GRAPH)
THREAT = "dep:npm:evil@1.0.0"
MONDAY_W40 = datetime(2026, 9, 28, 12, tzinfo=UTC)
MONDAY_W41 = datetime(2026, 10, 5, 12, tzinfo=UTC)


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    return tmp_path / "bbhome"


class _Clock:
    def __init__(self, at):
        self.at = at

    def __call__(self):
        return self.at


# ------------------------------------------------------------------ the tally


def test_bucket_edges():
    assert [digest.bucket_for(n).value for n in (1, 2, 9, 10, 99, 100, 5000)] == [
        "1", "2-9", "2-9", "10-99", "10-99", "100+", "100+"]
    assert [b.midpoint for b in digest.Bucket] == [1, 5, 55, 100]


def test_iso_week_naming_and_year_boundary():
    assert digest.iso_week(date(2026, 9, 28)) == "2026-W40"
    assert digest.iso_week(date(2027, 1, 1)) == "2026-W53"     # Jan 1 2027 belongs to 2026's last ISO week


def test_repeats_inside_the_report_cooldown_still_increment_the_tally(home):
    """The 6-hour cooldown refuses a repeat REPORT; the tally still counts it."""
    audit.mark_reported(THREAT)
    assert audit.recently_reported(THREAT)
    for _ in range(3):
        digest.record_verified_sighting(THREAT)
    assert digest.SightingTally().counts(digest.iso_week(datetime.now(UTC).date())) == {THREAT: 3}


def test_only_verified_tier_matches_enter_the_tally(monkeypatch, home):
    """A community-only match would tell whoever listed the value who met it (KI-158)."""
    monkeypatch.setattr(audit, "record", lambda **kw: None)
    monkeypatch.setattr(audit, "write_private_audit_ka", lambda *a, **k: None)
    monkeypatch.setattr(reporting, "DkgClient", lambda **kw: None)
    findings = [Finding(identifier=THREAT, category="dependency", severity="high", title="t", source="public"),
                Finding(identifier="ioc:domain:listed.example", category="ioc", severity="high", title="t",
                        source="community", confirmed=False),
                Finding(identifier="ioc:domain:guess.example", category="ioc", severity="high", title="t",
                        source="heuristic", confirmed=False)]
    reporting._report_and_audit(BlackboxConfig(), "pre_tool_call", findings, {})
    reporting._report_and_audit(BlackboxConfig(), "pre_tool_call", findings, {})   # a repeat
    assert digest.SightingTally().counts(digest.iso_week(datetime.now(UTC).date())) == {THREAT: 2}


def test_the_tally_knows_which_completed_weeks_are_due(tmp_path):
    clock = _Clock(MONDAY_W40)
    tally = digest.SightingTally(tmp_path / "tally.json", clock=clock)
    tally.record(THREAT)
    assert tally.due_weeks() == []                      # the current week is not complete
    clock.at = MONDAY_W41
    tally.record("ioc:domain:x.example")
    assert tally.due_weeks() == ["2026-W40"]
    tally.mark_published("2026-W40")
    assert tally.due_weeks() == []


def test_the_tally_survives_garbage_and_prunes_old_weeks(tmp_path):
    path = tmp_path / "tally.json"
    path.write_text("{nope", encoding="utf-8")
    tally = digest.SightingTally(path, clock=_Clock(MONDAY_W40))
    tally.record(THREAT)
    assert tally.counts("2026-W40") == {THREAT: 1}
    for week in range(20, 40):                          # 20 older weeks
        state = json.loads(path.read_text(encoding="utf-8"))
        state["weeks"][f"2026-W{week:02d}"] = {THREAT: 1}
        path.write_text(json.dumps(state), encoding="utf-8")
    tally.record(THREAT)
    assert len(json.loads(path.read_text(encoding="utf-8"))["weeks"]) <= 8


# ------------------------------------------------------------------ the digest


def _signer(reporter):
    return ReportSigner(private_key=reporter.key, environment=NETWORK, graph=GRAPH)


def test_the_digest_carries_no_time_finer_than_the_week():
    reporter = Reporter("0x54fd580f81be3e09ae45a05c507295d1c3635f0a")
    entries = digest.build_digest({THREAT: 12, "ioc:domain:a.example": 1})
    quads = digest.build_digest_quads(reporter_address=reporter.address, week="2026-W40", entries=entries,
                                      signer=_signer(reporter))
    serialized = "\n".join(q["object"] for q in quads)
    assert "2026-W40" in serialized and "T" not in serialized.replace("ThreatReport", "").replace("Threat", "")
    assert "dateModified" not in " ".join(q["predicate"] for q in quads)
    envelope = signing.from_text(json.loads(next(q["object"] for q in quads if q["predicate"].endswith("signedStatement"))))
    assert set(envelope.payload) == {"subject", "reporter", "framework", "week", "entries"}
    assert digest.parse_entries(envelope.payload["entries"]) == entries
    assert [e.bucket.value for e in entries] == ["10-99", "1"]            # the most-seen first, bucketed, no counts


def test_the_digest_caps_its_entries_to_the_most_seen():
    counts = {f"ioc:domain:t{i}.example": i + 1 for i in range(60)}
    entries = digest.build_digest(counts)
    assert len(entries) == digest.MAX_DIGEST_ENTRIES and entries[0].identifier == "ioc:domain:t59.example"


class _Node:
    def __init__(self):
        self.shares = []

    def status(self):
        return {"networkId": NETWORK}

    def agent_identity(self):
        return {"agentAddress": "0x" + "a" * 40}

    def share_knowledge_asset(self, cg_id, name, quads, **kw):
        self.shares.append((cg_id, name, quads))
        return {"state": "succeeded"}

    def context_graphs(self):
        return []

    def query(self, *a, **kw):
        return kw.get("on_error")


def test_publishing_sends_one_digest_per_completed_week_and_never_twice(monkeypatch, tmp_path, home):
    from plugins.blackbox.kernel import identity as kernel_identity
    monkeypatch.setattr(kernel_identity, "reporter_address", lambda c: "0x" + "a" * 40)
    clock = _Clock(MONDAY_W40)
    tally = digest.SightingTally(tmp_path / "tally.json", clock=clock)
    tally.record(THREAT)
    node = _Node()
    assert digest.publish_due_digests(node, CFG, tally) == 0            # nothing complete yet
    clock.at = MONDAY_W41
    assert digest.publish_due_digests(node, CFG, tally) == 1
    assert digest.publish_due_digests(node, CFG, tally) == 0            # the week is marked published
    cg, name, _quads = node.shares[0]
    assert cg == GRAPH and name.startswith("digest-") and len(node.shares) == 1
    assert audit.read_share_ledger()[0]["category"] == "digest"


def test_nothing_is_published_while_sharing_is_off(tmp_path):
    tally = digest.SightingTally(tmp_path / "tally.json", clock=_Clock(MONDAY_W41))
    tally.record(THREAT)
    assert digest.publish_due_digests(_Node(), BlackboxConfig(report=False, context_graph_id=GRAPH), tally) == 0


# ------------------------------------------------------------------ the reader


def _digest_row(reporter, week, counts, environment=NETWORK, graph=GRAPH):
    signer = ReportSigner(private_key=reporter.key, environment=environment, graph=graph)
    quads = digest.build_digest_quads(reporter_address=reporter.address, week=week, entries=digest.build_digest(counts),
                                      signer=signer)
    row = {"r": quads[0]["subject"]}
    for quad in quads:
        if quad["object"].startswith('"'):
            row[quad["predicate"].rsplit("/", 1)[-1]] = json.loads(quad["object"])
    return row


class _Graph:
    def __init__(self, reports=(), digests=()):
        self.rows = {"report": list(reports), "digest": list(digests)}

    def status(self):
        return {"networkId": NETWORK}

    def context_graphs(self):
        return []

    def query(self, sparql, cg_id, view=None, on_error=None, **kw):
        if "g:SightingDigest" in sparql:
            kind = "digest"
        elif "g:ThreatReport" in sparql:
            kind = "report"
        else:
            return []
        served, self.rows[kind] = self.rows[kind], []
        return served


def _counted(*reporters):
    return cv.CuratorView(counted={r.author: cv.CountedAuthor(r.author, r.address, "established", "", "2027-01-01")
                                   for r in reporters})


def test_heat_is_the_sum_of_bucket_midpoints_over_counted_authors_only():
    alice, bob, newcomer = Reporter("0xf79e09c14d5c229b89c4ac719117cf2bd56fe5f1"), Reporter("0x680964861de62daa6c399f0d8887109f83e17cff"), Reporter("0xff95c511e7c83f83bfefc70b7bba74f0ad0cbe50")
    rows = [_digest_row(alice, "2026-W40", {THREAT: 12}), _digest_row(bob, "2026-W40", {THREAT: 1}),
            _digest_row(newcomer, "2026-W40", {THREAT: 500})]
    found = digest_reader.verified_digests(rows, NETWORK, GRAPH)
    heat = digest_reader.heat_for_week(found, _counted(alice, bob), "2026-W40")
    assert heat[THREAT].agents == 55 + 1 and heat[THREAT].digests == 2      # the newcomer weighs 0
    assert digest_reader.heat_for_week(found, cv.CuratorView(), "2026-W40") == {}


def test_a_second_digest_for_the_same_week_is_ignored_first_observed_wins():
    alice = Reporter("0xf79e09c14d5c229b89c4ac719117cf2bd56fe5f1")
    first = digest_reader.verified_digests([_digest_row(alice, "2026-W40", {THREAT: 1})], NETWORK, GRAPH)[0]
    # The same (author, week) under another subject spelling cannot exist (the subject IS reporter+week),
    # so a duplicate can only be the same statement seen twice or a forged copy: either way one counts.
    later = digest_reader.VerifiedDigest(subject=first.subject + "-copy", author=first.author, reporter=first.reporter,
                                         week="2026-W40", entries=digest.build_digest({THREAT: 400}))
    kept = digest_reader.one_per_author_week([later, first], {first.subject: 1.0, later.subject: 2.0})
    assert kept == [first]


@pytest.mark.parametrize("tamper", ["unsigned", "other-network", "shown-week"])
def test_an_unverifiable_digest_is_ignored(tamper):
    alice = Reporter("0xf79e09c14d5c229b89c4ac719117cf2bd56fe5f1")
    row = _digest_row(alice, "2026-W40", {THREAT: 3}, environment="other" if tamper == "other-network" else NETWORK)
    if tamper == "unsigned":
        row.pop("signedStatement")
    if tamper == "shown-week":
        row["isoWeek"] = "2026-W41"
    assert digest_reader.verified_digests([row], NETWORK, GRAPH) == []


def test_the_community_read_carries_digests_and_heat_from_the_latest_week(monkeypatch):
    alice = Reporter("0xf79e09c14d5c229b89c4ac719117cf2bd56fe5f1")
    monkeypatch.setattr("plugins.blackbox.community.reader.read_curator_view", lambda *a, **k: _counted(alice))
    read = read_verified_reports(_Graph([signed_row(THREAT, alice)],
                                        [_digest_row(alice, "2026-W39", {THREAT: 1}),
                                         _digest_row(alice, "2026-W40", {THREAT: 50})]), CFG)
    assert [d.week for d in read.digests] == ["2026-W39", "2026-W40"]
    assert read.heat[THREAT].week == "2026-W40" and read.heat[THREAT].agents == 55
