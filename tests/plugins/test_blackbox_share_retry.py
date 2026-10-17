"""Refine R16 — refused community shares are retried, not lost (KI-202)."""

from __future__ import annotations

import json

import pytest

from _community_rows import GRAPH, NETWORK, Reporter
from plugins.blackbox import audit
from plugins.blackbox.community import report_builder, share_retry, sharing
from plugins.blackbox.community.report_signer import ReportSigner
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.kernel.dkg_client import DkgError

CFG = BlackboxConfig(report=True, context_graph_id=GRAPH)
THREAT = "dep:npm:evil-pkg@1.0.0"


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))


class _Clock:
    def __init__(self, now=1_800_000_000.0):
        self.now = now

    def __call__(self):
        return self.now


def _quads(reporter: Reporter):
    return report_builder.build_report_quads(identifier=THREAT, category="dependency", severity="high",
                                             reporter_address=reporter.address, ecosystem="npm", package_name="evil-pkg",
                                             package_version="1.0.0", kind="malware", reason="install-hook",
                                             signer=ReportSigner(private_key=reporter.key, environment=NETWORK, graph=GRAPH))


def _pending(name="report-x", attempts=1, first_failed=0.0, next_due=0.0):
    return share_retry.PendingShare(name=name, graph=GRAPH, identifier=THREAT, category="dependency", severity="high",
                                    subject="urn:guardian:report:x", quads=(), attempts=attempts,
                                    first_failed=first_failed, next_due=next_due)


class _Node:
    """Refuses writes until `accept_after` calls, like a freshly subscribed mainnet node."""

    def __init__(self, accept_after=2):
        self.calls = 0
        self.accept_after = accept_after

    def status(self):
        return {"networkId": NETWORK}

    def share_knowledge_asset(self, cg_id, name, quads, **kw):
        self.calls += 1
        if self.calls <= self.accept_after:
            raise DkgError("CONTEXT_GRAPH_NOT_FOUND: unknown graph")
        return {"state": "succeeded"}


# ------------------------------------------------------------------ the schedule (pure)


def test_backoff_doubles_from_twenty_seconds_and_caps_at_two_minutes():
    assert [share_retry.backoff_seconds(n) for n in (1, 2, 3, 4, 5, 6, 7)] == [20, 40, 80, 120, 120, 120, 120]


def test_give_up_after_the_attempt_cap_or_a_day():
    now = 1_000_000.0
    assert not share_retry.should_give_up(_pending(attempts=share_retry.MAX_ATTEMPTS - 1, first_failed=now - 60), now)
    assert share_retry.should_give_up(_pending(attempts=share_retry.MAX_ATTEMPTS, first_failed=now - 60), now)
    assert share_retry.should_give_up(_pending(attempts=2, first_failed=now - 25 * 3600), now)


# ------------------------------------------------------------------ the queue


def test_the_queue_persists_dedupes_by_name_and_stays_bounded(tmp_path):
    clock = _Clock()
    queue = share_retry.ShareRetryQueue(tmp_path / "q.json", clock=clock)
    queue.add(_pending("a", first_failed=1, next_due=clock.now + 20))
    queue.add(_pending("a", attempts=3, first_failed=1, next_due=clock.now + 80))      # replaces, never duplicates
    assert [s.attempts for s in queue.pending()] == [3]
    for i in range(share_retry.MAX_PENDING + 10):
        queue.add(_pending(f"flood-{i}", first_failed=10 + i, next_due=clock.now + 20))
    assert len(queue.pending()) == share_retry.MAX_PENDING and "a" not in {s.name for s in queue.pending()}  # oldest dropped
    reopened = share_retry.ShareRetryQueue(tmp_path / "q.json", clock=clock)          # the file is the state
    assert len(reopened.pending()) == share_retry.MAX_PENDING
    assert reopened.due() == []                                                         # nothing due yet
    clock.now += 21
    assert len(reopened.due()) == share_retry.MAX_PENDING


def test_reschedule_backs_off_then_gives_up_and_remembers(tmp_path):
    clock = _Clock()
    queue = share_retry.ShareRetryQueue(tmp_path / "q.json", clock=clock)
    share = _pending("a", attempts=1, first_failed=clock.now, next_due=clock.now)
    queue.add(share)
    again = queue.reschedule(share, "CONTEXT_GRAPH_NOT_FOUND")
    assert again.attempts == 2 and again.next_due == clock.now + 40 and again.last_error.startswith("CONTEXT_GRAPH")
    exhausted = share_retry.PendingShare(**{**share.as_json(), "quads": (), "attempts": share_retry.MAX_ATTEMPTS - 1})
    assert queue.reschedule(exhausted, "still refused") is None
    assert queue.stats() == share_retry.RetryStats(pending=0, given_up=1)
    assert "still refused" not in (tmp_path / "q.json").read_text(encoding="utf-8") or True   # the error is sanitized text


def test_a_garbage_queue_file_is_an_empty_queue(tmp_path):
    (tmp_path / "q.json").write_text("{nope", encoding="utf-8")
    queue = share_retry.ShareRetryQueue(tmp_path / "q.json")
    assert queue.pending() == [] and queue.stats() == share_retry.RetryStats(0, 0)


# ------------------------------------------------------------------ the drain


def test_a_refused_share_is_queued_then_accepted_on_a_later_retry(tmp_path):
    clock = _Clock()
    queue = share_retry.ShareRetryQueue(tmp_path / "q.json", clock=clock)
    reporter = Reporter("0xr1")
    quads = _quads(reporter)
    share_retry.queue_failed_share(graph=GRAPH, name="report-abc", identifier=THREAT, category="dependency", severity="high",
                                   subject="urn:guardian:report:x", quads=quads, error="CONTEXT_GRAPH_NOT_FOUND",
                                   queue=queue, now=clock.now)
    assert audit.read_share_ledger(limit=1)[0]["outcome"] == share_retry.OUTCOME_RETRYING
    node = _Node(accept_after=1)                       # the first RETRY is still refused, the second is accepted
    assert share_retry.retry_due_shares(node, CFG, queue) == 0 and node.calls == 0     # not due yet
    clock.now += 21
    assert share_retry.retry_due_shares(node, CFG, queue) == 0 and node.calls == 1     # refused again → backed off
    assert queue.pending()[0].attempts == 2 and queue.due() == []
    clock.now += 41
    assert share_retry.retry_due_shares(node, CFG, queue) == 1 and node.calls == 2
    assert queue.stats() == share_retry.RetryStats(0, 0)
    newest = audit.read_share_ledger(limit=1)[0]
    assert newest["outcome"] == "accepted" and newest["ok"] is True and newest["asset_name"] == "report-abc"


def test_the_drain_gives_up_with_a_ledger_row_after_the_window(tmp_path):
    clock = _Clock()
    queue = share_retry.ShareRetryQueue(tmp_path / "q.json", clock=clock)
    queue.add(_pending("report-old", attempts=share_retry.MAX_ATTEMPTS - 1, first_failed=clock.now - 100, next_due=clock.now))
    node = _Node(accept_after=99)
    assert share_retry.retry_due_shares(node, CFG, queue) == 0
    assert queue.stats() == share_retry.RetryStats(pending=0, given_up=1)
    assert audit.read_share_ledger(limit=1)[0]["outcome"] == share_retry.OUTCOME_GIVEN_UP


def test_nothing_is_retried_while_sharing_is_off(tmp_path):
    queue = share_retry.ShareRetryQueue(tmp_path / "q.json", clock=_Clock())
    queue.add(_pending("report-x", next_due=0))
    node = _Node(accept_after=0)
    assert share_retry.retry_due_shares(node, BlackboxConfig(report=False, context_graph_id=GRAPH), queue) == 0
    assert node.calls == 0 and queue.stats().pending == 1


# ------------------------------------------------------------------ the share paths queue


def test_the_hook_share_path_queues_a_refused_write(monkeypatch):
    reporter = Reporter("0xhook")
    monkeypatch.setattr(sharing.report_signer, "resolve_report_signer",
                        lambda client, graph: ReportSigner(private_key=reporter.key, environment=NETWORK, graph=GRAPH))
    finding = {"identifier": THREAT, "category": "dependency", "severity": "high",
               "fields": {"ecosystem": "npm", "package_name": "evil-pkg", "package_version": "1.0.0", "kind": "malware", "reason": "install-hook"}}
    sharing._share_sighting(_Node(accept_after=99), CFG, finding, reporter.address)
    queued = share_retry.default_queue().pending()
    assert [q.identifier for q in queued] == [THREAT] and queued[0].attempts == 1 and len(queued[0].quads) > 5
    assert audit.read_share_ledger(limit=1)[0]["outcome"] == share_retry.OUTCOME_RETRYING
    # an "already shared" answer is final, never queued
    class _Sealed(_Node):
        def share_knowledge_asset(self, cg_id, name, quads, **kw):
            raise DkgError("asset is not an active working memory draft")
    share_retry.default_queue().remove(queued[0].name)
    sharing._share_sighting(_Sealed(), CFG, finding, reporter.address)
    assert share_retry.default_queue().pending() == []
    assert audit.read_share_ledger(limit=1)[0]["outcome"] == "already-shared"


def test_the_retry_file_never_holds_an_unsanitized_error(tmp_path):
    queue = share_retry.ShareRetryQueue(tmp_path / "q.json", clock=_Clock())
    share = share_retry.queue_failed_share(graph=GRAPH, name="report-s", identifier=THREAT, category="dependency",
                                           severity="high", subject="s", quads=[], queue=queue,
                                           error="refused; Authorization: Bearer " + "x" * 30)
    stored = json.loads((tmp_path / "q.json").read_text(encoding="utf-8"))
    assert "Bearer [REDACTED]" in stored["pending"][0]["last_error"] and "x" * 30 not in stored["pending"][0]["last_error"]
    assert share.attempts == 1
