"""A finding's node-facing follow-up runs after the hook has answered.

Recording a finding locally is instant. The rest — asking the node who it is,
writing the private audit record, handing off the community share — used to run
on the hook's thread, so "block this call" waited for the node. These tests use
the REAL queue (``real_report_queue``); the rest of the suite runs follow-up
inline through tests/plugins/conftest.py.
"""

from __future__ import annotations

import logging
import threading

from plugins.blackbox import audit, guard
from plugins.blackbox.guard import report_queue, reporting
from plugins.blackbox.guard.report_queue import ReportQueue
from plugins.blackbox.kernel.config import BlackboxConfig

WAIT_S = 10


def test_reporting_returns_while_the_node_facing_step_is_still_running(real_report_queue, monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path))
    started, release, recorded = threading.Event(), threading.Event(), []
    monkeypatch.setattr(reporting.audit, "record", lambda **row: recorded.append(row["event"]))
    monkeypatch.setattr(reporting.desktop, "announce_findings", lambda *a, **k: None)

    def slow_node(cfg, event, finding_dicts):
        started.set()
        assert release.wait(WAIT_S)

    monkeypatch.setattr(reporting, "_share_findings", slow_node)
    finding = reporting.detection.Finding(category="ioc", severity="high", title="t", identifier="ioc:domain:x.example",
                                          source="public")
    reporting._report_and_audit(BlackboxConfig(), "pre_tool_call", [finding], {})
    # back already: the local row is written and the node-facing step has not finished
    assert recorded == ["pre_tool_call"]
    assert started.wait(WAIT_S) and guard.reports_settled(0.05) is False
    release.set()
    assert guard.reports_settled(WAIT_S) is True


def test_follow_up_queued_in_a_sandbox_run_stays_in_the_sandbox(real_report_queue, monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path))
    seen = []
    monkeypatch.setattr(reporting.audit, "record", lambda **row: None)
    monkeypatch.setattr(reporting.desktop, "announce_findings", lambda *a, **k: None)
    monkeypatch.setattr(reporting, "_share_findings", lambda *a: seen.append(audit.in_sandbox_run()))
    finding = reporting.detection.Finding(category="ioc", severity="high", title="t", identifier="ioc:domain:y.example",
                                          source="public")
    with audit.sandbox_run():
        reporting._report_and_audit(BlackboxConfig(), "pre_tool_call", [finding], {})
    reporting._report_and_audit(BlackboxConfig(), "pre_tool_call", [finding], {})
    assert guard.reports_settled(WAIT_S) and seen == [True, False]


def test_jobs_run_one_at_a_time_in_the_order_submitted():
    queue, order, running, overlaps = ReportQueue(), [], threading.Lock(), []

    def job(number):
        def run():
            overlaps.append(not running.acquire(blocking=False))
            order.append(number)
            running.release()
        return run

    for number in range(50):
        assert queue.submit(job(number)) is True
    assert queue.settled(WAIT_S) and order == list(range(50)) and not any(overlaps)


def test_a_failing_job_is_logged_by_class_only_and_the_next_still_runs(caplog):
    queue, done = ReportQueue(), []

    def fails():
        raise RuntimeError("argument text that must not reach the log")

    with caplog.at_level(logging.WARNING, logger=report_queue.__name__):
        queue.submit(fails)
        queue.submit(lambda: done.append("next"))
        assert queue.settled(WAIT_S)
    assert done == ["next"]
    assert "RuntimeError" in caplog.text and "argument text" not in caplog.text


def test_a_full_queue_drops_the_new_job_and_says_so(caplog):
    queue, release, started = ReportQueue(max_waiting=2), threading.Event(), threading.Event()
    queue.submit(lambda: (started.set(), release.wait(WAIT_S)))
    assert started.wait(WAIT_S)                       # the worker holds the first job
    assert queue.submit(lambda: None) and queue.submit(lambda: None)
    with caplog.at_level(logging.WARNING, logger=report_queue.__name__):
        assert queue.submit(lambda: None) is False    # two already waiting
    assert "queue is full" in caplog.text
    release.set()
    assert queue.settled(WAIT_S)


def test_the_worker_ends_when_idle_and_a_later_job_starts_a_new_one():
    queue, names = ReportQueue(), []
    queue.submit(lambda: names.append(threading.current_thread().name))
    assert queue.settled(WAIT_S)
    for _ in range(100):
        if queue._worker is None:
            break
        threading.Event().wait(0.01)
    assert queue._worker is None
    queue.submit(lambda: names.append(threading.current_thread().daemon))
    assert queue.settled(WAIT_S) and names == [report_queue.WORKER_NAME, True]
