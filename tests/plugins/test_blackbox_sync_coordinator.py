"""Behavior contracts for Blackbox's regular-first sync state machine."""

import pytest

from _blackbox_loader import load_blackbox


coordinator_mod = load_blackbox("sync_coordinator")


def _coordinator(events):
    def writer(status, **details):
        event = {"status": status, **details}
        events.append(event)
        return event

    return coordinator_mod.HybridSyncCoordinator(writer, "owner/graph", "curator")


def test_fallback_is_forbidden_while_regular_job_is_active():
    events = []
    coordinator = _coordinator(events)
    coordinator.publish_initial()
    coordinator.start_regular()
    coordinator.observe_regular(
        {"catchup": {"jobId": "job-1", "status": "running"}}
    )

    with pytest.raises(RuntimeError, match="fallback is forbidden"):
        coordinator.queue_fallback("regular path is slow")

    assert events[-1]["coordinator_state"] == coordinator_mod.REGULAR_ACTIVE
    assert events[-1]["sync_mode"] == "regular"


def test_terminal_regular_failure_can_cross_drain_gate_to_fallback():
    events = []
    coordinator = _coordinator(events)
    coordinator.publish_initial()
    coordinator.start_regular()
    coordinator.observe_regular({"jobId": "job-1", "status": "failed"})
    coordinator.queue_fallback("no regular peer had the graph")
    coordinator.start_fallback()

    assert [event["coordinator_state"] for event in events] == [
        coordinator_mod.PREPARING,
        coordinator_mod.REGULAR_SUBSCRIBING,
        coordinator_mod.REGULAR_TERMINAL,
        coordinator_mod.FALLBACK_PENDING,
        coordinator_mod.FALLBACK_ACTIVE,
    ]
    assert events[-1]["sync_mode"] == "fallback"
    assert events[-1]["regular_job_id"] == "job-1"


def test_clean_but_empty_regular_result_must_be_explicitly_marked():
    events = []
    coordinator = _coordinator(events)
    coordinator.publish_initial()
    coordinator.start_regular()
    coordinator.observe_regular({"jobId": "job-1", "status": "done"})

    with pytest.raises(RuntimeError, match="fallback is forbidden"):
        coordinator.queue_fallback("empty")

    coordinator.mark_regular_empty("empty")
    coordinator.queue_fallback("empty")
    assert events[-1]["coordinator_state"] == coordinator_mod.FALLBACK_PENDING


def test_regular_success_finishes_without_entering_fallback_mode():
    events = []
    coordinator = _coordinator(events)
    coordinator.publish_initial()
    coordinator.start_regular()
    coordinator.observe_regular({"jobId": "job-1", "status": "done"})
    coordinator.start_reconciling(public_entries=12)
    coordinator.complete(public_entries=12)

    assert events[-1]["status"] == "done"
    assert events[-1]["coordinator_state"] == coordinator_mod.COMPLETE
    assert not any(event["sync_mode"] == "fallback" for event in events)
