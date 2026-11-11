"""A degraded store is probed, not waited on (2026-10-22, FIX-0161).

The live lookup used to ask the store on every tool call even while it was
degraded, paying the 2 s timeout per chunk, per category, for the whole time a
wedged Oxigraph took to recover. Now, while degraded, one lookup probes it at
most every RETRY_AFTER_SECONDS and the rest answer could-not-tell at once.
"""

from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from plugins.blackbox.kernel.store.client import StoreAnswer
from plugins.blackbox.ruleset.live import lookup as live_lookup
from plugins.blackbox.ruleset.live.health import LookupHealth


class _Store:
    def __init__(self, answers):
        self.answers = list(answers)
        self.asked = 0

    def select(self, sparql, *, timeout=None):
        self.asked += 1
        return self.answers.pop(0) if self.answers else StoreAnswer(None, "timeout")


def _lookup(tmp_path, store):
    scope = SimpleNamespace(ready=True, spellings=lambda eco, name: [name],
                            assertion_graphs=set(), suppressed_subjects=set())
    return live_lookup.VerifiedLookup(scope, store, LookupHealth(tmp_path / "state.json"))


@pytest.fixture
def clock(monkeypatch):
    now = [1_000_000.0]
    monkeypatch.setattr(time, "time", lambda: now[0])
    return now


def test_while_degraded_the_store_is_not_asked_again_within_the_retry_window(tmp_path, clock):
    store = _Store([StoreAnswer(None, "timeout")])
    lookup = _lookup(tmp_path, store)

    first = lookup.dependencies([("npm", "left-pad", "1.0.0")])
    second = lookup.dependencies([("npm", "left-pad", "1.0.0")])

    assert first.outcome == live_lookup.COULD_NOT_TELL and store.asked == 1
    assert second.outcome == live_lookup.COULD_NOT_TELL and store.asked == 1
    assert "next probe" in second.reason


def test_after_the_window_one_probe_goes_out_and_a_good_answer_closes_the_breaker(tmp_path, clock):
    store = _Store([StoreAnswer(None, "timeout"), StoreAnswer([]), StoreAnswer([])])
    lookup = _lookup(tmp_path, store)
    lookup.dependencies([("npm", "a", "1")])
    clock[0] += live_lookup.RETRY_AFTER_SECONDS + 1

    probe = lookup.dependencies([("npm", "a", "1")])
    assert probe.outcome == live_lookup.CLEAN and store.asked == 2

    again = lookup.dependencies([("npm", "a", "1")])
    assert again.outcome == live_lookup.CLEAN and store.asked == 3   # healthy again: every call asks


def test_a_skipped_lookup_is_not_counted_as_a_failure(tmp_path, clock):
    """Skips never move the clock, or the breaker would never retry."""
    store = _Store([StoreAnswer(None, "timeout")])
    lookup = _lookup(tmp_path, store)
    lookup.iocs(["ioc:domain:example.test"])
    for _ in range(5):
        lookup.iocs(["ioc:domain:example.test"])

    assert lookup.health.read().failures == 1


def test_a_steady_ok_state_is_read_from_disk_once_per_process(tmp_path, monkeypatch):
    """When the file already said "ok", record(known=True) returned without keeping that state,
    so every later lookup in that agent process read the JSON file again — about four file reads
    per tool call on the hot path. The state read from the file is now kept."""
    path = tmp_path / "state.json"
    LookupHealth(path).record(True)          # another process wrote "ok"
    health = LookupHealth(path)
    reads = []
    real = LookupHealth._read_file
    monkeypatch.setattr(LookupHealth, "_read_file", lambda self: reads.append(1) or real(self))
    for _ in range(20):
        health.record(True)
        health.read()
    assert len(reads) == 1 and health.read().state == "ok"
