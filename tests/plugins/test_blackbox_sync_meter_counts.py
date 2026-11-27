"""The sync meter's background count reader (``dashboard/sync_meter/download_counts.py``).

BB-004 (blackbox-dev, 2026-11-27): the node's downloaded count took 5.7–10.1 s on a busy
store and was read inline on every page poll under a 5 s cap, so a reachable node read as
"node offline" with every number blank. The reader keeps that read off the request path,
paces it, waits long enough for a busy store, and keeps the last good count with its age.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from plugins.blackbox import ruleset
from plugins.blackbox.dashboard.sync_meter import download_counts
from plugins.blackbox.dashboard.sync_meter.download_counts import DownloadCountReader

VM_GRAPH = "0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox-vm"
OTHER_GRAPH = "0x00000000000000000000000000000000000000aa/other-vm"
HELD = ruleset.DownloadTotals(assets=1749, triples=18_080_131)


class _Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


def _cfg(graph: str = VM_GRAPH) -> Any:
    return type("Cfg", (), {"context_graph_id": graph, "dkg_url": "http://127.0.0.1:1", "dkg_home": "/nonexistent"})()


def _reader(answers: list[Optional[ruleset.DownloadTotals]], clock: _Clock,
            start: Optional[Callable[[Callable[[], None]], None]] = None) -> tuple[DownloadCountReader, list[Any]]:
    """A reader whose reads return *answers* in turn (inline unless *start* is given); returns it and its read log."""
    reads: list[Any] = []

    def read(cfg: Any) -> Optional[ruleset.DownloadTotals]:
        reads.append(cfg.context_graph_id)
        return answers.pop(0)

    return DownloadCountReader(clock=clock, start=start or (lambda work: work()), read=read), reads


def test_a_page_poll_never_waits_on_the_count():
    """The read is handed to the background starter; the poll returns at once with no count yet."""
    started: list[Callable[[], None]] = []
    reader, reads = _reader([HELD], _Clock(), start=started.append)

    reading = reader.reading(_cfg(), reachable=True)

    assert len(started) == 1 and reads == []          # scheduled, not run on the poll
    assert reading.totals is None and not reading.fresh and reading.note


def test_one_read_at_a_time_and_at_most_once_per_refresh():
    clock = _Clock()
    started: list[Callable[[], None]] = []
    reader, _ = _reader([HELD, HELD], clock, start=started.append)

    reader.reading(_cfg(), reachable=True)
    clock.now += download_counts.REFRESH_SECONDS * 5    # due again, but the first read is still running
    reader.reading(_cfg(), reachable=True)
    assert len(started) == 1

    started[0]()                                       # the read finishes
    reader.reading(_cfg(), reachable=True)             # too soon after it started? no: 5 refreshes passed
    assert len(started) == 2
    started[1]()
    clock.now += 1
    reader.reading(_cfg(), reachable=True)
    assert len(started) == 2                           # within the refresh window: no new read


def test_a_failed_read_keeps_the_last_good_count_with_its_age():
    clock = _Clock()
    reader, _ = _reader([HELD, None], clock)

    first = reader.reading(_cfg(), reachable=True)
    clock.now += download_counts.REFRESH_SECONDS
    after_failure = reader.reading(_cfg(), reachable=True)

    assert first.totals == HELD and first.fresh and first.read_at == 1_000.0
    assert after_failure.totals == HELD and after_failure.read_at == 1_000.0   # never blanked, never zero


def test_a_count_older_than_the_freshness_window_is_stale_and_says_so():
    clock = _Clock()
    reader, _ = _reader([HELD, None, None, None, None], clock)
    reader.reading(_cfg(), reachable=True)

    for _ in range(4):
        clock.now += download_counts.REFRESH_SECONDS
        reading = reader.reading(_cfg(), reachable=True)

    assert reading.totals == HELD and not reading.fresh
    assert "min ago" in reading.note


def test_a_node_that_is_not_answering_is_never_queried():
    reader, reads = _reader([HELD], _Clock())

    reading = reader.reading(_cfg(), reachable=False)

    assert reads == [] and reading.totals is None


def test_a_switch_to_another_graph_never_shows_the_old_graphs_count():
    clock = _Clock()
    reader, _ = _reader([HELD, None], clock)
    reader.reading(_cfg(VM_GRAPH), reachable=True)

    other = reader.reading(_cfg(OTHER_GRAPH), reachable=True)

    assert other.totals is None


def test_a_read_that_raises_is_a_failed_read_not_a_broken_page():
    def boom(cfg: Any) -> Optional[ruleset.DownloadTotals]:
        raise RuntimeError("store went away mid-read")

    reader = DownloadCountReader(clock=_Clock(), start=lambda work: work(), read=boom)

    reading = reader.reading(_cfg(), reachable=True)

    assert reading.totals is None and "busy" in reading.note


def test_the_node_read_waits_long_enough_for_a_busy_store(monkeypatch):
    """Measured 4.3–10.1 s on blackbox-dev; the old 5 s cap is what made BB-004."""
    seen: dict[str, Any] = {}

    def totals(client: Any, graph: str, timeout: Optional[float] = None) -> ruleset.DownloadTotals:
        seen["timeout"], seen["graph"] = timeout, graph
        return HELD

    monkeypatch.setattr(ruleset, "verified_download_totals", totals)
    reader = DownloadCountReader(clock=_Clock(), start=lambda work: work())

    reading = reader.reading(_cfg(), reachable=True)

    assert reading.totals == HELD and seen["graph"] == VM_GRAPH
    assert seen["timeout"] >= 30.0
