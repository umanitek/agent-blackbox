"""KI-304: a ruleset's compile time and its refresh schedule are two fields.

The refresh cycle used to BACKDATE ``synced_at`` to pull the next refresh
forward while the verified graph was still arriving (KI-288). Every display
and staleness check reads ``synced_at`` too, so a refresh from minutes ago
showed as "Last sync 1h ago" (bench bb-ours, 2026-10-08). Now ``synced_at`` is
only ever the real compile time and the schedule lives in ``refresh_due_at``.
"""

from __future__ import annotations

from typing import List

import pytest

from plugins.blackbox.kernel import constants
from plugins.blackbox.ruleset import compiler, disk_cache, refresh_cycle
from plugins.blackbox.ruleset.partitions import reader as partition_reader

NOW = 1_000_000.0
INTERVAL = 3600


class _Config:
    sync_interval = INTERVAL
    context_graph_id = "cg"


@pytest.fixture
def clock(monkeypatch, tmp_path):
    """One fixed clock for the refresh cycle and the progress record, in a throwaway home."""
    monkeypatch.setattr(constants, "blackbox_home", lambda: tmp_path)
    monkeypatch.setattr(refresh_cycle.time, "time", lambda: NOW)
    return NOW


def _compiled_ruleset() -> compiler.Ruleset:
    rs = compiler.build_from_rows([])
    rs.context_graph_id = "cg"
    rs.synced_at = NOW
    return rs


def _catching_up(compiled: int, total: int) -> None:
    partition_reader.record_progress("cg", partition_reader.PartitionRead(total=total, compiled=compiled))


def test_an_early_refresh_never_moves_the_compile_time(clock):
    _catching_up(137, 564)
    rs = _compiled_ruleset()

    refresh_cycle._schedule_next_refresh(rs, _Config(), False)

    assert rs.synced_at == NOW
    assert rs.refresh_due(INTERVAL) == NOW + refresh_cycle._CATCHING_UP_RETRY_S


def test_an_empty_read_asks_for_the_short_retry_without_moving_the_compile_time(clock):
    rs = _compiled_ruleset()

    refresh_cycle._schedule_next_refresh(rs, _Config(), True)

    assert rs.synced_at == NOW
    assert rs.refresh_due(INTERVAL) == NOW + refresh_cycle._EMPTY_RULESET_RETRY_S


def test_a_generation_that_caught_up_drops_its_earlier_early_schedule(clock, monkeypatch):
    monkeypatch.setattr(partition_reader, "GROWTH_QUIET_SECONDS", 0)
    _catching_up(564, 564)
    rs = _compiled_ruleset()
    rs.refresh_due_at = NOW - 10            # left over from a catching-up generation it was reused from

    refresh_cycle._schedule_next_refresh(rs, _Config(), False)

    assert rs.refresh_due_at == 0.0
    assert rs.refresh_due(INTERVAL) == NOW + INTERVAL


def test_an_early_schedule_never_pushes_the_refresh_past_one_interval():
    rs = compiler.Ruleset(synced_at=NOW, refresh_due_at=NOW + 5 * INTERVAL)

    assert rs.refresh_due(INTERVAL) == NOW + INTERVAL


def test_the_schedule_survives_the_disk_cache(clock):
    rs = _compiled_ruleset()
    rs.refresh_due_at = NOW + 120

    disk_cache._write_cache(rs)
    back = disk_cache._read_cache()

    assert back is not None
    assert back.synced_at == NOW and back.refresh_due_at == NOW + 120


def test_a_due_generation_is_refreshed_although_it_was_compiled_moments_ago(clock, monkeypatch):
    """The hooks' lazy refresh follows the schedule, not the compile age."""
    rs = _compiled_ruleset()
    rs.refresh_due_at = NOW - 1
    started: list[str] = []

    class _Thread:
        def __init__(self, target, args, name, daemon):
            self.name = name

        def start(self):
            started.append(self.name)

    monkeypatch.setattr(refresh_cycle, "_latest_cached_ruleset", lambda graph="": rs)
    monkeypatch.setattr(refresh_cycle.threading, "Thread", _Thread)
    monkeypatch.setattr(refresh_cycle, "_refreshing", False)

    refresh_cycle.get(_Config())

    assert started == ["blackbox-ruleset"]


def test_a_rules_cache_that_cannot_be_saved_is_said_out_loud(tmp_path, monkeypatch, caplog):
    """A failed ruleset.json write was logged at DEBUG: on a full disk the node kept serving a
    generation that never persisted and nothing visible said so (fail-open ≠ fail-silent)."""
    import logging
    from plugins.blackbox.ruleset import compiler, disk_cache

    def disk_full(path, text, **_kw):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(disk_cache, "atomic_write", disk_full)
    with caplog.at_level(logging.WARNING):
        disk_cache._write_cache(compiler.Ruleset())
    assert any("could not save the rules" in record.getMessage() for record in caplog.records)
