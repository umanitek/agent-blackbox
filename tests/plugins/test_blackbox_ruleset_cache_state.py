"""What a cached generation carries, and who may change it (review 2026-11-26, findings 11 and 12).

* Finding 11: ``curator_read_unavailable`` / ``community_read_unavailable`` were
  plain attributes, never saved, so a generation loaded from ``ruleset.json``
  lost its "could not tell" and the direct reader served it as known. They are
  fields now and survive the round trip (an older cache without them loads
  as False). The trusted manifest's legacy pin is kept the same way: a later
  refresh whose curator read could not tell still knows the last verdict.
* Finding 12: the generation in memory is read by every hook thread, so
  nothing edits it — ``request_refresh_now`` works on a copy (``derive``); and a
  generation read from disk is stamped with the stamp taken BEFORE the read, so a
  file another process replaced during the read is reloaded, never pinned stale.
"""

from __future__ import annotations

import json
import time

from plugins.blackbox.kernel import constants
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.ruleset import compiler, disk_cache, pulse_beat, refresh_cycle

GRAPH = "0x" + "a" * 40 + "/custom-graph"


def _round_trip(rs: compiler.Ruleset) -> compiler.Ruleset:
    return disk_cache._deserialize(json.loads(json.dumps(disk_cache._serialize(rs))))


def test_could_not_tell_survives_the_cache_round_trip():
    rs = compiler.Ruleset(context_graph_id=GRAPH)
    rs.curator_read_unavailable = True
    rs.community_read_unavailable = True
    loaded = _round_trip(rs)
    assert loaded.curator_read_unavailable is True and loaded.community_read_unavailable is True
    older = disk_cache._serialize(compiler.Ruleset(context_graph_id=GRAPH))
    for key in ("curator_read_unavailable", "community_read_unavailable", "curator_legacy_assets_hash"):
        older.pop(key, None)
    old_loaded = disk_cache._deserialize(older)
    assert (old_loaded.curator_read_unavailable, old_loaded.community_read_unavailable) == (False, False)
    assert old_loaded.curator_legacy_assets_hash is None                      # an older cache: could not tell


def test_the_legacy_pin_survives_the_cache_round_trip():
    for pin in ("", "ab" * 32, None):
        assert _round_trip(compiler.Ruleset(curator_legacy_assets_hash=pin)).curator_legacy_assets_hash == pin


class _Config:
    sync_interval = 3600
    context_graph_id = GRAPH
    dkg_url = constants.DEFAULT_DKG_URL
    dkg_home = None


def test_request_refresh_now_never_edits_the_generation_hooks_are_reading(monkeypatch, tmp_path):
    monkeypatch.setattr(constants, "blackbox_home", lambda: tmp_path)
    monkeypatch.setattr(refresh_cycle, "_memory", refresh_cycle._new_memory())
    serving = compiler.build_from_rows([])
    serving.context_graph_id, serving.synced_at = GRAPH, time.time()
    disk_cache._write_cache(serving)
    refresh_cycle._memory.store(serving)
    assert pulse_beat.request_refresh_now(_Config()) is True
    assert serving.refresh_due_at == 0.0                                       # untouched
    assert refresh_cycle.peek(_Config()).refresh_due(3600) <= time.time()      # the copy was installed


def test_a_file_replaced_during_the_read_is_reloaded_not_pinned(monkeypatch):
    stamp = {"now": 1}
    read_then, replaced = compiler.Ruleset(context_graph_id=GRAPH, synced_at=1.0), compiler.Ruleset(
        context_graph_id=GRAPH, synced_at=2.0)
    reads = []

    def read_cache():
        reads.append(1)
        if len(reads) == 1:
            return None                     # the memory's own look: nothing on disk yet
        stamp["now"] = 2                    # another process replaces the file while this read runs
        return read_then

    monkeypatch.setattr(refresh_cycle, "_cache_file_stamp", lambda: stamp["now"])
    monkeypatch.setattr(disk_cache, "_read_cache", read_cache)
    monkeypatch.setattr(refresh_cycle, "_memory", refresh_cycle._new_memory())
    assert refresh_cycle._current_or_empty(BlackboxConfig(context_graph_id=GRAPH)) is read_then
    monkeypatch.setattr(disk_cache, "_read_cache", lambda: replaced)
    assert refresh_cycle._memory.current() is replaced
