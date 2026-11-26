"""When the threat graph cannot answer, Blackbox SAYS so: one high finding per episode, never a
flood (``dashboard/sync_meter/lookup_alarm``, called by the dashboard's background look).

Linux round L8 (BB-LINUX-PENDING-7227a5): with the graph store stopped or stalled a graph-listed
package installed and nothing said so — no finding, no notice ("DKG node unreachable" in status
only). What Blackbox does in that case (lets the action through) is an open owner decision and
is NOT tested here; only that it is never silent.
"""

from __future__ import annotations

import pytest

from plugins.blackbox import audit
from plugins.blackbox.dashboard import sync_meter
from plugins.blackbox.dashboard.agent_hooks_routes import _Sweeper
from plugins.blackbox.ruleset.live.health import DEGRADED, OK, LookupState

alarm = sync_meter.lookup_alarm


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    (tmp_path / "bb").mkdir()
    return tmp_path


def _said() -> list[dict]:
    return [row for row in audit.read_findings(limit=50) if row.get("identifier") == alarm.UNAVAILABLE_ID]


def test_a_store_that_cannot_answer_is_one_high_finding_per_episode(home):
    down = LookupState(DEGRADED, "connection refused", 1000.0, 3, 1010.0)
    assert alarm.check(down, now=2000.0) is True
    [found] = _said()
    assert found["severity"] == "high" and "not being checked" in found["title"]
    assert alarm.check(LookupState(DEGRADED, "connection refused", 1000.0, 9, 1500.0), now=2100.0) is False   # same episode
    assert alarm.check(LookupState(DEGRADED, "timed out", 2050.0, 1, 2050.0), now=2200.0) is False            # flapping: rate-limited
    assert alarm.check(LookupState(DEGRADED, "timed out", 9000.0, 1, 9000.0), now=2000.0 + alarm.MIN_INTERVAL_SECONDS + 1) is True
    assert len(_said()) == 2
    assert alarm.check(LookupState(OK, "", 9100.0, 0, 9100.0), now=99999.0) is False


def test_an_outage_that_ended_before_the_dashboard_looked_is_still_said_once(home, tmp_path):
    """On bb-l7-u24 (L-W5 proof run) the store was OOM-killed and back while the dashboard was stopped:
    the recorded state read "ok" again by the time the dashboard looked, and nothing was said."""
    from plugins.blackbox.ruleset.live.health import LookupHealth
    health = LookupHealth(tmp_path / "lookups.json")
    health.record(False, "store did not answer", now=5000.0)
    health.record(False, "store did not answer", now=5030.0)
    health.record(True, now=5100.0)                                     # back before anyone looked
    state = LookupHealth(tmp_path / "lookups.json").read()               # another process reads the file
    assert not state.degraded and (state.ended_since, state.ended_until) == (5000.0, 5100.0)
    assert alarm.check(state, now=6000.0) is True
    assert "From " in _said()[0]["evidence"] and alarm.check(state, now=99999.0) is False


def test_the_dashboards_background_look_raises_it(home, monkeypatch):
    seen = []
    monkeypatch.setattr(alarm, "check", lambda *a, **k: seen.append(1) or False)
    from plugins.blackbox import agent_hooks
    for name in ("present", "keep_hooks", "sweep"):
        monkeypatch.setattr(agent_hooks, name, lambda *a, **k: frozenset())
    monkeypatch.setattr(agent_hooks.tracking, "observe_now", lambda: None)
    _Sweeper().step()
    assert seen
