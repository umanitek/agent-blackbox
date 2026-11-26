"""The finding that says the threat graph cannot answer — never silent, never a flood.

Linux round L8 (BB-LINUX-PENDING-7227a5, the SILENT part only): with the graph store stopped or
stalled, verified lookups could not answer and a graph-listed package installed. What Blackbox does
then (let the action through, Blackbox never breaks the agent) is an OPEN owner decision and is not
changed here. What was wrong besides is that nothing said so: `blackbox status` read "DKG node
unreachable", the panel "checks paused", and no finding, no notice. Now, the first time the
lookups' recorded state (``ruleset.live.HEALTH``, written by every process that looks up) is
degraded, ONE high-severity finding is recorded — which the notifier and the dashboard's findings
show — naming what it means: packages are not being checked against the threat graph.

Rate limit: one finding per degraded episode (keyed on the episode's start, kept in
:data:`STATE_NAME` so a dashboard restart does not say it again), and never more than one per
:data:`MIN_INTERVAL_SECONDS` whatever the store does (a flapping store is one finding).

Usage (the dashboard's background look, every few seconds)::

    lookup_alarm.check()    # True when it recorded the finding now
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from ...kernel import constants
from ...kernel.bounded_files import read_json_object, write_json_object

logger = logging.getLogger(__name__)

#: The finding's identifier and the audit event it is recorded under.
UNAVAILABLE_ID = "blackbox:threat-graph-unavailable"
UNAVAILABLE_EVENT = "threat_graph_unavailable"
TITLE = "Threat graph unavailable — packages are not being checked against it"
#: At most one finding this often, however often the store goes away.
MIN_INTERVAL_SECONDS = 30 * 60
#: The record of what was last said (the episode's start and when), in Blackbox's home.
STATE_NAME = "threat-graph-alarm.json"


def _state_path():
    return constants.blackbox_home() / STATE_NAME


def finding(reason: str, since: float) -> dict[str, Any]:
    """The finding for an episode that began at *since* with *reason*."""
    began = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(since)) if since else "a moment ago"
    return {"identifier": UNAVAILABLE_ID, "category": "dependency", "severity": "high", "title": TITLE,
            "matched": "threat-graph-unavailable", "source": "custom", "kind": "flag-only", "confirmed": False,
            "evidence": f"Since {began}: {reason or 'the graph store did not answer'}"[:300],
            "advice": ("Until the threat graph answers again, packages and addresses your agents use are not checked against "
                       "it. Check Blackbox's node and its store (`blackbox status`), then run `blackbox sync --wait`.")}


def check(health: Optional[Any] = None, now: Optional[float] = None) -> bool:
    """Record the finding when the lookups are degraded and this episode was not said yet (and the
    last one is :data:`MIN_INTERVAL_SECONDS` old). Fail-open: False on any error."""
    from ... import audit, ruleset   # late: the dashboard's look only
    try:
        state = ruleset.live.HEALTH.read() if health is None else health
        if not getattr(state, "degraded", False) or not constants.blackbox_home().is_dir():
            return False
        now = time.time() if now is None else now
        said = read_json_object(_state_path()) or {}
        since = float(getattr(state, "since", 0.0) or 0.0)
        if said.get("since") == since or now - float(said.get("at") or 0.0) < MIN_INTERVAL_SECONDS:
            return False
        audit.record(event=UNAVAILABLE_EVENT, findings=[finding(str(getattr(state, "reason", "")), since)],
                     detail={"decision": "flag", "failures": int(getattr(state, "failures", 0) or 0)})
        write_json_object(_state_path(), {"since": since, "at": now}, what="the threat-graph alarm's record")
        return True
    except Exception:   # health: allow BLE001 -- fail open: the look goes on; status and the panel still say it
        logger.debug("blackbox: the threat-graph alarm was not recorded", exc_info=True)
        return False


__all__ = ["MIN_INTERVAL_SECONDS", "TITLE", "UNAVAILABLE_ID", "check", "finding"]
