"""What the dashboard and a companion app read: the live tree, the history and one instance.

``live`` groups instances as product → profile → session → sub-agents and adds the agent
processes Blackbox has no hook in (``unprotected``). An instance is LIVE while its agent process
is still there (when Blackbox could find it) or, without a process to follow, while its events
are recent; it is closed here — "process-exit" or "quiet" — when neither holds.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from typing import Any, Iterable, Mapping, Optional

from ...kernel.agent_hosts import BY_ID, PROTECTION_HOOKS, PROTECTION_SANDBOXED, product_name
from . import store
from .model import Instance, Running

#: The default quiet limit (the person's is ``agent_activity.quiet_minutes``: ``store.quiet_seconds``).
QUIET_SECONDS = store.QUIET_SECONDS
#: A hook event this recent proves the process is hooked (a process younger than this may not
#: have reported yet, so it is not called unprotected).
GRACE_SECONDS = 20.0


def close_stale(alive: Optional[Iterable[int]] = None, *, read_at: Optional[float] = None) -> int:
    """End the instances whose process left (*alive*: the pids running when the process list was
    read at *read_at* — now when not given; None = unknown) or that went quiet (no event for
    ``agent_activity.quiet_minutes``). Returns how many were ended.

    WHY *read_at* (KI-571, real Gemini CLI 0.70.0, two sessions at once): the process list is
    cached for a moment, and a session whose process was learned AFTER that list was read is not
    in it — it was ended "process-exit" 4 ms after it started. Only a list read after the
    instance's latest event can say its process left."""
    pids = None if alive is None else set(alive)
    now, ended, quiet = time.time(), 0, store.quiet_seconds()
    read_at = now if read_at is None else read_at
    for item in store.all_instances():
        if item.ended is not None:
            continue
        reason = ""
        if item.kind == "session" and item.pid and pids is not None and item.pid not in pids and read_at > item.last:
            reason = "process-exit"
        elif now - item.last > quiet and not (item.pid and pids is not None and item.pid in pids):
            reason = "quiet"
        if reason:
            item.ended, item.end_reason = now, reason
            store.put(item)
            ended += 1
            if item.kind == "session":
                _end_sub_agents(item, now)
    return ended


def _end_sub_agents(session: Instance, now: float) -> int:
    """A session that ended this way takes its open sub-agents with it (KI-574: they stayed live
    until the quiet limit after their session's process had gone)."""
    count = 0
    for item in store.all_instances():
        if item.parent == session.key and item.ended is None:
            item.ended, item.end_reason = now, "session-ended"
            store.put(item)
            count += 1
    return count


#: What a waiting instance waits for, in the person's words.
WAITING_FOR = {"idle": "your next message", "permission": "your answer to a permission question", "attention": "your attention"}


#: How long sudo usually stays unlocked in a terminal after a password (its default timestamp_timeout).
SUDO_CACHE_SECONDS = 300


def root_note(item: Instance, now: Optional[float] = None) -> str:
    """What to say about root for *item* ("" = nothing): a program it started runs as root now,
    or did within sudo's usual unlocked time."""
    now = time.time() if now is None else now
    if item.ended is not None:
        return ""
    if item.root:
        return "A program this agent started is running as root right now."
    if item.root_last and now - item.root_last < SUDO_CACHE_SECONDS:
        return ("A program this agent started ran as root a moment ago. sudo usually stays unlocked for about "
                "5 minutes in that terminal, so the agent may run more as root without a password.")
    return ""


def _row(item: Instance, subs: Mapping[str, list[Instance]]) -> dict[str, Any]:
    row = asdict(item)
    row["root"] = bool(item.root) and item.ended is None
    row["root_note"] = root_note(item)
    waiting = item.waiting if item.ended is None else ""
    row["status"] = "ended" if item.ended is not None else "waiting" if waiting else "live"
    row["waiting"], row["waiting_for"] = waiting, WAITING_FOR.get(waiting, "")
    if row.get("last_action"):
        row["last_action"].pop("text", None)   # the live tree never carries a prompt's text
    row["protection"] = "sandboxed" if item.sandboxed else "hooks"
    row["protection_label"] = PROTECTION_SANDBOXED if item.sandboxed else PROTECTION_HOOKS   # said plainly, every screen
    row["sub_agents"] = [_row(sub, subs) for sub in sorted(subs.get(item.key, []), key=lambda sub: sub.started)]
    return row


def _unprotected(running: Iterable[Running], sessions: Iterable[Instance]) -> list[dict[str, Any]]:
    hooked = {item.pid for item in sessions if item.pid and item.ended is None}
    now = time.time()
    out = []
    for proc in running:
        if proc.pid in hooked or (not proc.hooks_skipped and now - proc.started < GRACE_SECONDS):
            continue
        host = BY_ID.get(proc.agent)
        out.append({"pid": proc.pid, "agent": proc.agent, "name": host.name if host else proc.agent, "launch": proc.launch,
                    "profile": proc.profile, "started": proc.started, "status": "unprotected",
                    "reason": proc.hooks_skipped or "Blackbox has seen no hook event from this process."})
    return out


def live(running: Iterable[Running] = (), profiles: Iterable[Mapping[str, Any]] = ()) -> dict[str, Any]:
    """The tree of instances that are live now (plus those ended in the last minute, so an
    ending is seen), per product and profile; *running* adds the unhooked agent processes."""
    everything = store.all_instances()
    now = time.time()
    shown = [item for item in everything if item.ended is None or now - item.ended < 60]
    subs: dict[str, list[Instance]] = {}
    for item in shown:
        if item.kind == "sub-agent":
            subs.setdefault(item.parent, []).append(item)
    products: dict[str, dict[str, Any]] = {}
    for item in sorted((item for item in shown if item.kind == "session"), key=lambda item: item.started):
        product = products.setdefault(item.agent, {"id": item.agent, "name": product_name(item.agent), "profiles": {}})
        product["profiles"].setdefault(item.profile, {"home": item.profile, "instances": []})["instances"].append(_row(item, subs))
    for product in products.values():
        product["profiles"] = list(product["profiles"].values())
    sessions = [item for item in everything if item.kind == "session"]
    return {"cursor": store.cursor(), "at": now, "products": list(products.values()),
            "unprotected": _unprotected(running, sessions), "profiles": list(profiles),
            "counts": {"live": sum(item.ended is None for item in shown if item.kind == "session"),
                       "root": sum(item.root and item.ended is None for item in shown if item.kind == "session"),
                       "sub_agents": sum(item.ended is None for item in shown if item.kind == "sub-agent")}}


#: The history's outcome filter: any, at least one refusal, at least one too-late action, either.
HISTORY_OUTCOMES = ("", "refused", "too-late", "stopped")


@dataclass(frozen=True)
class HistoryFilter:
    """Which ended instances a history page holds. Every field is optional ("" / 0 = any):
    *agent* an agent id, *project* a project folder's name (``Instance.folder``), *since* /
    *until* the ``ended`` time bounds in epoch seconds (inclusive), *outcome* one of
    :data:`HISTORY_OUTCOMES`."""

    agent: str = ""
    kind: str = "session"
    project: str = ""
    since: float = 0.0
    until: float = 0.0
    outcome: str = ""

    def holds(self, item: Instance) -> bool:
        ended = item.ended or 0.0
        return (item.ended is not None and item.kind == self.kind
                and (not self.agent or item.agent == self.agent) and (not self.project or item.folder == self.project)
                and (not self.since or ended >= self.since) and (not self.until or ended <= self.until)
                and _outcome_holds(self.outcome, item))


def _outcome_holds(outcome: str, item: Instance) -> bool:
    if outcome == "refused":
        return item.refused > 0
    if outcome == "too-late":
        return item.too_late > 0
    if outcome == "stopped":
        return item.refused > 0 or item.too_late > 0
    return True


def history(*, before: float = 0.0, limit: int = 50, **filters: Any) -> dict[str, Any]:
    """Ended instances, newest first, a page at a time (``before``: the ``ended`` of the last row
    of the previous page), narrowed by *filters* (the fields of :class:`HistoryFilter`).

    Answers ``{instances, more, next_before, facets: {agents, projects}}`` — *facets* are the
    agent ids and project names among every ended instance of the kind, so a view can offer them
    as filter choices without reading the whole history."""
    limit = max(1, min(limit, 200))
    wanted = HistoryFilter(**filters)
    everything = store.all_instances()
    rows = sorted((item for item in everything if wanted.holds(item) and (not before or (item.ended or 0) < before)),
                  key=lambda item: item.ended or 0, reverse=True)
    page = rows[:limit]
    subs: dict[str, list[Instance]] = {}
    for item in everything:
        if item.kind == "sub-agent":
            subs.setdefault(item.parent, []).append(item)
    ended = [item for item in everything if item.ended is not None and item.kind == wanted.kind]
    return {"instances": [_row(item, subs) for item in page], "more": len(rows) > limit,
            "next_before": page[-1].ended if page and len(rows) > limit else None,
            "facets": {"agents": sorted({item.agent for item in ended}), "projects": sorted({item.folder for item in ended if item.folder})}}


def detail(key: str, *, offset: int = 0, limit: int = 200, with_text: bool = False) -> Optional[dict[str, Any]]:
    """One instance with its sub-agents and a page of its timeline; None for an unknown key.
    *with_text*: prompt-text recording is on (see :func:`_action_row`)."""
    item = store.get(key)
    if item is None:
        return None
    subs: dict[str, list[Instance]] = {}
    for other in store.all_instances():
        if other.kind == "sub-agent":
            subs.setdefault(other.parent, []).append(other)
    return {"instance": _row(item, subs), "actions": [_action_row(action, with_text) for action in store.actions(key, offset=offset, limit=limit)],
            "offset": offset}


def _action_row(action: Any, with_text: bool) -> dict[str, Any]:
    """One timeline entry. ``text`` (a prompt's text) is THERE only while prompt-text recording
    is on — absent otherwise, even when an older entry still holds some."""
    row = asdict(action)
    if not (with_text and action.text):
        row.pop("text", None)
    return row
