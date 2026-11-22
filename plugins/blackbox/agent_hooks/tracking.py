"""Tracking: every hook event becomes part of an instance, and the live view knows which agent
processes exist — hooked or not.

Facade over :mod:`.instances` (the records), :mod:`.observe` (the read-only process list) and
:mod:`.profiles` (the config homes): ``agent_hooks.record_event`` calls :func:`track`; the
dashboard's ``/api/agents/*`` routes call :func:`live`, :func:`history` and :func:`detail`.

Usage::

    from . import tracking
    tracking.track(event, session_key, decision="block", findings=1)
    tracking.live()                 # {"cursor", "products", "unprotected", "profiles", "counts"}
    tracking.wait(cursor, 25.0)     # block until the live view changed (a long-poll)
"""

from __future__ import annotations

import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Optional

from ..kernel.agent_hosts import BY_ID, HOSTS
from . import observe, profiles, prompt_text, root_watch
from .instances import links, record, store, sub_key, views
from .instances.model import Profile, Running
from .protect import config_edit, own_files
from .protect.events import session_key as key_of_session

__all__ = ["Captured", "capture", "detail", "export", "history", "live", "new_profiles", "observe_now", "profile", "profile_rows", "prompt_text", "track", "wait"]

#: How long one reading of the process list is reused.
TABLE_SECONDS = 1.5
#: A process list read on purpose (a hook's process is not in the reused one) is never read
#: again sooner than this — many hooks at once share one reading.
FRESH_MIN_SECONDS = 0.05
#: How often one session whose agent process could not be found asks again for a fresh list.
FRESH_RETRY_SECONDS = 10.0
MAX_RETRIES_KEPT = 1024
_retried: dict[str, float] = {}
_OWN_FILE_STYLES = ("own-json", "scripts", "plugin")
_lock = threading.Lock()
_seen: dict[str, Any] = {"at": 0.0, "table": {}, "running": [], "pids": frozenset(), "new_profiles": False}


def _snapshot(*, max_age: float = TABLE_SECONDS) -> tuple[Mapping[int, observe.Proc], list[Running]]:
    """The process list and the agent processes in it, read again when the one held is
    *max_age* seconds old (by default :data:`TABLE_SECONDS`). A change in which agent processes
    exist moves the live view's cursor."""
    with _lock:
        if time.monotonic() - _seen["at"] >= max_age:
            table = observe.read_table()
            running = observe.running(table)
            pids = frozenset(proc.pid for proc in running)
            for proc in running:   # a running agent names a config home Blackbox has not hooked yet
                if proc.profile and profiles.remember(proc.agent, proc.profile):
                    _seen["new_profiles"] = True
            sessions = [item for item in store.all_instances() if item.kind == "session" and item.ended is None and item.pid]
            if sessions and table:   # a program an agent started that runs as root is recorded on its instance
                root_watch.scan(table, observe.read_users(), sessions)
            changed = pids != _seen["pids"]
            _seen.update(at=time.monotonic(), table=table, running=running, pids=pids)
            if changed:
                store.touch()
        return _seen["table"], _seen["running"]


def observe_now() -> None:
    """One look of the process observer, whoever is watching: read the process list (a running
    agent names a config home it uses — learned here, hooked by the sweep that asks
    :func:`new_profiles`). WHY (KI-553): the list was read only when the live view was read or a
    hook event came, so a moved home of an agent that sends no event was found only while
    someone watched. The dashboard calls this every few seconds. Instances whose process left or
    that went quiet are closed here as well, so the history is right with nobody watching (KI-549)."""
    table, _running = _snapshot(max_age=0.0)
    views.close_stale(table.keys() if table else None)


def new_profiles() -> bool:
    """True once after a config home was learned (the sweep then hooks it at once)."""
    with _lock:
        found, _seen["new_profiles"] = _seen["new_profiles"], False
        return bool(found)


def agent_process(session_key: str, hook_parent: int, agent: str) -> int:
    """The pid of the *agent* process a hook was run by (*hook_parent*: the hook's parent), 0 when
    none of its ancestors is that agent.

    WHY (KI-548): the hook's parent is often a short-lived shell the agent started for this one
    hook, younger than the reused process list — so it, and the path up to the agent, are not in
    it. While the hook waits for its answer that whole ancestry is alive, so when the reused list
    does not lead to the agent, the list is read again NOW and the ancestry walked in it
    (``observe.agent_of``: the outermost ancestor whose program is that agent). A session whose
    agent is still not found asks again at most every :data:`FRESH_RETRY_SECONDS`."""
    table, _running = _snapshot()
    found = observe.agent_of(table, hook_parent, agent)
    if found:
        return found
    with _lock:
        if hook_parent in table and time.monotonic() - _retried.get(session_key, float("-inf")) < FRESH_RETRY_SECONDS:
            return 0
        _retried[session_key] = time.monotonic()
        for old in list(_retried)[:-MAX_RETRIES_KEPT]:
            _retried.pop(old)
    table, _running = _snapshot(max_age=FRESH_MIN_SECONDS)
    return observe.agent_of(table, hook_parent, agent)


@dataclass(frozen=True)
class Captured:
    """The agent process a hook was run by (*agent_pid*, 0 when none) and how it was started
    (*launch*: :data:`.instances.model.LAUNCHES`, "" when unknown) — learned while the hook waits."""

    agent_pid: int
    launch: str


def capture(event: Mapping[str, Any], session_key: str) -> Optional[Captured]:
    """The agent process behind *event*'s hook, read NOW while the hook (and the short-lived shell
    that ran it) still exist — or None when the session already has its process.

    The hook's own ancestry is read from the kernel (``observe.ancestry``: microseconds, no
    ``ps``, no lock), so this can run before the agent gets its answer (KI-552); a system that
    cannot answer that way reads the whole process list as before (:func:`agent_process`)."""
    pid = event.get("pid")
    known = store.get(session_key)
    if not isinstance(pid, int) or pid <= 1 or (known is not None and known.pid and known.ended is None):
        return None
    chain = observe.ancestry(pid)
    if chain is not None:   # {} when the hook already left: no process is learned from it
        found = observe.agent_of(chain, pid, str(event.get("agent") or ""))
        return Captured(found, observe.launch_of(chain, found) if found else "")
    found = agent_process(session_key, pid, str(event.get("agent") or ""))
    return Captured(found, observe.launch_of(_snapshot()[0], found) if found else "")


#: A child session's own start and end, as its parent's sub-agent sees them.
_AS_SUB = {"session_start": "subagent_start", "stop": "subagent_stop"}


def _as_sub_agent(fields: dict[str, Any], session_key: str) -> str:
    """When *fields* come from a child session that is another session's sub-agent
    (:func:`.instances.links.resolve`), make them that sub-agent's event; the session key to
    record under. A sub-agent seen for the first time claims its spawn call's task and type."""
    agent, cwd = fields["agent"], str(fields.get("cwd") or "")
    link = links.resolve(fields, session_key, key_of=lambda raw: key_of_session(agent, raw, cwd),
                         known=store.get(session_key), sessions=store.all_instances())
    if link is not None:
        session_key = link.parent
        fields["sub"] = link.child   # a sub-agent the child names is shown flat under the parent
        fields["event"] = _AS_SUB.get(fields["event"], fields["event"])
    if fields.get("sub") and store.get(sub_key(session_key, str(fields["sub"]))) is None:
        spawn = links.claim(session_key)
        if spawn is not None:
            fields["task"] = fields.get("task") or spawn.task
            fields["sub_type"] = fields.get("sub_type") or spawn.type
    return session_key


def track(event: Mapping[str, Any], session_key: str, *, decision: str = "", findings: int = 0, reason: str = "",
          text: str = "", process: Optional[Captured] = None) -> None:
    """Record *event* against its instance; find the agent's process the first time a session is
    seen; link a child session to its parent (a sub-agent run as a session of its own); remember
    a config home the event names. *reason*: what the agent was told when Blackbox refused the
    action. *text*: a prompt's text — kept (redacted) only while the person has prompt-text
    recording on, dropped here otherwise. *process*: what :func:`capture` learned while the hook
    waited (the hook's answer went first; this runs later) — looked up here when not given."""
    fields = dict(event)
    # The process is looked up while it is unknown — and for an ended session, whose next event
    # may come from a new run of the same session id (instances._resumes compares them).
    found = process if process is not None else capture(event, session_key)
    if found is not None:
        fields["agent_pid"] = found.agent_pid or None
        if found.agent_pid and found.launch:   # how it was started, from its command line (KI-549)
            fields["launch"] = found.launch
    session_key = _as_sub_agent(fields, session_key)
    links.note_spawn(session_key, fields)
    if event.get("profile") and profiles.remember(event["agent"], str(event["profile"])):
        with _lock:
            _seen["new_profiles"] = True
    kept = prompt_text.keep(text) if event.get("event") == "prompt" else ""
    record(fields, session_key, decision=decision, findings=findings, reason=reason, prompt_text=kept)


def _hooked(host: Any, home: Path) -> bool:
    editor = own_files if host.style in _OWN_FILE_STYLES else config_edit
    return bool(editor.installed_commands(host, home))


def profile_rows(home: Optional[Path] = None) -> list[Profile]:
    """Every config home of every agent on this machine, whether Blackbox's hooks are in it and
    what would keep them from running there (and in the projects its sessions worked in)."""
    home = home or Path.home()
    projects: dict[str, set[str]] = {}
    for item in store.all_instances():
        if item.kind == "session" and item.cwd:
            projects.setdefault(item.agent, set()).add(item.cwd)
    rows = []
    for host in HOSTS:
        if not host.installed(home) and host.id not in projects:
            continue
        for folder, default in profiles.homes(host, home):
            variant = profiles.variant(host, folder, default=default)
            rows.append(Profile(host.id, str(folder), str(variant.config_path(home)), default, _hooked(variant, home),
                                profiles.problems(host, folder, sorted(projects.get(host.id, ())))))
    return rows


def live() -> dict[str, Any]:
    """The live tree (see :func:`.instances.views.live`), with stale instances closed first."""
    table, running = _snapshot()
    views.close_stale(table.keys() if table else None)
    prompt_text.expire()
    tree = views.live(running, [asdict(row) for row in profile_rows()])
    tree["prompt_text"] = asdict(prompt_text.status())
    return tree


def wait(cursor: int, seconds: float) -> int:
    """Block until the live view moved past *cursor* or *seconds* passed; the cursor now."""
    deadline = time.monotonic() + seconds
    while True:
        _snapshot()   # a process that came or went moves the cursor
        left = deadline - time.monotonic()
        now = store.wait_for_change(cursor, min(TABLE_SECONDS, max(0.0, left)))
        if now > cursor or left <= 0:
            return now


def history(**filters: Any) -> dict[str, Any]:
    return views.history(**filters)


def detail(key: str, *, with_text: bool = False, **page: Any) -> Optional[dict[str, Any]]:
    """One instance and a page of its timeline. *with_text*: the caller may see prompt text (it
    showed the session token); the text is there only while recording is on."""
    return views.detail(key, with_text=with_text and prompt_text.recording(), **page)


def export() -> dict[str, Any]:
    """Everything the agent history holds, as JSON the person can keep (their own data): every
    instance with its timeline, stored prompt text included."""
    rows = []
    for item in sorted(store.all_instances(), key=lambda item: item.started):
        rows.append({"instance": asdict(item), "actions": [asdict(action) for action in store.actions(item.key, limit=500)]})
    return {"exported_at": time.time(), "prompt_text": asdict(prompt_text.status()), "instances": rows}


def profile(agent: str, home: str, project: str = "") -> Optional[dict[str, Any]]:
    """One profile's detail from the real files (see :mod:`.profile_detail`); None when unknown."""
    from . import profile_detail
    found = profile_detail.read(agent, home, project, running=_snapshot()[1])
    return asdict(found) if found is not None else None


def known(agent: str) -> bool:
    return agent in BY_ID
