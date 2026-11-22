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
from dataclasses import asdict
from pathlib import Path
from typing import Any, Mapping, Optional

from ..kernel.agent_hosts import BY_ID, HOSTS
from . import observe, profiles, prompt_text, root_watch
from .instances import record, store, views
from .instances.model import Profile, Running
from .protect import config_edit, own_files

__all__ = ["detail", "export", "history", "live", "new_profiles", "profile", "profile_rows", "prompt_text", "track", "wait"]

#: How long one reading of the process list is reused.
TABLE_SECONDS = 1.5
_OWN_FILE_STYLES = ("own-json", "scripts", "plugin")
_lock = threading.Lock()
_seen: dict[str, Any] = {"at": 0.0, "table": {}, "running": [], "pids": frozenset(), "new_profiles": False}


def _snapshot() -> tuple[Mapping[int, observe.Proc], list[Running]]:
    """The process list and the agent processes in it, read at most every :data:`TABLE_SECONDS`.
    A change in which agent processes exist moves the live view's cursor."""
    with _lock:
        if time.monotonic() - _seen["at"] >= TABLE_SECONDS:
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


def new_profiles() -> bool:
    """True once after a config home was learned (the sweep then hooks it at once)."""
    with _lock:
        found, _seen["new_profiles"] = _seen["new_profiles"], False
        return bool(found)


def track(event: Mapping[str, Any], session_key: str, *, decision: str = "", findings: int = 0, reason: str = "",
          text: str = "") -> None:
    """Record *event* against its instance; find the agent's process the first time a session is
    seen; remember a config home the event names. *reason*: what the agent was told when
    Blackbox refused the action. *text*: a prompt's text — kept (redacted) only while the person
    has prompt-text recording on, dropped here otherwise."""
    fields = dict(event)
    known = store.get(session_key)
    # The process is looked up while it is unknown — and for an ended session, whose next event
    # may come from a new run of the same session id (instances._resumes compares them).
    if (known is None or not known.pid or known.ended is not None) and isinstance(event.get("pid"), int) and event["pid"] > 1:
        table, _running = _snapshot()
        fields["agent_pid"] = observe.agent_of(table, event["pid"], event["agent"]) or None
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
    found = profile_detail.read(agent, home, project)
    return asdict(found) if found is not None else None


def known(agent: str) -> bool:
    return agent in BY_ID
