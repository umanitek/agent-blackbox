"""Where instances live: in memory for the live view, on disk for history.

One writer (the dashboard process). Records are kept in a dict and flushed to
``$BLACKBOX_HOME/agent-hooks/instances/index.json`` at most every :data:`FLUSH_SECONDS` (and when
an instance ends), so a hook event costs a dict update, not a file rewrite. Each instance's
actions are appended to its own bounded ``actions/<name>.jsonl``. Bounded: ended instances older
than the person's ``agent_activity.history_days`` (:func:`history_days`; 30 unless set) go, and
the oldest go first past :data:`MAX_INSTANCES`. A prompt's text, when the person had it kept, is
removed by :func:`strip_text`.

Pattern: **Repository** — callers see ``get`` / ``put`` / ``all`` / ``append_action`` /
``actions``, never the files.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import asdict, fields
from pathlib import Path
from typing import Iterable, Optional

from ...kernel import constants
from ...kernel.bounded_files import atomic_write, read_small_text
from ...kernel.config import agent_activity
from .model import Action, Instance

#: How long an ended instance stays in the history when the setting cannot be read
#: (``agent_activity.history_days`` in config.yaml; see :func:`history_days`).
HISTORY_DAYS = 30
#: How long one reading of that setting is reused (a flush happens every few seconds).
DAYS_MEMO_SECONDS = 60.0
MAX_INSTANCES = 4000
#: The most actions kept per instance (later ones are counted, not listed).
MAX_ACTIONS = 2000
FLUSH_SECONDS = 2.0
MAX_INDEX_BYTES = 8 * 1024 * 1024
MAX_ACTIONS_BYTES = 2 * 1024 * 1024

_lock = threading.RLock()
_changed = threading.Condition(_lock)
_state: dict[str, object] = {"loaded": False, "instances": {}, "cursor": 0, "dirty": False, "flushed": 0.0}
_days: dict[str, float] = {"at": 0.0, "days": float(HISTORY_DAYS)}
_FIELDS = {item.name for item in fields(Instance)}


def folder() -> Path:
    return constants.blackbox_home() / "agent-hooks" / "instances"


def _action(row: object) -> Optional[Action]:
    """One saved timeline row as an :class:`Action` (None for anything else)."""
    if not isinstance(row, dict):
        return None
    try:
        return Action(float(row["ts"]), str(row["kind"]), str(row.get("tool", "")), str(row.get("what", "")),
                      str(row.get("verdict", "")), str(row.get("reason", "")), str(row.get("text", "")))
    except (KeyError, TypeError, ValueError):
        return None


def _load() -> dict[str, Instance]:
    """The instances dict, read from disk once per process (a damaged file starts empty)."""
    if not _state["loaded"]:
        found: dict[str, Instance] = {}
        try:
            rows = json.loads(read_small_text(str(folder() / "index.json"), MAX_INDEX_BYTES) or "{}").get("instances", [])
            for row in rows if isinstance(rows, list) else []:
                if isinstance(row, dict) and isinstance(row.get("key"), str):
                    values = {name: value for name, value in row.items() if name in _FIELDS}
                    values["last_action"] = _action(values.get("last_action"))
                    found[row["key"]] = Instance(**values)
        except (ValueError, TypeError):
            found = {}
        _state.update(loaded=True, instances=found)
    return _state["instances"]   # type: ignore[return-value]


def reset() -> None:
    """Forget what is in memory (tests; a new ``BLACKBOX_HOME``)."""
    with _lock:
        _state.update(loaded=False, instances={}, cursor=0, dirty=False, flushed=0.0)
        _days.update(at=0.0, days=float(HISTORY_DAYS))


def get(key: str) -> Optional[Instance]:
    with _lock:
        return _load().get(key)


def all_instances() -> list[Instance]:
    with _lock:
        return list(_load().values())


def cursor() -> int:
    with _lock:
        return int(_state["cursor"])   # type: ignore[arg-type]


def put(instance: Instance, *, flush: bool = False) -> None:
    """Keep *instance* and wake every reader waiting for a change."""
    with _changed:
        _load()[instance.key] = instance
        _state["cursor"] = int(_state["cursor"]) + 1   # type: ignore[arg-type]
        _state["dirty"] = True
        if flush or time.time() - float(_state["flushed"]) >= FLUSH_SECONDS:   # type: ignore[arg-type]
            _flush()
        _changed.notify_all()


def touch() -> None:
    """Something outside the instances changed what the live view shows (a process came or went)."""
    with _changed:
        _state["cursor"] = int(_state["cursor"]) + 1   # type: ignore[arg-type]
        _changed.notify_all()


def wait_for_change(since: int, seconds: float) -> int:
    """The cursor once it has moved past *since*, or after *seconds* (a long-poll's wait)."""
    deadline = time.monotonic() + max(0.0, seconds)
    with _changed:
        while int(_state["cursor"]) <= since:   # type: ignore[arg-type]
            left = deadline - time.monotonic()
            if left <= 0 or not _changed.wait(left):
                break
        return int(_state["cursor"])   # type: ignore[arg-type]


def history_days() -> int:
    """The person's retention for ended instances, read from the config at most once a minute."""
    with _lock:
        if time.monotonic() - _days["at"] >= DAYS_MEMO_SECONDS or not _days["at"]:
            try:
                _days.update(at=time.monotonic(), days=float(agent_activity().history_days))
            except Exception:   # health: allow BLE001 -- an unreadable config keeps the last known retention
                _days["at"] = time.monotonic()
        return int(_days["days"])


def _prune(instances: dict[str, Instance]) -> list[str]:
    horizon = time.time() - history_days() * 86400
    gone = [key for key, item in instances.items() if item.ended is not None and item.last < horizon]
    left = sorted((item for key, item in instances.items() if key not in gone), key=lambda item: item.last)
    gone += [item.key for item in left[:max(0, len(left) - MAX_INSTANCES)]]
    for key in gone:
        instances.pop(key, None)
    return gone


def _flush() -> None:
    instances = _load()
    for key in _prune(instances):
        _actions_path(key).unlink(missing_ok=True)
    try:
        folder().mkdir(parents=True, exist_ok=True)
        atomic_write(folder() / "index.json", json.dumps({"instances": [asdict(item) for item in instances.values()]}))
    except OSError:
        return   # the next change tries again; the live view is in memory
    _state.update(dirty=False, flushed=time.time())


def flush() -> None:
    with _lock:
        if _state["dirty"]:
            _flush()


def _actions_path(key: str) -> Path:
    return folder() / "actions" / (hashlib.sha256(key.encode("utf-8")).hexdigest()[:24] + ".jsonl")


def append_action(key: str, action: Action, count: int) -> None:
    """Add *action* to *key*'s timeline while it has room (*count* = actions recorded so far)."""
    if count > MAX_ACTIONS:
        return
    path = _actions_path(key)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(action), ensure_ascii=False) + "\n")
    except OSError:
        return


def actions(key: str, *, offset: int = 0, limit: int = 200) -> list[Action]:
    """*key*'s timeline, oldest first."""
    text = read_small_text(str(_actions_path(key)), MAX_ACTIONS_BYTES) or ""
    out = []
    for line in text.splitlines()[offset:offset + max(1, min(limit, 500))]:
        try:
            found = _action(json.loads(line))
        except ValueError:
            continue
        if found is not None:
            out.append(found)
    return out


def _timeline_files() -> list[Path]:
    try:
        return sorted((folder() / "actions").glob("*.jsonl"))
    except OSError:
        return []


def _rows_of(path: Path) -> list[dict]:
    rows = []
    for line in (read_small_text(str(path), MAX_ACTIONS_BYTES) or "").splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def count_text() -> int:
    """How many timeline entries hold a prompt's text now."""
    with _lock:
        return sum(bool(row.get("text")) for path in _timeline_files() for row in _rows_of(path))


def strip_text(older_than: Optional[float] = None) -> int:
    """Remove the prompt text from every timeline entry (or only those before *older_than*, a
    time); the entries themselves stay. Returns how many entries held text."""
    removed = 0
    with _lock:
        for path in _timeline_files():
            rows = _rows_of(path)
            hit = [row for row in rows if row.get("text") and (older_than is None or float(row.get("ts") or 0) < older_than)]
            if not hit:
                continue
            for row in hit:
                row.pop("text", None)
            try:
                atomic_write(path, "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows))
            except OSError:
                continue
            removed += len(hit)
    return removed


def replace_all(instances: Iterable[Instance]) -> None:
    """Tests: start from exactly these instances."""
    with _lock:
        _state.update(loaded=True, instances={item.key: item for item in instances}, dirty=True)
