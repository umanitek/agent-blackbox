"""Where instances live: in memory for the live view, on disk for history.

One writer (the dashboard process). Records are kept in a dict and flushed to
``$BLACKBOX_HOME/agent-hooks/instances/index.json`` at most every :data:`FLUSH_SECONDS` (and when
an instance ends), so a hook event costs a dict update, not a file rewrite. Each instance's
actions are appended to its own bounded ``actions/<name>.jsonl``. Bounded: ended instances older
than :data:`HISTORY_DAYS` go, and the oldest go first past :data:`MAX_INSTANCES`.

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
from .model import Action, Instance

#: How long an ended instance stays in the history.
HISTORY_DAYS = 30
MAX_INSTANCES = 4000
#: The most actions kept per instance (later ones are counted, not listed).
MAX_ACTIONS = 2000
FLUSH_SECONDS = 2.0
MAX_INDEX_BYTES = 8 * 1024 * 1024
MAX_ACTIONS_BYTES = 2 * 1024 * 1024

_lock = threading.RLock()
_changed = threading.Condition(_lock)
_state: dict[str, object] = {"loaded": False, "instances": {}, "cursor": 0, "dirty": False, "flushed": 0.0}
_FIELDS = {item.name for item in fields(Instance)}


def folder() -> Path:
    return constants.blackbox_home() / "agent-hooks" / "instances"


def _load() -> dict[str, Instance]:
    """The instances dict, read from disk once per process (a damaged file starts empty)."""
    if not _state["loaded"]:
        found: dict[str, Instance] = {}
        try:
            rows = json.loads(read_small_text(str(folder() / "index.json"), MAX_INDEX_BYTES) or "{}").get("instances", [])
            for row in rows if isinstance(rows, list) else []:
                if isinstance(row, dict) and isinstance(row.get("key"), str):
                    found[row["key"]] = Instance(**{name: value for name, value in row.items() if name in _FIELDS})
        except (ValueError, TypeError):
            found = {}
        _state.update(loaded=True, instances=found)
    return _state["instances"]   # type: ignore[return-value]


def reset() -> None:
    """Forget what is in memory (tests; a new ``BLACKBOX_HOME``)."""
    with _lock:
        _state.update(loaded=False, instances={}, cursor=0, dirty=False, flushed=0.0)


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


def _prune(instances: dict[str, Instance]) -> list[str]:
    horizon = time.time() - HISTORY_DAYS * 86400
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
            row = json.loads(line)
            out.append(Action(float(row["ts"]), str(row["kind"]), str(row.get("tool", "")), str(row.get("what", "")),
                              str(row.get("verdict", ""))))
        except (ValueError, KeyError, TypeError):
            continue
    return out


def replace_all(instances: Iterable[Instance]) -> None:
    """Tests: start from exactly these instances."""
    with _lock:
        _state.update(loaded=True, instances={item.key: item for item in instances}, dirty=True)
