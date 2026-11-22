"""The notifications feed: every notice Blackbox raised, in order — what the notifier and Blackbox
Desktop read, and the history the dashboard shows.

One writer (the dashboard process). Kept in memory and appended to
``$BLACKBOX_HOME/notifications/feed.jsonl`` (rewritten bounded when it passes
:data:`MAX_KEPT` rows). Each notice gets the next ``seq``; an ``id`` already in the feed is not
news and is dropped. ``delivered`` is the ONE cursor both deliverers share (:mod:`.deliver`).

Pattern: **Repository** — callers see ``publish`` / ``since`` / ``latest`` / ``wait``.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import asdict, fields, replace
from pathlib import Path
from typing import Optional

from ..kernel import constants
from ..kernel.bounded_files import append_line, atomic_write, read_json_object, read_small_text, write_json_object
from .model import Notice

logger = logging.getLogger(__name__)

MAX_KEPT = 500
MAX_FEED_BYTES = 2 * 1024 * 1024
_FIELDS = {item.name for item in fields(Notice)}
_lock = threading.RLock()
_changed = threading.Condition(_lock)
_state: dict[str, object] = {"loaded": False, "rows": [], "ids": set(), "seq": 0, "delivered": 0}


def folder() -> Path:
    return constants.blackbox_home() / "notifications"


def _load() -> list[Notice]:
    if not _state["loaded"]:
        rows: list[Notice] = []
        for line in (read_small_text(str(folder() / "feed.jsonl"), MAX_FEED_BYTES) or "").splitlines():
            try:
                raw = json.loads(line)
                rows.append(Notice(**{key: value for key, value in raw.items() if key in _FIELDS}))
            except (ValueError, TypeError):
                continue
        rows = rows[-MAX_KEPT:]
        cursor = read_json_object(folder() / "cursor.json") or {}
        top = max((row.seq for row in rows), default=0)
        delivered = cursor.get("delivered") if isinstance(cursor.get("delivered"), int) else top
        _state.update(loaded=True, rows=rows, ids={row.id for row in rows}, seq=max(top, int(cursor.get("seq") or 0)),
                      delivered=min(int(delivered), max(top, int(cursor.get("seq") or 0))))
    return _state["rows"]   # type: ignore[return-value]


#: The file that says "this is an installed Blackbox: show notifications on this machine's screen".
#: Written by ``blackbox notifications setup`` (the installer's notifier step), removed with the
#: notifier. WHY (2026-11-22): a test or a developer's dashboard on a temporary home ran the real
#: notifier and showed the founder notifications about his own agents. Without this file the feed
#: and the history still fill; nothing is handed to the system.
DELIVERS_HERE = "delivers-here"


def delivers_here() -> bool:
    """True on an installed Blackbox (:data:`DELIVERS_HERE` is in place)."""
    return (folder() / DELIVERS_HERE).is_file()


def set_delivers_here(on: bool) -> None:
    """Mark (or unmark) this Blackbox home as an installed one whose notices reach the screen."""
    if on:
        atomic_write(folder() / DELIVERS_HERE, "installed: notifications are shown on this machine\n")
    else:
        (folder() / DELIVERS_HERE).unlink(missing_ok=True)


def reset() -> None:
    """Forget what is in memory (tests; a new ``BLACKBOX_HOME``)."""
    with _lock:
        _state.update(loaded=False, rows=[], ids=set(), seq=0, delivered=0)


def _save_cursor() -> None:
    write_json_object(folder() / "cursor.json", {"seq": _state["seq"], "delivered": _state["delivered"]},
                      what="the notifications cursor")


def publish(notice: Notice) -> Optional[Notice]:
    """Add *notice* to the feed with the next ``seq``; None when its ``id`` is already there."""
    with _changed:
        rows = _load()
        if notice.id in _state["ids"]:   # type: ignore[operator]
            return None
        _state["seq"] = int(_state["seq"]) + 1   # type: ignore[arg-type]
        kept = replace(notice, seq=int(_state["seq"]))   # type: ignore[arg-type]
        rows.append(kept)
        _state["ids"].add(kept.id)   # type: ignore[union-attr]
        try:
            folder().mkdir(parents=True, exist_ok=True)
            if len(rows) > MAX_KEPT:
                del rows[:len(rows) - MAX_KEPT]
                _state["ids"] = {row.id for row in rows}
                atomic_write(folder() / "feed.jsonl", "".join(json.dumps(asdict(row), ensure_ascii=False) + "\n" for row in rows))
            else:
                append_line(folder() / "feed.jsonl", json.dumps(asdict(kept), ensure_ascii=False))
            _save_cursor()
        except OSError:
            logger.debug("blackbox notify: the feed file could not be written (it stays in memory)", exc_info=True)
        _changed.notify_all()
        return kept


def note_delivery(outcomes: dict[int, str]) -> None:
    """Keep what became of each notice (``seq`` → a :data:`.model.OUTCOMES` word) on the notice
    itself, so the history tells "delivered" from "macOS did not show it"."""
    if not outcomes:
        return
    with _lock:
        rows = _load()
        for index, row in enumerate(rows):
            if row.seq in outcomes:
                rows[index] = replace(row, delivery=outcomes[row.seq])
        try:
            atomic_write(folder() / "feed.jsonl", "".join(json.dumps(asdict(row), ensure_ascii=False) + "\n" for row in rows))
        except OSError:
            logger.debug("blackbox notify: the feed file could not be rewritten (it stays in memory)", exc_info=True)


def since(seq: int, limit: int = 100) -> list[Notice]:
    """The notices after *seq*, oldest first."""
    with _lock:
        return [row for row in _load() if row.seq > seq][:max(1, min(limit, MAX_KEPT))]


def latest(limit: int = 100, before: int = 0) -> list[Notice]:
    """The newest notices first (a history page; *before*: only those with a lower ``seq``)."""
    with _lock:
        rows = [row for row in _load() if not before or row.seq < before]
        return list(reversed(rows))[:max(1, min(limit, MAX_KEPT))]


def top() -> int:
    with _lock:
        _load()
        return int(_state["seq"])   # type: ignore[arg-type]


def delivered() -> int:
    """The ``seq`` up to which a deliverer has shown (or deliberately passed) the feed."""
    with _lock:
        _load()
        return int(_state["delivered"])   # type: ignore[arg-type]


def mark_delivered(seq: int) -> int:
    """Move the delivered cursor forward to *seq* (never back, never past the feed's top)."""
    with _lock:
        _load()
        new = max(int(_state["delivered"]), min(int(seq), int(_state["seq"])))   # type: ignore[arg-type]
        if new != _state["delivered"]:
            _state["delivered"] = new
            _save_cursor()
        return new


def wait(seq: int, seconds: float) -> int:
    """The feed's top once it passed *seq*, or after *seconds* (a long-poll's wait)."""
    deadline = time.monotonic() + max(0.0, seconds)
    with _changed:
        _load()
        while int(_state["seq"]) <= seq:   # type: ignore[arg-type]
            left = deadline - time.monotonic()
            if left <= 0 or not _changed.wait(left):
                break
        return int(_state["seq"])   # type: ignore[arg-type]
