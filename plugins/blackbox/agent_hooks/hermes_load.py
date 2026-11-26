"""The back-stop for a Hermes that started WITHOUT Blackbox: its plugin did not load, or its guard
did not come up — one HIGH "running without Blackbox" finding each time, read from Hermes's own log.

Private security finding ``2026-11-26-linux-hermes-plugin-load-past-hermes-s-1`` (Linux round L7,
High; BB-LINUX-PENDING-cc89c4): Hermes dropped the plugin when its load overran Hermes's deadline
(and, on that busy VM, when another plugin's abandoned loader raced it: "dictionary changed size
during iteration"). The agent then ran unguarded and nothing said so — a dropped plugin has no
hook left to report with. ``register()`` is now microseconds (``guard.startup``), but a load can
still fail in ways Blackbox cannot prevent from inside (a Hermes fault, a broken file), so the
failure is watched from OUTSIDE the agent: the dashboard reads Hermes's ``errors.log`` (WARNING
and above, every home: the main one and each profile) for the lines Hermes and the guard write
when that happens:

* Hermes: ``Failed to load plugin 'blackbox': <reason>``;
* the guard (``guard.startup.BROKEN_LINE``): ``Blackbox could not start in this Hermes: <reason>``.

Read incrementally (a byte cursor per log in ``agent-hooks/hermes-load-cursor.json``, a new file
after rotation read from its start); the first look at a log reads only its last
:data:`FIRST_LOOK_BYTES` and reports only lines younger than :data:`FIRST_LOOK_SECONDS`. Each line
is reported once, also across a cursor lost with a restart (its id is looked for among the newest
findings). WHAT IT CANNOT SEE: a plugin the person disabled (their choice, shown by ``attach``),
or a log an unguarded agent rewrote — an agent runs as the person, so this is a back-stop beside
the fast start, not a boundary.

Usage (the dashboard's observer look, every few seconds)::

    hermes_load.catch_up()   # how many findings were recorded
"""

from __future__ import annotations

import hashlib
import logging
import re
import threading
import time
from pathlib import Path
from typing import Any, Iterable, Optional

from ..kernel import constants
from ..kernel.agent_hosts import HERMES_ID, HERMES_NAME
from ..kernel.bounded_files import read_json_object, write_json_object
from .unguarded import UNGUARDED_ID

logger = logging.getLogger(__name__)

#: The plugin's name as Hermes logs it (``plugin.yaml``'s ``name``).
PLUGIN_NAME = "blackbox"
#: The guard's own line when it cannot start (``guard.startup.BROKEN_LINE``; agent_hooks does not import guard).
BROKEN_LINE = "Blackbox could not start in this Hermes"
_LINE = re.compile(
    r"^(?P<at>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\S*\s+\w+\s+\S+:\s+"
    rf"(?:Failed to load plugin '{PLUGIN_NAME}': (?P<load>.*)|{re.escape(BROKEN_LINE)}: (?P<start>.*))$")
MATCHED = "hermes-without-blackbox"
#: The most read from one log in one look, and on the first look at it (its end only).
MAX_READ_BYTES = 512 * 1024
FIRST_LOOK_BYTES = 256 * 1024
#: On the first look at a log, older lines are history, not news.
FIRST_LOOK_SECONDS = 24 * 3600
#: Profiles looked at besides the main home.
MAX_PROFILES = 32
RECENT_SCANNED = 500
_lock = threading.Lock()
_reported: set[str] = set()


def _cursor_path() -> Path:
    return constants.blackbox_home() / "agent-hooks" / "hermes-load-cursor.json"


def logs() -> list[Path]:
    """Every Hermes home's ``logs/errors.log``: the main home, then each profile's."""
    root = constants.hermes_root()
    homes = [root]
    try:
        homes += sorted(path for path in (root / "profiles").iterdir() if path.is_dir())[:MAX_PROFILES]
    except OSError:
        pass   # no profiles folder: the main home only
    return [home / "logs" / "errors.log" for home in homes]


def _new_lines(path: Path, cursor: dict[str, Any]) -> tuple[str, Optional[dict[str, int]], bool]:
    """(complete new lines of *path*, its next cursor entry, first look?) — ("", None, False) when unreadable."""
    try:
        stat = path.stat()
    except OSError:
        return "", None, False
    entry = cursor.get(str(path))
    known = isinstance(entry, dict) and entry.get("inode") == stat.st_ino and isinstance(entry.get("offset"), int) \
        and entry["offset"] <= stat.st_size
    first = not isinstance(entry, dict)
    start = int(entry["offset"]) if known else max(0, stat.st_size - FIRST_LOOK_BYTES) if first else 0
    if start >= stat.st_size:
        return "", {"inode": stat.st_ino, "offset": stat.st_size}, first
    try:
        with open(path, "rb") as handle:
            handle.seek(start)
            chunk = handle.read(MAX_READ_BYTES)
    except OSError:
        return "", None, False
    complete = chunk[:chunk.rfind(b"\n") + 1]   # a line still being written waits for the next look
    return complete.decode("utf-8", "replace"), {"inode": stat.st_ino, "offset": start + len(complete)}, first


def _when(stamp: str) -> float:
    try:
        return time.mktime(time.strptime(stamp, "%Y-%m-%d %H:%M:%S"))   # Hermes logs local time
    except (ValueError, OverflowError):
        return 0.0


def _call_id(path: Path, line: str) -> str:
    return "hermes-load:" + hashlib.sha256(f"{path}\n{line}".encode("utf-8", "replace")).hexdigest()[:24]


def _finding(home: str, reason: str, stamp: str) -> dict[str, Any]:
    return {"identifier": UNGUARDED_ID, "category": "escalation", "severity": "high",
            "title": f"{HERMES_NAME} started without Blackbox"[:200], "tool_name": HERMES_ID, "matched": MATCHED,
            "evidence": f"{stamp}: {reason}"[:300], "confirmed": False, "source": "custom", "kind": "flag-only",
            "advice": (f"Hermes did not load Blackbox at this start, so nothing that {HERMES_NAME} session did was checked "
                       "or recorded. Restart Hermes; if it happens again, run `blackbox status`."),
            "fields": {"agent": HERMES_ID, "folder": home[:400]}}


def _matches(path: Path, text: str, first: bool, now: float) -> Iterable[tuple[str, str, str]]:
    """(call id, reason, stamp) for each line of *text* that says Hermes runs without Blackbox."""
    for line in text.splitlines():
        found = _LINE.match(line.strip())
        if found is None:
            continue
        if first and now - _when(found["at"]) > FIRST_LOOK_SECONDS:
            continue
        reason = found["load"] if found["load"] is not None else f"its guard did not start ({found['start']})"
        yield _call_id(path, line.strip()), reason.strip(), found["at"]


def catch_up() -> int:
    """Record one HIGH finding per new line in Hermes's logs that says it runs without Blackbox;
    how many were recorded. Fail-open: 0 on any error. Writes nothing with no Blackbox home."""
    from .. import audit   # late: only the observer's look asks
    if not constants.blackbox_home().is_dir():
        return 0
    try:
        with _lock:
            cursor = read_json_object(_cursor_path()) or {}
            fresh: list[tuple[str, str, str, str]] = []
            now = time.time()
            for path in logs():
                text, entry, first = _new_lines(path, cursor)
                if entry is None:
                    continue
                cursor[str(path)] = entry
                home = str(path.parent.parent)
                fresh += [(call_id, reason, stamp, home) for call_id, reason, stamp in _matches(path, text, first, now)
                          if call_id not in _reported]
            write_json_object(_cursor_path(), cursor, what="the Hermes load-log cursor")
            if not fresh:
                return 0
            known = {str(found.get("tool_call_id") or "") for found in audit.read_findings(limit=RECENT_SCANNED)}
            recorded = 0
            for call_id, reason, stamp, home in fresh:
                _reported.add(call_id)
                if call_id in known:
                    continue
                audit.record_for(HERMES_ID, event="unguarded_run", workspace=home, findings=[_finding(home, reason, stamp)],
                                 detail={"decision": "flag", "tool_name": HERMES_ID, "tool_call_id": call_id,
                                         "agent": HERMES_ID, "workspace": home})
                recorded += 1
            return recorded
    except Exception:   # health: allow BLE001 -- fail open: the observer's look goes on without this back-stop
        logger.debug("blackbox: Hermes's load log not read", exc_info=True)
        return 0


__all__ = ["BROKEN_LINE", "MATCHED", "PLUGIN_NAME", "catch_up", "logs"]
