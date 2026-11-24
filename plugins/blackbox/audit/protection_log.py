"""The protection log: a hash-chained, append-only record of what Blackbox's protection refused.

Each entry carries the hash of the one before it, so an entry edited, removed or put in between
breaks the chain; a head kept beside the log (the sequence and hash of the newest entry, written on
every append) shows a log rolled back to an older copy (``rewound``) or replaced with another one of
the same length (``drift``). Blackbox checks it itself (:func:`verify`), and an organisation's
add-on can send :func:`head` elsewhere, where a head that went BACK shows what a local check can not:
someone who rewrote both the log and the head.

Entries hold no prompt, command, path or file content: a kind (``tamper``), a category, the agent's
catalogue id and a time (the details stay in the audit log, which is redacted and size-capped).

File shape (``$BLACKBOX_HOME/protection-log.jsonl``, one JSON object per line)::

    {"seq": 7, "at": 1795000000.0, "kind": "tamper", "what": "self-protection", "agent": "codex",
     "prev": "<hash of entry 6>", "hash": "<sha256 of this entry without its hash>"}

The log keeps its newest :data:`MAX_ENTRIES`; a trim records the entry before the oldest kept one in
the head file (``base``), so the check still starts from a known link. Both files are places
self-protection guards.

Usage::

    protection_log.append("tamper", "self-protection", agent="codex")
    protection_log.head()     # LogHead(seq=7, hash="…", state="ok", first_bad=0)
    protection_log.verify()   # the same: the head of the log as it is, and the result of the check
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..kernel import constants
from ..kernel.bounded_files import (
    atomic_write,
    file_lock,
    read_json_object,
    read_small_text,
    write_json_object,
)

GENESIS = "0" * 64
#: Entries kept; an older one is dropped from the front, its link kept as the base.
MAX_ENTRIES = 5000
#: The largest log read (an entry is about 200 bytes); past this the log counts as broken.
MAX_BYTES = 4 * 1024 * 1024
MAX_FIELD_CHARS = 64
LOCK_TIMEOUT_S = 2.0
OK, BROKEN, REWOUND, DRIFT, EMPTY = "ok", "broken", "rewound", "drift", "empty"


@dataclass(frozen=True)
class LogHead:
    """Where the log ends and what the check found.

    *state*: ``ok``; ``broken`` (an entry does not link to the one before, or does not match its
    hash — *first_bad* is its sequence); ``rewound`` (the log ends before the head written last);
    ``drift`` (it ends at the same place with another hash); ``empty`` (nothing logged yet).
    """

    seq: int
    hash: str
    state: str
    first_bad: int = 0


def _log() -> Path:
    return constants.blackbox_home() / "protection-log.jsonl"


def _head_file() -> Path:
    return constants.blackbox_home() / "protection-log.head.json"


def _digest(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _entries() -> list[Any] | None:
    """Every line, parsed (a line that is not JSON is kept as None); None when the log is there but
    can not be read as one (too big, a link put in its place, not a file)."""
    text = read_small_text(str(_log()), MAX_BYTES, nofollow=True)
    if text is None:
        return None if _log().is_symlink() or _log().exists() else []
    out: list[Any] = []
    for line in text.splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            out.append(None)
    return out


def _check(entries: list[Any], base: dict[str, Any]) -> LogHead:
    """Walk the chain from *base* (seq, hash of the entry before the first kept one)."""
    seq, previous = int(base.get("seq") or 0), str(base.get("hash") or GENESIS)
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("seq") != seq + 1 or entry.get("prev") != previous \
                or entry.get("hash") != _digest(entry):
            return LogHead(seq=seq, hash=previous, state=BROKEN, first_bad=seq + 1)
        seq, previous = entry["seq"], entry["hash"]
    return LogHead(seq=seq, hash=previous, state=OK if entries else EMPTY)


def verify() -> LogHead:
    """Check the whole log against itself and against the head written last."""
    entries = _entries()
    saved = read_json_object(_head_file()) or {}
    if entries is None:
        return LogHead(seq=int(saved.get("seq") or 0), hash=str(saved.get("hash") or ""), state=BROKEN, first_bad=0)
    found = _check(entries, saved.get("base") or {})
    if found.state == BROKEN:
        return found
    written = int(saved.get("seq") or 0)
    if found.seq < written:
        return LogHead(seq=found.seq, hash=found.hash, state=REWOUND)
    if written and found.seq == written and found.hash != saved.get("hash"):
        return LogHead(seq=found.seq, hash=found.hash, state=DRIFT)
    return found


def head() -> LogHead:
    """The log's head and the result of the check (the same as :func:`verify`)."""
    return verify()


def append(kind: str, what: str, *, agent: str = "") -> LogHead:
    """Add one entry and move the head. Raises ``OSError`` when the log can not be written (the
    caller, on a hook's path, is fail-open). A log that no longer checks is NOT repaired: the new
    entry links to its last good one, and the break stays visible."""
    with file_lock(_log().with_suffix(".lock"), timeout_s=LOCK_TIMEOUT_S):
        entries = _entries()
        if entries is None:   # never replaced by a fresh log: that would hide what was done to it
            raise OSError("the protection log can not be read; it is left as it is")
        saved = read_json_object(_head_file()) or {}
        last = _check(entries, saved.get("base") or {})
        entry: dict[str, Any] = {"seq": last.seq + 1, "at": round(time.time(), 3), "kind": kind[:MAX_FIELD_CHARS],
                                 "what": what[:MAX_FIELD_CHARS], "agent": agent[:MAX_FIELD_CHARS], "prev": last.hash}
        entry["hash"] = _digest(entry)
        kept = [e for e in entries if isinstance(e, dict)][-(MAX_ENTRIES - 1):] if last.state != BROKEN else entries
        base = saved.get("base") or {}
        if len(kept) < len(entries) and last.state != BROKEN:
            dropped = entries[len(entries) - len(kept) - 1]
            base = {"seq": dropped["seq"], "hash": dropped["hash"]}
        lines = [json.dumps(e, sort_keys=True) if e is not None else "" for e in kept] + [json.dumps(entry, sort_keys=True)]
        atomic_write(_log(), "\n".join(lines) + "\n", mode=0o600)
        write_json_object(_head_file(), {"seq": entry["seq"], "hash": entry["hash"], "base": base},
                          what="Blackbox's protection log head")
    return LogHead(seq=entry["seq"], hash=entry["hash"], state=OK if last.state in (OK, EMPTY) else last.state,
                   first_bad=last.first_bad)
