"""The local JSONL log files under ``$BLACKBOX_HOME`` and their size cap.

Append-only JSON-lines writes under one process lock, trimmed to a bounded
size; file discovery for findings/audit logs across protected agents.
"""

from __future__ import annotations

import contextlib
import contextvars
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, TypeVar
from ..kernel import constants
from ..kernel.bounded_files import append_line, atomic_write, file_lock, read_jsonl

logger = logging.getLogger(__name__)

T = TypeVar("T")

#: Set inside :func:`sandbox_run`: every log, ledger and cooldown this module's
#: callers write goes to ``$BLACKBOX_HOME/sandbox/`` instead (2026-10-21). A
#: ContextVar, so a share thread started with ``contextvars.copy_context()``
#: inherits it and two concurrent runs never see each other's setting.
_SANDBOX_RUN: contextvars.ContextVar[bool] = contextvars.ContextVar("blackbox_sandbox_run", default=False)
SANDBOX_DIR = "sandbox"


@contextlib.contextmanager
def sandbox_run() -> Iterator[None]:
    """Run a block whose local records must stay out of the real logs (Pattern: Context Object).

    Usage::

        with audit.sandbox_run():
            hooks.on_pre_tool_call(...)   # findings, activity, share ledger -> sandbox/
    """
    token = _SANDBOX_RUN.set(True)
    try:
        yield
    finally:
        _SANDBOX_RUN.reset(token)


def in_sandbox_run() -> bool:
    """True inside :func:`sandbox_run`."""
    return _SANDBOX_RUN.get()

# ---------------------------------------------------------------------------
# Bounded JSONL logs
# ---------------------------------------------------------------------------

_LOG_MAX_BYTES = 8 * 1024 * 1024  # trim each log at 8 MB
_LOG_KEEP_BYTES = 4 * 1024 * 1024  # keep the most recent ~4 MB after trimming
_lock = threading.Lock()
#: One lock file per log folder, shared by every agent process that writes there.
_LOGS_LOCK_FILE = ".logs.lock"
#: The longest a record waits for another process's append or trim. A hook must never
#: stall on a lock: past this, the record is written without it (and no trim is tried).
_LOGS_LOCK_WAIT_S = 0.5


def _home() -> Path:
    home = constants.blackbox_home() / SANDBOX_DIR if _SANDBOX_RUN.get() else constants.blackbox_home()
    try:
        home.mkdir(parents=True, exist_ok=True)
    except Exception:  # pragma: no cover - defensive
        pass
    return home


# ---------------------------------------------------------------------------
# Whole-log reads, cached by what is on disk
# ---------------------------------------------------------------------------

_read_cache: dict[str, tuple[tuple, Any]] = {}
_read_cache_lock = threading.Lock()


def _signature(paths: Iterable[Path]) -> tuple:
    """(path, mtime_ns, size) per file — what makes a parsed log stale. A missing file
    is part of the signature too, so its arrival invalidates the entry."""
    out = []
    for path in paths:
        try:
            st = path.stat()
            out.append((str(path), st.st_mtime_ns, st.st_size))
        except OSError:
            out.append((str(path), None, None))
    return tuple(out)


def cached(key: str, paths: Iterable[Path], build: Callable[[], T]) -> T:
    """``build()``'s result for *key*, rebuilt only when any of *paths* changed on disk.

    Why: the dashboard polls every 4 s and several readers parse, dedupe and sort
    every log in the home per request — up to 16 MB twice per poll for a page of
    50 (review 2026-10-22). Appends change a file's size, trims change its mtime,
    so (mtime, size) per file is a safe staleness key. Callers treat the value as
    read-only; the same object is handed to every caller until the logs change.
    """
    signature = _signature(paths)
    with _read_cache_lock:
        hit = _read_cache.get(key)
        if hit is not None and hit[0] == signature:
            return hit[1]
    value = build()
    with _read_cache_lock:
        _read_cache[key] = (signature, value)
    return value


def _append_jsonl(path: Path, record: dict[str, Any]) -> None:
    """Append *record* to the log at *path*, trimming the log when it is past its cap.

    Several agent processes write the same logs, so the append and the trim happen under
    the folder's cross-process lock: a trim reads the tail and swaps it in while no one
    else is appending, so no record is lost and no reader sees a half-written log. When
    the lock cannot be had in :data:`_LOGS_LOCK_WAIT_S` the record is still written (a
    record is never dropped for a lock) and the trim waits for a later append."""
    line = json.dumps(record, ensure_ascii=False)
    with _lock, _logs_lock(path) as locked:
        append_line(path, line)
        if locked:
            _trim_if_needed(path)


@contextlib.contextmanager
def _logs_lock(path: Path) -> Iterator[bool]:
    """The cross-process lock for *path*'s folder; yields False when it could not be taken."""
    with contextlib.ExitStack() as held:
        try:
            locked = held.enter_context(file_lock(path.with_name(_LOGS_LOCK_FILE), timeout_s=_LOGS_LOCK_WAIT_S))
        except OSError as exc:
            logger.debug("blackbox: log lock unavailable (%s); writing without it", exc)
            locked = False
        yield locked


def _trim_if_needed(path: Path) -> None:
    """Keep the tail of *path* when it grows past the cap (whole lines only). The caller
    holds the logs lock; the kept tail replaces the log in one rename."""
    try:
        if path.stat().st_size <= _LOG_MAX_BYTES:
            return
        with path.open("rb") as fh:
            fh.seek(-_LOG_KEEP_BYTES, os.SEEK_END)
            tail = fh.read()
        # Drop a possibly-partial first line.
        nl = tail.find(b"\n")
        if nl != -1:
            tail = tail[nl + 1 :]
        atomic_write(path, tail)
    except OSError as exc:
        logger.warning("blackbox: could not trim %s (%s); it keeps growing until a trim succeeds", path.name, exc)


def _findings_files() -> list[tuple[Path, str]]:
    """Return ``(path, default_framework)`` for every findings log in the home.

    ``findings.jsonl`` is the Hermes plugin's own log; sibling
    ``findings.<framework>.jsonl`` files come from other local agents (e.g.
    OpenClaw) sharing the same blackbox home. Framework is taken from each
    finding line when present, else the filename.
    """
    home = _home()
    out: list[tuple[Path, str]] = [(home / "findings.jsonl", "hermes")]
    try:
        for extra in sorted(home.glob("findings.*.jsonl")):
            # findings.<framework>.jsonl → framework from the middle segment.
            parts = extra.name.split(".")
            fw = parts[1] if len(parts) == 3 else "unknown"
            out.append((extra, fw))
    except Exception:  # pragma: no cover - defensive
        pass
    return out


def _audit_files() -> list[tuple[Path, str]]:
    """Return routine audit logs for Hermes and every attached framework."""
    home = _home()
    out: list[tuple[Path, str]] = [(home / "audit.jsonl", "hermes")]
    try:
        for extra in sorted(home.glob("audit.*.jsonl")):
            parts = extra.name.split(".")
            fw = parts[1] if len(parts) == 3 else "unknown"
            out.append((extra, fw))
    except Exception:  # pragma: no cover - defensive
        pass
    return out


def _load_jsonl(path: Path, default_event: str) -> list[dict[str, Any]]:
    """Load a jsonl file, tagging each row with ``event=default_event`` when
    the line has no explicit event (e.g. file_access.jsonl, dependencies.jsonl)."""
    rows = read_jsonl(path)
    for row in rows:
        row.setdefault("event", default_event)
    return rows
