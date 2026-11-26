"""What the live lookups could and could not answer — the record every surface reads.

Lookups run inside the agent's process; `blackbox status` and the dashboard run
in others. So the state lives in one small file in the Blackbox home
(``verified_lookup_state.json``), written only on a transition (ok → degraded,
degraded → ok) or at most once a minute while degraded — never once per tool call.

Why this exists (LES-011): a lookup that could not tell lets the action through
(Blackbox never breaks the host agent) but must never LOOK like protection. With
the fallback index off by default, this file is how "verified protection is
paused" reaches the operator.

Pattern: Global Object — one :data:`HEALTH` recorder per process, like
``community.PULSE``; tests build their own :class:`LookupHealth` on a temp path.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Optional

from ...kernel import constants
from ...kernel.bounded_files import atomic_write

logger = logging.getLogger(__name__)

OK = "ok"
DEGRADED = "degraded"
UNKNOWN = "unknown"

#: While degraded, the file is refreshed (failure count, last time) at most this often.
WRITE_INTERVAL_SECONDS = 60.0


@dataclass(frozen=True)
class LookupState:
    """``state`` — ``ok`` / ``degraded`` / ``unknown`` (never recorded);
    ``reason`` — the store's reason while degraded; ``since`` — epoch seconds the
    current state began; ``failures`` — lookups that could not tell since it began;
    ``last_at`` — epoch seconds of the last lookup recorded; ``ended_*`` — the last degraded
    episode that is over (its start, end, reason and failures; ``ended_since`` 0.0: none), kept so
    an outage that began and ended while no dashboard looked is still said once (L8,
    BB-LINUX-PENDING-7227a5: the store was OOM-killed mid-run and was back before the dashboard)."""

    state: str = UNKNOWN
    reason: str = ""
    since: float = 0.0
    failures: int = 0
    last_at: float = 0.0
    ended_since: float = 0.0
    ended_until: float = 0.0
    ended_reason: str = ""
    ended_failures: int = 0

    @property
    def degraded(self) -> bool:
        return self.state == DEGRADED

    def problem(self) -> str:
        """One line for the health alarm, "" when lookups are fine or never ran."""
        if not self.degraded:
            return ""
        minutes = max(0, int((time.time() - self.since) // 60))
        return f"{self.reason or 'the store did not answer'} ({self.failures} lookup(s) over {minutes} min)"


class LookupHealth:
    """Records lookup outcomes (:meth:`record`) and reads the state back (:meth:`read`).

    Usage: ``HEALTH.record(answer)`` after every live lookup (the lookup does
    this itself); ``HEALTH.read().problem()`` from status / health."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._state: Optional[LookupState] = None
        self._written_at = 0.0

    def _file(self) -> Path:
        return self._path or constants.blackbox_home() / "verified_lookup_state.json"

    def record(self, known: bool, reason: str = "", now: Optional[float] = None) -> None:
        """One lookup happened: *known* when the store answered (hit or clean)."""
        now = time.time() if now is None else now
        with self._lock:
            current = self._state or self._read_file()
            if known:
                if current.state == OK:
                    self._state = current   # kept: the hot path never re-reads the file in steady state
                    return                                   # steady state: nothing to write
                ended = (current.since, now, current.reason, current.failures) if current.degraded else \
                    (current.ended_since, current.ended_until, current.ended_reason, current.ended_failures)
                self._state = LookupState(OK, "", now, 0, now, *ended)
                self._write(now, force=True)
                return
            if current.degraded:
                self._state = replace(current, reason=reason or current.reason, failures=current.failures + 1, last_at=now)
                self._write(now, force=False)
            else:
                self._state = replace(current, state=DEGRADED, reason=reason, since=now, failures=1, last_at=now)
                self._write(now, force=True)
                logger.warning("blackbox: verified lookups degraded — %s; actions pass unchecked by the "
                               "verified graph until the store answers again", reason or "store did not answer")

    def read(self) -> LookupState:
        """The recorded state (this process's copy when it has one, else the file)."""
        with self._lock:
            return self._state or self._read_file()

    def _read_file(self) -> LookupState:
        try:
            data: dict[str, Any] = json.loads(self._file().read_text(encoding="utf-8-sig"))
            return LookupState(str(data.get("state", UNKNOWN)), str(data.get("reason", "")),
                               float(data.get("since", 0.0)), int(data.get("failures", 0)),
                               float(data.get("last_at", 0.0)), float(data.get("ended_since", 0.0)),
                               float(data.get("ended_until", 0.0)), str(data.get("ended_reason", "")),
                               int(data.get("ended_failures", 0)))
        except (OSError, ValueError, TypeError):
            return LookupState()

    def _write(self, now: float, *, force: bool) -> None:
        if not force and now - self._written_at < WRITE_INTERVAL_SECONDS:
            return
        try:
            path = self._file()
            path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(path, json.dumps(asdict(self._state)))
            self._written_at = now
        except OSError as exc:  # pragma: no cover - fail open: the state is still in memory
            logger.debug("blackbox: lookup state not written: %s", exc)


HEALTH = LookupHealth()
