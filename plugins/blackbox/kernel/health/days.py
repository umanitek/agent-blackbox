"""Day arithmetic every age and silence rule shares.

Six modules carried their own ``_days_between`` (four byte-identical) and three
their own ``_today`` before 2026-10-22. Days are ISO ``YYYY-MM-DD`` strings — the
form every curator statement, heartbeat and ledger row records — and they are UTC
days: a rule that compared one against the machine's LOCAL date was off by a day for
part of every day.

Usage::

    today_utc()                         # "2026-11-10"
    utc_day(record.filed_at)            # the UTC day of an epoch time
    utc_day_or(row.get("firstSeen"), today)   # …or a fallback when it is absent or unreadable
    days_between(first_day, today)
"""

from __future__ import annotations

from datetime import UTC, date, datetime


def days_between(earlier: str, later: str) -> int:
    """Whole days from *earlier* to *later* (negative when *later* is first);
    0 when either is not an ISO day — an unreadable date is never an alarm."""
    try:
        return (date.fromisoformat(later) - date.fromisoformat(earlier)).days
    except (TypeError, ValueError):
        return 0


def today_utc() -> str:
    """Today's UTC day as ``YYYY-MM-DD`` — the one clock the day rules read."""
    return datetime.now(UTC).date().isoformat()


def utc_day(epoch: float) -> str:
    """The UTC day (``YYYY-MM-DD``) an epoch time falls on."""
    return datetime.fromtimestamp(epoch, UTC).date().isoformat()


def utc_day_or(epoch: object, default: str) -> str:
    """The UTC day of *epoch*, or *default* when it is absent (falsy) or not a readable time."""
    try:
        return utc_day(float(epoch)) if epoch else default   # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError, OSError):
        return default
