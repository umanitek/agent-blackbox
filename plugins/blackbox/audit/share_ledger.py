"""Outbound-report bookkeeping: the share ledger, per-threat cooldown, daily cap.

:func:`record_share_outcome` / :func:`read_share_ledger` keep the durable
record of every community share attempt; :func:`recently_reported` /
:func:`mark_reported` enforce the 6-hour per-threat cooldown;
:func:`allow_report` the daily report cap. Lives beside the audit logs because
it shares their store and lock.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List
from ..kernel import constants
from ..kernel.bounded_files import atomic_write, read_json_object
from . import log_store
from . import redaction

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Outbound-report daily rate limiter
# ---------------------------------------------------------------------------


def _rate_state_path() -> Path:
    return log_store._home() / "report_rate.json"


# ---------------------------------------------------------------------------
# Community reports ledger ($BLACKBOX_HOME/reports_log.jsonl)
# ---------------------------------------------------------------------------

#: Durable record of every outbound community-report attempt (KI-015). The
#: cooldown state above prunes after 6h, so WITHOUT this file a node forgets
#: what it ever contributed; the ledger is what makes ``blackbox report
#: --status`` work offline and enables promotion-feedback later. Append-only
#: JSONL, size-capped by the shared trim like every other log here.
_REPORTS_LOG = "reports_log.jsonl"


def record_share_outcome(
    *,
    identifier: str,
    category: str,
    severity: str,
    subject: str,
    asset_name: str,
    ok: bool,
    error: str = "",
    outcome: str = "",
) -> None:
    """Append one outbound-share attempt (success or failure) to the ledger.

    ``outcome`` names what happened in more detail than ``ok``
    (``accepted`` / ``already-shared`` / ``failed`` — community.ShareOutcome);
    ``ok`` stays True only when a report actually reached the network.

    Called by the community share worker AFTER the share resolves, never on
    the hook hot path. ``error`` is sanitized like every audit text so a
    failure message can never smuggle a secret into the log. Fail-open.
    """
    try:
        log_store._append_jsonl(
            log_store._home() / _REPORTS_LOG,
            {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "identifier": str(identifier or "")[:512],
                "category": str(category or "")[:64],
                "severity": str(severity or "")[:16],
                "subject": str(subject or "")[:512],
                "asset_name": str(asset_name or "")[:128],
                "ok": bool(ok),
                "outcome": str(outcome or ("accepted" if ok else "failed"))[:32],
                "error": redaction.sanitize_text(error, 400) if error else "",
            },
        )
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: share-ledger write failed (%s)", exc)


def read_share_ledger(limit: int = 100) -> list[dict[str, Any]]:
    """Newest-first rows from the reports ledger; empty list when absent.

    The offline half of ``blackbox report --status`` (the graph-backed half
    is the Q9 reporter-profile query, merged by the caller when reachable).
    """
    path = log_store._home() / _REPORTS_LOG
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8-sig") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except Exception:
                    continue
                if isinstance(item, dict):
                    rows.append(item)
    except Exception:  # pragma: no cover - fail open
        return []
    return list(reversed(rows[-max(1, limit):]))


# Re-reporting the same identifier within this window adds no signal (the
# sighting KA name is stable per identifier+reporter, so a re-share only
# refreshes dateModified) — skip it to keep reports low-noise.
REPORT_COOLDOWN_SECS = 6 * 3600


def previously_accepted(asset_name: str) -> bool:
    """True when this node's ledger shows *asset_name* reached the network
    before (rows written before the outcome field count by ``ok``)."""
    if not asset_name:
        return False
    for row in read_share_ledger(limit=_LEDGER_SCAN_LIMIT):
        if row.get("asset_name") == asset_name and row.get("outcome", "accepted" if row.get("ok") else "") == "accepted":
            return True
    return False


#: How far back previously_accepted looks (the ledger is size-capped on disk).
_LEDGER_SCAN_LIMIT = 100_000


def _read_rate_state() -> dict[str, Any]:
    return read_json_object(_rate_state_path()) or {}


def recently_reported(identifier: str, cooldown: int = REPORT_COOLDOWN_SECS) -> bool:
    """True when *identifier* was reported within the last *cooldown* seconds.

    Fail-open: any state error reads as "not recently reported".
    """
    if not identifier:
        return False
    try:
        stamps = _read_rate_state().get("reported") or {}
        ts = float(stamps.get(identifier, 0))
        return (time.time() - ts) < max(1, cooldown)
    except Exception:  # pragma: no cover - fail open
        return False


def mark_reported(identifier: str) -> None:
    """Stamp *identifier* as handled now (per-threat cooldown), pruning expired.

    Decoupled from :func:`allow_report` so the cooldown also covers the private
    WM audit KA; otherwise, with reporting off or the daily cap hit, the stamp
    would never be set and the private KA would rewrite on every event.
    """
    if not identifier:
        return
    try:
        with log_store._lock:
            state = _read_rate_state()
            stamps = state.get("reported")
            stamps = dict(stamps) if isinstance(stamps, dict) else {}
            now = time.time()
            stamps[identifier] = now
            state["reported"] = {
                k: v for k, v in stamps.items()
                if isinstance(v, (int, float)) and (now - v) < REPORT_COOLDOWN_SECS
            }
            atomic_write(_rate_state_path(), json.dumps(state))   # a torn file would reset every cooldown
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: mark_reported failed (%s)", exc)


def allow_report(daily_limit: int) -> bool:
    """Return True if another outbound SWM report is within today's cap.

    Only the date-keyed daily counter; the per-threat cooldown is enforced by
    :func:`recently_reported` / :func:`mark_reported`. Fail-open: on any state
    error, allow the report.

    Concurrency (KI-038, decided): the counter is guarded by an in-process
    lock only. Several agent PROCESSES sharing one BLACKBOX_HOME can race the
    read-modify-write and land slightly over the cap. Accepted deliberately:
    the cap is an anti-flood brake (order-of-magnitude bound), not an exact
    quota — the per-threat cooldown and one-subject-per-(reporter,threat)
    naming bound the graph impact regardless, and a cross-process file lock
    here would put lock-contention I/O on the finding path for no real gain.
    """
    today = time.strftime("%Y-%m-%d", time.gmtime())
    path = _rate_state_path()
    try:
        with log_store._lock:
            state = _read_rate_state()
            if state.get("date") != today:
                # New day: reset the counter but preserve the cooldown stamps.
                state = {"date": today, "count": 0, "reported": state.get("reported", {})}
            limit = constants.effective_daily_report_limit(daily_limit)   # never "off" (Refine R1)
            if int(state.get("count", 0)) >= limit:
                logger.debug("blackbox: daily report limit %s reached", daily_limit)
                return False
            state["count"] = int(state.get("count", 0)) + 1
            atomic_write(path, json.dumps(state))   # a torn file would reset the daily cap
            return True
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: rate-limit state failed (%s); allowing", exc)
        return True


def erase_share_records() -> int:
    """Delete this node's share ledger and cooldown/cap state (Refine R1,
    ``blackbox report --erase-identity``). Returns how many files were removed."""
    removed = 0
    for path in (log_store._home() / _REPORTS_LOG, _rate_state_path()):
        try:
            path.unlink()
            removed += 1
        except FileNotFoundError:
            continue
    return removed
