"""Recording and reading findings (what Blackbox flagged or blocked).

:func:`record` writes one finding (redacted, with bounded conversation
context); :func:`record_file_access` / :func:`record_dependency` write the
activity side-logs; :func:`read_findings` / :func:`count_findings` and the
framework helpers serve the CLI and dashboard.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional
from ..kernel import constants
from ..kernel.bounded_files import read_jsonl
from . import finding_display, log_store
from . import redaction

logger = logging.getLogger(__name__)


# Read-path caps for the conversation context on a finding row, so a huge log
# line can't bloat the ``/api/findings`` response.
_CONTEXT_MAX_TURNS = 16
_CONTEXT_TURN_CHARS = 3000
_CONTEXT_FIELD_CHARS = 6000


def _bounded_context(ctx: Any) -> Optional[dict[str, Any]]:
    """Normalize, redact, and bound a finding's local conversation ``context``.

    Shape ``{turns: [{role, text}], input, result, truncated}``, every field
    optional. Every text field passes through :func:`sanitize_text` so it is
    safe even if a caller forgot to redact. Returns ``None`` when empty; bad
    shapes degrade to ``None`` rather than raising (fail-open).
    """
    if not isinstance(ctx, dict):
        return None
    out: dict[str, Any] = {}
    raw_turns = ctx.get("turns")
    if isinstance(raw_turns, list) and raw_turns:
        turns: list[dict[str, str]] = []
        for turn in raw_turns[-_CONTEXT_MAX_TURNS:]:
            if not isinstance(turn, dict):
                continue
            text = redaction.sanitize_text(str(turn.get("text") or ""), _CONTEXT_TURN_CHARS)
            if not text:
                continue
            turns.append({
                "role": str(turn.get("role") or "user")[:32],
                "text": text,
            })
        if turns:
            out["turns"] = turns
    for key in ("input", "result"):
        val = ctx.get(key)
        if isinstance(val, str) and val:
            out[key] = redaction.sanitize_text(val, _CONTEXT_FIELD_CHARS)
    if not out:
        return None
    if ctx.get("truncated"):
        out["truncated"] = True
    return out


def finding_of(record: dict[str, Any]) -> dict[str, Any]:
    """The finding a findings.jsonl record holds — THE fallback every reader uses: ``finding``,
    else the first of ``findings`` (older rows), else ``{}``."""
    found = record.get("finding") or (record.get("findings") or [{}])[0] or {}
    return found if isinstance(found, dict) else {}


def is_confirmed(finding: dict[str, Any]) -> bool:
    """Whether a recorded finding came from a verified rule. The writer
    (:func:`_finding_summary`) always records it, defaulting to True; a row without it reads the
    same way in every view (the activity feed once read it as False, the findings list as True)."""
    return bool(finding.get("confirmed", True))


def _flatten_finding_row(rec: dict[str, Any], default_fw: str) -> dict[str, Any]:
    # Lift the per-line ``finding`` fields up to a dashboard-friendly row.
    finding = finding_of(rec)
    detail = rec.get("detail") or {}
    row = {
        "time": rec.get("iso") or rec.get("ts"),
        "ts": rec.get("ts") or 0,
        "event": rec.get("event"),
        "session_id": detail.get("session_id"),
        "task_id": detail.get("task_id"),
        "turn_id": detail.get("turn_id"),
        "identifier": finding.get("identifier"),
        "category": finding.get("category"),
        "severity": finding.get("severity"),
        "title": finding.get("title"),
        "framework": finding.get("framework") or rec.get("framework") or default_fw,
        "workspace": finding.get("workspace") or rec.get("workspace") or detail.get("workspace"),
        "tool_name": finding.get("tool_name") or detail.get("tool_name"),
        "evidence": finding.get("evidence") or finding.get("title"),
        "confirmed": is_confirmed(finding),
        "source": finding.get("source") or ("public" if is_confirmed(finding) else "heuristic"),
        # What the hook did with it: "block" | "flag" ("" for rows older than KI-189).
        "decision": str(detail.get("decision") or ""),
        # Local-only conversation snapshot (redacted upstream).
        "context": _bounded_context(detail.get("context") or finding.get("context")),
        "found_in": finding.get("found_in") or "",
    }
    # What the pages group on (one threat on screen) and which row stands for it — served, not re-derived.
    row["display_key"], row["display_rank"] = finding_display.display_key(row), finding_display.display_rank(row)
    return row


def _dedupe_finding_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse repeated findings emitted by multiple API calls in one turn."""
    deduped: dict[tuple, dict[str, Any]] = {}
    order: list[tuple] = []
    for row in rows:
        scope = row.get("turn_id") or row.get("task_id") or row.get("session_id") or row.get("time")
        key = (
            row.get("framework"),
            row.get("workspace"),
            row.get("event"),
            scope,
            row.get("identifier"),
            row.get("evidence"),
        )
        existing = deduped.get(key)
        if existing is None:
            deduped[key] = row
            order.append(key)
            continue
        if (row.get("ts") or 0) < (existing.get("ts") or 0):
            deduped[key] = row
    return [deduped[key] for key in order]


def read_findings(limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
    """Return findings newest-first, paged, merged across every agent's log.

    Reads ``findings.jsonl`` plus any ``findings.<framework>.jsonl`` siblings —
    once per change on disk (:func:`log_store.cached`); pages are slices of
    that one parsed, deduped, sorted list. Empty on any error.
    """
    return _all_findings()[offset : offset + limit]


def _all_findings() -> list[dict[str, Any]]:
    files = log_store._findings_files()
    key = f"findings:{log_store._home()}"
    return log_store.cached(key, [path for path, _ in files], lambda: _load_finding_rows(files))


def _load_finding_rows(files: list[tuple[Any, str]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path, default_fw in files:
        rows.extend(_flatten_finding_row(rec, default_fw) for rec in read_jsonl(path))   # object rows only
    rows = _dedupe_finding_rows(rows)
    # Newest-first across all logs; rows with no numeric ts keep insertion order.
    rows.sort(key=lambda r: r.get("ts") or 0, reverse=True)
    return rows


#: Rows scanned when counting how often each threat fired here (bounded).
_FIRED_SCAN_LIMIT = 5_000


def blocked_counts_by_identifier(limit: int = _FIRED_SCAN_LIMIT) -> dict[str, int]:
    """How many actions each threat identifier BLOCKED on this machine (newest
    *limit* findings whose hook decision was ``block``, KI-189). R10 uses it
    for "a revoked threat blocked N actions here"; a flag-only firing is not
    an action the operator lost."""
    counts: dict[str, int] = {}
    for row in read_findings(limit=limit):
        identifier = str(row.get("identifier") or "")
        if identifier and row.get("decision") == "block":
            counts[identifier] = counts.get(identifier, 0) + 1
    return counts


def count_findings() -> int:
    return len(_all_findings())


def local_frameworks() -> list[str]:
    """Frameworks that have written findings into this shared home (for the
    dashboard's agent list). Always includes ``hermes`` when its log exists."""
    out: list[str] = []
    for path, default_fw in log_store._findings_files():
        if path.exists() and default_fw not in out:
            out.append(default_fw)
    return out


def local_active_frameworks() -> list[str]:
    """Frameworks with observed local Blackbox activity.

    Findings identify their framework explicitly through ``findings*.jsonl``;
    routine activity lives in ``audit.jsonl`` / ``audit.<framework>.jsonl``.
    """
    out = local_frameworks()
    for audit_path, framework in log_store._audit_files():
        if framework in out or not audit_path.exists():
            continue
        try:
            if any(line.strip() for line in audit_path.read_text(encoding="utf-8-sig").splitlines()):
                if framework == "hermes":
                    out.insert(0, framework)
                else:
                    out.append(framework)
        except Exception:
            pass
    return out


# ---------------------------------------------------------------------------
# Recording
# ---------------------------------------------------------------------------


def record(
    *,
    event: str,
    findings: Optional[list[dict[str, Any]]] = None,
    detail: Optional[dict[str, Any]] = None,
) -> None:
    """Append an audit record; on findings also append to findings.jsonl.

    *findings* are Finding dicts (evidence already redacted). *detail* is extra
    context (tool name, ids, args) and is redacted again here before writing.
    """
    try:
        now = time.time()
        base = {
            "ts": now,
            "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "event": event,
            # Profile-level identity is local-only and lets the dashboard keep
            # separate Hermes homes from inheriting each other's activity.
            "workspace": str(constants.hermes_home()),
        }
        if detail:
            # Redact the detail normally, but rebuild ``detail.context`` via
            # ``_bounded_context``: a plain ``redact`` would re-clamp the
            # conversation snapshot to the 1200-char ``input``/``prompt`` cap.
            raw_context = detail.get("context") if isinstance(detail, dict) else None
            base["detail"] = redaction.redact(detail)
            bounded = _bounded_context(raw_context) if isinstance(raw_context, dict) else None
            if bounded:
                base["detail"]["context"] = bounded
            elif isinstance(base["detail"], dict):
                base["detail"].pop("context", None)
        if findings:
            base["findingCount"] = len(findings)
            base["findings"] = [_finding_summary(f) for f in findings]
        log_store._append_jsonl(log_store._home() / "audit.jsonl", base)
        for finding in findings or []:
            log_store._append_jsonl(log_store._home() / "findings.jsonl", {**base, "finding": _finding_summary(finding)})
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: audit record failed: %s", exc)


def _finding_summary(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "identifier": finding.get("identifier"),
        "category": finding.get("category"),
        "severity": finding.get("severity"),
        "title": finding.get("title"),
        "framework": finding.get("framework") or "hermes",
        "tool_name": finding.get("tool_name"),
        "evidence": redaction.sanitize_text(str(finding.get("evidence") or ""), 700),
        "confirmed": bool(finding.get("confirmed", True)),
        "candidate": bool(finding.get("candidate", not finding.get("confirmed", True))),
        "source": str(finding.get("source") or ("public" if finding.get("confirmed", True) else "heuristic")),
        "ts": time.time(),
        # threat profiles: the closed-vocabulary sighting the guard attached (goal, at risk, outcome…).
        "sighting": {str(k)[:64]: str(v)[:128] for k, v in (finding.get("sighting") or {}).items()},
        # Where an injection was met — a closed word (constants.INJECTION_CONTEXTS), never content.
        "found_in": _found_in(finding),
    }


def _found_in(finding: dict[str, Any]) -> str:
    """The closed context an injection finding was met in ("in-tool-output", …), or ""."""
    fields = finding.get("fields")
    context = fields.get("context") if isinstance(fields, dict) else None
    return context if context in constants.INJECTION_CONTEXTS else ""


# ---------------------------------------------------------------------------
# File-access visibility log ($BLACKBOX_HOME/file_access.jsonl)
# ---------------------------------------------------------------------------


def record_file_access(tool: str, path: str, mode: str) -> None:
    """Append a file-access visibility record so a user can see what files
    their agent touched.

    Visibility log, distinct from findings: local-only, NEVER shared to SWM.
    The path is the point of the log, but a URL can carry a secret (a seed phrase in
    its query or its path, KI-377): it goes through the one redactor like every other
    logged text — an ordinary path comes out unchanged. Best-effort and fail-open.
    """
    try:
        now = time.time()
        log_store._append_jsonl(log_store._home() / "file_access.jsonl", {
            "ts": now,
            "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "tool": str(tool or "")[:120],
            "path": redaction.sanitize_text(str(path or ""), 1000),
            "mode": str(mode or "")[:16],
            "workspace": str(constants.hermes_home()),
        })
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: file access record failed: %s", exc)


def record_dependency(ecosystem: str, name: str, version: str, tool: str = "") -> None:
    """Append a dependency-install record.

    Lib-inventory trail: EVERY install is recorded (not only threats), so an
    operator can see every package an agent pulled in. Local-only visibility
    log, never shared to SWM; best-effort and fail-open.
    """
    try:
        now = time.time()
        log_store._append_jsonl(log_store._home() / "dependencies.jsonl", {
            "ts": now,
            "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "ecosystem": str(ecosystem or "")[:40],
            "name": str(name or "")[:200],
            "version": str(version or "")[:80],
            "tool": str(tool or "")[:120],
            "workspace": str(constants.hermes_home()),
        })
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: dependency record failed: %s", exc)


def read_file_access(limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
    """Return file-access visibility records newest-first, paged."""
    rows = read_jsonl(log_store._home() / "file_access.jsonl")
    return rows[::-1][offset : offset + limit]
