"""Local audit trail, secret redaction, and outbound-report rate limiting.

Everything here is best-effort and fails open — audit logging must never break
the agent loop. Two JSONL logs live under ``$BLACKBOX_HOME``:

* ``audit.jsonl`` — every observed lifecycle/tool/api event (routine).
* ``findings.jsonl`` — only events that produced a Finding (threats).

Both are size-bounded (trimmed when they exceed a cap). On a finding we also
write a **private** WM audit knowledge asset (observed command/prompt kept
here, never shared to SWM) and count the sighting against a daily limit.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import constants, quads

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Redaction (ported verbatim from the original plugin/node-ui regexes)
# ---------------------------------------------------------------------------

_MAX_TEXT = 2000

_SECRET_KEY_RE = re.compile(
    r"(api[_-]?key|token|secret|password|passwd|credential|authorization|private[_-]?key"
    r"|client[_-]?secret|access[_-]?token|refresh[_-]?token)",
    re.IGNORECASE,
)
_BEARER_RE = re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)


def sanitize_text(value: str, max_len: int = _MAX_TEXT) -> str:
    """Redact common secret shapes from *value* and truncate to *max_len*.

    Uses the canonical secret-value patterns from :mod:`quads` plus opaque
    ``Bearer`` tokens, so a secret never lands raw in the audit log.
    """
    text = _BEARER_RE.sub("Bearer [REDACTED]", str(value))
    text = quads.redact_secret_values(text)
    if len(text) > max_len:
        return text[:max_len] + "...[truncated]"
    return text


def redact(value: Any, depth: int = 0) -> Any:
    """Recursively redact secrets from an arbitrary JSON-ish structure."""
    if depth > 5:
        return "[truncated-depth]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, (list, tuple)):
        return [redact(item, depth + 1) for item in list(value)[:50]]
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for key, child in value.items():
            key_str = str(key)
            if _SECRET_KEY_RE.search(key_str):
                out[key_str] = "[REDACTED]"
            elif key_str.lower() in {"content", "body", "input", "prompt"} and isinstance(child, str):
                out[key_str] = sanitize_text(child, 1200)
            else:
                out[key_str] = redact(child, depth + 1)
        return out
    return sanitize_text(str(value))


# ---------------------------------------------------------------------------
# Bounded JSONL logs
# ---------------------------------------------------------------------------

_LOG_MAX_BYTES = 8 * 1024 * 1024  # trim each log at 8 MB
_LOG_KEEP_BYTES = 4 * 1024 * 1024  # keep the most recent ~4 MB after trimming
_lock = threading.Lock()


def _home() -> Path:
    home = constants.blackbox_home()
    try:
        home.mkdir(parents=True, exist_ok=True)
    except Exception:  # pragma: no cover - defensive
        pass
    return home


def _append_jsonl(path: Path, record: Dict[str, Any]) -> None:
    line = json.dumps(record, ensure_ascii=False)
    with _lock:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        _trim_if_needed(path)


def _trim_if_needed(path: Path) -> None:
    """Keep the tail of *path* when it grows past the cap (whole lines only)."""
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
        path.write_bytes(tail)
    except Exception:  # pragma: no cover - defensive
        pass


def _findings_files() -> List["tuple[Path, str]"]:
    """Return ``(path, default_framework)`` for every findings log in the home.

    ``findings.jsonl`` is the Hermes plugin's own log; sibling
    ``findings.<framework>.jsonl`` files come from other local agents (e.g.
    OpenClaw) sharing the same blackbox home. Framework is taken from each
    finding line when present, else the filename.
    """
    home = _home()
    out: List["tuple[Path, str]"] = [(home / "findings.jsonl", "hermes")]
    try:
        for extra in sorted(home.glob("findings.*.jsonl")):
            # findings.<framework>.jsonl → framework from the middle segment.
            parts = extra.name.split(".")
            fw = parts[1] if len(parts) == 3 else "unknown"
            out.append((extra, fw))
    except Exception:  # pragma: no cover - defensive
        pass
    return out


def _audit_files() -> List["tuple[Path, str]"]:
    """Return routine audit logs for Hermes and every attached framework."""
    home = _home()
    out: List["tuple[Path, str]"] = [(home / "audit.jsonl", "hermes")]
    try:
        for extra in sorted(home.glob("audit.*.jsonl")):
            parts = extra.name.split(".")
            fw = parts[1] if len(parts) == 3 else "unknown"
            out.append((extra, fw))
    except Exception:  # pragma: no cover - defensive
        pass
    return out


# Read-path caps for the conversation context on a finding row, so a huge log
# line can't bloat the ``/api/findings`` response.
_CONTEXT_MAX_TURNS = 16
_CONTEXT_TURN_CHARS = 3000
_CONTEXT_FIELD_CHARS = 6000


def _bounded_context(ctx: Any) -> Optional[Dict[str, Any]]:
    """Normalize, redact, and bound a finding's local conversation ``context``.

    Shape ``{turns: [{role, text}], input, result, truncated}``, every field
    optional. Every text field passes through :func:`sanitize_text` so it is
    safe even if a caller forgot to redact. Returns ``None`` when empty; bad
    shapes degrade to ``None`` rather than raising (fail-open).
    """
    if not isinstance(ctx, dict):
        return None
    out: Dict[str, Any] = {}
    raw_turns = ctx.get("turns")
    if isinstance(raw_turns, list) and raw_turns:
        turns: List[Dict[str, str]] = []
        for turn in raw_turns[-_CONTEXT_MAX_TURNS:]:
            if not isinstance(turn, dict):
                continue
            text = sanitize_text(str(turn.get("text") or ""), _CONTEXT_TURN_CHARS)
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
            out[key] = sanitize_text(val, _CONTEXT_FIELD_CHARS)
    if not out:
        return None
    if ctx.get("truncated"):
        out["truncated"] = True
    return out


def _flatten_finding_row(rec: Dict[str, Any], default_fw: str) -> Dict[str, Any]:
    # Lift the per-line ``finding`` fields up to a dashboard-friendly row.
    finding = rec.get("finding") or (rec.get("findings") or [{}])[0] or {}
    detail = rec.get("detail") or {}
    return {
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
        "confirmed": bool(finding.get("confirmed", True)),
        "source": finding.get("source") or ("public" if finding.get("confirmed", True) else "heuristic"),
        # Local-only conversation snapshot (redacted upstream).
        "context": _bounded_context(detail.get("context") or finding.get("context")),
    }


def _dedupe_finding_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collapse repeated findings emitted by multiple API calls in one turn."""
    deduped: Dict[tuple, Dict[str, Any]] = {}
    order: List[tuple] = []
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


def read_findings(limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    """Return findings newest-first, paged, merged across every agent's log.

    Reads ``findings.jsonl`` plus any ``findings.<framework>.jsonl`` siblings.
    Empty on any error.
    """
    rows: List[Dict[str, Any]] = []
    for path, default_fw in _findings_files():
        if not path.exists():
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except Exception:
            continue
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            rows.append(_flatten_finding_row(rec, default_fw))
    rows = _dedupe_finding_rows(rows)
    # Newest-first across all logs; rows with no numeric ts keep insertion order.
    rows.sort(key=lambda r: r.get("ts") or 0, reverse=True)
    return rows[offset : offset + limit]


def count_findings() -> int:
    return len(read_findings(limit=1_000_000))


def local_frameworks() -> List[str]:
    """Frameworks that have written findings into this shared home (for the
    dashboard's agent list). Always includes ``hermes`` when its log exists."""
    out: List[str] = []
    for path, default_fw in _findings_files():
        if path.exists() and default_fw not in out:
            out.append(default_fw)
    return out


def local_active_frameworks() -> List[str]:
    """Frameworks with observed local Blackbox activity.

    Findings identify their framework explicitly through ``findings*.jsonl``;
    routine activity lives in ``audit.jsonl`` / ``audit.<framework>.jsonl``.
    """
    out = local_frameworks()
    for audit_path, framework in _audit_files():
        if framework in out or not audit_path.exists():
            continue
        try:
            if any(line.strip() for line in audit_path.read_text(encoding="utf-8").splitlines()):
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
    findings: Optional[List[Dict[str, Any]]] = None,
    detail: Optional[Dict[str, Any]] = None,
    framework: str = "hermes",
    workspace: Optional[str] = None,
) -> None:
    """Append an audit record; on findings also append to the findings log.

    *findings* are Finding dicts (evidence already redacted). *detail* is extra
    context (tool name, ids, args) and is redacted again here before writing.
    Hermes retains the original ``audit.jsonl`` / ``findings.jsonl`` names;
    external hosts use ``audit.<framework>.jsonl`` and
    ``findings.<framework>.jsonl`` so the shared dashboard can distinguish
    Claude Code and Codex activity without changing the existing readers.
    """
    try:
        framework_name = _framework_name(framework)
        suffix = "" if framework_name == "hermes" else f".{framework_name}"
        now = time.time()
        base = {
            "ts": now,
            "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "event": event,
            "framework": framework_name,
            # Profile-level identity is local-only and lets the dashboard keep
            # separate Hermes homes from inheriting each other's activity.
            "workspace": str(
                workspace
                or (constants.hermes_home() if framework_name == "hermes" else "")
            ),
        }
        if detail:
            # Redact the detail normally, but rebuild ``detail.context`` via
            # ``_bounded_context``: a plain ``redact`` would re-clamp the
            # conversation snapshot to the 1200-char ``input``/``prompt`` cap.
            raw_context = detail.get("context") if isinstance(detail, dict) else None
            base["detail"] = redact(detail)
            bounded = _bounded_context(raw_context) if isinstance(raw_context, dict) else None
            if bounded:
                base["detail"]["context"] = bounded
            elif isinstance(base["detail"], dict):
                base["detail"].pop("context", None)
        if findings:
            base["findingCount"] = len(findings)
            base["findings"] = [
                _finding_summary({**f, "framework": f.get("framework") or framework_name})
                for f in findings
            ]
        _append_jsonl(_home() / f"audit{suffix}.jsonl", base)
        for finding in findings or []:
            summary = _finding_summary(
                {**finding, "framework": finding.get("framework") or framework_name}
            )
            _append_jsonl(
                _home() / f"findings{suffix}.jsonl",
                {**base, "finding": summary},
            )
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: audit record failed: %s", exc)


def _framework_name(value: Any) -> str:
    """Return a filename-safe, dashboard-stable framework identifier."""
    name = re.sub(r"[^a-z0-9_-]+", "-", str(value or "hermes").strip().lower())
    return name.strip("-")[:64] or "hermes"


_AGENT_SESSIONS_DIR = "agent-sessions"
_AGENT_SESSION_ID_CHARS = 512
_AGENT_SESSION_TITLE_CHARS = 120
_AGENT_SESSION_WORKSPACE_CHARS = 1000


def record_agent_session(
    *,
    framework: str,
    session_id: str,
    workspace: str = "",
    session_slug: str = "",
    session_title: str = "",
    title_source: str = "",
) -> None:
    """Remember one Claude/Codex session for local dashboard identity.

    Each session owns an atomically replaced file because command hooks run in
    separate processes. Only an explicit host title is retained. Prompt text is
    conversation content and must never become a dashboard session name.
    """
    try:
        host = _framework_name(framework)
        raw_session_id = str(session_id or "").strip()[:_AGENT_SESSION_ID_CHARS]
        if host not in {"claude-code", "codex"} or not raw_session_id:
            return

        state_dir = _home() / _AGENT_SESSIONS_DIR
        state_dir.mkdir(parents=True, exist_ok=True)
        session_key = quads.stable_hash(f"{host}\0{raw_session_id}", 24)
        path = state_dir / f"{host}-{session_key}.json"
        existing: Dict[str, Any] = {}
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                existing = loaded
        except Exception:
            pass

        compact_title = " ".join(str(session_title or "").split())
        compact_title = sanitize_text(compact_title, _AGENT_SESSION_TITLE_CHARS)
        source = str(title_source or "").strip().lower()
        old_source = str(existing.get("title_source") or "").strip().lower()
        old_title = (
            str(existing.get("session_title") or "")
            if old_source == "host"
            else ""
        )
        if source != "host" or not compact_title:
            compact_title = old_title
            source = "host" if old_title else ""

        clean_slug = re.sub(r"[^a-z0-9_-]+", "-", str(session_slug or "").strip().lower())
        clean_slug = clean_slug.strip("-")[:64]
        now = time.time()
        record = {
            "framework": host,
            "session_id": raw_session_id,
            "session_key": session_key,
            "session_slug": clean_slug or str(existing.get("session_slug") or ""),
            "session_title": compact_title,
            "title_source": source,
            "workspace": str(workspace or existing.get("workspace") or "")[
                :_AGENT_SESSION_WORKSPACE_CHARS
            ],
            "first_seen": existing.get("first_seen") or now,
            "last_seen": now,
        }
        temp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        temp.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
        os.replace(temp, path)
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: external agent session record failed: %s", exc)


def read_agent_sessions(limit: int = 512) -> List[Dict[str, Any]]:
    """Return recently observed Claude/Codex sessions, newest first."""
    rows: List[Dict[str, Any]] = []
    directory = _home() / _AGENT_SESSIONS_DIR
    try:
        for path in directory.glob("*.json"):
            try:
                row = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(row, dict) and row.get("session_id"):
                    rows.append(row)
            except Exception:
                continue
    except Exception:
        return []
    rows.sort(key=lambda row: row.get("last_seen") or 0, reverse=True)
    return rows[: max(0, int(limit))]


def _finding_summary(finding: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "identifier": finding.get("identifier"),
        "category": finding.get("category"),
        "severity": finding.get("severity"),
        "title": finding.get("title"),
        "framework": finding.get("framework") or "hermes",
        "tool_name": finding.get("tool_name"),
        "evidence": sanitize_text(str(finding.get("evidence") or ""), 700),
        "confirmed": bool(finding.get("confirmed", True)),
        "candidate": bool(finding.get("candidate", not finding.get("confirmed", True))),
        "source": str(finding.get("source") or ("public" if finding.get("confirmed", True) else "heuristic")),
        "ts": time.time(),
    }


# ---------------------------------------------------------------------------
# File-access visibility log ($BLACKBOX_HOME/file_access.jsonl)
# ---------------------------------------------------------------------------


def record_file_access(tool: str, path: str, mode: str) -> None:
    """Append a file-access visibility record so a user can see what files
    their agent touched.

    Visibility log, distinct from findings: local-only, NEVER shared to SWM.
    The path is truncated but not redacted (it is the point of the log).
    Best-effort and fail-open.
    """
    try:
        now = time.time()
        _append_jsonl(_home() / "file_access.jsonl", {
            "ts": now,
            "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "tool": str(tool or "")[:120],
            "path": str(path or "")[:1000],
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
        _append_jsonl(_home() / "dependencies.jsonl", {
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


def read_file_access(limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    """Return file-access visibility records newest-first, paged."""
    path = _home() / "file_access.jsonl"
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []
    out: List[Dict[str, Any]] = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out[offset : offset + limit]


def _load_jsonl(path: Path, default_event: str) -> List[Dict[str, Any]]:
    """Load a jsonl file, tagging each row with ``event=default_event`` when
    the line has no explicit event (e.g. file_access.jsonl, dependencies.jsonl)."""
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []
    out: List[Dict[str, Any]] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except Exception:
            continue
        if "event" not in row:
            row["event"] = default_event
        out.append(row)
    return out


# Default severity per non-finding event type. Everything is ``info`` so the
# dashboard's "Threats only" filter cleanly hides routine activity.
_EVENT_SEVERITY = {
    "session_start": "info",
    "session_end": "info",
    "pre_api_request": "info",
    "pre_tool_call": "info",
    "post_tool_call": "info",
    "file_access": "info",
    "dependency_install": "info",
}


def _finding_event_rows() -> List[Dict[str, Any]]:
    """Findings from every framework, shaped for the merged activity feed.

    Each row carries an explicit ``framework`` and lifts finding severity to the
    top level so the severity filter works uniformly across event types.
    """
    out: List[Dict[str, Any]] = []
    for path, default_fw in _findings_files():
        if not path.exists():
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except Exception:
            continue
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            finding = rec.get("finding") or (rec.get("findings") or [{}])[0] or {}
            out.append({
                "ts": rec.get("ts") or 0,
                "iso": rec.get("iso") or "",
                "event": "flagged",
                "framework": finding.get("framework") or rec.get("framework") or default_fw,
                "workspace": finding.get("workspace") or rec.get("workspace") or (rec.get("detail") or {}).get("workspace"),
                "severity": finding.get("severity") or "warning",
                "finding": finding,
                "detail": rec.get("detail") or {},
            })
    return out


def _tag_events(rows: List[Dict[str, Any]], default_event: str, framework: str = "hermes") -> List[Dict[str, Any]]:
    """Stamp every row with a ``framework`` + default ``event``/``severity`` so
    later merging can treat every source the same."""
    out: List[Dict[str, Any]] = []
    for r in rows:
        r.setdefault("event", default_event)
        r.setdefault("framework", framework)
        r.setdefault("severity", _EVENT_SEVERITY.get(r["event"], "info"))
        out.append(r)
    return out


def read_audit(limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    """Return the unified agent-activity feed, newest first, paged.

    Merges local sources into one timestamped, severity-tagged, framework-
    aware view for the dashboard's Audit trail:
      * ``audit.jsonl``            — session lifecycle + tool/API events (Hermes)
      * ``audit.<fw>.jsonl``       — routine events from other local agents
      * ``file_access.jsonl``      — sensitive-path reads (hermes, info)
      * ``dependencies.jsonl``     — install visibility (hermes, info)
      * ``findings.jsonl``         — threats detected by hermes (severity from finding)
      * ``findings.<fw>.jsonl``    — threats detected by other agents (openclaw, …)

    Sorted by ``ts`` descending. Fail-open per source.
    """
    home = _home()
    merged: List[Dict[str, Any]] = []
    for path, framework in _audit_files():
        merged.extend(_tag_events(_load_jsonl(path, "event"), "event", framework))
    merged.extend(_tag_events(_load_jsonl(home / "file_access.jsonl", "file_access"), "file_access"))
    merged.extend(_tag_events(_load_jsonl(home / "dependencies.jsonl", "dependency_install"), "dependency_install"))
    merged.extend(_finding_event_rows())
    merged.sort(key=lambda r: r.get("ts") or 0, reverse=True)
    return merged[offset : offset + limit]


def count_audit() -> int:
    """Total merged activity rows on disk (fail-open: returns 0 on any error)."""
    total = 0
    paths = [path for path, _ in _audit_files()]
    paths.extend(_home() / name for name in ("file_access.jsonl", "dependencies.jsonl"))
    for path in paths:
        if not path.exists():
            continue
        try:
            total += sum(1 for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip())
        except Exception:
            continue
    for path, _ in _findings_files():
        if not path.exists():
            continue
        try:
            total += sum(1 for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip())
        except Exception:
            continue
    return total


def _tool_action(tool_name: Any, args: Any) -> str:
    """Best short description of what a tool call did (command / path / url).

    Lets the local graph label a node without the frontend re-parsing args
    (mirrors the dashboard's ``toolActionText``). Secret values are redacted.
    """
    if not isinstance(args, dict):
        return sanitize_text(str(args), 200) if args else ""
    for key in ("command", "cmd", "script", "shell", "input"):
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            return sanitize_text(val, 200)
    for key in ("path", "file", "filename"):
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            return sanitize_text(val, 200)
    for key in ("url", "query", "name"):
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            return sanitize_text(val, 200)
    for val in args.values():
        if isinstance(val, str) and val.strip():
            return sanitize_text(val, 200)
    return ""


def _result_status(result: Any) -> Optional[str]:
    """Classify a tool result as ``blocked`` | ``error`` | ``ok`` (or None).

    Reads the redacted result string so the graph can colour a node by outcome
    without shipping the raw payload to the browser.
    """
    if not result:
        return None
    text = result if isinstance(result, str) else json.dumps(result)
    low = text.lower()
    if "blackbox" in low and "block" in low:
        return "blocked"
    if '"exit_code": 0' in text or '"exitCode": 0' in text:
        return "ok"
    if "error" in low or "exception" in low or "traceback" in low or "exit_code" in low:
        return "error"
    return "ok"


def _max_severity(sevs: List[str]) -> Optional[str]:
    """Highest severity in *sevs* by :data:`constants.SEVERITY_ORDER`."""
    order = list(getattr(constants, "SEVERITY_ORDER", ["info", "low", "medium", "high", "critical"]))
    best = None
    best_rank = -1
    for s in sevs:
        s = (s or "info").lower()
        rank = order.index(s) if s in order else -1
        if rank > best_rank:
            best_rank, best = rank, s
    return best


def read_local_activity(max_sessions: int = 60) -> Dict[str, Any]:
    """Reconstruct the user's LOCAL threat activity as sessions → events → threats.

    The local graph's data source, built entirely from this machine's own logs
    (``audit*.jsonl``, ``file_access.jsonl``, ``dependencies.jsonl``, findings) —
    never the DKG node. Each session carries its ordered events; each tool call
    carries the threats it triggered (matched by ``tool_call_id``). Newest first.
    """
    home = _home()
    raw: List[Dict[str, Any]] = []
    for path, framework in _audit_files():
        raw.extend(_tag_events(_load_jsonl(path, "event"), "event", framework))
    raw.extend(_tag_events(_load_jsonl(home / "file_access.jsonl", "file_access"), "file_access"))
    raw.extend(_tag_events(_load_jsonl(home / "dependencies.jsonl", "dependency_install"), "dependency_install"))
    findings = _finding_event_rows()

    def _sid(entry: Dict[str, Any]) -> str:
        det = entry.get("detail") or {}
        return det.get("session_id") or entry.get("session_id") or "unattributed"

    # Index threats so each can hang off the exact tool call that triggered it.
    threats_by_call: Dict[tuple, List[Dict[str, Any]]] = {}
    threats_loose: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        fd = f.get("finding") or {}
        det = f.get("detail") or {}
        sid = _sid(f)
        threat = {
            "identifier": fd.get("identifier"),
            "category": fd.get("category") or "other",
            "severity": (fd.get("severity") or "info").lower(),
            "title": fd.get("title") or fd.get("identifier") or "Threat",
            "source": fd.get("source"),
            "confirmed": bool(fd.get("confirmed")),
            "tool": fd.get("tool_name") or det.get("tool_name"),
            "ts": f.get("ts") or 0,
        }
        tcid = det.get("tool_call_id")
        if tcid:
            threats_by_call.setdefault((sid, tcid), []).append(threat)
        else:
            threats_loose.setdefault(sid, []).append(threat)

    sessions: Dict[str, Dict[str, Any]] = {}

    def _sess(sid: str) -> Dict[str, Any]:
        return sessions.setdefault(sid, {
            "id": sid, "start": None, "end": None, "agent": "hermes",
            "model": None, "status": "active", "ended": False,
            "events": [], "_calls": {},
        })

    for e in raw:
        ev = e.get("event")
        det = e.get("detail") or {}
        sid = _sid(e)
        s = _sess(sid)
        ts = e.get("ts") or 0
        fw = e.get("framework")
        if fw:
            s["agent"] = fw
        if ts:
            if s["start"] is None or ts < s["start"]:
                s["start"] = ts
            if s["end"] is None or ts > s["end"]:
                s["end"] = ts

        if ev == "session_end":
            s["ended"] = True
            reason = str(det.get("reason") or "").lower()
            if det.get("interrupted") or reason in ("shutdown", "restart"):
                s["status"] = "interrupted"
            elif det.get("completed") or reason in ("new", "reset", "idle", "daily", "compaction", "deleted"):
                s["status"] = "completed"
            else:
                s["status"] = "ended"
        elif ev == "pre_api_request":
            if det.get("model"):
                s["model"] = det.get("model")
            s["events"].append({"type": "api", "ts": ts, "model": det.get("model"), "provider": det.get("provider")})
        elif ev == "pre_tool_call":
            tcid = det.get("tool_call_id") or ("tc-%s" % ts)
            call = {
                "type": "tool", "ts": ts, "tool": det.get("tool_name") or "tool",
                "action": _tool_action(det.get("tool_name"), det.get("args")),
                "toolCallId": tcid, "resultStatus": None, "durationMs": None,
                "threats": list(threats_by_call.get((sid, tcid), [])),
            }
            s["_calls"][tcid] = call
            s["events"].append(call)
        elif ev == "post_tool_call":
            tcid = det.get("tool_call_id")
            call = s["_calls"].get(tcid)
            if call:
                call["durationMs"] = det.get("duration_ms")
                call["resultStatus"] = _result_status(det.get("result"))
            else:
                s["events"].append({
                    "type": "tool", "ts": ts, "tool": det.get("tool_name") or "tool", "action": "",
                    "toolCallId": tcid, "resultStatus": _result_status(det.get("result")),
                    "durationMs": det.get("duration_ms"),
                    "threats": list(threats_by_call.get((sid, tcid), [])),
                })
        elif ev == "file_access":
            s["events"].append({
                "type": "file", "ts": ts,
                "path": e.get("path") if "path" in e else det.get("path"),
                "mode": e.get("mode") if "mode" in e else det.get("mode"),
                "tool": e.get("tool") if "tool" in e else det.get("tool"),
                "threats": [],
            })
        elif ev == "dependency_install":
            s["events"].append({
                "type": "dependency", "ts": ts,
                "ecosystem": e.get("ecosystem") if "ecosystem" in e else det.get("ecosystem"),
                "name": e.get("name") if "name" in e else det.get("name"),
                "version": e.get("version") if "version" in e else det.get("version"),
                "tool": e.get("tool") if "tool" in e else det.get("tool"),
                "threats": [],
            })

    out: List[Dict[str, Any]] = []
    for sid, s in sessions.items():
        for threat in threats_loose.get(sid, []):
            s["events"].append({"type": "threat", "ts": threat["ts"], "tool": threat.get("tool"), "threats": [threat]})
        s["events"].sort(key=lambda x: x.get("ts") or 0)
        s.pop("_calls", None)
        all_threats = [t for ev in s["events"] for t in ev.get("threats", [])]
        s["threatCount"] = len(all_threats)
        s["maxSeverity"] = _max_severity([t["severity"] for t in all_threats])
        s["toolCount"] = sum(1 for ev in s["events"] if ev.get("type") == "tool")
        s["durationMs"] = int((s["end"] - s["start"]) * 1000) if (s["start"] and s["end"]) else None
        s["shortId"] = (str(sid)[-6:] if sid and sid != "unattributed" else "local")
        out.append(s)

    out.sort(key=lambda x: x.get("start") or 0, reverse=True)
    total_threats = sum(s["threatCount"] for s in out)
    return {"sessions": out[:max_sessions], "sessionCount": len(out), "threatCount": total_threats}


def write_private_audit_ka(client: Any, cg_id: str, event: str, finding: Dict[str, Any]) -> None:
    """Write a private WM audit KA carrying the observed command/prompt.

    Privacy split: the redacted-but-local evidence lives in the node's private
    working memory, never shared to SWM. Best-effort — failures are swallowed.
    """
    from . import quads

    try:
        ident = str(finding.get("identifier") or "unknown")
        ts = quads.datetime_literal()
        subj = f"urn:guardian:audit:{quads.stable_hash(ident + str(time.time()), 24)}"
        q = [
            {"subject": subj, "predicate": constants.RDF_TYPE, "object": f"{constants.BLACKBOX_ONTOLOGY}AuditRecord"},
            {"subject": subj, "predicate": constants.IDENTIFIER_PRED, "object": quads.literal(ident)},
            {"subject": subj, "predicate": constants.SEVERITY_PRED, "object": quads.literal(str(finding.get("severity") or "info"))},
            {"subject": subj, "predicate": constants.SCHEMA_DESCRIPTION_PRED, "object": quads.literal(sanitize_text(str(finding.get("evidence") or ""), 1200))},
            {"subject": subj, "predicate": constants.SCHEMA_DATE_MODIFIED_PRED, "object": ts},
        ]
        # Private: create+write+seal in WM, do NOT share to SWM.
        client.write_private_knowledge_asset(cg_id, subj.rsplit(":", 1)[-1], q)
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: private audit KA write failed: %s", exc)


# ---------------------------------------------------------------------------
# Outbound-report daily rate limiter
# ---------------------------------------------------------------------------


def _rate_state_path() -> Path:
    return _home() / "report_rate.json"


# Re-reporting the same identifier within this window adds no signal (the
# sighting KA name is stable per identifier+reporter, so a re-share only
# refreshes dateModified) — skip it to keep reports low-noise.
REPORT_COOLDOWN_SECS = 6 * 3600


def _read_rate_state() -> Dict[str, Any]:
    path = _rate_state_path()
    if not path.exists():
        return {}
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
        return state if isinstance(state, dict) else {}
    except Exception:
        return {}


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
        with _lock:
            state = _read_rate_state()
            stamps = state.get("reported")
            stamps = dict(stamps) if isinstance(stamps, dict) else {}
            now = time.time()
            stamps[identifier] = now
            state["reported"] = {
                k: v for k, v in stamps.items()
                if isinstance(v, (int, float)) and (now - v) < REPORT_COOLDOWN_SECS
            }
            _rate_state_path().write_text(json.dumps(state), encoding="utf-8")
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: mark_reported failed (%s)", exc)


def allow_report(daily_limit: int) -> bool:
    """Return True if another outbound SWM report is within today's cap.

    Only the date-keyed daily counter; the per-threat cooldown is enforced by
    :func:`recently_reported` / :func:`mark_reported`. Fail-open: on any state
    error, allow the report.
    """
    today = time.strftime("%Y-%m-%d", time.gmtime())
    path = _rate_state_path()
    try:
        with _lock:
            state = _read_rate_state()
            if state.get("date") != today:
                # New day: reset the counter but preserve the cooldown stamps.
                state = {"date": today, "count": 0, "reported": state.get("reported", {})}
            if daily_limit > 0 and int(state.get("count", 0)) >= daily_limit:
                logger.debug("blackbox: daily report limit %s reached", daily_limit)
                return False
            state["count"] = int(state.get("count", 0)) + 1
            path.write_text(json.dumps(state), encoding="utf-8")
            return True
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: rate-limit state failed (%s); allowing", exc)
        return True
