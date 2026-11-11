"""The merged local activity timeline the dashboard shows.

Reads the audit and findings logs back into one severity-tagged event stream
(:func:`read_audit`, :func:`count_audit`, :func:`read_local_activity`).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from ..kernel import constants
from ..kernel.bounded_files import read_jsonl
from . import log_store
from .findings import _bounded_context
from . import redaction

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


def _finding_event_rows() -> list[dict[str, Any]]:
    """Findings from every framework, shaped for the merged activity feed.

    Each row carries an explicit ``framework`` and lifts finding severity to the
    top level so the severity filter works uniformly across event types.
    """
    out: list[dict[str, Any]] = []
    for path, default_fw in log_store._findings_files():
        for rec in read_jsonl(path):   # object rows only: a damaged line is skipped, never fatal
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


def _tag_events(rows: list[dict[str, Any]], default_event: str, framework: str = "hermes") -> list[dict[str, Any]]:
    """Stamp every row with a ``framework`` + default ``event``/``severity`` so
    later merging can treat every source the same."""
    out: list[dict[str, Any]] = []
    for r in rows:
        r.setdefault("event", default_event)
        r.setdefault("framework", framework)
        r.setdefault("severity", _EVENT_SEVERITY.get(r["event"], "info"))
        out.append(r)
    return out


def read_audit(limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
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
    return log_store.cached(f"audit:{log_store._home()}", _activity_log_paths(), _load_merged_audit)[offset : offset + limit]


def _activity_log_paths() -> list[Any]:
    """Every log the activity readers merge — the cache key's files."""
    home = log_store._home()
    paths = [path for path, _ in log_store._audit_files()]
    paths += [home / "file_access.jsonl", home / "dependencies.jsonl"]
    return paths + [path for path, _ in log_store._findings_files()]


def _raw_activity() -> list[dict[str, Any]]:
    """Every audit, file-access and dependency row on disk, each tagged with its event and
    framework (fresh rows, unsorted) — what both activity builders start from."""
    home = log_store._home()
    raw: list[dict[str, Any]] = []
    for path, framework in log_store._audit_files():
        raw.extend(_tag_events(log_store._load_jsonl(path, "event"), "event", framework))
    raw.extend(_tag_events(log_store._load_jsonl(home / "file_access.jsonl", "file_access"), "file_access"))
    raw.extend(_tag_events(log_store._load_jsonl(home / "dependencies.jsonl", "dependency_install"), "dependency_install"))
    return raw


def _load_merged_audit() -> list[dict[str, Any]]:
    merged = _raw_activity() + _finding_event_rows()
    merged.sort(key=lambda r: r.get("ts") or 0, reverse=True)
    return merged


def count_audit() -> int:
    """How many rows the activity feed holds (:func:`read_audit`'s pager total) — the same
    cached list, so a dashboard poll re-reads no log that has not changed."""
    return len(log_store.cached(f"audit:{log_store._home()}", _activity_log_paths(), _load_merged_audit))


def _tool_action(tool_name: Any, args: Any) -> str:
    """Best short description of what a tool call did (command / path / url).

    Lets the local graph label a node without the frontend re-parsing args
    (mirrors the dashboard's ``toolActionText``). Secret values are redacted.
    """
    if not isinstance(args, dict):
        return redaction.sanitize_text(str(args), 200) if args else ""
    for key in ("command", "cmd", "script", "shell", "input"):
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            return redaction.sanitize_text(val, 200)
    for key in ("path", "file", "filename"):
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            return redaction.sanitize_text(val, 200)
    for key in ("url", "query", "name"):
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            return redaction.sanitize_text(val, 200)
    for val in args.values():
        if isinstance(val, str) and val.strip():
            return redaction.sanitize_text(val, 200)
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


def _max_severity(sevs: list[str]) -> Optional[str]:
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


def _threat_row(row: dict[str, Any], finding: dict[str, Any], detail: dict[str, Any]) -> dict[str, Any]:
    """One local threat as the dashboard's Local view shows it (from a findings.jsonl row)."""
    return {
        "identifier": finding.get("identifier"),
        "category": finding.get("category") or "other",
        "severity": (finding.get("severity") or "info").lower(),
        "title": finding.get("title") or finding.get("identifier") or "Threat",
        "source": finding.get("source"),
        "confirmed": bool(finding.get("confirmed")),
        "tool": finding.get("tool_name") or detail.get("tool_name"),
        "ts": row.get("ts") or 0,
        "profile": finding.get("sighting") or {},   # threat profiles: goal, at risk, outcome…
        "found_in": finding.get("found_in") or "",  # where an injection was met (a closed word)
        "evidence": finding.get("evidence") or "",
        "decision": detail.get("decision") or "",
        # What led to it (the turn that asked), redacted and size-capped; local only.
        "context": _bounded_context(detail.get("context")),
    }


def read_local_activity(max_sessions: int = 60) -> dict[str, Any]:
    """Reconstruct the user's LOCAL threat activity as sessions → events → threats.

    The local graph's data source, built entirely from this machine's own logs
    (``audit*.jsonl``, ``file_access.jsonl``, ``dependencies.jsonl``, findings) —
    never the DKG node. Each session carries its ordered events; each tool call
    carries the threats it triggered (matched by ``tool_call_id``). Newest first.
    Rebuilt only when a log changed on disk (:func:`log_store.cached`); treat the
    result as read-only.
    """
    return log_store.cached(f"local-activity:{max_sessions}:{log_store._home()}", _activity_log_paths(),
                            lambda: _build_local_activity(max_sessions))


def _build_local_activity(max_sessions: int) -> dict[str, Any]:   # health: allow CC -- the body read_local_activity had; renamed for the cache (FIX-0162), baselined shrink-only
    raw = _raw_activity()
    findings = _finding_event_rows()

    def _sid(entry: dict[str, Any]) -> str:
        det = entry.get("detail") or {}
        return det.get("session_id") or entry.get("session_id") or "unattributed"

    # Index threats so each can hang off the exact tool call that triggered it.
    threats_by_call: dict[tuple, list[dict[str, Any]]] = {}
    threats_loose: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        fd = f.get("finding") or {}
        det = f.get("detail") or {}
        sid = _sid(f)
        threat = _threat_row(f, fd, det)
        tcid = det.get("tool_call_id")
        if tcid:
            threats_by_call.setdefault((sid, tcid), []).append(threat)
        else:
            threats_loose.setdefault(sid, []).append(threat)

    sessions: dict[str, dict[str, Any]] = {}

    def _sess(sid: str) -> dict[str, Any]:
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

        if ev == "session_end":   # health: allow HX011 -- pre-existing ladder, renamed function only (FIX-0162)
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
            tcid = det.get("tool_call_id") or (f"tc-{ts}")
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

    out: list[dict[str, Any]] = []
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
