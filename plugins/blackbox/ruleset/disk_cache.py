"""The on-disk ruleset cache (``ruleset.json``) and its lock-file path.

Atomic tmp+rename writes; :func:`_deserialize` re-normalizes injection
patterns so a cache written by an older version still compiles safely.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, Optional
from ..kernel import constants
from ..kernel.bounded_files import atomic_write
from . import compiler
from . import safe_regex
from . import row_adapters
from . import live

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cache persistence
# ---------------------------------------------------------------------------


def _cache_path() -> Path:
    return constants.blackbox_home() / "ruleset.json"


def _lock_path() -> Path:
    return constants.blackbox_home() / "ruleset.lock"


def _serialize(rs: compiler.Ruleset) -> dict[str, Any]:
    return {
        "synced_at": rs.synced_at,
        "refresh_due_at": rs.refresh_due_at,
        "context_graph_id": rs.context_graph_id,
        "injection": [
            {k: v for k, v in rule.items() if k != "pattern"} for rule in rs.injection
        ],
        "escalation": rs.escalation,
        "dependency": rs.dependency,
        "fileaccess": rs.fileaccess,
        "skill": rs.skill,
        "ioc": rs.ioc,
        "graph_threats": rs.graph_threats,
        "community": rs.community,
        "community_paused": rs.community_paused,
        "community_fingerprint": rs.community_fingerprint,
        "community_empty_since": rs.community_empty_since,
        "kill_list": rs.kill_list,
        "kill_list_refused": rs.kill_list_refused,
        "curator_manifest_state": rs.curator_manifest_state,
        "verified_scope": rs.verified_scope.to_json() if rs.verified_scope is not None else None,
        "curator_revoked": sorted(rs.curator_revoked),
    }


def _deserialize(data: dict[str, Any]) -> compiler.Ruleset:
    rs = compiler.Ruleset(
        synced_at=float(data.get("synced_at", 0.0)),
        refresh_due_at=float(data.get("refresh_due_at", 0.0)),
        context_graph_id=str(data.get("context_graph_id") or ""),
    )
    for rule in data.get("injection", []):
        src = row_adapters._normalize_injection_pattern(str(rule.get("pattern_src") or ""))
        if not src:
            continue
        try:
            compiled = safe_regex.compile_bounded(src, re.IGNORECASE)   # G6: the same gate as the graph read
        except safe_regex.UnsafePattern:
            continue
        if rule.get("source", "public") == "public":
            rs.injection.append({**rule, "pattern_src": src, "pattern": compiled})
    # KI-001: community rules SURVIVE the cache round-trip. The scan lists
    # (injection/escalation/fileaccess/skill) stay public-only — community
    # content never enters a scanned/compiled structure (KI-004); the
    # identifier-keyed lookup dicts (dependency/ioc) keep both tiers, and the
    # community store reloads verbatim so corroboration outlives restarts.
    rs.escalation = [r for r in data.get("escalation", []) if r.get("source", "public") == "public"]
    rs.dependency = {
        k: r
        for k, r in data.get("dependency", {}).items()
        if r.get("source", "public") in ("public", "community")
    }
    rs.fileaccess = [r for r in data.get("fileaccess", []) if r.get("source", "public") == "public"]
    rs.skill = [r for r in data.get("skill", []) if r.get("source", "public") == "public"]
    rs.ioc = {
        k: r
        for k, r in data.get("ioc", {}).items()
        if r.get("source", "public") in ("public", "community")
    }
    rs.graph_threats = [r for r in data.get("graph_threats", []) if r.get("source", "public") == "public"]
    community = data.get("community")
    rs.community = {
        str(k): dict(v)
        for k, v in (community or {}).items()
        if isinstance(v, dict)
    } if isinstance(community, dict) else {}
    rs.community_paused = bool(data.get("community_paused", False))
    rs.community_fingerprint = str(data.get("community_fingerprint") or "")
    rs.community_empty_since = float(data.get("community_empty_since") or 0.0)
    rs.kill_list = dict(data.get("kill_list") or {}) if isinstance(data.get("kill_list"), dict) else {}
    rs.kill_list_refused = str(data.get("kill_list_refused") or "")
    rs.curator_manifest_state = str(data.get("curator_manifest_state") or "")
    _restore_live_scope(rs, data)
    return rs


def _restore_live_scope(rs: compiler.Ruleset, data: dict[str, Any]) -> None:
    """The live verified scope and the curator's revocations (DKG-lookup B2)."""
    scope = data.get("verified_scope")
    rs.verified_scope = live.VerifiedScope.from_json(scope) if isinstance(scope, dict) else None
    revoked = data.get("curator_revoked")
    rs.curator_revoked = frozenset(str(i) for i in revoked) if isinstance(revoked, list) else frozenset()


def _write_cache(rs: compiler.Ruleset) -> None:
    """Persist *rs* (temp file + rename). A failure is logged at WARNING: fail-open is not
    fail-silent — a full disk would otherwise keep serving a generation that never persists."""
    try:
        atomic_write(_cache_path(), json.dumps(_serialize(rs)))
    except (OSError, TypeError, ValueError) as exc:
        logger.warning("blackbox: could not save the rules to %s (%s); they stay in memory only", _cache_path(), exc)


def _read_cache() -> Optional[compiler.Ruleset]:
    """The persisted generation, or None when there is none or it cannot be read (said at WARNING)."""
    path = _cache_path()
    if not path.exists():
        return None
    try:
        return _deserialize(json.loads(path.read_text(encoding="utf-8-sig")))
    except Exception as exc:  # health: allow BLE001 -- a damaged or older cache of any shape is rebuilt by the next refresh, never fatal
        logger.warning("blackbox: could not read the saved rules in %s (%s); the next refresh rebuilds them", path, exc)
        return None
