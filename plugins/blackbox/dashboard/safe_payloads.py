"""Making community- and graph-derived values safe to serve (the dashboard's one sanitizer).

:func:`safe_text` is THE sanitization for every community-authored string an
endpoint serves (LES-001/002) and :func:`safe_identifier` the one for threat
identifiers (tokens the page hands back); :func:`sanitized_ledger` serves this node's
outbound share ledger through it. Split out of :mod:`.server` so the route
modules can use it without importing the server.
"""

from __future__ import annotations

from typing import Any, Mapping

from ..kernel import display_safety, threat_ids

#: The ingest cap on an identifier (community.report_schema.MAX_IDENTIFIER_CHARS; the kernel may not import it).
MAX_IDENTIFIER_CHARS = 512


def safe_text(value: Any, limit: int = 256) -> str:
    """Sanitize a community/graph-derived string for any client payload.

    THE one sanitization for the dashboard's JSON (LES-001/002), delegating to
    ``kernel.display_safety.web_safe``: control and format characters
    stripped, length clamped, indicators defanged (``hxxp``, ``[.]``) and shown
    in both IDN forms. NOT HTML-escaped: the page escapes exactly once when it
    inserts text (R8 / KI-191 — escaping here as well produced the
    double-escaped ``&amp;lt;`` seen on the benches and literal entities in
    text nodes). Every community-authored value served by any endpoint passes
    through here.
    """
    return display_safety.web_safe(value, limit)


def safe_identifier(value: Any) -> str:
    """A threat identifier as a client payload carries it: control and format
    characters stripped and the length clamped, otherwise VERBATIM. An
    identifier is a token the page hands back (`blackbox report dispute
    <identifier>`, lookups against this node's own rows), so it is never
    defanged or annotated the way free text is — ingest already refuses
    identifiers that are not a clean single token (§07)."""
    return display_safety.strip_controls(value)[:MAX_IDENTIFIER_CHARS]


def graph_tier_item(item: Mapping[str, Any], *, community: bool) -> dict[str, Any]:
    """One ``/api/graph`` threat as the client payload carries it.

    The category ALWAYS comes from the identifier (``threat_ids.category_for``):
    the page's colour table knows only those names, and a community-store
    entry once reached it as ``dep`` and crashed the community tab (KI-197).
    Community items are attacker-adjacent, so their strings are sanitized, and
    they carry the R3 stage fields the page's leaf nodes show (the endpoint
    used to drop them, KI-198).
    """
    identifier = str(item.get("identifier") or "")
    name = str(item.get("name") or "")
    out: dict[str, Any] = {
        "identifier": safe_identifier(identifier) if community else identifier,
        "category": threat_ids.category_for(identifier),
        "severity": str(item.get("severity") or "info").lower(),
        "name": safe_text(name) if community else name,
    }
    if community:
        out.update({
            "reporterCount": int(item.get("reporterCount") or 0),
            "lastSeen": item.get("lastSeen"),
            "stage": safe_text(item.get("stage"), 16),
            "stageReason": safe_text(item.get("stageReason"), 200),
            "stageSource": safe_text(item.get("stageSource") or "local", 16),   # R3-attest: local | curator
            "enforcement": safe_text(item.get("enforcement"), 16),
            "disputed": safe_text(item.get("disputed"), 4),
            # R5: "no" = the network copies expired and this node keeps the threat locally for a while.
            "networkLive": safe_text(item.get("networkLive") or "yes", 3),
            # threat profiles: what the reports say the threat goes after and what happened (closed words).
            "profile": {key: safe_text(item.get(key), 64) for key in _PROFILE_KEYS if item.get(key)},
        })
    return out


#: The threat-profile fields a community rule carries (community.sighting.vocab), shown as-is.
_PROFILE_KEYS = ("threatGoal", "resourceAtRisk", "attackTechnique", "outcome", "agentAction", "agentTool",
                 "verifiedSubject")


def sanitized_ledger(limit: int = 50) -> list[dict[str, Any]]:
    """This node's outbound reports ledger, sanitized for serving."""
    from .. import audit as _audit

    rows = []
    try:
        for row in _audit.read_share_ledger(limit=limit):
            rows.append({
                "ts": safe_text(row.get("ts"), 32),
                "identifier": safe_identifier(row.get("identifier")),
                "category": safe_text(row.get("category"), 32),
                "severity": safe_text(row.get("severity"), 16),
                "ok": bool(row.get("ok")),
                "outcome": safe_text(row.get("outcome") or ("accepted" if row.get("ok") else "failed"), 32),
            })
    except Exception:  # pragma: no cover - fail open
        return []
    return rows
