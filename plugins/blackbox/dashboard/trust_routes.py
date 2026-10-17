"""The dashboard's trust panel endpoint (Community Curation C10).

``GET /api/trust`` — who curates (both authorities: manifest state, expiry,
each curator key's heartbeat), who is trusted (the reporters either authority
lists), what is confirmed (the community curators' standing confirmations and
the evidence they cite), and whether the trust read itself is healthy. It
serves the SAME read model `blackbox status` prints
(``community.trust_panel``), from the server's cached community read.

Every value that came from someone else's statement — addresses,
organisations, evidence references, identifiers — passes through
:mod:`.safe_payloads` before it is served; keys are shortened hex.
"""

from __future__ import annotations

from typing import Any, Callable, Dict

from .safe_payloads import safe_identifier, safe_text

#: Most rows of each list one response carries (the totals are always exact).
MAX_ROWS = 200
#: Hex characters of a key shown on the page.
KEY_CHARS = 16


def trust_payload(community_read: Callable[[Any], Any]) -> dict[str, Any]:
    """The trust panel for the page, sanitized."""
    from .. import community
    from ..kernel.config import load_blackbox_config

    cfg = load_blackbox_config()
    if not getattr(cfg, "context_graph_id", ""):
        return {"configured": False}
    panel = community.trust_panel(community_read(cfg))
    if not panel["available"]:
        return {"configured": True, "available": False, "reason": safe_text(panel["reason"], 200)}
    return {
        "configured": True,
        "available": True,
        "authorities": [{
            "authority": facts["authority"], "trusted": facts["trusted"], "state": facts["state"],
            "state_day": safe_text(facts["state_day"], 16), "expires": safe_text(facts["expires"], 16),
            "root_epoch": facts["root_epoch"], "version": facts["version"], "keys": facts["keys"], "threshold": facts["threshold"],
            "heartbeats": [{"key": safe_text(beat["key"][:KEY_CHARS], KEY_CHARS), "day": safe_text(beat["day"], 16),
                            "silent": beat["silent"]} for beat in facts["heartbeats"]],
        } for facts in panel["authorities"]],
        "reporters_total": len(panel["reporters"]),
        "reporters": [{"key": safe_text(reporter["key"][:KEY_CHARS], KEY_CHARS), "address": safe_text(reporter["address"], 64),
                       "class": safe_text(reporter["author_class"], 16), "org": safe_text(reporter["org"], 64),
                       "expires": safe_text(reporter["expires"], 16), "listed_by": reporter["listed_by"]}
                      for reporter in panel["reporters"][:MAX_ROWS]],
        "confirmed_total": len(panel["confirmed"]),
        "confirmed": [{"identifier": safe_identifier(entry["identifier"]), "evidence": safe_text(entry["evidence"], 240),
                       "when": safe_text(entry["day"], 16), "curators": entry["curators"], "reporters": entry["reporters"]}
                      for entry in panel["confirmed"][:MAX_ROWS]],
        "held_raising": panel["held_raising"],
        "lookup_incomplete": panel["lookup_incomplete"],
    }


def register_trust_routes(app: Any, *, community_read: Callable[[Any], Any]) -> None:
    """Add ``GET /api/trust`` to *app* (a FastAPI app)."""

    @app.get("/api/trust")
    def trust() -> Any:
        return trust_payload(community_read)
