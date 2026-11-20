"""The verdict a runtime that is not Hermes asks for before each tool call (2026-11-20).

* ``POST /api/guard/verdict`` ``{"tool_name": str, "args": object | str}`` →
  ``{"findings": [...], "blocked": [identifier], "decision": str, "message": str}`` —
  :func:`guard.tool_call_verdict`: the same checks a Hermes agent's hook runs (verified threat
  graph, protected paths, every shield, kill list, local overrides).

WHY: the OpenClaw plugin carried its own copy of the checks, and the copy fell behind — a real
OpenClaw agent installed a package the verified graph lists as malware and read a wallet key
while Hermes blocked both on the same machine. Asking here means one implementation judges both.
Nothing is recorded by this route; the asking runtime records the finding under its own agent.

Who may ask: a local process. It is a POST, so the app-wide browser boundary demands the session
token from ``GET /api/session`` (a web page in the operator's browser cannot get one — KI-028 /
LES-006). The body is bounded (:data:`MAX_BODY_BYTES`); a failure answers 503 and the asker falls
back to its own built-in checks.
"""

# No ``from __future__ import annotations`` here: FastAPI must see the handler's ``Request``
# annotation as the class itself, and that class is imported inside ``register``.
import json
import logging
from typing import Any, Callable

logger = logging.getLogger(__name__)

NO_CACHE = {"Cache-Control": "no-store"}
#: The largest request read: a tool call's arguments (a long command, a file being written).
MAX_BODY_BYTES = 512 * 1024
#: The longest tool name accepted.
MAX_TOOL_NAME_CHARS = 120

Cache = Callable[..., Any]


def register(app: Any, swr: Cache) -> None:
    """Add the verdict route to *app* (called once by the dashboard; *swr* is not used —
    a verdict is never cached)."""
    from fastapi import Request
    from fastapi.responses import JSONResponse

    from ... import guard

    @app.post("/api/guard/verdict")
    async def guard_verdict(request: Request) -> Any:
        raw = await request.body()
        if len(raw) > MAX_BODY_BYTES:
            return JSONResponse({"error": "request too large"}, status_code=413, headers=NO_CACHE)
        try:
            body = json.loads(raw.decode("utf-8-sig") or "{}")
        except (ValueError, RecursionError):
            return JSONResponse({"error": "body must be JSON"}, status_code=400, headers=NO_CACHE)
        tool_name = body.get("tool_name") if isinstance(body, dict) else None
        if not isinstance(tool_name, str) or not tool_name.strip() or len(tool_name) > MAX_TOOL_NAME_CHARS:
            return JSONResponse({"error": "tool_name must be a short string"}, status_code=400, headers=NO_CACHE)
        try:
            verdict = guard.tool_call_verdict(tool_name=tool_name, args=body.get("args"))
        except Exception:   # health: allow BLE001 -- any failure is "could not tell": 503, the asker uses its own checks
            logger.warning("blackbox dashboard: could not judge a %s call for another runtime", tool_name[:40], exc_info=True)
            return JSONResponse({"error": "verdict unavailable"}, status_code=503, headers=NO_CACHE)
        return JSONResponse(verdict, headers=NO_CACHE)
