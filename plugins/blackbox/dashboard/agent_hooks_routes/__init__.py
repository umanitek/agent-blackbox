"""The coding agents Blackbox protects through their own hooks (``agent_hooks``), over HTTP.

* ``GET  /api/agent-hooks`` → ``{"agents": [AgentRow…], "kinds": [...]}`` — every coding agent
  found here or hooked, with its honest state and its recent sessions (hashed ids only).
* ``POST /api/agent-hooks/event`` — one event from the hook runner: recorded, and a ``pre_tool``
  answered with the guard's verdict ``{"decision": "allow" | "block", "message"}``. 400 for a
  malformed event; 503 when it could not be judged (the runner then lets the agent continue).
* ``POST /api/agent-hooks/protection`` ``{"kind": <agent id>, "enabled": bool}`` — install or
  remove an agent's hooks (Protect / Stop protecting, on the dashboard or in Blackbox Desktop).

Both POSTs pass the app-wide browser boundary (the session token from ``GET /api/session``), so a
web page cannot reach them. While "Protect new agents automatically" is on, a background sweep
hooks newly installed agents every :data:`SWEEP_SECONDS` (``agent_hooks.sweep``).
"""

# No ``from __future__ import annotations`` here: FastAPI must see the handlers' ``Request``
# annotation as the class itself.
import json
import logging
import threading
from dataclasses import asdict
from typing import Any, Callable

logger = logging.getLogger(__name__)

NO_CACHE = {"Cache-Control": "no-store"}
#: The largest event read (a write tool's whole file can be in its arguments).
MAX_BODY_BYTES = 1024 * 1024
SWEEP_SECONDS = 300.0

Cache = Callable[..., Any]
_sweeper: dict[str, Any] = {"thread": None}


def _sweep_forever() -> None:
    from ... import agent_hooks
    stop = threading.Event()
    while not stop.wait(SWEEP_SECONDS if _sweeper.get("ran") else 20.0):
        _sweeper["ran"] = True
        try:
            agent_hooks.sweep()
        except Exception:   # health: allow BLE001 -- a sweep that fails tries again next round
            logger.warning("blackbox dashboard: the agent hooks sweep failed", exc_info=True)


def register(app: Any, swr: Cache) -> None:
    """Add the agent-hooks routes to *app* and start the sweep (once per process)."""
    from fastapi import Request
    from fastapi.concurrency import run_in_threadpool
    from fastapi.responses import JSONResponse

    from ... import agent_hooks

    @app.get("/api/agent-hooks")
    def agent_hooks_list() -> Any:
        return JSONResponse({"agents": [asdict(row) for row in agent_hooks.rows()], "kinds": list(agent_hooks.KINDS)},
                            headers=NO_CACHE)

    async def _body(request: Request) -> Any:
        raw = await request.body()
        if len(raw) > MAX_BODY_BYTES:
            raise ValueError("request too large")
        return json.loads(raw.decode("utf-8-sig") or "{}")

    @app.post("/api/agent-hooks/event")
    async def agent_hooks_event(request: Request) -> Any:
        body: Any = None
        try:
            body = await _body(request)
            # The guard reads rules and files: off the event loop, so other requests keep flowing.
            return JSONResponse(await run_in_threadpool(agent_hooks.record_event, body), headers=NO_CACHE)
        except (ValueError, RecursionError) as exc:
            return JSONResponse({"error": str(exc)[:200]}, status_code=400, headers=NO_CACHE)
        except Exception:   # health: allow BLE001 -- "could not judge": 503, the runner lets the agent continue
            agent = body.get("agent") if isinstance(body, dict) else ""
            if agent in agent_hooks.KINDS:
                agent_hooks.note_error(agent)
            logger.warning("blackbox dashboard: an agent hook event could not be checked", exc_info=True)
            return JSONResponse({"error": "could not check the event"}, status_code=503, headers=NO_CACHE)

    @app.post("/api/agent-hooks/protection")
    async def agent_hooks_protection(request: Request) -> Any:
        try:
            body = await _body(request)
        except (ValueError, RecursionError) as exc:
            return JSONResponse({"error": str(exc)[:200]}, status_code=400, headers=NO_CACHE)
        kind, enabled = body.get("kind") if isinstance(body, dict) else None, body.get("enabled") if isinstance(body, dict) else None
        if kind not in agent_hooks.KINDS or not isinstance(enabled, bool):
            return JSONResponse({"error": "kind must be a known agent and enabled true or false"}, status_code=400, headers=NO_CACHE)
        result = await run_in_threadpool(agent_hooks.set_protection, kind, enabled)
        return JSONResponse(result, status_code=200 if result["ok"] else 400, headers=NO_CACHE)

    if _sweeper["thread"] is None:
        _sweeper["thread"] = threading.Thread(target=_sweep_forever, name="blackbox-agent-hooks-sweep", daemon=True)
        _sweeper["thread"].start()
