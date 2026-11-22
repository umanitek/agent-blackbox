"""Every instance of every coding agent, over HTTP (``agent_hooks.tracking``) — what Blackbox
Desktop's live view and history read. All GETs; hashed ids, no prompt text (see ``instances``).

* ``GET /api/agent-instances/live[?cursor=N&wait=S]`` → the live tree ``{cursor, at, products:
  [{id, name, profiles: [{home, instances: [Instance + status + sub_agents]}]}], unprotected:
  [agent processes with no hook], profiles: [Profile + problems], counts}``. With ``cursor`` and
  ``wait`` (≤ :data:`MAX_WAIT_SECONDS`) the answer is held until something changed — a long-poll,
  so a view is current within about a second without polling fast.
* ``GET /api/agent-instances/history[?agent=&kind=session|sub-agent&before=&limit=]`` → ended
  instances, newest first: ``{instances, more, next_before}``.
* ``GET /api/agent-instances/detail?key=<instance key>[&offset=&limit=]`` → one instance, its
  sub-agents and a page of its timeline ``{instance, actions: [{ts, kind, tool, what,
  verdict}], offset}``; 404 for an unknown key.
* ``GET /api/agent-instances/profiles`` → every config home of every agent and what keeps
  Blackbox's hooks from running there.
"""

# No ``from __future__ import annotations`` here: FastAPI must see the handlers' annotations.
from dataclasses import asdict
from typing import Any

NO_CACHE = {"Cache-Control": "no-store"}
MAX_WAIT_SECONDS = 25.0


def _number(text: str, default: float = 0.0) -> float:
    try:
        return float(text)
    except (TypeError, ValueError):
        return default


def register(app: Any) -> None:
    """Add the agent-instances routes to *app*."""
    from fastapi.responses import JSONResponse

    from ...agent_hooks import tracking

    @app.get("/api/agent-instances/live")
    def agent_instances_live(cursor: str = "", wait: str = "") -> Any:   # sync: a long-poll waits in the thread pool
        seconds = min(max(_number(wait), 0.0), MAX_WAIT_SECONDS)
        if cursor.isdigit() and seconds:
            tracking.wait(int(cursor), seconds)
        return JSONResponse(tracking.live(), headers=NO_CACHE)

    @app.get("/api/agent-instances/history")
    def agent_instances_history(agent: str = "", kind: str = "session", before: str = "", limit: str = "50") -> Any:
        if kind not in ("session", "sub-agent") or (agent and not tracking.known(agent)):
            return JSONResponse({"error": "unknown agent or kind"}, status_code=400, headers=NO_CACHE)
        return JSONResponse(tracking.history(agent=agent, kind=kind, before=_number(before), limit=int(_number(limit, 50))),
                            headers=NO_CACHE)

    @app.get("/api/agent-instances/detail")
    def agent_instances_detail(key: str = "", offset: str = "0", limit: str = "200") -> Any:
        found = tracking.detail(key[:200], offset=max(0, int(_number(offset))), limit=int(_number(limit, 200)))
        if found is None:
            return JSONResponse({"error": "no such instance"}, status_code=404, headers=NO_CACHE)
        return JSONResponse(found, headers=NO_CACHE)

    @app.get("/api/agent-instances/profiles")
    def agent_instances_profiles() -> Any:
        return JSONResponse({"profiles": [asdict(row) for row in tracking.profile_rows()]}, headers=NO_CACHE)
