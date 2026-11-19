"""The dashboard's "Connect your agent's AI model" panel and its routes (2026-11-19).

* ``GET /model-connect.js`` — the panel script (draws ``#model-connect-root``; the first-detection
  card and the assistant read the same state through ``window.blackboxAgentModel``);
* ``GET /api/agent-model`` — ``{state: ready|missing|unknown, providers, nous, fix}``: Hermes' own
  answer for this agent (cached :data:`STATE_TTL_SECONDS`; Hermes imports its CLI to answer);
* ``POST /api/agent-model/key`` ``{provider, key}`` — store an API key through Hermes;
* ``POST /api/agent-model/nous`` / ``POST /api/agent-model/nous/cancel`` — the free Nous sign-in.

The POSTs are state changes, so the app-wide browser boundary already demands the session token
(KI-028 / LES-006). A key is never echoed back, logged or kept by Blackbox (``model_connect``).
"""

from __future__ import annotations

import itertools
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "model_connect.js"
NO_CACHE = {"Cache-Control": "no-store"}
#: How long Hermes' answer is reused across polls (the panel polls every few seconds).
STATE_TTL_SECONDS = 20.0

Cache = Callable[..., Any]


def register(app: Any, swr: Cache) -> None:
    """Add the panel script and the agent-model routes to *app*."""
    from fastapi import Body
    from fastapi.responses import FileResponse, JSONResponse
    from ...kernel.host_command import FIX_COMMAND
    from ... import model_connect

    generation = itertools.count(1)
    current: dict[str, Any] = {"generation": next(generation), "nous_status": "idle"}

    def fresh_after_change() -> None:
        current["generation"] = next(generation)   # a new cache key: the next read asks Hermes again

    def payload() -> dict[str, Any]:
        nous = model_connect.nous().view()
        if nous.get("status") != current["nous_status"]:
            current["nous_status"] = nous.get("status")
            if nous.get("status") == "connected":
                fresh_after_change()   # once per sign-in that finished, not once per poll
        key = f"agent-model:{current['generation']}"
        state = swr(key, model_connect.state, "unknown", STATE_TTL_SECONDS)
        return {"state": state, "fix": FIX_COMMAND, "nous": nous,
                "providers": [{"id": pid, "name": name} for pid, name in model_connect.KEY_PROVIDERS.items()]}

    @app.get("/model-connect.js")
    def model_connect_script() -> Any:
        return FileResponse(str(SCRIPT), media_type="application/javascript", headers=NO_CACHE)

    @app.get("/api/agent-model")
    def agent_model() -> Any:
        return JSONResponse(payload(), headers=NO_CACHE)

    @app.post("/api/agent-model/key")
    def agent_model_key(body: dict[str, Any] = Body(...)) -> Any:
        body = body if isinstance(body, dict) else {}
        result = model_connect.save_api_key(str(body.get("provider") or ""), str(body.get("key") or ""))
        if result.get("ok"):
            fresh_after_change()
        return JSONResponse(result, status_code=200 if result.get("ok") else 400, headers=NO_CACHE)

    @app.post("/api/agent-model/nous")
    def agent_model_nous() -> Any:
        return JSONResponse(model_connect.nous().start(), headers=NO_CACHE)

    @app.post("/api/agent-model/nous/cancel")
    def agent_model_nous_cancel() -> Any:
        return JSONResponse(model_connect.nous().cancel(), headers=NO_CACHE)
