"""The dashboard's "Connect your agent's AI model" panel and its routes (2026-11-19).

* ``GET /model-connect.js`` — the panel script (draws ``#model-connect-root``; the first-detection
  card and the assistant read the same state through ``window.blackboxAgentModel``);
* ``GET /api/agent-model`` — ``{state: ready|missing|unknown, providers, nous, fix}``: Hermes' own
  answer for this agent (cached :data:`STATE_TTL_SECONDS`; Hermes imports its CLI to answer);
* ``POST /api/agent-model/key`` ``{provider, key}`` — store an API key through Hermes;
* ``POST /api/agent-model/nous`` / ``POST /api/agent-model/nous/cancel`` — the free Nous sign-in;
* ``POST /api/agent-model/recommended`` / ``/model`` ``{model}`` / ``/disconnect`` — the card's changes
  (``connection`` in the GET says provider, model, account and Hermes' "exhausted" mark).

The POSTs are state changes, so the app-wide browser boundary already demands the session token
(KI-028 / LES-006). A key is never echoed back, logged or kept by Blackbox (``model_connect``).
"""

from __future__ import annotations

import itertools
from pathlib import Path
from typing import Any, Callable

#: The panel script, kept with the dashboard's other static files (``dashboard/static/``).
SCRIPT = Path(__file__).resolve().parents[1] / "static" / "model_connect.js"
NO_CACHE = {"Cache-Control": "no-store"}
#: How long Hermes' answer is reused across polls (the panel polls every few seconds).
STATE_TTL_SECONDS = 20.0

Cache = Callable[..., Any]


class _AgentModelView:
    """What GET /api/agent-model returns: Hermes' answer and the card, cached per *generation*.

    A change (a key saved, a model chosen, a sign-in that finished, a sign-out) starts a new
    generation, so the next read asks Hermes again instead of showing the old answer."""

    def __init__(self, swr: Cache) -> None:
        self._swr = swr
        self._generation = itertools.count(1)
        self._current = next(self._generation)
        self._nous_status: Any = "idle"

    def changed(self) -> None:
        self._current = next(self._generation)

    def payload(self) -> dict[str, Any]:
        from ...kernel.host_command import FIX_COMMAND
        from ... import model_connect

        nous = model_connect.nous().view()
        if nous.get("status") != self._nous_status:
            self._nous_status = nous.get("status")
            if self._nous_status == "connected":
                self.changed()   # once per sign-in that finished, not once per poll
        key = f"agent-model:{self._current}"
        state = self._swr(key, model_connect.state, "unknown", STATE_TTL_SECONDS)
        card = self._swr(key + ":connection", lambda: model_connect.connection(model_connect.HermesRun()), {},
                         STATE_TTL_SECONDS) if state == "ready" else {}
        return {"state": state, "fix": FIX_COMMAND, "nous": nous, "connection": card,
                "providers": [{"id": pid, "name": name} for pid, name in model_connect.KEY_PROVIDERS.items()]}


def register(app: Any, swr: Cache) -> None:
    """Add the panel script and the agent-model routes to *app*."""
    from fastapi import Body
    from fastapi.responses import FileResponse, JSONResponse
    from ... import model_connect

    view = _AgentModelView(swr)

    def changed(result: dict[str, Any]) -> Any:
        if result.get("ok"):
            view.changed()
        return JSONResponse(result, status_code=200 if result.get("ok") else 400, headers=NO_CACHE)

    @app.get("/model-connect.js")
    def model_connect_script() -> Any:
        return FileResponse(str(SCRIPT), media_type="application/javascript", headers=NO_CACHE)

    @app.get("/api/agent-model")
    def agent_model() -> Any:
        return JSONResponse(view.payload(), headers=NO_CACHE)

    @app.post("/api/agent-model/key")
    def agent_model_key(body: dict[str, Any] = Body(...)) -> Any:
        body = body if isinstance(body, dict) else {}
        return changed(model_connect.save_api_key(str(body.get("provider") or ""), str(body.get("key") or "")))

    @app.post("/api/agent-model/nous")
    def agent_model_nous() -> Any:
        return JSONResponse(model_connect.nous().start(), headers=NO_CACHE)

    @app.post("/api/agent-model/nous/cancel")
    def agent_model_nous_cancel() -> Any:
        return JSONResponse(model_connect.nous().cancel(), headers=NO_CACHE)

    @app.post("/api/agent-model/recommended")
    def agent_model_recommended() -> Any:
        return changed(model_connect.use_recommended_model(model_connect.HermesRun()))

    @app.post("/api/agent-model/model")
    def agent_model_set(body: dict[str, Any] = Body(...)) -> Any:
        model = str(body.get("model") or "") if isinstance(body, dict) else ""
        return changed(model_connect.set_model(model, model_connect.HermesRun()))

    @app.post("/api/agent-model/disconnect")
    def agent_model_disconnect() -> Any:
        return changed(model_connect.disconnect(model_connect.HermesRun()))
