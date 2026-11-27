"""The dashboard's Docs page: everything Blackbox does, explained where every install can read it.

Routes (added by :func:`register`, one of the dashboard's route packages):

* ``GET /docs`` — the page (``docs.html``; its prose ships with the plugin, so the docs work
  offline and match the installed version).
* ``GET /docs/assets/{name}`` — ``docs.css``, ``docs.js`` and ``agents.js`` only (an exact allowlist).
* ``GET /api/docs/agents`` — "What Blackbox protects": the platform map and test registry of the
  coding agents (:mod:`.agent_registry`), with what is installed here and a notice when an
  installed agent is newer than the last tested version.
* ``GET /api/docs`` — the live data the page draws (:mod:`.payload`): shields, their packs with
  each wallet's stores and sources, browser folders, the tested attack tables and the
  real-machine test runs. Cached briefly through the dashboard's cache like ``/api/shields``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from .agent_registry import docs_section
from .payload import build_payload

HERE = Path(__file__).resolve().parent
PAGE = HERE / "docs.html"
#: The only files ``/docs/assets/`` serves, with their media types (never a path from the request).
ASSETS = {"docs.css": "text/css", "docs.js": "application/javascript", "agents.js": "application/javascript"}
CACHE_KEY = "docs"
CACHE_TTL_SECONDS = 30.0
NO_CACHE = {"Cache-Control": "no-store"}

Cache = Callable[..., Any]


def register(app: Any, swr: Cache) -> None:
    """Add ``GET /docs``, ``GET /docs/assets/{name}`` and ``GET /api/docs`` to *app*."""
    from fastapi.responses import FileResponse, JSONResponse

    @app.get("/docs")
    def docs_page() -> Any:
        return FileResponse(str(PAGE), media_type="text/html", headers=NO_CACHE)

    @app.get("/docs/assets/{name}")
    def docs_asset(name: str) -> Any:
        media_type = ASSETS.get(name)
        if media_type is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        return FileResponse(str(HERE / name), media_type=media_type, headers=NO_CACHE)

    @app.get("/api/docs/agents")
    def docs_agents() -> Any:
        return JSONResponse(docs_section(), headers=NO_CACHE)

    @app.get("/api/docs")
    def docs_data() -> Any:
        return swr(CACHE_KEY, build_payload, {"version": "", "shields": [], "settings": {"permissions": [], "always_blocked": [], "always_on": []},
                                              "field_tests": []}, CACHE_TTL_SECONDS)
