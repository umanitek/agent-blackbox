"""Every agent protected, now and later — what the dashboard shows of it (2026-11-19).

* ``GET /agent-coverage.js`` — draws ``#agent-coverage-root`` above Connected agents: one slim
  line naming each agent on this machine Blackbox does NOT protect (never one the operator
  switched off), with "Protect" and "Protect every agent, now and later"; and a corner note
  "New agent protected: Hermes · coder" each time the sweep protects one by itself.
* ``GET /api/agent-coverage`` — :func:`attach.coverage` (``{auto_attach, unprotected, recent}``),
  reused for :data:`TTL_SECONDS` across polls.
* ``POST /api/agent-coverage/protect-all`` — the operator's yes from the page: saves
  ``auto_attach: true`` (the same writer as the installers' ``blackbox attach --all --auto``)
  and protects every agent found now, except any the operator switched off.

The POST is a state change, so the app-wide browser boundary demands the session token
(KI-028 / LES-006); an agent cannot reach it either (the guard flags its own settings routes).
"""

from __future__ import annotations

import itertools
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "agent_coverage.js"
NO_CACHE = {"Cache-Control": "no-store"}
#: How long one discovery pass is reused across polls (discovery reads every agent's config).
TTL_SECONDS = 5.0

Cache = Callable[..., Any]


def register(app: Any, swr: Cache) -> None:
    """Add the coverage script and routes to *app* (called once by the dashboard)."""
    from fastapi.responses import FileResponse, JSONResponse

    from ... import attach
    from ...kernel import settings

    generation = itertools.count(1)
    current = {"generation": next(generation)}

    def view() -> dict[str, Any]:
        return swr(f"agent-coverage-{current['generation']}", attach.coverage,
                   {"auto_attach": False, "unprotected": [], "recent": []}, ttl=TTL_SECONDS)

    @app.get("/agent-coverage.js")
    def agent_coverage_script() -> Any:
        return FileResponse(str(SCRIPT), media_type="application/javascript", headers=NO_CACHE)

    @app.get("/api/agent-coverage")
    def agent_coverage() -> Any:
        return JSONResponse(view(), headers=NO_CACHE)

    @app.post("/api/agent-coverage/protect-all")
    def agent_coverage_protect_all() -> Any:
        saved = settings.write_settings({"auto_attach": True})
        if not saved.get("ok"):
            return JSONResponse({"ok": False, "error": "; ".join(saved.get("errors") or ["could not save"])},
                                status_code=400, headers=NO_CACHE)
        report = attach.attach_all(auto_attach=True)   # automatic: an agent switched off stays off
        current["generation"] = next(generation)
        failed = [row for kind in ("hermes", "openclaw") for row in report.get(kind, []) if row.get("error")]
        return JSONResponse({"ok": not failed, "protected": report.get("count"),
                             "error": "; ".join(str(row["error"]) for row in failed)}, headers=NO_CACHE)
