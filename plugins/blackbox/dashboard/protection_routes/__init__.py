"""The Protection page over HTTP: what agents tried against Blackbox, whether its record of that is
whole, and the person's watch rules.

* ``GET /api/protection`` → ``{tamper: {category: {count, last_at, last_agent}}, log: {seq, hash,
  state, first_bad}, rules: [RuleView]}`` — the tamper counts (``audit.tamper_counts``), the
  protection log's check (``audit.protection_log.verify``: ``ok`` | ``empty`` | ``broken`` |
  ``rewound`` | ``drift``) and every watch rule with its hits (``watch.view``).
* ``POST /api/protection/watch`` ``{kind, value, note?}`` → the settings writer's ``{ok, errors}``;
  a new rule starts in ``watch``.
* ``POST /api/protection/watch/promote`` ``{rule_id}`` → ``{ok, errors}``; the rule now blocks.
* ``POST /api/protection/watch/suggest`` ``{finding}`` → ``{suggestion: {kind, value, note} | null}``
  — a rule pre-filled from a finding row, for the person to confirm.
* ``GET /protection`` and ``/protection.js`` — the page.

Taking a rule off, or moving a blocking rule back to watch, is saved through ``POST /api/settings``
``{"watch_rules": {...}}``: it turns protection down, so the approval gate holds it (the judge
``watch.weakening`` is registered here). Adding and promoting only strengthen and are written at
once. POSTs pass the browser boundary (the session token).
"""

# No ``from __future__ import annotations`` here: FastAPI must see the handlers' annotations.
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable

NO_CACHE = {"Cache-Control": "no-store"}
STATIC = Path(__file__).resolve().parent.parent / "static"
PAGE, SCRIPT = STATIC / "protection.html", STATIC / "protection.js"

Cache = Callable[..., Any]


def register(app: Any, swr: Cache) -> None:
    """Add the Protection routes to *app*."""
    from fastapi.responses import FileResponse, JSONResponse

    from ... import approvals, audit, watch

    # Taking a blocking watch rule off waits for the person, like any change that turns protection down.
    approvals.SECTION_JUDGES[watch.SECTION] = watch.weakening

    @app.get("/api/protection")
    def protection() -> Any:
        return JSONResponse({"tamper": audit.tamper_counts(), "log": asdict(audit.protection_log.verify()),
                             "rules": watch.view()}, headers=NO_CACHE)

    @app.post("/api/protection/watch")
    def protection_watch(body: dict[str, Any]) -> Any:
        answer = watch.add(str(body.get("kind") or ""), str(body.get("value") or ""), note=str(body.get("note") or ""))
        return JSONResponse(answer, status_code=200 if answer.get("ok") else 400, headers=NO_CACHE)

    @app.post("/api/protection/watch/promote")
    def protection_promote(body: dict[str, Any]) -> Any:
        answer = watch.promote(str(body.get("rule_id") or ""))
        return JSONResponse(answer, status_code=200 if answer.get("ok") else 400, headers=NO_CACHE)

    @app.post("/api/protection/watch/suggest")
    def protection_suggest(body: dict[str, Any]) -> Any:
        finding = body.get("finding")
        return JSONResponse({"suggestion": watch.suggest(finding) if isinstance(finding, dict) else None}, headers=NO_CACHE)

    @app.get("/protection")
    def protection_page() -> Any:
        return FileResponse(str(PAGE), media_type="text/html", headers=NO_CACHE)

    @app.get("/protection.js")
    def protection_script() -> Any:
        return FileResponse(str(SCRIPT), media_type="application/javascript", headers=NO_CACHE)
