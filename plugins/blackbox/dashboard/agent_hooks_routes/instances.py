"""Every instance of every coding agent, over HTTP (``agent_hooks.tracking``) — what a
companion app's live view and history read. Hashed ids. No GET ever carries a prompt's text: the text a
person chose to keep (``agent_hooks.prompt_text``, off by default) is served only by the POST
routes below, which the browser boundary answers only with the session token — so a program that
merely curls this dashboard cannot read it.

* ``GET /api/agent-instances/live[?cursor=N&wait=S]`` → the live tree ``{cursor, at, products:
  [{id, name, profiles: [{home, instances: [Instance + status + sub_agents]}]}], unprotected:
  [agent processes with no hook], profiles: [Profile + problems], counts}``. With ``cursor`` and
  ``wait`` (≤ :data:`MAX_WAIT_SECONDS`) the answer is held until something changed — a long-poll,
  so a view is current within about a second without polling fast.
* ``GET /api/agent-instances/history[?agent=&kind=session|sub-agent&project=&since=&until=&outcome=&before=&limit=]``
  → ended instances, newest first: ``{instances, more, next_before, facets: {agents, projects}}``.
  ``project`` is a project folder's name, ``since`` / ``until`` bound when it ended (epoch
  seconds), ``outcome`` is ``refused`` / ``too-late`` / ``stopped`` (either); 400 for an
  unknown agent, kind or outcome.
* ``GET /api/agent-instances/detail?key=<instance key>[&offset=&limit=]`` → one instance, its
  sub-agents and a page of its timeline ``{instance, actions: [{ts, kind, tool, what,
  verdict, reason}], offset}``; 404 for an unknown key. An instance row carries ``status``
  (``live`` / ``waiting`` / ``ended``), ``waiting`` + ``waiting_for``, and ``last_action``.
* ``POST /api/agent-instances/detail`` ``{key, offset?, limit?}`` (session token) → the same,
  and each prompt entry also carries ``text`` WHILE prompt-text recording is on (absent
  otherwise).
* ``GET /api/agent-instances/prompt-text`` → ``{recording, days, stored, since, statement}``.
* ``POST /api/agent-instances/prompt-text/delete`` (session token) → removes every stored
  prompt text now: ``{deleted, prompt_text}``.
* ``POST /api/agent-instances/export`` (session token) → the whole history as JSON the person
  can keep: ``{exported_at, prompt_text, instances: [{instance, actions}]}``.
* ``GET /api/agent-instances/profiles`` → every config home of every agent and what keeps
  Blackbox's hooks from running there.
* ``GET /api/agent-instances/profile?agent=<id>&home=<a home from the list>[&project=<a folder a
  session ran in>]`` → what that profile operates under, read from the real files (instruction
  files with their redacted text, settings per scope, hooks, MCP servers, definitions, where
  sessions are stored, the program and version, and risk notes derived from those facts);
  404 for a home or agent Blackbox does not know.
"""

# No ``from __future__ import annotations`` here: FastAPI must see the handlers' annotations.
from dataclasses import asdict
from typing import Any

NO_CACHE = {"Cache-Control": "no-store"}
MAX_WAIT_SECONDS = 25.0
#: A project folder name longer than this is cut before it is matched.
MAX_PROJECT_CHARS = 200


def _number(text: Any, default: float = 0.0) -> float:
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
    def agent_instances_history(agent: str = "", kind: str = "session", project: str = "", since: str = "", until: str = "",
                                outcome: str = "", before: str = "", limit: str = "50") -> Any:
        if kind not in ("session", "sub-agent") or (agent and not tracking.known(agent)) or outcome not in tracking.HISTORY_OUTCOMES:
            return JSONResponse({"error": "unknown agent, kind or outcome"}, status_code=400, headers=NO_CACHE)
        return JSONResponse(tracking.history(agent=agent, kind=kind, project=project[:MAX_PROJECT_CHARS], since=_number(since),
                                             until=_number(until), outcome=outcome, before=_number(before),
                                             limit=int(_number(limit, 50))), headers=NO_CACHE)

    @app.get("/api/agent-instances/detail")
    def agent_instances_detail(key: str = "", offset: str = "0", limit: str = "200") -> Any:
        found = tracking.detail(key[:200], offset=max(0, int(_number(offset))), limit=int(_number(limit, 200)))
        if found is None:
            return JSONResponse({"error": "no such instance"}, status_code=404, headers=NO_CACHE)
        return JSONResponse(found, headers=NO_CACHE)

    _register_kept_text(app, tracking)

    @app.get("/api/agent-instances/profile")
    def agent_instances_profile(agent: str = "", home: str = "", project: str = "") -> Any:
        found = tracking.profile(agent[:60], home[:1000], project[:1000])
        if found is None:
            return JSONResponse({"error": "no such profile"}, status_code=404, headers=NO_CACHE)
        return JSONResponse(found, headers=NO_CACHE)

    @app.get("/api/agent-instances/profiles")
    def agent_instances_profiles() -> Any:
        return JSONResponse({"profiles": [asdict(row) for row in tracking.profile_rows()]}, headers=NO_CACHE)


def _register_kept_text(app: Any, tracking: Any) -> None:
    """The routes that touch a prompt's kept text or the whole history: POSTs, so the browser
    boundary answers them only with the session token (see the module doc)."""
    from fastapi.responses import JSONResponse

    @app.post("/api/agent-instances/detail")
    def agent_instances_detail_with_text(body: dict[str, Any]) -> Any:   # POST: the boundary required the session token
        key = str(body.get("key") or "")[:200]
        found = tracking.detail(key, with_text=True, offset=max(0, int(_number(body.get("offset")))),
                                limit=int(_number(body.get("limit"), 200)))
        if found is None:
            return JSONResponse({"error": "no such instance"}, status_code=404, headers=NO_CACHE)
        return JSONResponse(found, headers=NO_CACHE)

    @app.get("/api/agent-instances/prompt-text")
    def agent_instances_prompt_text() -> Any:
        return JSONResponse(asdict(tracking.prompt_text.status()), headers=NO_CACHE)

    @app.post("/api/agent-instances/prompt-text/delete")
    def agent_instances_prompt_text_delete() -> Any:
        deleted = tracking.prompt_text.delete_stored()
        return JSONResponse({"deleted": deleted, "prompt_text": asdict(tracking.prompt_text.status())}, headers=NO_CACHE)

    @app.post("/api/agent-instances/export")
    def agent_instances_export() -> Any:
        return JSONResponse(tracking.export(), headers=NO_CACHE)
