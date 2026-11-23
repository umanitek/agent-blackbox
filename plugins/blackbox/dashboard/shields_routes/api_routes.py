"""``GET`` / ``POST /api/shields/{shield_id}/api/{name}`` — a shield's own endpoints.

The routes never name a shield: they look the endpoint up through ``shields.call_api`` and hand
it a :class:`~....shields.ShieldContext` built here from what only the dashboard may use — the
verified graph's network lists (``ruleset.network_indicators``) and its file fingerprints
(``lookup_hashes``), Blackbox's assistant (the one
runner, ``dashboard/assistant/runner.py``) and the current Block/Audit mode.

A write is a POST, so the app-wide browser boundary already demands the session token
(KI-028 / LES-006); its body is capped at ``shields.API_MAX_WRITE_BYTES`` before it is
parsed. Answers are never cached: shield endpoints serve live data.
"""

# No ``from __future__ import annotations`` here: FastAPI must see the handlers' ``Request``
# annotation as the class itself, and that class is imported inside ``register``.
import json
import re
from typing import Any

from ... import agent_hooks, approvals, guard, ruleset, shields
from ...kernel import threat_ids
from ...kernel.config import load_blackbox_config
from .. import sync_meter
from ..assistant import runner as assistant_runner

NO_CACHE = {"Cache-Control": "no-store"}
_NAME = re.compile(shields.API_NAME_PATTERN)
_SHIELD_ID = re.compile(r"[a-z][a-z0-9-]{0,31}")


def ask_assistant(message: str) -> shields.AssistantAnswer:
    """One turn of Blackbox's assistant, as the record a shield receives."""
    payload, status = assistant_runner.ask(message)
    if status == 200 and payload.get("ok", True):
        return shields.AssistantAnswer(ok=True, answer=str(payload.get("answer") or ""))
    return shields.AssistantAnswer(ok=False, error=str(payload.get("error") or "Blackbox could not answer."),
                                   needs_model=bool(payload.get("needs_model") or payload.get("model_problem")))


def lookup_hashes(hashes: list) -> tuple:
    """Which of these SHA-256 fingerprints the verified graph lists (a feed may store a hash
    bare or as ``sha256:<hex>``), and whether every one could be asked."""
    asked: dict[str, str] = {}
    for sha in hashes:
        for spelling in (sha, f"sha256:{sha}"):
            asked[threat_ids.ioc_identifier("hash", spelling)] = sha
    found, why = ruleset.peek().verified_subset_answer(asked)
    return frozenset(asked[identifier] for identifier in found if identifier in asked), not why


def finding_owners() -> Any:
    """The agent tracker's resolver for findings rows, as the shields' own record (KI-588)."""
    owner_of = agent_hooks.owners.finding_owners()

    def resolve(row: Any) -> Any:
        found = owner_of(row)
        return shields.InstanceRef(found.agent, found.instance, found.sub_agent) if found is not None else None

    return resolve


def owner_of_pid(pid: int) -> Any:
    """The agent instance a process belongs to by its ancestry (KI-605), as the shields' own record."""
    found = agent_hooks.owners.of_pid(pid)
    return shields.InstanceRef(found.agent, found.instance, found.sub_agent, found.folder) if found is not None else None


def context(body: bytes = b"", headers: Any = None) -> shields.ShieldContext:
    """The context one shield endpoint call receives (*body* / *headers*: the request's own)."""
    return shields.ShieldContext(
        request_body=body,
        request_headers={str(name).lower(): str(value) for name, value in dict(headers or {}).items()},
        network_indicators=ruleset.network_indicators,
        network_indicators_now=lambda: ruleset.network_indicators(wait=False),
        graph_reachable=ruleset.graph_reachable,
        graph_sync_state=sync_meter.current_state,
        ask_assistant=ask_assistant,
        lookup_hashes=lookup_hashes,
        blocking=load_blackbox_config().mode == "block",
        finding_owners=finding_owners,
        tool_call_verdict=lambda tool, args: guard.tool_call_verdict(tool_name=tool, args=args),
        owner_of_pid=owner_of_pid,
    )


def _valid(shield_id: str, name: str) -> bool:
    return bool(_SHIELD_ID.fullmatch(shield_id) and _NAME.fullmatch(name))


def register(app: Any) -> None:
    """Adds the two routes to *app*, and holds a loosening of the agents' Homebrew installs
    (``agent_packages``) and of the sandbox permissions (``agent_sandbox``) for the person's approval."""
    approvals.SECTION_JUDGES[shields.PACKAGE_INSTALLS] = shields.package_installs_weakening
    approvals.SECTION_JUDGES[shields.AGENT_SANDBOX] = shields.agent_sandbox_weakening
    from fastapi import Request
    from fastapi.responses import JSONResponse, Response
    from starlette.concurrency import run_in_threadpool

    def answer(shield_id: str, method: str, name: str, data: Any, raw: bytes = b"", headers: Any = None) -> Any:
        if not _valid(shield_id, name):
            return JSONResponse({"error": "unknown shield endpoint"}, status_code=404, headers=NO_CACHE)
        try:
            result = shields.call_api(shield_id, method, name, context(raw, headers), data)
            if isinstance(result, shields.RawAnswer):   # signed bytes: sent exactly as built
                return Response(content=result.body, media_type="application/json", headers={**NO_CACHE, **dict(result.headers)})
            return JSONResponse(result, headers=NO_CACHE)
        except shields.ShieldApiError as refusal:
            return JSONResponse({"error": refusal.message}, status_code=refusal.status, headers=NO_CACHE)

    @app.get("/api/shields/{shield_id}/api/{name}")
    def shield_api_read(shield_id: str, name: str, request: Request) -> Any:
        return answer(shield_id, "GET", name, dict(request.query_params), headers=request.headers)

    @app.post("/api/shields/{shield_id}/api/{name}")
    async def shield_api_write(shield_id: str, name: str, request: Request) -> Any:
        raw = await request.body()
        if len(raw) > shields.API_MAX_WRITE_BYTES:
            return JSONResponse({"error": "request too large"}, status_code=413, headers=NO_CACHE)
        try:
            body = json.loads(raw.decode("utf-8-sig") or "{}")
        except (ValueError, RecursionError):
            return JSONResponse({"error": "body must be JSON"}, status_code=400, headers=NO_CACHE)
        if not isinstance(body, dict):
            return JSONResponse({"error": "body must be a JSON object"}, status_code=400, headers=NO_CACHE)
        # WHY the thread pool: an endpoint may take minutes (an assistant answer); run in
        # this async route directly it would stall every other request of the dashboard.
        return await run_in_threadpool(answer, shield_id, "POST", name, body, raw, request.headers)
