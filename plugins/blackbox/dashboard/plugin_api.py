"""Blackbox's routes for Hermes Desktop: ``/api/plugins/blackbox/status`` and ``/findings``.

Hermes mounts this file for the Desktop half (``desktop/plugin.js``, ``ctx.rest('/status')``) when
the plugin is enabled. Hermes imports it on its own, as ``hermes_dashboard_plugin_blackbox``, outside
Blackbox's package, so relative imports cannot work here. It finds the Blackbox package Hermes
already loaded in this process (the one whose folder holds this file) and reads everything through
its ``desktop`` module; if Blackbox is not loaded here, it loads its own copy of the package once.
The routes read protection status and the newest findings (never evidence or commands), and
``POST /mode`` switches between audit and block, ``GET /readiness`` says where the machine is between
plugin install and synced and ``POST /setup`` starts ``hermes blackbox setup`` (``desktop.readiness``), and ``/dash/<path>`` forwards an allowlisted set
of the running dashboard's own API (threat graph, Trader Shield, agents, community, settings) so the
Desktop page shows every panel without a second copy of its logic (``desktop.dashboard_link``);
``POST /dash-call/<path>`` + ``GET /dash-call/<id>`` run the calls that outlast Desktop's 30 s request
limit in the background (``desktop.long_calls``). Hermes refuses every request here that does not
carry Desktop's own credential (401), so an agent's ``curl`` cannot reach the switch; Blackbox's
tamper rule also flags any agent command aimed at these routes.

Data shapes are documented on ``desktop.status_payload`` and ``desktop.findings_payload``.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Optional

from fastapi import APIRouter, Body, Query, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

router = APIRouter()

PLUGIN_DIR = Path(__file__).resolve().parents[1]
_OWN_COPY = "hermes_blackbox_desktop_backend"   # the name this file loads the package under, if it must
_desktop: Optional[ModuleType] = None


def _loaded_package() -> Optional[str]:
    """The module name Hermes loaded this Blackbox folder under, or None."""
    for name, module in list(sys.modules.items()):
        paths = getattr(module, "__path__", None) or []
        # Only the package itself has this folder on its __path__; its sub-packages have their own.
        if name != _OWN_COPY and any(Path(p).resolve() == PLUGIN_DIR for p in paths):
            return name
    return None


def _load_own_copy() -> str:
    spec = importlib.util.spec_from_file_location(
        _OWN_COPY, PLUGIN_DIR / "__init__.py", submodule_search_locations=[str(PLUGIN_DIR)])
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load Blackbox from {PLUGIN_DIR}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[_OWN_COPY] = module
    spec.loader.exec_module(module)
    return _OWN_COPY


def _desktop_module() -> ModuleType:
    global _desktop
    if _desktop is None:
        package = _loaded_package() or _load_own_copy()
        _desktop = importlib.import_module(f"{package}.desktop")
    return _desktop


def _unavailable(exc: Exception) -> dict[str, Any]:
    return {"available": False, "error": f"Blackbox is not loaded in this Hermes: {exc}"[:300]}


@router.get("/status")
def status() -> Any:
    try:
        return {"available": True, **_desktop_module().status_payload()}
    except Exception as exc:   # health: allow BLE001 -- the Desktop page shows "unavailable", never an HTML 500
        return _unavailable(exc)


@router.get("/findings")
def findings(limit: int = Query(50, ge=1, le=100)) -> Any:
    try:
        return {"available": True, **_desktop_module().findings_payload(limit=limit)}
    except Exception as exc:   # health: allow BLE001 -- the Desktop page shows "unavailable", never an HTML 500
        return _unavailable(exc)


@router.post("/mode")
def mode(body: dict[str, Any] = Body(default={})) -> Any:
    try:
        return {"available": True, **_desktop_module().set_mode(str(body.get("mode") or ""))}
    except Exception as exc:   # health: allow BLE001 -- the Desktop page shows "unavailable", never an HTML 500
        return _unavailable(exc)


@router.get("/readiness")
def readiness() -> Any:
    try:
        return {"available": True, **_desktop_module().readiness_status()}
    except Exception as exc:   # health: allow BLE001 -- the Desktop page shows "unavailable", never an HTML 500
        return _unavailable(exc)


@router.post("/setup")
def setup() -> Any:
    try:
        return {"available": True, **_desktop_module().start_setup()}
    except Exception as exc:   # health: allow BLE001 -- the Desktop page shows "unavailable", never an HTML 500
        return _unavailable(exc)


async def _json_body(request: Request) -> Any:
    try:
        return await request.json() if request.method == "POST" else None
    except ValueError:
        return {}


async def _answer(call: Callable[[], Any]) -> Any:
    """Run a blocking dashboard *call* on a worker thread and send its LinkAnswer.

    WHY a thread: these routes run on Hermes' own event loop, so a blocking request made here
    froze every Desktop request (the whole page went blank while one assistant turn ran)."""
    try:
        answer = await run_in_threadpool(call)
    except Exception as exc:   # health: allow BLE001 -- the Desktop page shows "unavailable", never an HTML 500
        return _unavailable(exc)
    return JSONResponse(answer.body, status_code=answer.status)


async def _forward(request: Request, path: str) -> Any:
    body = await _json_body(request)
    return await _answer(lambda: _desktop_module().dashboard_link().forward(request.method, path, request.url.query, body))


@router.post("/dash-call/{path:path}")
async def dash_call_start(request: Request, path: str) -> Any:
    """Start a dashboard call that outlasts Desktop's 30 s limit (an assistant turn, a Playground test)."""
    body = await _json_body(request)
    return await _answer(lambda: _desktop_module().long_calls().start(path, body))


@router.get("/dash-call/{call_id}")
async def dash_call_result(call_id: str) -> Any:
    """202 while the call runs, then the dashboard's own answer."""
    return await _answer(lambda: _desktop_module().long_calls().result(call_id))


@router.get("/dash/{path:path}")
async def dash_read(request: Request, path: str) -> Any:
    return await _forward(request, path)


@router.post("/dash/{path:path}")
async def dash_write(request: Request, path: str) -> Any:
    return await _forward(request, path)
