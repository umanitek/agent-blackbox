"""Blackbox's routes for Hermes Desktop: ``/api/plugins/blackbox/status`` and ``/findings``.

Hermes mounts this file for the Desktop half (``desktop/plugin.js``, ``ctx.rest('/status')``) when
the plugin is enabled. Hermes imports it on its own, as ``hermes_dashboard_plugin_blackbox``, outside
Blackbox's package, so relative imports cannot work here. It finds the Blackbox package Hermes
already loaded in this process (the one whose folder holds this file) and reads everything through
its ``desktop`` module; if Blackbox is not loaded here, it loads its own copy of the package once.
The routes read protection status and the newest findings (never evidence or commands), and
``POST /mode`` switches between audit and block. Hermes refuses every request here that does not
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
from typing import Any, Optional

from fastapi import APIRouter, Body, Query

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
