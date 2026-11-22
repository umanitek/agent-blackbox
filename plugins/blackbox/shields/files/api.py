"""File Shield's endpoints — ``/api/shields/file-shield/api/<name>`` (Facade over the shield).

Reads (GET):

* ``protected`` — the person's protected items, each with whether it is a file or a folder and
  whether it exists, and how many times an agent was refused on it;
* ``hits`` — the newest refusals (``?limit=``, at most 200);
* ``changes`` — the helper's real-time changes after ``?since=<seq>`` (Blackbox Desktop follows these);
* ``watch-plan`` — what the system protection helper watches, SIGNED for its nonce (helper_link);
* ``sandbox`` — Layer 2: which agents run inside the OS sandbox, whether their launchers are in
  place, and the GUI editors that can be opened inside it (:mod:`.sandbox`).

Writes (POST):

* ``protect`` ``{"path": "~/Documents/Taxes"}`` — adds an item at once (stricter, never asks);
* ``unprotect`` ``{"path": …}`` — removes one: turns protection DOWN, so the core's approvals gate
  holds it for the person (:data:`API` ``weakening``);
* ``file-report`` — the helper's signed real-time changes (:mod:`.changes`), including the
  sandbox's refusals the helper reads from the system log;
* ``open-protected`` ``{"app": "cursor"}`` — relaunches a GUI editor inside the sandbox (stricter,
  never asks).

Every write goes through the ONE settings writer (``kernel.settings.write_settings``) with File
Shield's own validator — never a second path into the config.
"""

from __future__ import annotations

import os
from typing import Any, Mapping

from ...kernel.settings import write_settings
from .. import helper_link
from ..shield_api import ShieldApi, ShieldApiError, ShieldContext
from . import changes, events, mode as mode_module, sandbox
from .protect import is_folder

MAX_HITS = 200


def _item(body: Mapping[str, Any]) -> str:
    item = mode_module.canonical_item(body.get("path"))
    if item is None:
        raise ShieldApiError(400, "Name one file or folder, written from ~/ or / — not the whole disk or your whole home folder.")
    return item


def _write(items: list[str]) -> dict[str, Any]:
    result = write_settings({"shields": {mode_module.SHIELD_ID: {mode_module.OPT_PROTECTED: items}}},
                            validators=(mode_module.validate,))
    if not result.get("ok"):
        raise ShieldApiError(400, "; ".join(result.get("errors") or ["File Shield's list could not be saved"]))
    _sync_sandbox()
    return protected_view(None)


def _sync_sandbox() -> dict[str, Any]:
    """The sandbox profile and launchers made to match the setting (fail-open: never breaks a read)."""
    try:
        return sandbox.sync()
    except Exception as error:   # health: allow BLE001 -- the sandbox is Layer 2; Layer 1 still refuses
        return {"unavailable": f"The agent sandbox could not be updated: {type(error).__name__}"}


def _stored() -> list[str]:
    return list(mode_module.current().options.get(mode_module.OPT_PROTECTED, ()))


def protected_view(_context: Any, _params: Mapping[str, str] | None = None) -> dict[str, Any]:
    """The protected items, each with its kind, whether it exists and its refusals so far."""
    counts: dict[str, int] = {}
    for hit in events.hits(limit=MAX_HITS):
        counts[hit["item"]] = counts.get(hit["item"], 0) + 1
    current = mode_module.current()
    return {"enabled": current.enabled,
            "items": [{"item": item, "kind": "folder" if is_folder(item) else "file",
                       "exists": os.path.lexists(os.path.expanduser(item)), "hits": counts.get(item, 0)}
                      for item in current.options.get(mode_module.OPT_PROTECTED, ())]}


def protect(_context: ShieldContext, body: Mapping[str, Any]) -> dict[str, Any]:
    item = _item(body)
    items = _stored()
    if item not in items:
        if len(items) >= mode_module.MAX_PROTECTED:
            raise ShieldApiError(400, f"File Shield protects at most {mode_module.MAX_PROTECTED} items.")
        items.append(item)
    return _write(items)


def unprotect(_context: ShieldContext, body: Mapping[str, Any]) -> dict[str, Any]:
    item = _item(body)
    items = _stored()
    if item not in items:
        raise ShieldApiError(404, f"{item} is not on File Shield's protected list.")
    return _write([each for each in items if each != item])


def unprotect_weakens(body: Mapping[str, Any]) -> list[str]:
    """Why ``unprotect`` turns protection down: always — unless it names nothing on the list."""
    item = mode_module.canonical_item(body.get("path"))
    if item is None or item not in _stored():
        return []
    return [f"Stop protecting {item} from AI agents (File Shield)"]


def hits(_context: ShieldContext, params: Mapping[str, str]) -> dict[str, Any]:
    raw = str(params.get("limit") or "")
    limit = min(int(raw), MAX_HITS) if raw.isdigit() else 50
    return {"hits": events.hits(limit=limit)}


def changes_view(_context: ShieldContext, params: Mapping[str, str]) -> dict[str, Any]:
    raw = str(params.get("since") or "0")
    seq, new = changes.since(int(raw) if raw.isdigit() else 0)
    return {"seq": seq, "changes": [change.as_json() for change in new[-changes.MAX_KEPT:]]}


def sandbox_view(_context: ShieldContext, _params: Mapping[str, str]) -> dict[str, Any]:
    return _sync_sandbox()


def open_protected(_context: ShieldContext, body: Mapping[str, Any]) -> dict[str, Any]:
    app = str(body.get("app") or "")
    try:
        return {"message": sandbox.open_app(app)}
    except ValueError:
        raise ShieldApiError(400, "Name an editor Blackbox can open inside its sandbox: cursor or windsurf.")
    except (LookupError, RuntimeError) as error:
        raise ShieldApiError(409, str(error))


def watch_plan(_context: ShieldContext, params: Mapping[str, str]) -> Any:
    """What the helper watches in real time, signed for its nonce (a keyed helper obeys nothing else).
    Every poll (about every 2 s) also brings the sandbox profile up to date with the list."""
    _sync_sandbox()
    current = mode_module.current()
    return helper_link.signed({"watch": current.enabled, "paths": list(mode_module.watch_paths(current))}, params)


def file_report(context: ShieldContext, body: Mapping[str, Any]) -> dict[str, Any]:
    helper_link.require_signed_report(context)   # once paired, only this Mac's helper may report
    events_in = body.get("events")
    if not isinstance(events_in, list):
        raise ShieldApiError(400, "a file report carries a list of events")
    kept = changes.record(events_in, mode_module.current())
    return {"kept": len(kept)}


API = ShieldApi(
    reads={"protected": protected_view, "hits": hits, "changes": changes_view, "watch-plan": watch_plan,
           "sandbox": sandbox_view},
    writes={"protect": protect, "unprotect": unprotect, "file-report": file_report, "open-protected": open_protected},
    weakening={"unprotect": unprotect_weakens},
)
