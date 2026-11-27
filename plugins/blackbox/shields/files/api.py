"""File Shield's endpoints — ``/api/shields/file-shield/api/<name>`` (Facade over the shield).

Reads (GET):

* ``protected`` — the person's protected items, each with whether it is a file or a folder and
  whether it exists, and how many times an agent was refused on it;
* ``hits`` — the newest refusals (``?limit=``, at most 200);
* ``alerts`` — what a Mac notification may say: changes inside protected items and refusals,
  lock-screen safe (:mod:`.alerts`; ``?limit=``, at most 50);
* ``changes`` — the helper's real-time changes after ``?since=<seq>`` (a companion app follows these);
* ``watch-plan`` — what the system protection helper watches, SIGNED for its nonce (helper_link);
* ``sandbox`` — Layer 2: which agents run inside the OS sandbox, whether their launchers are in
  place, and the GUI editors that can be opened inside it (:mod:`.sandbox`);
* ``permissions`` — the sandbox permissions per agent and project (``sandbox.permissions``), each
  explained where it is edited; ``?agent=&project=`` answers each mode as it is for that scope;
* ``permission-requests`` — what agents asked for and the person has not answered yet.

Writes (POST):

* ``protect`` ``{"path": "~/Documents/Taxes"}`` — adds an item at once (stricter, never asks);
* ``unprotect`` ``{"path": …}`` — removes one: turns protection DOWN, so the core's approvals gate
  holds it for the person (:data:`API` ``weakening``);
* ``file-report`` — the helper's signed real-time changes (:mod:`.changes`), including the
  sandbox's refusals the helper reads from the system log;
* ``open-protected`` ``{"app": "cursor"}`` — relaunches a GUI editor inside the sandbox (stricter,
  never asks);
* ``permission-set`` / ``permission-clear`` / ``folder-set`` / ``folder-clear`` — the sandbox
  permissions; a loosening waits for the person (``sandbox.permissions.API_WEAKENING``), and the
  profiles are brought in step after each write;
* ``permission-answer`` ``{"id", "choice"}`` — Allow once / Always for this agent here (both wait for
  the person) / Keep blocked (at once);
* ``stop-agent`` ``{"instance"}`` — stops a running agent that still has its old sandbox
  permissions (``permissions``' ``restart_needed``), so it restarts with the new ones; the person
  confirms it.

Every write goes through the ONE settings writer (``kernel.settings.write_settings``) with File
Shield's own validator — never a second path into the config.
"""

from __future__ import annotations

import os
from typing import Any, Callable, Mapping

from ...kernel import agent_hosts
from ...kernel.settings import write_settings
from .. import helper_link
from ..shield_api import ShieldApi, ShieldApiError, ShieldContext
from . import alerts, changes, events, mode as mode_module, sandbox
from .sandbox import brokered, packages, permissions
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


def hits(context: ShieldContext, params: Mapping[str, str]) -> dict[str, Any]:
    """``hits``: the newest refusals, each with the agent instance it belongs to (KI-588)."""
    raw = str(params.get("limit") or "")
    limit = min(int(raw), MAX_HITS) if raw.isdigit() else 50
    owner_of = context.finding_owners() if context.finding_owners is not None else None
    return {"hits": events.hits(limit=limit, owner_of=owner_of)}


def alerts_view(_context: ShieldContext, params: Mapping[str, str]) -> dict[str, Any]:
    """``alerts``: what a Mac notification may say (lock-screen safe), newest first (:mod:`.alerts`)."""
    limit = int(params["limit"]) if str(params.get("limit", "")).isdigit() else alerts.MAX_ALERTS
    return {"alerts": alerts.alerts(min(limit, alerts.MAX_ALERTS))}


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
    # The person's items first (the helper names at most 64 paths in its log filter), then the
    # files the sandbox keeps closed for Blackbox, whose refusals are self-protection (KI-581).
    paths = dict.fromkeys(mode_module.watch_paths(current) + sandbox.self_protected_files(current))
    plan: dict[str, Any] = {"watch": current.enabled, "paths": list(paths)}
    agents = sandbox.network_rules()   # Linux: each sandboxed agent's network rules, keyed by its policy's digest
    if agents:
        plan["agents"] = agents
    return helper_link.signed(plan, params)


def file_report(context: ShieldContext, body: Mapping[str, Any]) -> dict[str, Any]:
    helper_link.require_signed_report(context)   # once paired, only this Mac's helper may report
    events_in = body.get("events")
    if not isinstance(events_in, list):
        raise ShieldApiError(400, "a file report carries a list of events")
    current = mode_module.current()
    kept = changes.record(events_in, current, self_protected=sandbox.self_protected_files(current),
                          owner_of_pid=context.owner_of_pid,
                          sandboxed_agents=(lambda: [run.agent for run in context.sandboxed_runs()]) if context.sandboxed_runs else None)
    return {"kept": len(kept)}


def permission_answer(context: ShieldContext, body: Mapping[str, Any]) -> dict[str, Any]:
    """``permission-answer`` ``{"id", "choice"}``: the person's answer (``permissions.answers``)."""
    answered = permissions.answers.answer(body, act=sandbox.act_on)
    _sync_sandbox()
    return {**answered, **permissions.answers.read(context, {})}


def _runs(context: Any) -> list[Any]:
    if context is None or context.sandboxed_runs is None:
        return []
    try:
        return list(context.sandboxed_runs())
    except Exception:   # health: allow BLE001 -- the list is shown without the restart notes
        return []


def permissions_view(context: ShieldContext, params: Mapping[str, str]) -> dict[str, Any]:
    """The sandbox permissions — for one agent and/or project when ``?agent=&project=`` name one —
    and every running agent that still has its old ones (``restart_needed``)."""
    scoped = {key: params.get(key, "") for key in ("agent", "project")} if params else {}
    view = permissions.view(sandbox.chosen(mode_module.current()), scoped)
    why = sandbox.unavailable()
    if why:   # nothing here enforces a permission: say so instead of offering controls (KI-660)
        return permissions.not_here(view, why)
    view["restart_needed"] = [{"agent": run.agent, "name": agent_hosts.product_name(run.agent), "instance": run.instance,
                               "pid": run.pid, "note": sandbox.RESTART_NOTE} for run in sandbox.stale_runs(_runs(context))]
    return view


def _stale(context: Any, body: Mapping[str, Any]) -> Any:
    instance = str(body.get("instance") or "")
    return next((run for run in sandbox.stale_runs(_runs(context)) if run.instance == instance), None)


def stop_agent(context: ShieldContext, body: Mapping[str, Any]) -> dict[str, Any]:
    """``stop-agent`` ``{"instance"}``: stops a running agent that still has its old sandbox
    permissions, so it restarts with the new ones (the person confirms it: :func:`stop_agent_weakens`)."""
    run = _stale(context, body)
    if run is None:
        raise ShieldApiError(404, "No running agent with old sandbox permissions has that id.")
    if not sandbox.stop_run(run):
        raise ShieldApiError(409, "Blackbox could not stop it; quit it yourself.")
    return {"stopped": run.instance}


def stop_agent_weakens(body: Mapping[str, Any]) -> list[str]:
    """Stopping an agent ends the person's work in it: they confirm it (the approval gate)."""
    instance = str(body.get("instance") or "")
    agent = instance.split(":", 1)[0]
    return [f"Stop {agent_hosts.product_name(agent)} now, so it starts again with its new sandbox permissions"] if instance else []


WriteHandler = Callable[[ShieldContext, Mapping[str, Any]], dict[str, Any]]


def _then_sync(write: WriteHandler) -> WriteHandler:
    """*write*, then the profiles brought in step with the new permissions; answers the new view."""
    def handler(context: ShieldContext, body: Mapping[str, Any]) -> dict[str, Any]:
        write(context, body)
        _sync_sandbox()
        return permissions_view(context, {})
    return handler


API = ShieldApi(
    reads={"protected": protected_view, "hits": hits, "alerts": alerts_view, "changes": changes_view, "watch-plan": watch_plan,
           "sandbox": sandbox_view, "permissions": permissions_view,
           "permission-requests": permissions.answers.read, **packages.API_READS, **brokered.API_READS},
    writes={"protect": protect, "unprotect": unprotect, "file-report": file_report, "open-protected": open_protected,
            **packages.API_WRITES, **{name: _then_sync(write) for name, write in permissions.API_WRITES.items()},
            "permission-answer": permission_answer, "stop-agent": stop_agent, **brokered.API_WRITES},
    weakening={"unprotect": unprotect_weakens, **permissions.API_WEAKENING,
               "permission-answer": permissions.answers.weakening, "stop-agent": stop_agent_weakens},
)
