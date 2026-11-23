"""The person's answer to a permission request (``permission-requests`` / ``permission-answer``).

* **Allow once** — a broker's permission: a single-use grant bound to the exact request
  (:mod:`.grants`, 120 s); a profile's permission: a one-launch profile the agent's launcher takes
  at its next start (the Hermes agent: its next command), handed to *once_profile* (the facade's
  ``grant_once``, so this package never imports the facade);
* **Always for this agent here** (F3) — a rule: this permission allowed for this agent in this
  project, written like any other rule;
* **Keep blocked** — nothing changes; the same instance is not asked again for a while.

Allow once and Always turn protection up for the agent, so the approval gate holds them (428)
until the person confirms in the companion app (its signed answer) or with their password; Keep
blocked is applied at once. The dialog's words are built here from the stored request and the
catalogue; the agent's own words appear only as the quoted ``what``, at most 200 characters.
AppleScript is offered "once" and "keep blocked" only (F5).

Usage::

    answer({"id": "…", "choice": "once"}, once_profile=sandbox.grant_once)
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Mapping

from ..... import audit
from .....kernel.agent_hosts import product_name
from .....kernel.settings import write_settings
from ....shield_api import ShieldApiError
from . import grants, requests
from .catalogue import BY_ID
from .model import Choice, Mode, OnceGrant, PermissionRequest, Route, Rule, Scope, Settings
from .section import SECTION, as_section, current

logger = logging.getLogger(__name__)
OnceProfile = Callable[[PermissionRequest], None]


def choices(request: PermissionRequest) -> list[str]:
    """The answers offered for *request* (AppleScript: never "always", F5)."""
    allowed = Mode.ALLOW in BY_ID[request.permission].modes
    return [Choice.ONCE.value] + ([Choice.ALWAYS.value] if allowed else []) + [Choice.KEEP_BLOCKED.value]


def row(request: PermissionRequest) -> dict[str, Any]:
    """One request as the ``permission-requests`` read shows it."""
    permission = BY_ID[request.permission]
    return {"id": request.id, "permission": request.permission, "name": permission.name, "cost": permission.cost,
            "agent": request.agent, "agent_name": product_name(request.agent), "instance": request.instance,
            "project": request.project, "what": request.what, "created": request.created, "choices": choices(request),
            "text": f"{product_name(request.agent)}{' in ' + request.project if request.project else ''} wants to use {permission.name}."}


def _request(body: Mapping[str, Any]) -> tuple[PermissionRequest, Choice]:
    request = requests.get(str(body.get("id") or ""))
    if request is None:
        raise ShieldApiError(404, "no such request (it was answered or it expired)")
    choice = next((each for each in Choice if each.value == body.get("choice")), None)
    if choice is None or choice.value not in choices(request):
        raise ShieldApiError(400, f"answer with one of: {', '.join(choices(request))}")
    return request, choice


def weakening(body: Mapping[str, Any]) -> list[str]:
    """Allow once / Always wait for the person; the words come from the request and the catalogue."""
    try:
        request, choice = _request(body)
    except ShieldApiError:
        return []
    if choice is Choice.KEEP_BLOCKED:
        return []
    who = product_name(request.agent) + (f" in {request.project}" if request.project else "")
    how = "once" if choice is Choice.ONCE else "from now on"
    quoted = f' ("{request.what}")' if request.what else ""
    return [f"Let {who} use {BY_ID[request.permission].name} {how}{quoted}"]


def answer(body: Mapping[str, Any], once_profile: OnceProfile) -> dict[str, Any]:
    """Applies the person's answer (see the module doc); answers ``{"answered": id, "choice": …}``."""
    request, choice = _request(body)
    if choice is Choice.ALWAYS:
        scope = Scope(agent=request.agent, project=request.project)
        now = current()
        kept = tuple(each for each in now.rules if (each.permission, each.scope) != (request.permission, scope))
        result = write_settings({SECTION: as_section(Settings(kept + (Rule(request.permission, Mode.ALLOW, scope),), now.folders))})
        if not result.get("ok"):
            raise ShieldApiError(400, "; ".join(result.get("errors") or ["the permission could not be saved"]))
    elif choice is Choice.ONCE:
        if BY_ID[request.permission].route is Route.BROKER:
            grants.grant(OnceGrant(request.permission, Scope(agent=request.agent, project=request.project), request.digest,
                                   time.time() + grants.ONCE_SECONDS))
        else:
            once_profile(request)
    else:
        requests.keep_blocked(request)
    requests.take(request.id)
    _audit(request, choice)
    return {"answered": request.id, "choice": choice.value}


def _audit(request: PermissionRequest, choice: Choice) -> None:
    try:
        audit.record_for(audit.SANDBOX_RECORDER, event="permission_answered", workspace=request.project,
                         detail={"permission": request.permission, "agent": request.agent, "session_id": request.instance,
                                 "choice": choice.value})
    except Exception:   # health: allow BLE001 -- the answer is applied; a failed record is logged
        logger.warning("blackbox: a permission answer was not recorded", exc_info=True)


def requested(request: PermissionRequest) -> None:
    """The audit row of a new request (``permission_requested``)."""
    try:
        audit.record_for(audit.SANDBOX_RECORDER, event="permission_requested", workspace=request.project,
                         detail={"permission": request.permission, "agent": request.agent, "session_id": request.instance})
    except Exception:   # health: allow BLE001 -- the request stands; a failed record is logged
        logger.warning("blackbox: a permission request was not recorded", exc_info=True)


def read(_context: Any, _params: Mapping[str, str]) -> dict[str, Any]:
    return {"requests": [row(each) for each in requests.pending()]}


__all__ = ["OnceProfile", "answer", "choices", "read", "requested", "row", "weakening"]
