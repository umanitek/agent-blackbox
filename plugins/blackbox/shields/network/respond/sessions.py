"""The remote-access actions a person takes from the Remote access page (RESPOND) — each one
confirmed in the window first, each carried out through ``network.protect.remote_lock``:

* ``end-session`` ``{"session_id": …}`` — only a session the helper reports as live right now; the
  helper ends it on its next plan, after checking it is still exactly that session;
* ``block-address`` ``{"ip": …, "minutes": 1440}`` / ``unblock-address`` ``{"ip": …}``;
* ``remote-settings`` ``{"lock": bool, "brute_force": {…}}`` — Lock remote access and auto-block.
"""

from __future__ import annotations

from typing import Any, Mapping

from ....shields.shield_api import ShieldApiError
from ..monitor import remote_access
from ..protect import remote_lock


def end_session(body: Mapping[str, Any]) -> dict[str, Any]:
    wanted = str(body.get("session_id") or "")
    session = next((s for s in remote_access.live_sessions() if s["id"] == wanted), None)
    if session is None:
        raise ShieldApiError(404, "That session has already ended.")
    remote_lock.request_end(session)
    return {"requested": True, "session_id": wanted}


def block_address(body: Mapping[str, Any]) -> dict[str, Any]:
    minutes = body.get("minutes", remote_lock.DEFAULT_BLOCK_MINUTES)
    return remote_lock.block(body.get("ip"), minutes)


def unblock_address(body: Mapping[str, Any]) -> dict[str, Any]:
    return remote_lock.unblock(body.get("ip"))


def remote_settings(body: Mapping[str, Any]) -> dict[str, Any]:
    return remote_lock.update(body)
