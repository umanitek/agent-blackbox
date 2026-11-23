"""Who asked a broker, and the sandbox permission's answer for them — shared by every brokered
action (open a link, open an app, stop a process, run AppleScript).

The agent and instance come from Blackbox's own attribution of the asking pid
(``ShieldContext.owner_of_pid``), never from the request; the working folder is the client's
(an agent can ``cd`` anywhere, so naming it is no weaker than being there).

Usage::

    asked = Asking.of(context, body)
    decide("open-links", asked, "open https://github.com/login/device")   # raises unless allowed
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from ....shield_api import InstanceRef, ShieldApiError, ShieldContext
from .. import permissions

#: The broker's answer while the person has not answered the request yet: the client asks again.
WAITING = 423
MAX_CWD_CHARS = 1024
logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Asking:
    """The asker of one brokered request: *owner* (None when not known), its working *folder*
    (canonical, "" when not given) and the client's parent *pid* (0 when not given)."""

    owner: Optional[InstanceRef]
    folder: str
    pid: int

    @property
    def agent(self) -> str:
        return self.owner.agent if self.owner is not None else ""

    @property
    def instance(self) -> str:
        return self.owner.instance if self.owner is not None else ""

    @staticmethod
    def of(context: ShieldContext, body: Mapping[str, Any]) -> Asking:
        raw_pid, cwd = body.get("pid"), body.get("cwd")
        pid = raw_pid if isinstance(raw_pid, int) and not isinstance(raw_pid, bool) and raw_pid > 1 else 0
        folder = os.path.realpath(cwd) if isinstance(cwd, str) and cwd.startswith("/") and len(cwd) <= MAX_CWD_CHARS \
            and "\x00" not in cwd else ""
        owner = None
        if pid and context.owner_of_pid is not None:
            try:
                owner = context.owner_of_pid(pid)
            except Exception:   # health: allow BLE001 -- the request is judged as an unknown agent's
                logger.debug("blackbox: the asking agent of a brokered request could not be found", exc_info=True)
        return Asking(owner, folder, pid)


def decide(permission: str, asked: Asking, what: str) -> None:
    """Raises :class:`ShieldApiError` (423 while the person is asked, 403 when refused) unless
    *permission* lets *asked* do *what* now (a once grant is spent here)."""
    decision = permissions.broker_decision(permission, asked.agent, asked.instance, asked.folder, what, asked.pid)
    if decision == permissions.WAITING:
        raise ShieldApiError(WAITING, "Blackbox asked you whether this agent may do this; it happens once you allow it.")
    if decision == permissions.REFUSED:
        name = permissions.BY_ID[permission].name
        raise ShieldApiError(403, f"{name} is blocked for this AI agent in Blackbox's sandbox permissions; do it yourself.")


__all__ = ["WAITING", "Asking", "decide"]
