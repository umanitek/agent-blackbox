"""The agent sandbox by default: every agent found here is picked, unless the person took it out.

Founder direction (2026-11-22): until the OS's own file checks exist (Layer 3, Endpoint Security),
every agent runs inside Blackbox's sandbox by default, with a setting to turn it off per agent.
On install, upgrade and attach (``blackbox attach`` — the installer runs it on both), :func:`apply`
puts every agent detected on this machine into ``shields.file-shield.sandboxed`` and engages File
Shield when it was never set (the sandbox works only while it is on; a File Shield the person
turned off stays off, and nothing is picked). An agent the person took out of the sandbox is in
``sandbox_declined`` (``mode.declined_after``: kept by every settings write) and is NEVER picked
again: their choice is kept, never overridden. Taking one out stays a weakening change (the
approval dialog in a companion app, or the person's password).

ON BY DEFAULT (founder decision, 2026-11-23, after security round 5): both blockers round 4 named
are proven fixed with real agents — the places something starts from by itself are closed inside
the sandbox, and the root helper idles at ~1 % CPU. :data:`SANDBOX_DEFAULT` is ``"on"``.

Adding agents only protects more, so it is written without approval (the settings writer, with
File Shield's validator); then the profile and launchers are brought in step (``sync``).

Usage::

    apply()                        # the agents it picked now ([] when nothing new)
    picks(mode, ("claude-code",))  # what apply would store, without writing
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional, Sequence

from ....kernel import agent_hosts
from ....kernel.settings import write_settings
from ...contract import ShieldMode
from .. import mode as mode_module
from . import platform

#: On by default (founder, 2026-11-23, after security round 5).
SANDBOX_DEFAULT = "on"
logger = logging.getLogger(__name__)


def detected(home: Optional[Path] = None) -> tuple[str, ...]:
    """The agents the sandbox can start that are installed here (the Hermes agent always is)."""
    home = home or Path.home()
    return tuple(host.id for host in mode_module.sandboxable()
                 if host.id == agent_hosts.HERMES_ID or agent_hosts.BY_ID[host.id].installed(home))


def picks(mode: ShieldMode, agents: Sequence[str]) -> list[str]:
    """``sandboxed`` after the default: what is there now, plus every agent in *agents* the person
    has not taken out (``sandbox_declined``)."""
    declined = set(mode.options.get(mode_module.OPT_DECLINED, ()))
    now = list(mode.options.get(mode_module.OPT_SANDBOXED, ()))
    return list(dict.fromkeys([*now, *(agent for agent in agents if agent not in declined)]))


def _ever_set() -> bool:
    """True when File Shield's section was ever written (the person, or an earlier default, chose)."""
    from ....kernel.config import shield_entry
    shields = shield_entry().get("shields")
    return isinstance(shields, dict) and mode_module.SHIELD_ID in shields


def apply(default: str = SANDBOX_DEFAULT, home: Optional[Path] = None) -> list[str]:
    """Picks every detected agent for the sandbox (and engages File Shield) when *default* is
    ``"on"`` and this OS can sandbox agents; answers the agents added now. Fail-open: logged,
    never raised — an install or attach never fails on it."""
    if default != "on" or platform.unavailable() is not None:
        return []
    try:
        current = mode_module.current()
        if not current.enabled and _ever_set():
            return []   # the person turned File Shield off: their choice
        chosen = picks(current, detected(home))
        added = [agent for agent in chosen if agent not in current.options.get(mode_module.OPT_SANDBOXED, ())]
        if not added and current.enabled:
            return []
        result = write_settings({"shields": {mode_module.SHIELD_ID: {"enabled": True, mode_module.OPT_SANDBOXED: chosen}}},
                                validators=(mode_module.validate,))
        if not result.get("ok"):
            return []
        from .. import sandbox   # lazy: the facade imports this module
        sandbox.sync()           # the profile and launchers in step with the new choice
        return added
    except Exception:   # health: allow BLE001 -- the default never breaks an install; the reason is logged
        logger.warning("blackbox: the agent sandbox default could not be applied", exc_info=True)
        return []
