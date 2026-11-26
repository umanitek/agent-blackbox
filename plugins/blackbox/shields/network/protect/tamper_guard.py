"""The DNS tamper guard (opt-in, off by default): while Network Shield's DNS Shield is on, a change
of the Mac's DNS away from Blackbox's resolver is put back at once by the root helper
(``netd/enforce/restore.rs``). Kept in ``<BLACKBOX_HOME>/network-shield/tamper-guard.json``.

**Undo:** switching the guard off stops it; it never keeps anything of its own — DNS Shield's own
restore puts the person's saved DNS servers back when DNS Shield is switched off. With Network
Shield off the plan carries the guard off.
"""

from __future__ import annotations

from typing import Any

from ....kernel import constants
from ....kernel.bounded_files import read_json_object, write_json_object
from ....shields.shield_api import ShieldApiError


def _path() -> Any:
    return constants.blackbox_home() / "network-shield" / "tamper-guard.json"


def is_on() -> bool:
    return bool((read_json_object(_path()) or {}).get("on"))


def set_on(on: Any) -> bool:
    if not isinstance(on, bool):
        raise ShieldApiError(400, "on must be true or false")
    write_json_object(_path(), {"on": on}, what="Network Shield's tamper guard")
    return on


def plan_part(shield_on: bool) -> dict[str, Any]:
    return {"tamper_guard": shield_on and is_on()}
