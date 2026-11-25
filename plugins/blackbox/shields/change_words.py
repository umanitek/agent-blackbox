"""The words the person's approval dialog shows for a shield's settings change (KI-538, E2E full4
2026-11-22: "Turn off gemini-cli in file-shield" showed internal ids). A shield may say it in its
own words (``Shield.describe_change``); otherwise a sentence is built from its name.

Usage::

    describe_change("file-shield", "sandboxed", ["gemini-cli"], added=False)
    # "Take Gemini CLI out of the agent sandbox (File Shield)"
    shield_name("network-shield")   # "Network Shield"
"""

from __future__ import annotations

from typing import Any, Optional


def describe_change(shield_id: str, option: str, values: list[str], added: bool) -> str:
    """The sentence the approval dialog shows for a weakening change of list *option*: the
    shield's own words when it has them, else one built from its name (never internal ids alone)."""
    shield = _shield(shield_id)
    shown = ", ".join(map(str, values[:4]))
    if shield is not None and shield.describe_change is not None:
        return shield.describe_change(option, values, added)
    name = shield.name if shield is not None else shield_id
    label = option.replace("_", " ")
    return f"Allow {shown} ({label}, {name})" if added else f"Remove {shown} from {label} ({name})"


def shield_name(shield_id: str) -> str:
    """The shield's name for a person (its id when it is not registered)."""
    shield = _shield(shield_id)
    return shield.name if shield is not None else shield_id


def _shield(shield_id: str) -> Optional[Any]:
    from .. import shields   # the registry is this package's entry; read when asked (it imports this module)
    return shields.get(shield_id)
