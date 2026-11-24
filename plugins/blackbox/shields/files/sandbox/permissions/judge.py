"""Which change of the sandbox permissions turns protection DOWN — and so waits for the person.

A change loosens when, at any scope either side names (and everywhere), a permission's effective
mode moves up (block → ask → allow), local-ports gains a reachable port, or a folder rule is
removed or widened (none → read). Clearing a "block" rule is a loosening when the mode it falls
back to is higher. A current setting that can not be read counts as the most protective one, so
any change of it is held. The reasons are built here from the catalogue, never from the caller's
words.

Registered as ``approvals.SECTION_JUDGES["agent_sandbox"]`` (so ``/api/settings`` can not go
round it) and used by the permission endpoints' weakening judges.

Usage::

    loosened(before, after)   # ["Let Claude Code in ~/work/shop use Docker (without asking; was: ask)"]
"""

from __future__ import annotations

from typing import Optional

from .....kernel.agent_hosts import product_name
from .catalogue import PERMISSIONS, THIS_MACHINE
from .model import Access, Mode, Scope, Settings

#: Said for any change while the current setting can not be read.
UNREADABLE = "Change the agent sandbox's permissions (the current setting could not be read, so Blackbox asks)"


def _points(*settings: Settings) -> list[Scope]:
    """Every scope the settings name, and everywhere."""
    scopes = [Scope()] + [rule.scope for each in settings for rule in each.rules] \
        + [folder.scope for each in settings for folder in each.folders]
    return list(dict.fromkeys(scopes))


def _folder_of(scope: Scope) -> str:
    return scope.project_path() or "/"


def loosened(before: Optional[Settings], after: Settings) -> list[str]:
    """Why going from *before* to *after* turns protection down (``[]`` when it does not)."""
    if before is None:
        return [UNREADABLE]
    reasons: list[str] = []
    for scope in _points(before, after):
        folder = _folder_of(scope)
        for permission in PERMISSIONS:
            was, now = before.mode(permission, scope.agent, folder), after.mode(permission, scope.agent, folder)
            if now.rank > was.rank:
                reasons.append(f"Let {scope.words(product_name)} use {permission.name} "
                               f"({'ask you each time' if now is Mode.ASK else 'without asking'}; was: {was.value})")
            elif permission.ports and now is Mode.BLOCK:
                added = set(after.ports(permission.id, scope.agent, folder)) - set(before.ports(permission.id, scope.agent, folder))
                if added:
                    reasons.append(f"Let {scope.words(product_name)} reach port{'s' if len(added) > 1 else ''} "
                                   f"{', '.join(map(str, sorted(added)))} on {THIS_MACHINE}")
    kept = {(each.path, each.scope): each.access for each in after.folders}
    for each in before.folders:
        access = kept.get((each.path, each.scope))
        if access is None:
            reasons.append(f"Stop keeping {each.path} from {each.scope.words(product_name)}")
        elif each.access is Access.NONE and access is Access.READ:
            reasons.append(f"Let {each.scope.words(product_name)} read {each.path}")
    return list(dict.fromkeys(reasons))


__all__ = ["UNREADABLE", "loosened"]
