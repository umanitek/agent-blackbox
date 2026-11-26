"""The person's folder rules inside Blackbox's guard: the hook layer refuses what the sandbox refuses (F9).

A folder rule (Sandbox permissions on File Shield's page) keeps a folder OUT of an agent's reach
or makes it READ ONLY, everywhere or for one agent, one project or both. The sandbox profile
renders them for an agent started inside it; an agent on hooks only (not picked for the sandbox,
or an OS without one) is judged here, on every tool call, from the SAME answer —
``sandbox.permissions.folder_limits`` for the acting agent in the folder it works in
(``kernel.action_context``, set by the guard's caller) — so the two layers can not drift (LES-137).

* kept out: any touch at all is refused — reading, listing, a ``cd``, writing, a whole-tree
  command on a folder above it (the protected-items answer, ``every_route``);
* read only: only a change is refused — a write, a delete, a move, a new file, a re-permission
  there, or a whole-tree change of a folder above it (``changes``); reading stays allowed.

A hit is ``files:folder-hit`` with ``matched`` ``detection.PERSON_PROTECTED``: refused in every
mode, Audit included, like a protected item — the person's own explicit rule. Local-only.

**Limits, said plainly:** this is Layer 1, the hook: it judges what a call names. A program that
opens a path it builds at run time is stopped only by the sandbox (docs/file-shield.md).

Usage::

    with action_context.working_in("/Users/me/shop", agent="claude-code"):
        folder_rules.detect("terminal", {"command": "cat ~/Taxes/2025.pdf"})   # [Finding] when kept out
"""

from __future__ import annotations

from typing import Any

from ...detection import PERSON_PROTECTED, Finding, protected_path_touches
from ...kernel import action_context
from .protect import CATEGORY, FOLDER_HIT_ID, ROUTES
from .sandbox import permissions

#: How each rule is named in a finding, for a person.
KEPT_OUT, READ_ONLY = "kept out", "read only"


def detect(tool_name: str, args: Any) -> list[Finding]:
    """One finding when this call reaches a folder a rule keeps from the acting agent (none without rules)."""
    limits = permissions.folder_limits(permissions.current(), action_context.acting_agent(), action_context.working_folder())
    checks = ((limits.hidden, KEPT_OUT, {"every_route": True}), (limits.read_only, READ_ONLY, {"changes": True}))
    for folders, rule, how in checks:
        if not folders:
            continue
        for touch in protected_path_touches(tool_name, args, list(folders), whole=True, first_only=True, **how):
            verb = ROUTES.get(touch.mode, "use") if rule == KEPT_OUT else "change"
            return [Finding(
                identifier=FOLDER_HIT_ID, category=CATEGORY, severity="critical",
                title=f"File Shield: an AI agent tried to {verb} {touch.path} in {touch.pattern}, which your folder rule keeps {rule}",
                tool_name=touch.tool, matched=PERSON_PROTECTED,
                evidence=f"{touch.mode} {touch.path} — folder rule: {touch.pattern} {rule}"[:400], confirmed=False,
                source="custom", fields={"path": touch.path[:400], "item": touch.pattern, "route": touch.mode,
                                         "kind": "folder", "rule": rule})]
    return []


__all__ = ["KEPT_OUT", "READ_ONLY", "detect"]
