"""Which settings and command-line flags make a coding agent act WITHOUT asking its person.

Each agent has a mode that skips its permission prompts: Claude Code's ``acceptEdits`` /
``bypassPermissions`` (``--dangerously-skip-permissions``), Codex's ``--full-auto`` and
``--yolo`` (``approval_policy = "never"``, ``sandbox_mode = "danger-full-access"``), Gemini CLI's
``--yolo`` / ``--approval-mode auto_edit``, Copilot CLI's ``--allow-all-tools``. Blackbox still
judges every action its hooks see — but a person who would have been asked is not, so a profile
running that way carries a risk note. This module is data plus two readers; it decides nothing.

Usage::

    from . import permission_risks
    permission_risks.from_settings("claude-code", settings_dict)   # ["permissions.defaultMode = bypassPermissions"]
    permission_risks.from_command("codex", ["codex", "--full-auto"])  # ["--full-auto"]
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

__all__ = ["FLAGS", "SETTINGS", "from_command", "from_settings"]

#: Per agent: ``(dotted settings key, the values that skip prompts)``.
SETTINGS: dict[str, tuple[tuple[str, frozenset[str]], ...]] = {
    "claude-code": (("permissions.defaultMode", frozenset({"acceptEdits", "bypassPermissions"})),),
    "codex": (("approval_policy", frozenset({"never"})), ("sandbox_mode", frozenset({"danger-full-access"}))),
    "gemini-cli": (("general.defaultApprovalMode", frozenset({"auto_edit", "yolo"})),),
}

#: Per agent: a flag that skips prompts by itself (value ``None``), or a flag whose VALUE does
#: (the values that skip).
FLAGS: dict[str, dict[str, frozenset[str] | None]] = {
    "claude-code": {"--dangerously-skip-permissions": None, "--permission-mode": frozenset({"acceptEdits", "bypassPermissions"})},
    "codex": {"--full-auto": None, "--yolo": None, "--dangerously-bypass-approvals-and-sandbox": None,
              "--ask-for-approval": frozenset({"never"}), "-a": frozenset({"never"}),
              "--sandbox": frozenset({"danger-full-access"}), "-s": frozenset({"danger-full-access"})},
    "gemini-cli": {"--yolo": None, "-y": None, "--approval-mode": frozenset({"yolo", "auto_edit"})},
    "copilot-cli": {"--allow-all-tools": None, "--allow-all": None, "--yolo": None},
}


def _lookup(data: Any, dotted: str) -> Any:
    for part in dotted.split("."):
        data = data.get(part) if isinstance(data, Mapping) else None
    return data


def from_settings(agent: str, data: Mapping[str, Any]) -> list[str]:
    """Each setting in *data* (one settings file of *agent*) that skips its prompts, as
    ``key = value``."""
    return [f"{key} = {value}" for key, values in SETTINGS.get(agent, ())
            if isinstance(value := _lookup(data, key), str) and value in values]


def from_command(agent: str, words: Sequence[str]) -> list[str]:
    """Each flag on *agent*'s command line (*words*: its arguments) that skips its prompts, as
    written (``--yolo``, ``--permission-mode bypassPermissions``)."""
    flags, found = FLAGS.get(agent, {}), []
    for position, word in enumerate(words):
        name, _, inline = word.partition("=")
        if name not in flags:
            continue
        values = flags[name]
        if values is None:
            found.append(name)
            continue
        value = inline or (words[position + 1] if position + 1 < len(words) else "")
        if value in values:
            found.append(f"{name} {value}")
    return found
