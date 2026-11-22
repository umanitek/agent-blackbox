"""File Shield — the third shield: files and folders the person protects from every AI agent,
and the folders where new files arrive, watched in real time. The core of it lives here;
Blackbox Desktop adds file fingerprints and reputation through :mod:`..extensions`.

Founder direction (Amos, 2026-11-21): an active defence, not a reactive watcher. An item the
person protects can not be touched by ANY AI agent by ANY route, in Audit mode as well as Block
mode; every attempt is recorded and shown; protect on demand; unprotecting asks the person first.

* :mod:`.protect` — inside Blackbox's guard: the refusal (``files:file-hit`` / ``files:folder-hit``)
  and the prompt flag (``files:protected-mention``);
* :mod:`.changes` — the system protection helper's real-time changes (FSEvents), signed;
* :mod:`.watched` — what a watched folder's scan found (new and known-bad files), reported by
  Blackbox Desktop's add-on and worded here as alerts;
* :mod:`.sandbox` — Layer 2: the coding agents the person picks run inside the OS sandbox built
  from the list (launchers first on PATH; Cursor/Windsurf opened inside it on request);
* :mod:`.events` / :mod:`.status` — the events report and the card;
* :mod:`.api` — its endpoints (``/api/shields/file-shield/api/<name>``);
* :mod:`.mode` — its setting, ``shields.file-shield``.

How far it reaches, and what it cannot see: ``docs/file-shield.md``.

Usage::

    from plugins.blackbox import shields
    files = shields.get("file-shield")
    files.detect("terminal", {"command": "cat ~/Documents/Taxes/2025.pdf"}, files.mode())
"""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any, Mapping

from ...kernel import agent_hosts
from ..contract import Capability, Shield, ShieldMode
from . import alerts, api, changes, events, mode, protect, sandbox, status, watched

#: What another package (Blackbox Desktop's add-on) may use: the shield, its mode (watched folders,
#: protected items), its real-time changes, its events and :mod:`.watched` (where a watched
#: folder's scan reports what it found — File Shield words the notification).
__all__ = ["CAPABILITIES", "FILES", "FINDING_KINDS", "changes", "events", "mode", "protect", "sandbox", "watched"]

HERE = Path(__file__).resolve().parent
FINDING_KINDS = protect.FINDING_KINDS
_CLAIMED = tuple(kind.identifier for kind in FINDING_KINDS)

#: What File Shield protects inside Blackbox's guard — each proven by a row of its attack table
#: driven through the real hook (tests/plugins/test_blackbox_shields_files.py).
CAPABILITIES: tuple[Capability, ...] = (
    Capability("protected-items", "Your protected files and folders",
               "no AI agent opens, copies, lists, changes, moves or deletes them — in any mode; a prompt naming one is flagged",
               claims=(protect.FILE_HIT_ID, protect.FOLDER_HIT_ID)),
)


def _current_mode() -> ShieldMode:
    # Looked up on every call, not bound once: a test stands a mode in by patching mode.current.
    return mode.current()


def claims(finding: Mapping[str, Any]) -> bool:
    """True for the findings File Shield raises."""
    identifier = str(finding.get("identifier") or "")
    return any(fnmatch.fnmatchcase(identifier, pattern) for pattern in _CLAIMED)


def allows(_finding: Mapping[str, Any], current: ShieldMode) -> bool:
    """A File Shield finding counts only while the shield is on."""
    return current.enabled


def describe_change(option: str, values: list[str], added: bool) -> str:
    """The approval dialog's sentence for a File Shield list change that turns protection down."""
    if option == mode.OPT_SANDBOXED:
        names = ", ".join(agent_hosts.BY_ID[value].name if value in agent_hosts.BY_ID else value for value in values[:4])
        return f"Take {names} out of the agent sandbox (File Shield)"
    shown = ", ".join(values[:4])
    if option == mode.OPT_PROTECTED:
        return f"Stop protecting {shown} (File Shield)"
    if option == mode.OPT_FOLDERS:
        return f"Stop watching {shown} for new files (File Shield)"
    return f"{'Allow' if added else 'Remove'} {shown} ({option}, File Shield)"


FILES = Shield(
    id=mode.SHIELD_ID, name="File Shield",
    tagline="Keep every AI agent away from the files and folders you protect — and see new files arrive.",
    beta=True, mode=_current_mode, validate=mode.validate, detect=protect.detect,
    claims=claims, allows=allows, status=status.build, events=events.report, settings_fields=mode.fields,
    finding_kinds=FINDING_KINDS, capabilities=CAPABILITIES, packs=HERE / "packs",
    page=HERE / "page" / "files.html", attacks=HERE / "attacks.json", api=api.API,
    prompt_check=protect.prompt_check, describe_change=describe_change, alerts=alerts.shield_alerts,
)
