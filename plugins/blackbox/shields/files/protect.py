"""File Shield inside Blackbox's guard: no AI agent touches an item the person protected.

Every AI-agent tool call already passes through ``shields.check`` — the Hermes agent's hook,
every coding agent's hook (``agent_hooks`` → ``guard.tool_call_verdict``), the OpenClaw bridge
(it asks the same verdict) and Blackbox's own assistant (a Hermes profile). This detector asks the
ONE protected-path answer (``detection.protected_path_touches``, canonical paths — LES-105) with
``every_route``: reading, copying, archiving, writing, deleting, moving, listing, a ``cd`` into
it, a whole-tree command on a folder that holds it, code that opens it, an MCP tool's path or
command argument. A hit is a critical finding whose ``matched`` is ``detection.PERSON_PROTECTED``:
refused in EVERY mode, Audit included — the person's own explicit rule, like Blackbox's
self-protection.

Findings (local-only, like every shield's — never reported to the community graph; no file
contents, ever): ``files:file-hit`` for a protected file, ``files:folder-hit`` for a protected
folder (or a file inside it). A prompt that NAMES a protected item is ``files:protected-mention``
(high, flagged, never blocking): naming is not touching, and no prompt text is kept.

**Limits, said plainly:** this is Layer 1 (hooks). A program an agent wrote or downloaded and then
runs reads files without telling a hook what it opens. Only the operating system sees that (an
OS sandbox around each agent, or the OS's own file checks); Blackbox uses neither today
(docs/file-shield.md).

**Undo:** refuses only while File Shield is on and the item is on the list; it never moves,
deletes or changes a file.
"""

from __future__ import annotations

import os
from typing import Any

from ...detection import PERSON_PROTECTED, Finding, protected_path_mentions, protected_path_touches
from ..contract import FindingKind, ShieldMode
from . import mode as mode_module

FILE_HIT_ID = "files:file-hit"
FOLDER_HIT_ID = "files:folder-hit"
MENTION_ID = "files:protected-mention"
#: File Shield's own category (the identifier's prefix), classified by the sighting layer.
CATEGORY = "files"
#: What ``matched`` says on a prompt that names a protected item (flags, never blocks).
MENTIONED = "person-protected-mention"
FINDING_KINDS: tuple[FindingKind, ...] = (
    FindingKind("data-exfil", "host-system", "T1005", identifier=FILE_HIT_ID),
    FindingKind("data-exfil", "host-system", "T1005", identifier=FOLDER_HIT_ID),
    FindingKind("data-exfil", "host-system", "T1005", identifier=MENTION_ID),
)
#: What each route is called in the finding, for a person.
ROUTES = {"read": "open", "copy": "copy", "write": "change", "name": "use", "tree": "reach (through its folder)",
          "mention": "ask for"}


def is_folder(item: str) -> bool:
    """True when the protected *item* is a folder: one on disk, or — not there (yet) — a name
    without a file ending (``~/Documents/Taxes`` is a folder, ``~/notes.txt`` a file)."""
    path = os.path.expanduser(item)
    if os.path.lexists(path):
        return os.path.isdir(path)
    return not os.path.splitext(os.path.basename(path.rstrip("/")))[1]


def detect(tool_name: str, args: Any, mode: ShieldMode) -> list[Finding]:
    """One finding when this tool call touches a protected item (none while the shield is off)."""
    items = mode_module.protected(mode)
    if not items:
        return []
    for touch in protected_path_touches(tool_name, args, items, whole=True, first_only=True, every_route=True):
        folder = is_folder(touch.pattern)
        what = "folder" if folder else "file"
        return [Finding(
            identifier=FOLDER_HIT_ID if folder else FILE_HIT_ID, category=CATEGORY, severity="critical",
            title=f"File Shield: an AI agent tried to {ROUTES.get(touch.mode, 'use')} your protected {what} {touch.pattern}",
            tool_name=touch.tool, matched=PERSON_PROTECTED,
            evidence=f"{touch.mode} {touch.path} — protected {what} {touch.pattern}"[:400],
            confirmed=False, source="custom",
            fields={"path": touch.path[:400], "item": touch.pattern, "route": touch.mode, "kind": what})]
    return []


def prompt_check(text: str, mode: ShieldMode) -> list[Finding]:
    """A flag for each protected item a prompt names (none while off). The prompt is never kept:
    the finding names the item, which is the person's own list."""
    items = mode_module.protected(mode)
    found = protected_path_mentions(text, items) if items else []
    seen = dict.fromkeys(touch.pattern for touch in found)
    return [Finding(identifier=MENTION_ID, category=CATEGORY, severity="high",
                    title=f"File Shield: a prompt asks an AI agent for your protected item {item}",
                    tool_name="prompt", matched=MENTIONED, evidence=f"a prompt names protected item {item}"[:400],
                    confirmed=False, source="custom", fields={"item": item, "route": "mention"})
            for item in seen]
