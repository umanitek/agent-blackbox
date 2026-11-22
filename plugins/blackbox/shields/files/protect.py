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

**Limits, said plainly:** this is Layer 1 (hooks). A script an agent writes is judged by its text
when written and again when run (:mod:`.written`), but a program an agent compiled or downloaded,
or a script that assembles a path from pieces that are not written in it, reads files without
telling a hook what it opens. Only the operating system sees that: an
agent the person puts in the sandbox (Layer 2, :mod:`.sandbox`) is stopped there by the kernel;
any other agent keeps this layer only (docs/file-shield.md).

**Undo:** refuses only while File Shield is on and the item is on the list; it never moves,
deletes or changes a file.
"""

from __future__ import annotations

import os
from typing import Any

from ... import audit
from ...detection import (KIND_FLAG_ONLY, PERSON_PROTECTED, SHELL_TOOLS, Finding, builds_hidden_command, command_from_args,
                           protected_path_mentions, protected_path_touches)
from ...kernel import threat_ids
from ..contract import FindingKind, ShieldMode
from . import mode as mode_module, written

FILE_HIT_ID = "files:file-hit"
FOLDER_HIT_ID = "files:folder-hit"
MENTION_ID = "files:protected-mention"
#: A command beside a protected item that builds what it opens at run time (flagged, with that reason).
UNSEEN_ID = "files:unseen-route"
#: File Shield's own category (the identifier's prefix), classified by the sighting layer.
CATEGORY = "files"
#: What ``matched`` says on a prompt that names a protected item (flags, never blocks).
MENTIONED = "person-protected-mention"
FINDING_KINDS: tuple[FindingKind, ...] = (
    FindingKind("data-exfil", "host-system", "T1005", identifier=FILE_HIT_ID),
    FindingKind("data-exfil", "host-system", "T1005", identifier=FOLDER_HIT_ID),
    FindingKind("data-exfil", "host-system", "T1005", identifier=MENTION_ID),
    FindingKind("data-exfil", "host-system", "T1005", identifier=UNSEEN_ID),
)
#: What each route is called in the finding, for a person.
ROUTES = {"read": "open", "copy": "copy", "write": "change", "name": "use", "tree": "reach (through its folder)",
          "mention": "ask for", "sandbox": "reach from inside the sandbox", "unseen": "run a command it cannot read beside",
          "script": "reach through a script it wrote"}
#: The agent named on a refusal the OS sandbox made (Layer 2): the log names the program, not the agent.
SANDBOX_AGENT = audit.SANDBOX_RECORDER   # not an agent: any sandboxed program (KI-538)


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
    return _script_hit(tool_name, args, items) or _unseen_route(tool_name, args, items)


def _script_hit(tool_name: str, args: Any, items: list[str]) -> list[Finding]:
    """A refusal when this call WRITES a script that names a protected item, or RUNS a script an
    agent wrote that does (:mod:`.written`); each script written is remembered for its run."""
    shell = (tool_name or "").strip().lower() in SHELL_TOOLS
    command = command_from_args(tool_name, args) if shell else ""
    writes = written.script_writes(tool_name, args, command)
    for path, content in writes:
        if (found := _content_hit(content, path, items, "write a script that opens")):
            return found
    for path, _content in writes:
        written.remember(os.path.normpath(os.path.expanduser(path)))
    for path, content in written.scripts_run(command) if shell else ():
        if (found := _content_hit(content, path, items, "run a script that opens")):
            return found
    return []


def _content_hit(content: str, script: str, items: list[str], route: str) -> list[Finding]:
    for touch in protected_path_touches("terminal", written.as_call(script, content), items, whole=True, first_only=True,
                                        every_route=True):
        folder = is_folder(touch.pattern)
        what = "folder" if folder else "file"
        return [Finding(
            identifier=FOLDER_HIT_ID if folder else FILE_HIT_ID, category=CATEGORY, severity="critical",
            title=f"File Shield: an AI agent tried to {route} your protected {what} {touch.pattern}",
            tool_name="terminal", matched=PERSON_PROTECTED,
            evidence=f"script {script} — {touch.path} — protected {what} {touch.pattern}"[:400], confirmed=False, source="custom",
            fields={"path": touch.path[:400], "item": touch.pattern, "route": "script", "kind": what, "script": script[:400]})]
    return []


def _parents(items: list[str]) -> list[str]:
    """The folder each protected item sits in (never the home folder or the disk itself)."""
    home = os.path.expanduser("~").rstrip("/")
    out = []
    for item in items:
        parent = os.path.dirname(os.path.expanduser(item).rstrip("/"))
        if parent and parent not in ("/", home):
            out.append(parent)
    return list(dict.fromkeys(out))


def _unseen_route(tool_name: str, args: Any, items: list[str]) -> list[Finding]:
    """A FLAG (never a refusal) when a shell command names the folder a protected item sits in AND
    builds part of what it runs or opens at run time in a way a hook cannot read (a substitution
    whose output is not fixed, a decode of something that is not written on the line). WHY: those
    forms are beyond Layer 1 (``detection.hidden_commands``); the person is told plainly instead of
    seeing an unexplained "allowed" — the OS sandbox is what stops them."""
    if (tool_name or "").strip().lower() not in SHELL_TOOLS:
        return []
    parents = _parents(items)
    command = command_from_args(tool_name, args)
    if not parents or not builds_hidden_command(command):
        return []
    for touch in protected_path_touches(tool_name, args, parents, whole=True, first_only=True, every_route=True):
        return [Finding(
            identifier=UNSEEN_ID, category=CATEGORY, severity="high", kind=KIND_FLAG_ONLY,
            title=(f"File Shield: an AI agent ran a command beside your protected items in {touch.pattern} that builds what it "
                   "opens while it runs, so a hook cannot see which file it reads"),
            tool_name=touch.tool, matched="person-protected-unseen",
            evidence=f"{touch.mode} {touch.path} — beside protected items in {touch.pattern}"[:400], confirmed=False, source="custom",
            fields={"path": touch.path[:400], "item": touch.pattern, "route": "unseen", "kind": "folder"})]
    return []


def sandbox_hit(item: str, path: str, program: str) -> Finding:
    """The finding for a refusal the OS sandbox made (Layer 2): a program an agent started tried to
    reach *path* inside the protected *item*; the system log names the *program*. Blocked by the
    kernel already — the finding records it, like a hook refusal."""
    folder = is_folder(item)
    what = "folder" if folder else "file"
    return Finding(
        identifier=FOLDER_HIT_ID if folder else FILE_HIT_ID, category=CATEGORY, severity="critical",
        title=f"File Shield: the sandbox stopped {program or 'a program'} reaching your protected {what} {item}",
        tool_name=(program or "program")[:64], matched=PERSON_PROTECTED,
        evidence=f"sandbox {path} — protected {what} {item}"[:400], confirmed=False, source="custom",
        fields={"path": path[:400], "item": item, "route": "sandbox", "kind": what, "program": program[:64]})


def sandbox_self_hit(path: str, program: str) -> Finding:
    """The finding for a refusal the OS sandbox made of a write to a file it keeps closed for
    Blackbox (an agent's hook config, a shell startup file): Blackbox's self-protection, worded as
    that (``kernel.threat_ids.SELF_PROTECTION``) — the kernel already refused (KI-581)."""
    return Finding(
        identifier=threat_ids.fileaccess_identifier("sandbox", threat_ids.SELF_PROTECTION), category="fileaccess",
        severity="critical", title=f"Blackbox's sandbox stopped {program or 'a program'} changing {path}, which keeps Blackbox's hook",
        tool_name=(program or "program")[:64], matched=threat_ids.SELF_PROTECTION,
        evidence=f"sandbox {path} — kept closed for Blackbox"[:400], confirmed=False, source="custom",
        fields={"path": path[:400], "route": "self", "program": program[:64]})


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
