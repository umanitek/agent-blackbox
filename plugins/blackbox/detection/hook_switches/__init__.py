"""An agent may not switch off an agent's hooks — its own or another's, user-level or in any
project — by any route, in ANY mode.

Private security finding ``2026-11-25-hooks-only-an-agent-may-write-a-project-`` (macOS round R8,
High): a hooks-only agent wrote ``{"disableAllHooks": true}`` into a project's (and a sibling
project's) ``.claude/settings.json`` and ``settings.local.json``, ``codex_hooks = false`` into a
project ``.codex/config.toml`` and Gemini CLI's hooks switch into ``.gemini/settings.json``: all
allowed. A Claude Code session started there later ran with no hook at all — a protected file was
read, and Blackbox recorded no session.

The files and their switches are the ONE list in ``kernel.agent_hosts.hook_switches`` (the agent
sandbox and the hook watch read it too). A call is judged by the SAME reading self-protection uses
(:func:`.paths.guard_settings.tampering`: every shell route — redirects, ``tee``, copies, moves,
``sed -i``, nested shells, base64, heredocs —, code, file tools and Codex's ``apply_patch``), run
against those files (``guard_places.HOOKS``); then only a change that switches hooks OFF is refused:

* a file tool's write is judged on the file it LEAVES — the write applied to the file as it is
  now, parsed (JSON, or TOML for a ``.toml``): refused when a switch is OFF afterwards and was not
  before. A permission rule, a model, the person's own hooks stay the agent's to edit; a switch the
  person had already set stays theirs;
* a command, code, a patch or a script that writes such a file is refused when its text — or a
  file it copies onto it — spells a switch set OFF (``disableAllHooks: true``,
  ``codex_hooks = false``, ``hooksConfig … enabled: false``);
* a script file a shell call RUNS is judged by its text with its arguments
  (:func:`.script_files.judge_runs`, the one script judgement).

What stays open (:data:`KNOWN_LIMITS`) is why the back-stop exists: an agent process that runs
with no Blackbox session is a HIGH finding naming the agent and its folder (``agent_hooks.tracking``).

``source="custom"`` and ``matched`` is self-protection's (``kernel.threat_ids.SELF_PROTECTION``):
refused in every mode and counted as tamper.

Usage::

    detect_hook_switch_off("write_file", {"path": "/w/app/.claude/settings.json", "content": '{"disableAllHooks": true}'})
    # -> [Finding(identifier="fileaccess:write_file:blackbox-settings", ...)]
    detect_hook_switch_off("write_file", {"path": "/w/app/.claude/settings.json", "content": '{"model": "opus"}'})   # -> []
"""

from __future__ import annotations

import json
import os
import re
import tomllib
from typing import Any, Optional

from .. import action_parsing, script_files, shell_shapes
from ..finding import Finding
from ...kernel import action_context, threat_ids
from ...kernel.agent_hosts import hook_switches, product_name
from ...kernel.bounded_files import read_small_text
from ..paths import guard_places, guard_settings, guard_startup, shell_files

MATCHED = threat_ids.SELF_PROTECTION
TITLE = "Would switch off an agent's hooks"
ADVICE = ("An AI agent may not turn off the hooks Blackbox protects agents through — in its own settings, another agent's "
          "or any project's: the next session there would run unseen. If you meant it, change the setting yourself.")
KNOWN_LIMITS = (
    "a script that builds the switch's name at run time from pieces (the kernel sandbox closes the user-level files; "
    "a session started with its hooks off is reported)",
)
_MAX_FILE_BYTES = 256 * 1024
#: The most files a command copies from that are read to see what they would put in place.
_MAX_SOURCES = 8
#: Python's and JavaScript's spellings of the OFF values beside JSON's and TOML's.
_SPELLED = {True: r"(?:true|True|1)\b", False: r"(?:false|False|0)\b"}
#: Between a key and its value: quotes, ``:`` / ``=``, spaces, escaped quotes.
_GAP = r"""[\s"'\\:=]{0,12}"""


def _switch_spelling() -> re.Pattern[str]:
    """ONE expression that finds any switch of the list set OFF in text: the switch's last key
    word next to its OFF value, after its parent's word when the last word alone is common
    (``hooksConfig … enabled: false``, ``[features] … hooks = false``)."""
    forms = []
    for key, off in dict.fromkeys(pair for entry in hook_switches.switch_files() for pair in entry.switches):
        *parents, last = key.split(".")
        value = _SPELLED.get(off) if isinstance(off, bool) else re.escape(json.dumps(off))
        near = rf"\b{re.escape(last)}{_GAP}{value}"
        forms.append(near if not parents or "_" in last or len(last) >= 10
                     else rf"\b{re.escape(parents[-1])}\b[^\n]{{0,8}}(?:[^}}]{{0,400}}?){near}")
    return re.compile("|".join(forms), re.DOTALL)


_SWITCH_OFF = _switch_spelling()


def _parsed(path: str, text: str) -> Optional[object]:
    try:
        return tomllib.loads(text) if path.endswith(".toml") else json.loads(text or "{}")
    except (ValueError, tomllib.TOMLDecodeError, RecursionError):
        return None


def _after_write(path: str, args: dict[str, Any], current: str) -> Optional[str]:
    """The file a file tool's write LEAVES: its whole content, or its edits applied to *current*;
    None when the shape can not be applied here (a patch, an old text not in the file)."""
    # An edit first: a host's canonical form of an edit also carries its new text as "content".
    edits = isinstance(args.get("edits"), list) or any(isinstance(args.get(key), str) for key in guard_startup.OLD_KEYS)
    for key in () if edits else ("content", "text", "file_text"):
        if isinstance(args.get(key), str):
            return args[key]
    pairs = guard_startup._edit_pairs(args)
    if pairs is None:
        return None
    result = current
    for old, new, every in pairs:
        if old not in result:
            return None
        result = result.replace(old, new) if every else result.replace(old, new, 1)
    return result


def _file_write_turns_off(path: str, args: Any) -> str:
    """The switch a file tool's write of switch file *path* turns OFF ("" = none)."""
    entries = hook_switches.matching(path)
    current = read_small_text(path, _MAX_FILE_BYTES) or ""
    after = _after_write(path, args, current) if isinstance(args, dict) else None
    if after is None:
        written = guard_settings._written_text(args)
        return "a switch set off" if _SWITCH_OFF.search(written) and not _SWITCH_OFF.search(current) else ""
    before_data, after_data = _parsed(path, current), _parsed(path, after)
    if after_data is None:   # not parsable (yet): its text
        return "a switch set off" if _SWITCH_OFF.search(after) and not _SWITCH_OFF.search(current) else ""
    found = hook_switches.turned_off(entries, after_data)
    return found if found and not hook_switches.turned_off(entries, before_data) else ""


def _copied_texts(command: str) -> list[str]:
    """The text of the files *command* copies or moves from (the first few that are small files)."""
    folder = action_context.working_folder()
    out = []
    for arg in shell_files.shell_file_args(command)[:_MAX_SOURCES * 4]:
        if arg.destination:
            continue
        path = os.path.expanduser(arg.path)
        path = path if os.path.isabs(path) or not folder else os.path.join(folder, path)
        text = read_small_text(path, _MAX_FILE_BYTES) if os.path.isfile(path) else None
        if text:
            out.append(text)
        if len(out) >= _MAX_SOURCES:
            break
    return out


def _call_text(tool: str, args: Any) -> str:
    if tool in shell_shapes.SHELL_TOOLS:
        return shell_shapes.whole_command_from_args(tool, args)
    return guard_settings._written_text(args) or (str(args.get("code")) if isinstance(args, dict) else str(args))


def _place_named(args: Any) -> str:
    """The agent whose switch file the call names first ("Claude Code's"), or a general phrase."""
    text = str(args)
    for entry in hook_switches.switch_files():
        if entry.path in text:
            return f"{product_name(entry.agent)}'s hooks ({entry.path})"
    return "an agent's hooks"


def _named_switch_files(command: str) -> list[str]:
    """The switch files a command line's words name (relative words joined onto the folder the
    agent works in), at most :data:`_MAX_SOURCES`."""
    folder = action_context.working_folder() or os.path.expanduser("~")
    out = []
    for word in shell_files._words(command):
        path = os.path.expanduser(word.strip("'\""))
        path = os.path.normpath(path if os.path.isabs(path) else os.path.join(folder, path))
        if hook_switches.matching(path) and path not in out:
            out.append(path)
    return out[:_MAX_SOURCES]


def _code_spells_a_switch(tool: str, args: Any) -> bool:
    """True when code the call runs — inline (``python3 -c``, a code tool, a heredoc) — writes a
    file and spells a switch set OFF. WHY not only when it names the file: a path built at run time
    (``sys.argv[1] + '/settings.json'``) names none, and the switch's own spelling is what matters."""
    text = shell_files.with_base64_decoded(_call_text(tool, args))
    return bool(_SWITCH_OFF.search(text)) and bool(guard_settings._CODE_WRITES.search(text))


def _judged(tool_name: str, args: Any) -> str:
    """What the call does to a hooks-off switch, as a finding's evidence; "" for nothing."""
    tool = (tool_name or "").strip().lower()
    with guard_places.judging(guard_places.HOOKS):
        tool, how = guard_settings.tampering(tool_name, args)
    if how not in ("write", "code", "command"):
        if (tool in shell_shapes.SHELL_TOOLS or isinstance(args, dict) and isinstance(args.get("code"), str)) \
                and _code_spells_a_switch(tool, args):
            return f"code that switches off {_place_named(args)}"
        return ""
    access = action_parsing.file_access_arg(tool_name, args) if how == "write" else None
    if access is not None:
        path = os.path.normpath(os.path.expanduser(str(access["path"])))
        if not os.path.isabs(path):
            path = os.path.join(action_context.working_folder() or os.path.expanduser("~"), path)
        if hook_switches.matching(path):
            found = _file_write_turns_off(path, args)
            return f"a write that switches off {_place_named(args)}: {found}" if found else ""
    # A command, code, a patch or a script written to run: what it spells, or what it copies in place.
    text = _call_text(tool, args)
    copied = _copied_texts(text) if tool in shell_shapes.SHELL_TOOLS else []
    if any(_SWITCH_OFF.search(candidate) for candidate in [shell_files.with_base64_decoded(text), *copied]):
        return f"a {'command' if how == 'command' else 'change'} that switches off {_place_named(args)}"
    # An in-place edit (``sed -i 's/false/true/'``) of a file that already holds a switch: what it
    # leaves can not be worked out here, and only this file's switch could change.
    if how == "command":
        for path in _named_switch_files(text):
            current = read_small_text(path, _MAX_FILE_BYTES) or ""
            if any(key.split(".")[-1] in current for entry in hook_switches.matching(path) for key, _off in entry.switches):
                return f"a command that rewrites {_place_named(args)}, where a hooks switch is set"
    return ""


def _script_judged(tool: str, args: Any) -> str:
    """The evidence when a script file this shell call runs switches hooks off; "" for none."""
    if tool not in shell_shapes.SHELL_TOOLS:
        return ""
    hit = script_files.judge_runs(shell_shapes.command_from_args(tool, args), lambda _run, call: _judged("terminal", call))
    return f"a script it runs ({os.path.basename(hit[0].path)}): {hit[1]}" if hit else ""


def _finding(tool: str, evidence: str) -> Finding:
    return Finding(identifier=threat_ids.fileaccess_identifier(tool, MATCHED), category="fileaccess", severity="critical",
                   title=TITLE, advice=ADVICE, tool_name=tool, matched=MATCHED, evidence=evidence[:400], confirmed=False,
                   source="custom", fields={})


def detect_hook_switch_off(tool_name: str, args: Any) -> list[Finding]:
    """A finding when an agent's call would switch an agent's hooks off — itself or through a
    script file it runs —, else []."""
    try:
        tool = (tool_name or "").strip().lower()
        evidence = _judged(tool_name, args) or _script_judged(tool, args)
        return [_finding(tool, evidence)] if evidence else []
    except Exception:  # pragma: no cover  # health: allow BLE001 -- fail open: a detector fault never breaks the agent's tool call
        return []


__all__ = ["ADVICE", "KNOWN_LIMITS", "MATCHED", "TITLE", "detect_hook_switch_off"]
