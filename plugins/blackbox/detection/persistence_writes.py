"""The places something starts from by itself — an agent may not write them, in ANY mode.

Private security finding ``2026-11-23-hooks-only-an-agent-appends-an-ssh-key-t`` (security round 5,
High): a hooks-only Claude Code appended ``ssh-ed25519 …`` to ``~/.ssh/authorized_keys`` (allowed,
flagged 0), wrote a LaunchAgent and a program into ``/opt/homebrew/bin`` and scheduled an ``at`` job.
The agent sandbox refused every one of them; the hooks judged none, because their places lived only
in the sandbox's profile. Both now read ONE list, ``kernel.persistence_places``, so they can not
drift apart again.

How a call is judged: by the SAME reading self-protection uses (:func:`.paths.guard_settings.tampering`:
every shell route — redirects, ``tee``, copies, moves, links, archives, ``sed -i``, nested shells,
base64, heredocs, ``cd`` then a bare name —, code, file tools and Codex's ``apply_patch``), run
against the persistence places instead of Blackbox's own (``guard_places.judging``):

* :data:`.paths.guard_places.STARTS` — launchd jobs, login items, cron and ``at`` spools, OpenSSH's login
  files, the shell startup files: any change but a read is refused;
* :data:`.paths.guard_places.PROGRAMS` — Homebrew's own folders: only a WRITE is refused (running
  ``/opt/homebrew/bin/git`` or giving ``-L /opt/homebrew/lib`` to a compiler stays ordinary);
* a command that leaves a job without naming a file (``crontab -``, ``at now + 1 hour``,
  ``launchctl submit``, a login item through System Events: ``kernel.persistence_places.schedules``).

Reads stay allowed (``cat ~/.ssh/authorized_keys``). ``~/.local/bin``, npm's global prefix and
``pipx`` stay writable (founder decision 2026-11-23, option b): the persistence watch raises a
critical alert for every new program an agent writes there.

``source="custom"`` and :data:`MATCHED` is in ``detection.ALWAYS_BLOCKED_MATCHES``: refused in
every mode, as the sandbox refuses it.

Usage::

    detect_persistence_write("terminal", {"command": "echo 'ssh-ed25519 AAAA… x' >> ~/.ssh/authorized_keys"})
    # -> [Finding(identifier="fileaccess:terminal:startup-item", severity="critical", ...)]
    detect_persistence_write("terminal", {"command": "cat ~/.ssh/authorized_keys"})   # -> [] (a read)
"""

from __future__ import annotations

import os
from typing import Any

from . import shell_shapes
from .finding import Finding
from ..kernel import persistence_places, threat_ids
from .paths import guard_paths, guard_places, guard_settings, shell_files

MATCHED = persistence_places.STARTUP_ITEM
TITLE = "Would leave something that starts by itself"
ADVICE = ("An AI agent may not add a startup item, a scheduled job, an SSH login key, a shell startup line or a "
          "program in Homebrew's folders: it would run later, outside Blackbox's checks. If you meant it, do it "
          "yourself in your own terminal.")
#: What each kind of change is, in the evidence of a finding.
_HOW = {"write": "a write to {place}", "code": "code that writes {place}", "command": "a command that writes {place}"}


def _schedules(command: str) -> bool:
    """True when a command line leaves a job without naming its file (``echo … | crontab -``) —
    also when it hands that command to another shell (``bash -lc "launchctl bootstrap …"``,
    Codex's wrapper: round 6 loaded a launchd job, a cron and an ``at`` job that way)."""
    for line in shell_shapes.with_nested_commands(command).split("\n"):
        for segment in guard_paths._segments(shell_files._with_variables(shell_files._words(line))):
            name, rest = guard_paths._command_of(segment)
            if persistence_places.schedules(name, rest):
                return True
    return False


def _place_named(args: Any) -> str:
    """The words for the persistence place the call names first ("an SSH login file"), or a
    general phrase when it can not be told."""
    text = os.path.expandvars(os.path.expanduser(str(args)))
    home = os.path.expanduser("~")
    places = persistence_places.hook_places(home)
    for place in (*places.starts, *places.programs):
        bare = place.split("*", 1)[0]
        if bare and (bare in text or bare.replace(home, "~", 1) in str(args)):
            return persistence_places.describe(place)
    return "a place something starts from by itself"


def _finding(tool: str, evidence: str) -> Finding:
    return Finding(identifier=threat_ids.fileaccess_identifier(tool, MATCHED), category="fileaccess", severity="critical",
                   title=TITLE, advice=ADVICE, tool_name=tool, matched=MATCHED, evidence=evidence, confirmed=False,
                   source="custom", fields={})


def detect_persistence_write(tool_name: str, args: Any) -> list[Finding]:
    """A finding when an agent's call would write a place something starts from by itself, else []."""
    try:
        tool = (tool_name or "").strip().lower()
        if tool in shell_shapes.SHELL_TOOLS and _schedules(shell_shapes.whole_command_from_args(tool_name, args)):
            return [_finding(tool, "a command that schedules a job (cron, at, launchd or a login item)")]
        for scope in (guard_places.STARTS, guard_places.PROGRAMS):
            with guard_places.judging(scope):
                tool, how = guard_settings.tampering(tool_name, args)
            if how in _HOW:   # "long" and "page" are self-protection's alone
                return [_finding(tool, _HOW[how].format(place=_place_named(args)))]
        return []
    except Exception:  # pragma: no cover  # health: allow BLE001 -- fail open: a detector fault never breaks the agent's tool call
        return []


__all__ = ["ADVICE", "MATCHED", "TITLE", "detect_persistence_write"]
