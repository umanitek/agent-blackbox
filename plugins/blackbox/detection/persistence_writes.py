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
  files: any change but a read is refused;
* :data:`.paths.guard_places.SHELL` — the shell startup files (``~/.zshrc``, ``~/.bashrc``,
  ``~/.profile``, fish's ``config.fish`` and ``conf.d``): the same, as :data:`SHELL_MATCHED` with its
  own words, so the person's ``shell-startup`` permission decides them apart from ``startup-items``
  (Blackbox's own PATH block in such a file stays self-protection's, refused whatever they pick);
* :data:`.paths.guard_places.PROGRAMS` — Homebrew's own folders: only a WRITE is refused (running
  ``/opt/homebrew/bin/git`` or giving ``-L /opt/homebrew/lib`` to a compiler stays ordinary);
* a command that leaves a job without naming a file (``crontab -``, ``at now + 1 hour``,
  ``launchctl submit``, a login item through System Events, ``sfltool add-item``, a ``defaults
  write`` of the login window's preferences: ``kernel.persistence_places.schedules``);
* a SCRIPT FILE the command runs (``python3 w.py rary Agents x``, also inside ``/bin/zsh -lc '…'``):
  read from disk (:mod:`.script_files`, bounded) and judged by its text as the inline code it is,
  with the arguments the command hands it — the same reading File Shield gives a script for the
  person's protected items. Private finding ``2026-11-23-re-test-round-6-hooks-only-agents-still-``
  (round 6, High): Codex, Cline and Claude Code on hooks only ran a pre-placed ``k.py`` that
  appended an SSH key and a ``w.py`` that wrote a LaunchAgent, both building the path from their
  arguments (``"." + sys.argv[1]``, ``"Lib" + sys.argv[1]``) — allowed, left behind. A script
  that builds its path any other way at run time is beyond a hook: only the sandbox stops it.

Reads stay allowed (``cat ~/.ssh/authorized_keys``). ``~/.local/bin``, npm's global prefix and
``pipx`` stay writable (founder decision 2026-11-23, option b): the persistence watch raises a
critical alert for every new program an agent writes there.

``source="custom"``; :data:`MATCHED` and :data:`SHELL_MATCHED` are in ``detection.ALWAYS_BLOCKED_MATCHES``:
refused in every mode, as the sandbox refuses it, unless the person allowed that permission for the
acting agent (``guard.hooks``).

Usage::

    detect_persistence_write("terminal", {"command": "echo 'ssh-ed25519 AAAA… x' >> ~/.ssh/authorized_keys"})
    # -> [Finding(identifier="fileaccess:terminal:startup-item", severity="critical", ...)]
    detect_persistence_write("terminal", {"command": "echo 'alias x=y' >> ~/.zshrc"})
    # -> [Finding(identifier="fileaccess:terminal:shell-startup", ...)]
    detect_persistence_write("terminal", {"command": "cat ~/.ssh/authorized_keys"})   # -> [] (a read)
"""

from __future__ import annotations

import os
from typing import Any

from . import script_files, shell_shapes
from .finding import Finding
from ..kernel import persistence_places, threat_ids
from .paths import guard_paths, guard_places, guard_settings, shell_words

MATCHED = persistence_places.STARTUP_ITEM
TITLE = "Would leave something that starts by itself"
ADVICE = ("An AI agent may not add a startup item, a scheduled job, a systemd unit, an SSH login key, a session "
          "startup line or a program in Homebrew's folders: it would run later, outside Blackbox's checks. If you meant it, do it "
          "yourself in your own terminal.")
SHELL_MATCHED = persistence_places.SHELL_STARTUP
SHELL_TITLE = "Would change a shell startup file"
SHELL_ADVICE = ("An AI agent may not edit ~/.zshrc, ~/.bashrc, ~/.profile or another file your shell runs when it starts: "
                "a line there runs in your next terminal, outside Blackbox's checks. If you meant it, edit the file yourself, "
                "or allow \"Editing your shell startup files\" for this agent in Blackbox's sandbox permissions.")
#: Each place set judged, with what a write there is (``matched``, title, advice).
_SCOPES = ((guard_places.STARTS, MATCHED, TITLE, ADVICE), (guard_places.SHELL, SHELL_MATCHED, SHELL_TITLE, SHELL_ADVICE),
           (guard_places.PROGRAMS, MATCHED, TITLE, ADVICE))
#: What each kind of change is, in the evidence of a finding.
_HOW = {"write": "a write to {place}", "code": "code that writes {place}", "command": "a command that writes {place}"}


def _schedules(command: str) -> bool:
    """True when a command line leaves a job without naming its file (``echo … | crontab -``) —
    also when it hands that command to another shell (``bash -lc "launchctl bootstrap …"``,
    Codex's wrapper: round 6 loaded a launchd job, a cron and an ``at`` job that way)."""
    for line in shell_shapes.with_nested_commands(command).split("\n"):
        for segment in shell_words.segments(shell_words.with_variables(shell_words.words(line))):
            name, rest = guard_paths.command_of(segment)
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


#: What one call does to a persistence place: ``(matched, title, advice, evidence)``.
_Judged = tuple[str, str, str, str]


def _finding(tool: str, judged: _Judged) -> Finding:
    matched, title, advice, evidence = judged
    return Finding(identifier=threat_ids.fileaccess_identifier(tool, matched), category="fileaccess", severity="critical",
                   title=title, advice=advice, tool_name=tool, matched=matched, evidence=evidence, confirmed=False,
                   source="custom", fields={})


_SCHEDULES = ("a command that schedules a job or leaves something to run later (cron, at, launchd, a login item, a systemd "
              "unit or timer, lingering, a desktop setting, git's hooks)")


def _judged(tool_name: str, args: Any) -> _Judged | None:
    """What the call itself does to a persistence place (the first place set it reaches), or None."""
    tool = (tool_name or "").strip().lower()
    if tool in shell_shapes.SHELL_TOOLS and _schedules(shell_shapes.whole_command_from_args(tool_name, args)):
        return MATCHED, TITLE, ADVICE, _SCHEDULES
    for scope, matched, title, advice in _SCOPES:
        with guard_places.judging(scope):
            _tool, how = guard_settings.tampering(tool_name, args)
        if how in _HOW:   # "long" and "page" are self-protection's alone
            return matched, title, advice, _HOW[how].format(place=_place_named(args))
    return None


def _script_judged(tool: str, args: Any) -> _Judged | None:
    """What a script file this shell call runs does to a persistence place, judged by the one
    script judgement (:func:`.script_files.judge_runs`); None for nothing."""
    if tool not in shell_shapes.SHELL_TOOLS:
        return None
    hit = script_files.judge_runs(shell_shapes.command_from_args(tool, args), lambda _run, call: _judged("terminal", call))
    if not hit:
        return None
    matched, title, advice, evidence = hit[1]
    return matched, title, advice, f"a script it runs ({os.path.basename(hit[0].path)}): {evidence}"


def detect_persistence_write(tool_name: str, args: Any) -> list[Finding]:
    """A finding when an agent's call would write a place something starts from by itself — itself
    or through a script file it runs —, else []."""
    try:
        judged = _judged(tool_name, args) or _script_judged((tool_name or "").strip().lower(), args)
        return [_finding((tool_name or "").strip().lower(), judged)] if judged else []
    except Exception:  # pragma: no cover  # health: allow BLE001 -- fail open: a detector fault never breaks the agent's tool call
        return []


__all__ = ["ADVICE", "MATCHED", "SHELL_ADVICE", "SHELL_MATCHED", "SHELL_TITLE", "TITLE", "detect_persistence_write"]
