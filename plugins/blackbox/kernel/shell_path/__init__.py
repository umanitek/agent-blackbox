"""A folder Blackbox puts FIRST on the person's PATH, through one marked block in their shell
startup files — and takes out again (File Shield's agent launchers; ``blackbox uninstall``).

The block is Blackbox's only edit of a file it does not own, so it is fenced by two marker lines.
It is first written at the end of the file, and it puts the folder first AGAIN before every prompt
(zsh ``precmd_functions``, bash ``PROMPT_COMMAND``): a PATH line the person adds further down — nvm,
Homebrew — can not put the real agent program ahead of Blackbox's launcher, so the block never has
to stay last and the person's file is never rewritten to move it (KI-540, E2E full5 2026-11-22).
Adding twice changes nothing; removing takes out exactly the fenced lines and leaves the person's
own lines as they were.

Files: ``~/.zshrc`` (created when missing: macOS's default shell) and, when they exist,
``~/.bashrc`` and ``~/.bash_profile``.

Guarding the block (KI-535, E2E full4 2026-11-22: a sandboxed agent appended to ``~/.zshrc`` and so
could have deleted the block, sending every later agent outside the sandbox): every file a shell
reads at start (:data:`STARTUP_FILES`) is closed to writes inside the agent sandbox, a file that
holds the block is one of Blackbox's guarded places for every agent (only the person's own lines
stay editable, :func:`section`), and :func:`intact` lets File Shield put a removed or changed block
back at once.

Usage::

    add(Path("~/.hermes/blackbox/agent-bin").expanduser())   # files changed
    remove()                                                 # files changed
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from .. import agent_hosts

BEGIN = "# >>> Blackbox agent sandbox >>> (managed by Blackbox — `blackbox uninstall` removes it)"
END = "# <<< Blackbox agent sandbox <<<"
ALWAYS = (".zshrc",)
IF_PRESENT = (".bashrc", ".bash_profile")
#: Every file zsh or bash reads when it starts: one written into could undo the block (a PATH line
#: after it, or ``ZDOTDIR`` pointing zsh at other files), so the agent sandbox may write none of them.
STARTUP_FILES = (".zshrc", ".zshenv", ".zprofile", ".zlogin", ".zlogout", ".bashrc", ".bash_profile", ".bash_login",
                 ".profile")


def _files(home: Path) -> list[Path]:
    return [home / name for name in ALWAYS] + [home / name for name in IF_PRESENT if (home / name).is_file()]


def _without_block(text: str) -> str:
    out, inside = [], False
    for line in text.splitlines(keepends=True):
        if line.rstrip("\n") == BEGIN:
            inside = True
            continue
        if inside:
            inside = line.rstrip("\n") != END
            continue
        out.append(line)
    return "".join(out)


#: The shell function the block defines and hooks before every prompt.
FUNCTION = "_blackbox_agent_path"


def block(folder: Path) -> str:
    """The fenced lines that put *folder* first on PATH now and again before every prompt, in zsh
    and in bash alike (one text: the file may be read by either)."""
    quoted = str(folder).replace('"', '\\"')
    return (f"{BEGIN}\n"
            f"{FUNCTION}() {{ case \":$PATH:\" in \":{quoted}:\"*) ;; *) PATH=\"{quoted}:$PATH\"; export PATH ;; esac; }}\n"
            f"{FUNCTION}\n"
            f"if [ -n \"$ZSH_VERSION\" ]; then precmd_functions=(${{precmd_functions:#{FUNCTION}}} {FUNCTION}); "
            f"elif [ -n \"$BASH_VERSION\" ]; then case \";$PROMPT_COMMAND;\" in *\";{FUNCTION};\"*) ;; "
            f"*) PROMPT_COMMAND=\"{FUNCTION}${{PROMPT_COMMAND:+;$PROMPT_COMMAND}}\" ;; esac; fi\n"
            f"{END}\n")


def _legacy_block(folder: Path) -> str:
    """The block as Blackbox wrote it before it re-asserted itself (FIX-0297): replacing it is an
    upgrade, never a restoration the person must be told about."""
    quoted = str(folder).replace('"', '\\"')
    return f"{BEGIN}\ncase \":$PATH:\" in *\":{quoted}:\"*) ;; *) export PATH=\"{quoted}:$PATH\" ;; esac\n{END}\n"


#: A line that could take an agent command away from Blackbox's launcher or switch the block off:
#: PATH itself, the prompt hooks, another startup folder, the shell's command cache, Blackbox's
#: own words — and an alias, function or unset of an agent's command (built below).
_UNDOES_ALWAYS = (r"\bPATH\b", r"\bpath\s*[+=(]", r"precmd", r"PROMPT_COMMAND", r"add-zsh-hook", r"ZDOTDIR",
                  r"\bhash\b", r"\brehash\b", r"blackbox", r"agent-bin", FUNCTION)
_AGENT_COMMANDS = sorted({command for host in agent_hosts.HOSTS for command in host.commands} | {"cursor", "windsurf"})
_UNDOES = re.compile("|".join(_UNDOES_ALWAYS) + r"|\b(?:alias|unalias|unset|unfunction|function|builtin|command|disable)\b[^#\n]*\b(?:"
                     + "|".join(map(re.escape, _AGENT_COMMANDS)) + r")\b|\b(?:" + "|".join(map(re.escape, _AGENT_COMMANDS))
                     + r")\s*\(\s*\)", re.IGNORECASE)


def undoing_lines(added: str, before: str = "") -> list[str]:
    """The lines of *added* (a startup file's new text) that could undo the block, leaving out
    comments and any line already in *before* (an edit that keeps the person's PATH line as it was
    is not a new risk). Empty answer: the added text can not send an agent round the launcher."""
    kept = {line.strip() for line in before.splitlines()}
    return [line for line in added.splitlines()
            if line.strip() and not line.lstrip().startswith("#") and line.strip() not in kept and _UNDOES.search(line)]


def add(folder: Path, home: Optional[Path] = None) -> list[Path]:
    """Puts the block for *folder* at the END of each startup file; answers the files changed."""
    home = home or Path.home()
    changed = []
    wanted_block = block(folder)
    for path in _files(home):
        text = path.read_text(encoding="utf-8-sig") if path.is_file() else ""
        if _holds_exactly(text, wanted_block):
            continue   # already whole, wherever it sits: the person's file is never rewritten
        base = _without_block(text)
        wanted = base + ("" if not base or base.endswith("\n") else "\n") + wanted_block
        if wanted != text:
            path.write_text(wanted, encoding="utf-8")
            changed.append(path)
    return changed


def remove(home: Optional[Path] = None) -> list[Path]:
    """Takes the block out of every startup file that holds it; answers the files changed."""
    home = home or Path.home()
    changed = []
    for name in ALWAYS + IF_PRESENT:
        path = home / name
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8-sig")
        cleaned = _without_block(text)
        if cleaned != text:
            path.write_text(cleaned, encoding="utf-8")
            changed.append(path)
    return changed


def present(home: Optional[Path] = None) -> bool:
    """True when a startup file holds Blackbox's block."""
    home = home or Path.home()
    return any((home / name).is_file() and BEGIN in (home / name).read_text(encoding="utf-8-sig")
               for name in ALWAYS + IF_PRESENT)


def holding(home: Optional[Path] = None) -> list[Path]:
    """The startup files that hold Blackbox's block now."""
    home = home or Path.home()
    return [home / name for name in ALWAYS + IF_PRESENT
            if (home / name).is_file() and BEGIN in (home / name).read_text(encoding="utf-8-sig")]


def section(text: str) -> str:
    """The block's lines in startup-file *text* (markers included), or "" when it holds none."""
    start = text.find(BEGIN)
    if start < 0:
        return ""
    end = text.find(END, start)
    return text[start:] if end < 0 else text[start:end + len(END)]


def _holds_exactly(text: str, wanted: str) -> bool:
    return text.count(BEGIN) == 1 and text.count(END) == 1 and section(text) + "\n" == wanted


def intact(folder: Path, home: Optional[Path] = None) -> bool:
    """True when every file :func:`add` writes holds the block for *folder* exactly once and byte
    for byte as Blackbox wrote it — wherever it sits (the block re-asserts PATH before every prompt,
    so lines the person adds after it are theirs, KI-540)."""
    home = home or Path.home()
    wanted = block(folder)
    return all(_holds_exactly(path.read_text(encoding="utf-8-sig") if path.is_file() else "", wanted)
               for path in _files(home))


def upgradable(folder: Path, home: Optional[Path] = None) -> bool:
    """True when every file holding a block holds an OLDER whole block for *folder* (Blackbox's own
    earlier text): writing the current one is an upgrade, not a restoration."""
    home = home or Path.home()
    old = _legacy_block(folder)
    found = [path for path in _files(home) if path.is_file()]
    return bool(found) and all(_holds_exactly(path.read_text(encoding="utf-8-sig"), old) for path in found)
