"""File Shield's setting: on or off, the files and folders the person protected from every AI
agent, and the folders where new files arrive (watched).

Founder direction (Amos, 2026-11-21): File Shield is an active defence, not a reactive watcher —
an item the person protects can not be touched by any AI agent by any route (file tools, shell,
code, MCP tools, any agent), in Audit mode as well as Block mode (their own explicit rule). Adding
an item applies at once; removing one turns protection down and waits for the person's approval
(``approvals``: ``protected`` is a protecting list). Off (the default) it protects and watches
nothing.

Config, under ``plugins.entries.blackbox``::

    shields:
      file-shield:
        enabled: true
        protected: ["~/Documents/Taxes", "~/.config/my-app/token.json"]   # nothing may touch these
        folders: ["~/Downloads"]                                          # new files reported (default ~/Downloads)
        sandboxed: ["claude-code", "codex"]                               # agents started inside the OS sandbox (Layer 2)

``sandboxed`` lists the coding agents Blackbox starts inside an operating-system sandbox built from
the protected list (``sandbox/``): a protecting list, so adding one applies at once and removing one
waits for approval. Empty by default (decision D7: a sandboxed agent can not use ``sudo``).

An item is stored in ONE canonical spelling (LES-105): written from the home folder (``~/…``)
when it is inside it, absolute otherwise, with ``..`` folded away and an existing link resolved —
so ``$HOME/Docs/../Taxes`` and ``~/Taxes`` are the same item and cannot be added twice or removed
by a different spelling. The whole disk, the home folder itself and the folders that hold every
user (``/Users``) are refused: protecting them would stop every agent from working at all.

Usage::

    mode = current()
    protected(mode)        # ("~/Documents/Taxes",)
    watch_paths(mode)      # absolute paths the system protection helper watches in real time
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping, Optional

from ..contract import SettingField, SettingOption, ShieldMode

SHIELD_ID = "file-shield"
OPT_PROTECTED = "protected"
OPT_FOLDERS = "folders"
OPT_SANDBOXED = "sandboxed"
DEFAULT_FOLDERS = ("~/Downloads",)
#: Most items the person may protect, and most folders watched for new files.
MAX_PROTECTED = 200
MAX_FOLDERS = 10
#: The longest item, as written.
MAX_ITEM_CHARS = 1024
#: The pattern Settings checks each protected line against (the validator is the authority).
ITEM_PATTERN = r"^(~|/)[^\x00]{1,1023}$"
#: The pattern Settings checks each watched folder against: a path from the home folder.
FOLDER_PATTERN = r"^~/[^\x00]{1,200}$"
#: Places too broad to protect: protecting them would stop every agent working at all.
# no-tmp: ok — a place too broad to protect (it names the system's temp folder), never scratch space
_TOO_BROAD = frozenset({"/", "/Users", "/home", "/Volumes", "/private", "/System", "/var", "/tmp"})

ENGAGE_HELP = ("Protect the files and folders you choose from every AI agent — Hermes, Blackbox's assistant, "
               "Claude Code, Codex, Cursor, Gemini, Copilot, Windsurf, Cline, OpenCode, OpenClaw and their MCP "
               "tools. An agent is refused any access to them by any route (opening, copying, listing, moving, "
               "deleting, a shell command or code), in Audit mode too, and every attempt is shown to you. "
               "Also watches the folders where new files arrive. Off stops all of it.")


def _home() -> str:
    return os.path.realpath(os.path.expanduser("~"))


def canonical_item(value: Any) -> Optional[str]:
    """*value* as ONE spelling of a protected item (see the module doc); None when it is not a path
    from the home folder or the root, or names a place too broad to protect."""
    text = str(value or "").strip()
    if not text or len(text) > MAX_ITEM_CHARS or "\x00" in text or "\n" in text:
        return None
    for variable in ("${HOME}", "$HOME"):
        if text.startswith(variable):
            text = "~" + text[len(variable):]
    if not (text.startswith("~/") or text.startswith("/")):
        return None
    real = os.path.realpath(os.path.expanduser(text))
    home = _home()
    if real in _TOO_BROAD or real == home or home.startswith(real.rstrip("/") + "/"):
        return None
    return "~" + real[len(home):] if real.startswith(home + "/") else real


def normalise_folder(value: Any) -> Optional[str]:
    """A watched folder as ``~/Some/Folder`` (no trailing slash, no ``..``); None for anything else."""
    text = str(value or "").strip().rstrip("/")
    if not text.startswith("~/") or len(text) > 202 or "\x00" in text:
        return None
    parts = text[2:].split("/")
    if not parts or any(part in ("", ".", "..") for part in parts):
        return None
    return text


def build(enabled: bool = False, protected: tuple[str, ...] = (), folders: Optional[tuple[str, ...]] = None,
          sandboxed: tuple[str, ...] = ()) -> ShieldMode:
    """File Shield's mode (None: the default watched folders)."""
    return ShieldMode(enabled=enabled, options={OPT_PROTECTED: protected,
                                                OPT_FOLDERS: DEFAULT_FOLDERS if folders is None else folders,
                                                OPT_SANDBOXED: sandboxed})


def protected(mode: ShieldMode) -> tuple[str, ...]:
    """The items *mode* protects, as stored (``~/…`` or absolute) — empty while the shield is off."""
    return tuple(mode.options.get(OPT_PROTECTED, ())) if mode.enabled else ()


def folders(mode: ShieldMode) -> tuple[str, ...]:
    """The folders *mode* watches for new files, as written (``~/…``)."""
    return tuple(mode.options.get(OPT_FOLDERS, ()))


def resolved(mode: ShieldMode, home: Optional[Path] = None) -> tuple[Path, ...]:
    """The watched folders as real paths, keeping only those inside the home folder."""
    home = (home or Path(os.path.expanduser("~"))).resolve()
    found = []
    for folder in folders(mode):
        path = (home / folder[2:]).resolve()
        if path == home or home in path.parents:
            found.append(path)
    return tuple(dict.fromkeys(found))


def watch_paths(mode: ShieldMode) -> tuple[str, ...]:
    """Every absolute path the system protection helper watches in real time while the shield is
    on: each protected item and each watched folder (empty while off)."""
    if not mode.enabled:
        return ()
    items = [os.path.realpath(os.path.expanduser(item)) for item in protected(mode)]
    return tuple(dict.fromkeys(items + [str(path) for path in resolved(mode)]))


def _items(raw: Any) -> Optional[tuple[str, ...]]:
    if not isinstance(raw, list) or len(raw) > MAX_PROTECTED:
        return None
    entries = [canonical_item(item) for item in raw]
    if any(entry is None for entry in entries):
        return None
    return tuple(dict.fromkeys(entry for entry in entries if entry))


def _folders(raw: Any) -> Optional[tuple[str, ...]]:
    if not isinstance(raw, list) or len(raw) > MAX_FOLDERS:
        return None
    entries = [normalise_folder(item) for item in raw]
    if any(entry is None for entry in entries):
        return None
    return tuple(dict.fromkeys(entry for entry in entries if entry))


def _sandboxed(raw: Any) -> Optional[tuple[str, ...]]:
    """Agent ids from the catalogue that have a command-line launcher; None for anything else."""
    from ...kernel.agent_hosts import BY_ID, HERMES_ID
    if not isinstance(raw, list) or len(raw) > len(BY_ID) + 1:
        return None
    if any(not isinstance(item, str) or (item != HERMES_ID and (item not in BY_ID or not BY_ID[item].commands or item == "windsurf"))
           for item in raw):
        return None
    return tuple(dict.fromkeys(raw))


def from_entry(entry: Mapping[str, Any]) -> ShieldMode:
    """The mode as the ``blackbox`` config entry states it (defaults when absent or invalid)."""
    shields = entry.get("shields")
    section = shields.get(SHIELD_ID) if isinstance(shields, Mapping) else None
    section = section if isinstance(section, Mapping) else {}
    chosen = _folders(section.get(OPT_FOLDERS)) if OPT_FOLDERS in section else None
    return build(enabled=section.get("enabled") is True, protected=_items(section.get(OPT_PROTECTED)) or (),
                 folders=chosen, sandboxed=_sandboxed(section.get(OPT_SANDBOXED)) or ())


def current() -> ShieldMode:
    """The mode in force now, read from the Hermes config like every other setting."""
    from ...kernel.config import shield_entry   # plugins.entries.blackbox, once per shields snapshot
    return from_entry(shield_entry())


def validate(payload: Mapping[str, Any]) -> tuple[str, dict[str, Any], list[str]]:
    """``("file-shield", section, errors)`` for ``payload["shields"]["file-shield"]``.

    Anything invalid is refused with a sentence and nothing is stored. A section that changes
    anything is written COMPLETE (a field the payload leaves out keeps its current value)."""
    shields = payload.get("shields")
    raw = shields.get(SHIELD_ID) if isinstance(shields, Mapping) else None
    if raw is None or raw == {}:
        return SHIELD_ID, {}, []
    if not isinstance(raw, Mapping):
        return SHIELD_ID, {}, [f"shields.{SHIELD_ID} must be an object"]
    updates: dict[str, Any] = {}
    errors: list[str] = []
    if "enabled" in raw:
        if isinstance(raw["enabled"], bool):
            updates["enabled"] = raw["enabled"]
        else:
            errors.append(f"shields.{SHIELD_ID}.enabled must be true or false")
    if OPT_PROTECTED in raw:
        chosen = _items(raw[OPT_PROTECTED])
        if chosen is None:
            errors.append(f"shields.{SHIELD_ID}.protected must be a list of up to {MAX_PROTECTED} files or folders, "
                          "each written from ~/ or / — not the whole disk or your whole home folder")
        else:
            updates[OPT_PROTECTED] = list(chosen)
    if OPT_FOLDERS in raw:
        chosen = _folders(raw[OPT_FOLDERS])
        if chosen is None:
            errors.append(f"shields.{SHIELD_ID}.folders must be a list of up to {MAX_FOLDERS} folders inside your "
                          "home folder, each written from ~/ (for example ~/Downloads)")
        else:
            updates[OPT_FOLDERS] = list(chosen)
    if OPT_SANDBOXED in raw:
        chosen = _sandboxed(raw[OPT_SANDBOXED])
        if chosen is None:
            errors.append(f"shields.{SHIELD_ID}.sandboxed must list coding agents Blackbox knows (for example claude-code)")
        else:
            updates[OPT_SANDBOXED] = list(chosen)
    if errors or not updates:
        return SHIELD_ID, {}, errors
    now = current()
    section = {"enabled": now.enabled, OPT_PROTECTED: list(now.options.get(OPT_PROTECTED, ())),
               OPT_FOLDERS: list(folders(now)), OPT_SANDBOXED: list(now.options.get(OPT_SANDBOXED, ())), **updates}
    return SHIELD_ID, section, []


def fields() -> list[SettingField]:
    """What Settings draws for File Shield: the engage switch first, as every shield."""
    return [
        SettingField("enabled", "toggle", "Engage File Shield", ENGAGE_HELP),
        SettingField(OPT_PROTECTED, "lines", "Protected from every AI agent",
                     "One file or folder per line, from ~/ or /. A folder protects everything inside it. "
                     "Removing one asks you first.", pattern=ITEM_PATTERN),
        SettingField(OPT_SANDBOXED, "multi-pick", "Run these agents inside the sandbox",
                     "Blackbox starts the agents you pick inside your Mac's own sandbox, so no program they run can open "
                     "your protected files either. A sandboxed agent can not use sudo. Taking one off asks you first; "
                     "a running agent keeps its protection until you restart it.",
                     options=_agent_options()),
        SettingField(OPT_FOLDERS, "lines", "Folders to watch for new files",
                     f"One per line, written from your home folder (for example ~/Downloads). Up to {MAX_FOLDERS}.",
                     pattern=FOLDER_PATTERN),
    ]


def _agent_options() -> tuple[SettingOption, ...]:
    from ...kernel.agent_hosts import HERMES_ID, HERMES_NAME, HOSTS
    return tuple(SettingOption(id=host.id, name=host.name, status="") for host in HOSTS
                 if host.commands and host.id != "windsurf") + (SettingOption(id=HERMES_ID, name=HERMES_NAME, status=""),)
