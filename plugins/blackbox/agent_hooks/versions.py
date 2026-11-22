"""Which version of each coding agent is installed here, and where its program is.

Read by asking the agent's own command for ``--version`` (bounded, cached for
:data:`CACHE_SECONDS`; an agent that does not answer has no version, never an error). The Docs
page compares it with the versions Blackbox was tested against.

Usage::

    from . import versions
    versions.installed()      # {"claude-code": Installed(path, version), …}
"""

from __future__ import annotations

import plistlib
import re
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..kernel.agent_hosts import HOSTS, USER_BIN_DIRS, Host

__all__ = ["Installed", "installed", "parse"]

TIMEOUT_SECONDS = 4.0
CACHE_SECONDS = 600.0
_VERSION = re.compile(r"\d+(?:\.\d+){1,3}")
_lock = threading.Lock()
_cache: dict[str, object] = {"at": 0.0, "found": {}}


@dataclass(frozen=True)
class Installed:
    path: str
    version: str   # "" when the command gave none


def parse(text: str) -> str:
    """The first dotted version number in a ``--version`` answer ("" when there is none)."""
    match = _VERSION.search(text or "")
    return match.group(0) if match else ""


def _program(host: Host, home: Path) -> Optional[str]:
    folders = [str(home / folder) for folder in USER_BIN_DIRS]
    for command in host.commands:
        found = shutil.which(command) or next((hit for folder in folders if (hit := shutil.which(command, path=folder))), None)
        if found:
            return found
    return None


def _ask(program: str) -> str:
    try:
        done = subprocess.run([program, "--version"], capture_output=True, encoding="utf-8", errors="replace", timeout=TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    return parse(done.stdout or done.stderr)


def _bundle(host: Host) -> Optional[Installed]:
    """The agent's application bundle when it has no command on PATH (the Cursor and Windsurf
    apps): the bundle's own program, named by its ``Contents/Info.plist``, and the version it
    declares there — so the signer of every catalogued program can be checked."""
    for sign in host.signs:
        info = Path(sign) / "Contents" / "Info.plist"
        if not sign.endswith(".app") or not info.is_file():
            continue
        try:
            with open(info, "rb") as handle:
                data = plistlib.load(handle)
        except (OSError, plistlib.InvalidFileException, ValueError):
            continue
        program = Path(sign) / "Contents" / "MacOS" / str(data.get("CFBundleExecutable") or "")
        if program.is_file():
            return Installed(str(program), parse(str(data.get("CFBundleShortVersionString") or "")))
    return None


def installed(home: Optional[Path] = None) -> dict[str, Installed]:
    """Each agent whose command (or application bundle) is on this machine, with its version (cached)."""
    with _lock:
        if time.monotonic() - float(_cache["at"]) < CACHE_SECONDS and _cache["found"]:   # type: ignore[arg-type]
            return dict(_cache["found"])   # type: ignore[call-overload]
        found = {}
        for host in HOSTS:
            program = _program(host, home or Path.home())
            if program:
                found[host.id] = Installed(program, _ask(program))
            elif (bundle := _bundle(host)) is not None:
                found[host.id] = bundle
        _cache.update(at=time.monotonic(), found=found)
        return dict(found)
