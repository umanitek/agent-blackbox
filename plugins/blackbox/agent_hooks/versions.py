"""Which version of each coding agent is installed here, and where its program is.

Read by asking the agent's own command for ``--version`` (bounded, cached for
:data:`CACHE_SECONDS`; an agent that does not answer has no version, never an error). The Docs
page compares it with the versions Blackbox was tested against.

Usage::

    from . import versions
    versions.installed()      # {"claude-code": Installed(path, version), …}
"""

from __future__ import annotations

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


def installed(home: Optional[Path] = None) -> dict[str, Installed]:
    """Each agent whose command is on this machine, with its version (cached)."""
    with _lock:
        if time.monotonic() - float(_cache["at"]) < CACHE_SECONDS and _cache["found"]:   # type: ignore[arg-type]
            return dict(_cache["found"])   # type: ignore[call-overload]
        found = {}
        for host in HOSTS:
            program = _program(host, home or Path.home())
            if program:
                found[host.id] = Installed(program, _ask(program))
        _cache.update(at=time.monotonic(), found=found)
        return dict(found)
