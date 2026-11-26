"""macOS: who signed a program, asked of ``codesign`` and Gatekeeper's ``spctl`` (see
:mod:`kernel.code_signing` for what each answer means). Each ``*_command`` builds one argument
list; :func:`run` runs it with a hard timeout."""

from __future__ import annotations

import subprocess
from typing import Optional

CODESIGN = "/usr/bin/codesign"
SPCTL = "/usr/sbin/spctl"
TIMEOUT_SECONDS = 5.0


def intact_command(path: str) -> list[str]:
    """The signature is intact: the code is what was signed."""
    return [CODESIGN, "--verify", "--strict", path]


def requirement_command(path: str, requirement: str) -> list[str]:
    """The signature satisfies the code *requirement* (who it chains to)."""
    return [CODESIGN, "--verify", f"-R={requirement}", path]


def notarisation_command(bundle: str) -> list[str]:
    """Gatekeeper's verdict on *bundle* (it names a notarised Developer ID)."""
    return [SPCTL, "--assess", "--type", "execute", "-vv", bundle]


def entitlements_command(path: str) -> list[str]:
    """The entitlements *path* is signed with, as plist XML."""
    return [CODESIGN, "-d", "--entitlements", "-", "--xml", path]


def display_command(path: str) -> list[str]:
    """What *path* claims about its signer (``codesign -dv`` only displays it)."""
    return [CODESIGN, "-dv", "--verbose=2", path]


def run(command: list[str]) -> Optional[tuple[int, str]]:
    """``(exit status, stdout + stderr)``, or None when the tool could not run in time."""
    try:
        done = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=TIMEOUT_SECONDS, stdin=subprocess.DEVNULL, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.returncode, (done.stdout or "") + (done.stderr or "")


__all__ = ["CODESIGN", "SPCTL", "TIMEOUT_SECONDS", "display_command", "entitlements_command", "intact_command",
           "notarisation_command", "requirement_command", "run"]
