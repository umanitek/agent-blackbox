"""Whether an agent process was started by Blackbox's own sandbox launcher — the one signal that
lets the back-stop wait longer for its first hook event before calling the run unseen.

Linux round L7 (BB-LINUX-PENDING-b4bf05, Medium): every sandboxed start raised a false "X is
running without Blackbox" notice and finding — the back-stop's grace is 20 s, and an agent started
through the launcher on the busy VM sent its first hook event at +23 s (the launcher makes its
namespaces and waits for the helper's network rules first; a hooks-only start sent it at +9 s).

The signal is the launcher's own: it exports ``BLACKBOX_SANDBOX_PROFILE=<profile>#<digest>`` to
the agent it starts (``shields/files/sandbox/platform/posix_scripts.pick_profile``). It counts only
when the profile is a file inside Blackbox's sandbox folder and its recorded digest is that file's
own (line 2, ``sha256:…``) — a stale or invented value does not count.

WHAT IT CAN NOT DO — the security argument (LES-154): an agent's environment is the agent's own,
so a process could carry this value without having been launched by Blackbox. The signal therefore
never SUPPRESSES the alert: it only lengthens the grace from ``views.GRACE_SECONDS`` to
``views.LAUNCHED_GRACE_SECONDS`` (bounded), after which a launched run with no hook event is
reported exactly like any other; and a run whose hooks are known to be switched off
(``hooks_skipped``: ``--bare``, a project switch, untrusted Codex hooks) is reported at once,
launched or not. The worst a forged value buys is a delayed finding, never a missing one.

Usage::

    launched_by_blackbox(pid)   # True / False
"""

from __future__ import annotations

import re
from pathlib import Path

from ...kernel import constants
from . import platform

#: The variable Blackbox's launcher exports to the agent it starts (``runner.SANDBOX_PROFILE_ENV``).
PROFILE_ENV = "BLACKBOX_SANDBOX_PROFILE"
#: A profile's own digest, on its second line (the launcher reads the same line).
_DIGEST = re.compile(r"sha256:([0-9a-f]{16,128})")
#: The most of a profile read to find its digest line.
MAX_HEAD_BYTES = 4096


def _sandbox_home() -> Path:
    return constants.blackbox_home() / "sandbox"   # File Shield's sandbox folder (shields.files.sandbox.layout.home)


def launched_by_blackbox(pid: int) -> bool:
    """True when process *pid* carries the profile Blackbox's launcher hands the agent it starts:
    a profile file inside Blackbox's sandbox folder whose own digest matches the one recorded."""
    value = platform.process_variable(pid, PROFILE_ENV)
    if "#" not in value:
        return False
    file, digest = value.rsplit("#", 1)
    try:
        path = Path(file).resolve(strict=True)
        home = _sandbox_home().resolve()
        if not path.is_relative_to(home) or not path.is_file():
            return False
        with open(path, "rb") as handle:
            head = handle.read(MAX_HEAD_BYTES).decode("utf-8", "replace").splitlines()
    except (OSError, ValueError):
        return False
    found = _DIGEST.search(head[1]) if len(head) > 1 else None
    return bool(digest) and found is not None and found.group(1) == digest


__all__ = ["PROFILE_ENV", "launched_by_blackbox"]
