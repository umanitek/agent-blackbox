"""What is known of the sandboxed run a tool's output came from, for judging its refusals OUTSIDE
the sandbox (the dashboard's process): the profile its launcher applied and whether it has its own
PID namespace. LES-157: a check that reads the disk from here sees the outside view (KI-685: the
Docker socket is the sandbox's mask only inside), so the run's own profile decides.

The profile is read by the agent sandbox (a shield), which this package never imports: the composer
registers its answer with :func:`answer_hidden_sockets_with` (Observer-style seam).

Usage::

    answer_hidden_sockets_with(shields.run_hides_socket)      # the dashboard, once
    hides(SandboxRun("/…/claude-code.policy#ab12"), "/var/run/docker.sock")   # True / False / None
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SandboxRun:
    """*profile*: the profile the run's launcher applied (``<file>#<digest>``, from the run's own
    hook); *pid_namespace*: True when it runs in its own PID namespace (Linux below 6.12)."""

    profile: str = ""
    pid_namespace: bool = False


#: ``judge(profile, socket) -> bool``: does the profile a run started with hide *socket*?
_judge: list[Callable[[str, str], bool]] = []


def answer_hidden_sockets_with(judge: Callable[[str, str], bool]) -> None:
    """Registers how a run's profile is asked whether it hides a socket (one judge; the last wins)."""
    _judge[:] = [judge]


def hides(run: SandboxRun, socket: str) -> Optional[bool]:
    """Whether *run*'s profile hides *socket*; None when that can not be asked (no profile known, no
    judge registered, or the judge failed) — the caller then reads what it can see itself."""
    if not run.profile or not _judge:
        return None
    try:
        return bool(_judge[0](run.profile, socket))
    except Exception:   # health: allow BLE001 -- a judge's fault leaves the caller's own reading
        logger.warning("blackbox: the hidden-socket judge failed", exc_info=True)
        return None


__all__ = ["SandboxRun", "answer_hidden_sockets_with", "hides"]
