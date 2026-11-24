"""The sandbox's own tools on Linux, first on the SANDBOXED PATH only: a stand-in that says why for
each program that needs to raise its privileges (``sudo``, ``su``, ``pkexec``, ``crontab``, ``at``,
``snap``…). Inside, ``PR_SET_NO_NEW_PRIVS`` is set: a setuid or setgid program runs, but without
its privileges, and fails with its own words (``sudo``: 'The "no new privileges" flag is set') —
the stand-in says it plainly instead. An absolute ``/usr/bin/sudo`` still gets the program's own
refusal; the hook wording reads it (``agent_hooks.protect.sandbox_errors``).

No ``ps`` copy is needed (Linux's ``ps`` reads ``/proc`` with the agent's own rights).

Usage::

    refresh_tools(launchers)        # <launchers>/sandbox-tools made current
    tools_dir(launchers)            # where they live
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from ......kernel.bounded_files import atomic_write, read_small_text
from ..posix_scripts import standin

TOOLS_FOLDER = "sandbox-tools"
#: The programs that only work by raising their privileges (or, ``snap``, by a setuid helper).
SETUID_TOOLS = ("/usr/bin/sudo", "/usr/bin/su", "/bin/su", "/usr/bin/pkexec", "/usr/bin/doas", "/usr/bin/crontab",
                "/usr/bin/at", "/usr/bin/atq", "/usr/bin/atrm", "/usr/bin/batch", "/usr/bin/snap", "/usr/bin/newuidmap",
                "/usr/bin/newgidmap", "/usr/bin/passwd", "/usr/bin/chsh", "/usr/bin/newgrp")
SETUID_NOTE = ("the agent sandbox runs with no new privileges, so programs that raise them (sudo, su, pkexec, crontab, "
               "snap apps) can not work inside it; run it in your own terminal")
_TOOLS_STAMP = ".linux"


def tools_dir(launchers: str) -> str:
    return os.path.join(launchers, TOOLS_FOLDER)


def _present() -> list[str]:
    return sorted({os.path.basename(tool) for tool in SETUID_TOOLS if os.path.exists(tool)})


def refresh_tools(launchers: str, wanted: bool = True) -> bool:
    """Makes ``<launchers>/sandbox-tools`` hold a stand-in for each of :data:`SETUID_TOOLS` this
    machine has, again whenever that set changes; removes the folder when no agent is sandboxed
    (*wanted* False). Answers True when it wrote them. Fail-open: a read-only folder keeps none."""
    folder = tools_dir(launchers)
    if not wanted:
        shutil.rmtree(folder, ignore_errors=True)
        return False
    present = _present()
    stamp = " ".join(present) + "\n"
    marker = os.path.join(folder, _TOOLS_STAMP)
    if read_small_text(marker, len(stamp) + 1) == stamp:
        return False
    try:
        os.makedirs(folder, exist_ok=True)
        for name in present:
            atomic_write(Path(folder, name), standin(name, SETUID_NOTE), mode=0o755)
        atomic_write(Path(marker), stamp, mode=0o644)
    except OSError:
        return False
    return True


__all__ = ["SETUID_NOTE", "SETUID_TOOLS", "TOOLS_FOLDER", "refresh_tools", "tools_dir"]
