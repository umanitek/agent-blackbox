"""The operating-system seam of the agent observer: what it reads to see which agent
processes exist is read here, one module per operating system (per-OS structure, 2026-11-21).

Each function answers raw text, or ``""`` when this machine cannot be read that way, so a missing
tool degrades to "no process seen", never to an error. READ-ONLY by construction: nothing here
(or anywhere in ``observe``) signals, stops or changes a process.

``macos.py`` reads the kernel and ``ps``; ``linux.py`` reads ``/proc``; ``unsupported.py`` sees nothing.

Pattern: **Strategy** (one module per OS) behind a **Facade** (this module).

Usage::

    from . import platform
    platform.process_table()        # "pid ppid <start> command…" lines, "" when unreadable
    platform.process_environment(1234)
    platform.process_users()        # "pid ruid euid" lines (who started each process, who it acts as)
    platform.process_variable(1234, "CLAUDE_CONFIG_DIR")   # one variable's value, spaces kept; "" when unreadable
    platform.process_argv(1234)     # ["claude", "--settings", '{"a": 1}'] — each word whole; [] when unreadable
    platform.process_ancestry(1234, 12)  # [(pid, ppid, started, command)] up its parents; [] gone, None unreadable
    platform.process_path(1234)     # the executable it runs ("" when unreadable)
    platform.process_sandboxed(1234)   # the kernel runs it in a sandbox: True / False, None when unknown
    platform.host_pid("blackbox-agent-…scope", 2)   # a PID-namespace pid as the host's (Linux below 6.12)
"""

from __future__ import annotations

import sys

if sys.platform == "darwin":
    from .macos import (host_pid, process_ancestry, process_argv, process_cwd, process_environment, process_path, process_sandboxed,
                        process_table, process_users, process_variable)
elif sys.platform.startswith("linux"):
    from .linux import (host_pid, process_ancestry, process_argv, process_cwd, process_environment, process_path, process_sandboxed,
                        process_table, process_users, process_variable)
else:
    from .unsupported import (host_pid, process_ancestry, process_argv, process_cwd, process_environment, process_path, process_sandboxed,
                              process_table, process_users, process_variable)

__all__ = ["host_pid", "process_ancestry", "process_argv", "process_cwd", "process_environment", "process_path", "process_sandboxed",
           "process_table", "process_users", "process_variable"]
