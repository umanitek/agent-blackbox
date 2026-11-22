"""macOS: the process list and one process's environment (read-only).

``ps`` prints an environment as words, so a value with a space cannot be told from two values;
:func:`process_variable` asks the kernel instead (``sysctl kern.procargs2``: the same data, with
each ``NAME=value`` kept whole). Both read only what macOS lets this user read: this user's own
processes, and not the programs Apple ships (``/bin/sleep``, ``/bin/sh`` answer with no
environment). Measured on macOS 27.2.1, 2026-11-22: a coding agent (a Developer ID program, or
``node`` running one) answers with its full environment; a process of ANOTHER user answers
nothing without root — such an agent's config home is learned from its first hook event instead.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import struct
import subprocess

TIMEOUT_SECONDS = 4.0
MAX_OUTPUT_CHARS = 4 * 1024 * 1024


def _run(argv: list[str]) -> str:
    try:
        done = subprocess.run(argv, capture_output=True, encoding="utf-8", errors="replace", timeout=TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    return done.stdout[:MAX_OUTPUT_CHARS] if done.returncode == 0 else ""


def process_table() -> str:
    """Every process as ``pid ppid <lstart: 5 words> command…``, one per line."""
    return _run(["/bin/ps", "-axo", "pid=,ppid=,lstart=,command="])


def process_environment(pid: int) -> str:
    """*pid*'s command line followed by its environment (``NAME=value`` words) — only for this
    user's own processes, and empty for the programs macOS keeps closed."""
    return _run(["/bin/ps", "eww", "-o", "command=", "-p", str(int(pid))])


_CTL_KERN, _KERN_PROCARGS2 = 1, 49
MAX_PROCARGS_BYTES = 1024 * 1024


def _procargs(pid: int) -> bytes:
    """The kernel's record of *pid*'s arguments and environment (b"" when it may not be read)."""
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        mib = (ctypes.c_int * 3)(_CTL_KERN, _KERN_PROCARGS2, int(pid))
        size = ctypes.c_size_t(0)
        if libc.sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0 or not 0 < size.value <= MAX_PROCARGS_BYTES:
            return b""
        buffer = ctypes.create_string_buffer(size.value)
        if libc.sysctl(mib, 3, buffer, ctypes.byref(size), None, 0) != 0:
            return b""
        return buffer.raw[:size.value]
    except (OSError, ValueError, AttributeError, TypeError):
        return b""


def process_variable(pid: int, name: str) -> str:
    """The value of the environment variable *name* in process *pid*, whole (spaces kept); ""
    when it is not set or the process may not be read."""
    raw = _procargs(pid)
    if len(raw) < 8:
        return ""
    argc = struct.unpack("i", raw[:4])[0]
    _program, _, rest = raw[4:].partition(b"\0")
    words = rest.lstrip(b"\0").split(b"\0")
    prefix = name.encode("utf-8") + b"="
    for word in words[max(0, argc):]:
        if word.startswith(prefix):
            return word[len(prefix):].decode("utf-8", "replace")
    return ""
