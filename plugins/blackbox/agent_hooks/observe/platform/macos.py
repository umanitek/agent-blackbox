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


def process_users() -> str:
    """Every process as ``pid ruid euid``, one per line: the user that started it and the user it
    acts as. A program ``sudo`` started has BOTH 0; a setuid system tool (``ps``, ``sudo`` while it
    still asks for the password) has only the second."""
    return _run(["/bin/ps", "-axo", "pid=,ruid=,uid="])


def process_environment(pid: int) -> str:
    """*pid*'s command line followed by its environment (``NAME=value`` words) — only for this
    user's own processes, and empty for the programs macOS keeps closed."""
    return _run(["/bin/ps", "eww", "-o", "command=", "-p", str(int(pid))])


_CTL_KERN, _KERN_PROCARGS2 = 1, 49
_KERN_PROC, _KERN_PROC_PID = 14, 1
MAX_PROCARGS_BYTES = 1024 * 1024
#: ``struct kinfo_proc`` (sys/sysctl.h) on 64-bit macOS: its size, where the start time
#: (``kp_proc.p_starttime``, a timeval), the short program name (``kp_proc.p_comm``, 17 bytes)
#: and the parent (``kp_eproc.e_ppid``) are. Checked against ``ps`` on macOS 27.2 (2026-11-22).
_KINFO_SIZE, _START_AT, _COMM_AT, _COMM_SIZE, _PPID_AT = 648, 0, 243, 17, 560


def _procargs(pid: int) -> bytes:
    """The kernel's record of *pid*'s arguments and environment (b"" when it may not be read)."""
    try:
        libc = _libc()
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


def _libc() -> ctypes.CDLL:
    return ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


def _kinfo(libc: ctypes.CDLL, pid: int) -> tuple[int, float, str] | None:
    """(parent pid, start time, short program name) of *pid* from the kernel; None when gone."""
    mib = (ctypes.c_int * 4)(_CTL_KERN, _KERN_PROC, _KERN_PROC_PID, int(pid))
    size = ctypes.c_size_t(_KINFO_SIZE)
    buffer = ctypes.create_string_buffer(_KINFO_SIZE)
    if libc.sysctl(mib, 4, buffer, ctypes.byref(size), None, 0) != 0 or size.value != _KINFO_SIZE:
        return None   # no such process (the kernel answers an empty record)
    seconds = struct.unpack_from("q", buffer.raw, _START_AT)[0]
    parent = struct.unpack_from("i", buffer.raw, _PPID_AT)[0]
    name = buffer.raw[_COMM_AT:_COMM_AT + _COMM_SIZE].split(b"\0")[0].decode("utf-8", "replace")
    return parent, float(seconds), name


def _command(pid: int) -> str:
    """*pid*'s argv joined by spaces — what ``ps -o command=`` prints — or "" when unreadable."""
    raw = _procargs(pid)
    if len(raw) < 8:
        return ""
    argc = struct.unpack("i", raw[:4])[0]
    _program, _, rest = raw[4:].partition(b"\0")
    words = rest.lstrip(b"\0").split(b"\0")[:max(0, argc)]
    return " ".join(word.decode("utf-8", "replace") for word in words)


def process_ancestry(pid: int, limit: int) -> list[tuple[int, int, float, str]] | None:
    """*pid* and up to *limit* of its ancestors as ``(pid, ppid, started, command)``, nearest
    first — straight from the kernel, a few microseconds a process (no ``ps``, no full list).
    WHY (KI-552): a hook's ancestry was found by re-reading EVERY process with ``ps`` while the
    hook waited — hundreds of milliseconds each on a busy Mac, one at a time behind a lock — so
    under load every hook waited for it. [] when *pid* is gone; None when the kernel cannot be asked."""
    try:
        libc = _libc()
        chain = []
        current = int(pid)
        while current > 1 and len(chain) <= limit:
            found = _kinfo(libc, current)
            if found is None:
                break
            parent, started, name = found
            chain.append((current, parent, started, _command(current) or name))
            current = parent
        return chain
    except (OSError, ValueError, AttributeError, TypeError, struct.error):
        return None


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
