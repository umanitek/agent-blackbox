"""Linux: the process list and one process's environment, read straight from ``/proc``
(read-only; no program is run for them, so a hook's ancestry costs a few file reads) — and
Blackbox's own marks in the person's system journal (:func:`journal_marks`, ``journalctl``).

Each function answers in the macOS module's shapes (see the facade, ``platform/__init__``), so the
observer parses one format: :func:`process_table` prints ``ps -o lstart`` dates, computed from the
kernel's boot time (``/proc/stat`` ``btime``) plus the process's start tick (``stat`` field 22).
What Linux lets this user read is what is answered: every process's ``stat``, ``status`` and
``cmdline``; only this user's own processes' ``environ``, ``cwd`` and ``exe`` (another user's
answer "" — such an agent's config home is learned from its first hook event instead, as on macOS).

Every function takes ``proc_root`` (default ``/proc``) so a test hands it a fake tree.

An agent sandboxed on a kernel older than 6.12 runs in its own PID namespace, so its hooks report
namespace pids; :func:`host_pid` turns one back into the host's, from the launcher's
``BLACKBOX_SANDBOX_ID`` (its cgroup scope's name) and each process's ``NSpid``.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time

PROC_ROOT = "/proc"
#: ``environ`` and ``cmdline`` can be large; more than this is never needed.
MAX_READ_BYTES = 1024 * 1024
#: Small files (``stat``, ``status``, ``cgroup``).
MAX_SMALL_BYTES = 64 * 1024
#: ``stat``'s fields after ``(comm)``: index 0 is field 3 (state), so field N is index N - 3.
_PPID_INDEX, _STARTTIME_INDEX = 4 - 3, 22 - 3
#: ``ps -o lstart``'s date (the macOS module answers it, the observer parses it).
LSTART_FORMAT = "%a %b %d %H:%M:%S %Y"
#: The cgroup scope Blackbox's agent sandbox runs each agent in (design §1.1 step 8).
SANDBOX_SCOPE_MARK = "blackbox-agent-"
#: The sandbox ids ``blackbox-sandbox`` exports: its scope's unit name, or ``noscope-<id>`` without one.
SANDBOX_ID = re.compile(r"^(?:blackbox-agent-(?:[0-9a-f]{12}|nodigest)-[0-9a-f]{1,16}\.scope|noscope-[0-9a-f]{1,16})$")
SANDBOX_ID_VARIABLE = "BLACKBOX_SANDBOX_ID"
#: ``readlink`` of a deleted executable or folder ends with this.
_DELETED = " (deleted)"


def _read(path: str, limit: int = MAX_SMALL_BYTES) -> bytes | None:
    """Up to *limit* bytes of *path*; None when it cannot be read (gone, another user's)."""
    try:
        with open(path, "rb") as handle:
            return handle.read(limit)
    except OSError:
        return None


def _text(path: str) -> str:
    raw = _read(path)
    return raw.decode("utf-8", "replace") if raw is not None else ""


def _words(raw: bytes | None) -> list[str]:
    """NUL-separated words (``cmdline``, ``environ``) without the trailing empty one."""
    if not raw:
        return []
    return [word.decode("utf-8", "replace") for word in raw.rstrip(b"\0").split(b"\0")]


def _pids(proc_root: str) -> list[int]:
    try:
        return sorted(int(name) for name in os.listdir(proc_root) if name.isdigit())
    except OSError:
        return []


def _stat(proc_root: str, pid: int) -> tuple[str, list[str]] | None:
    """(short program name, the fields after it) of ``/proc/<pid>/stat``; None when gone. The name
    is in parentheses and may itself hold spaces and parentheses, so it ends at the LAST ``)``."""
    text = _text(f"{proc_root}/{pid}/stat")
    head, closing, rest = text.rpartition(")")
    if not closing or "(" not in head:
        return None
    return head.partition("(")[2], rest.split()


def _boot_time(proc_root: str) -> float:
    for line in _text(f"{proc_root}/stat").splitlines():
        if line.startswith("btime "):
            value = line.split()[1]
            return float(value) if value.isdigit() else 0.0
    return 0.0


def _ticks_per_second() -> int:
    try:
        return int(os.sysconf("SC_CLK_TCK")) or 100
    except (ValueError, OSError, AttributeError):
        return 100


def _started(fields: list[str], boot: float, ticks: int) -> float:
    tick = fields[_STARTTIME_INDEX] if len(fields) > _STARTTIME_INDEX else ""
    return boot + int(tick) / ticks if tick.isdigit() and boot else 0.0


def _ppid(fields: list[str]) -> int:
    value = fields[_PPID_INDEX] if len(fields) > _PPID_INDEX else ""
    return int(value) if value.isdigit() else 0


def _command(proc_root: str, pid: int, name: str) -> str:
    """What ``ps -o command=`` prints: the argv joined by spaces, ``[name]`` for a kernel thread."""
    return " ".join(_words(_read(f"{proc_root}/{pid}/cmdline", MAX_READ_BYTES))) or f"[{name}]"


def process_table(proc_root: str = PROC_ROOT) -> str:
    """Every process as ``pid ppid <lstart: 5 words> command…``, one per line ("" when ``/proc``
    cannot be read)."""
    boot, ticks = _boot_time(proc_root), _ticks_per_second()
    lines = []
    for pid in _pids(proc_root):
        found = _stat(proc_root, pid)
        if found is None:
            continue   # ended while the list was read
        name, fields = found
        started = _started(fields, boot, ticks)
        lstart = time.strftime(LSTART_FORMAT, time.localtime(started)) if started else "Thu Jan 01 00:00:00 1970"
        lines.append(f"{pid} {_ppid(fields)} {lstart} {_command(proc_root, pid, name)}")
    return "\n".join(lines) + ("\n" if lines else "")


def _status(proc_root: str, pid: int) -> dict[str, str]:
    """``/proc/<pid>/status`` as {field: value} ({} when gone)."""
    fields = {}
    for line in _text(f"{proc_root}/{pid}/status").splitlines():
        key, colon, value = line.partition(":")
        if colon:
            fields[key.strip()] = value.strip()
    return fields


def process_users(proc_root: str = PROC_ROOT) -> str:
    """Every process as ``pid ruid euid``, one per line (``status``'s ``Uid:`` real and effective)."""
    lines = []
    for pid in _pids(proc_root):
        uids = _status(proc_root, pid).get("Uid", "").split()
        if len(uids) >= 2 and uids[0].isdigit() and uids[1].isdigit():
            lines.append(f"{pid} {uids[0]} {uids[1]}")
    return "\n".join(lines) + ("\n" if lines else "")


def process_environment(pid: int, proc_root: str = PROC_ROOT) -> str:
    """*pid*'s command line followed by its environment (``NAME=value`` words), as macOS's
    ``ps eww`` prints it — only for this user's own processes ("" otherwise)."""
    environment = _read(f"{proc_root}/{int(pid)}/environ", MAX_READ_BYTES)
    if environment is None:
        return ""
    return " ".join(_words(_read(f"{proc_root}/{int(pid)}/cmdline", MAX_READ_BYTES)) + _words(environment))


def process_variable(pid: int, name: str, proc_root: str = PROC_ROOT) -> str:
    """The value of the environment variable *name* in process *pid*, whole (spaces kept); ""
    when it is not set or the process may not be read."""
    prefix = f"{name}="
    for word in _words(_read(f"{proc_root}/{int(pid)}/environ", MAX_READ_BYTES)):
        if word.startswith(prefix):
            return word[len(prefix):]
    return ""


def process_argv(pid: int, proc_root: str = PROC_ROOT) -> list[str]:
    """*pid*'s arguments, each word WHOLE ([] when unreadable). Like macOS's procargs2, a program
    may rewrite its own ``cmdline``, so this is what it says it runs, not proof."""
    return _words(_read(f"{proc_root}/{int(pid)}/cmdline", MAX_READ_BYTES))


def process_ancestry(pid: int, limit: int, proc_root: str = PROC_ROOT) -> list[tuple[int, int, float, str]] | None:
    """*pid* and up to *limit* of its ancestors as ``(pid, ppid, started, command)``, nearest
    first, from each one's ``stat`` and ``cmdline``. [] when *pid* is gone; None when ``/proc``
    cannot be read at all (callers then read the whole list)."""
    if not os.path.isdir(proc_root):
        return None
    boot, ticks = _boot_time(proc_root), _ticks_per_second()
    chain = []
    current = int(pid)
    while current > 1 and len(chain) <= limit:
        found = _stat(proc_root, current)
        if found is None:
            break
        name, fields = found
        parent = _ppid(fields)
        chain.append((current, parent, _started(fields, boot, ticks), _command(proc_root, current, name)))
        current = parent
    return chain


def _link(path: str) -> str:
    try:
        target = os.readlink(path)
    except OSError:
        return ""
    return target.removesuffix(_DELETED)


def process_cwd(pid: int, proc_root: str = PROC_ROOT) -> str:
    """The folder process *pid* works in; "" when it is gone or may not be read."""
    return _link(f"{proc_root}/{int(pid)}/cwd")


def process_path(pid: int, proc_root: str = PROC_ROOT) -> str:
    """The executable *pid* runs; "" when gone or not readable."""
    return _link(f"{proc_root}/{int(pid)}/exe")


def process_sandboxed(pid: int, proc_root: str = PROC_ROOT) -> bool | None:
    """Whether *pid* runs in a sandbox: Blackbox's agent sandbox (its cgroup scope), or any
    sandbox that set no-new-privileges, a seccomp filter AND its own mount namespace (bubblewrap,
    Flatpak, snap, a container). None when it cannot be read."""
    status = _status(proc_root, pid)
    if not status:
        return None
    if SANDBOX_SCOPE_MARK in _text(f"{proc_root}/{int(pid)}/cgroup"):
        return True
    restricted = status.get("NoNewPrivs") == "1" and status.get("Seccomp") == "2"
    own_mounts = _link(f"{proc_root}/{int(pid)}/ns/mnt")
    return bool(restricted and own_mounts and own_mounts != _link(f"{proc_root}/self/ns/mnt"))


def host_pid(sandbox_id: str, pid: int, proc_root: str = PROC_ROOT) -> int:
    """The host pid of process *pid* as seen inside the sandbox *sandbox_id* (a PID namespace's
    number); *pid* itself when no process of that sandbox has it as its innermost pid (no PID
    namespace: the number is the host's already) or when *sandbox_id* is not one the launcher makes."""
    if pid <= 0 or not SANDBOX_ID.match(sandbox_id or ""):
        return pid
    scope = "/" + sandbox_id if sandbox_id.endswith(".scope") else ""
    for candidate in _pids(proc_root):
        levels = _status(proc_root, candidate).get("NSpid", "").split()
        if len(levels) < 2 or levels[-1] != str(pid):
            continue
        if scope and any(line.endswith(scope) for line in _text(f"{proc_root}/{candidate}/cgroup").splitlines()):
            return candidate
        if not scope and process_variable(candidate, SANDBOX_ID_VARIABLE, proc_root) == sandbox_id:
            return candidate
    return pid


#: The most journal marks read in one look, and how long ``journalctl`` may take.
MAX_JOURNAL_MARKS, JOURNAL_SECONDS = 500, 10.0
_JOURNAL_FIELD = re.compile(r"^(?:BLACKBOX_[A-Z_]{1,40}|_PID|_SYSTEMD_USER_UNIT|_SYSTEMD_CGROUP|__REALTIME_TIMESTAMP)$")


def journal_marks(tag: str, cursor_file: str) -> list[dict[str, str]] | None:
    """The person's journal entries tagged *tag* written since the last call that used *cursor_file*
    (``journalctl --cursor-file`` keeps the place), oldest first, each as its ``BLACKBOX_*`` fields
    and the journal's own trusted ones (``_PID``, the unit, the time); None when the journal can
    not be read here. At most :data:`MAX_JOURNAL_MARKS` per call."""
    try:
        done = subprocess.run(["journalctl", "--user", "--quiet", "--no-pager", "--output=json", f"--identifier={tag}",
                               f"--cursor-file={cursor_file}", f"--lines={MAX_JOURNAL_MARKS}"],
                              capture_output=True, text=True, timeout=JOURNAL_SECONDS, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    marks = []
    for line in done.stdout.splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict):
            marks.append({key: str(value)[:600] for key, value in entry.items() if _JOURNAL_FIELD.match(key) and isinstance(value, str)})
    return marks
