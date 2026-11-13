"""The DKG node's process limits: settings it can only get from its environment.

DKG reads the V8 heap cap (``NODE_OPTIONS``) and the store queue limit
(``DKG_STORE_QUEUE_LIMIT``) from its process environment only; no config.json
key exists for them (dkg-storage store-priority-scheduler.js, 10.0.22). So
whoever launches the node must pass them, or the node runs with Node's ~4 GB
default heap and DKG's default queue.

The graph-list projection switch (``DKG_LIST_CONTEXT_GRAPHS_PROJECTION``) is
deliberately NOT one of them: it stays an install-time setting. With it on, the
node's context-graph listing leaves out the verified graph it is subscribed to
(10.0.22, bench 2026-10-09: 36 rows without it vs 39 with subscribed=true), so
a running node with it on reads as "not subscribed" — the dashboard says so
and every sync re-subscribes.

The installer chooses them once and records them with :func:`write_process_limits`
(``blackbox-process-limits.json`` in the node's home); every node restart
Blackbox makes reads them back (:func:`read_process_limits`) and applies them
(:func:`apply_process_limits`), falling back to the installer's own defaults
(:func:`default_process_limits`). This closes the gap Umanitek's PR #21 closed
with live process capture: a restart by ``blackbox sync`` or the dashboard no
longer drops the limits.

Shared with the installer through ``scripts/blackbox-dkg-runtime-fingerprint.py``,
which loads this file by path, so it imports nothing from the plugin. Standard
library only.

Usage::

    limits = read_process_limits(dkg_home) or default_process_limits()
    apply_process_limits(env, limits)      # env: the launch environment, edited in place
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional


class ProcessLimitsError(RuntimeError):
    """Raised when a safe process limit cannot be chosen."""


_CGROUP_MEMORY_LIMIT_PATHS = (
    Path("/sys/fs/cgroup/memory.max"),
    Path("/sys/fs/cgroup/memory/memory.limit_in_bytes"),
)
_UNLIMITED_MEMORY_THRESHOLD = 1 << 50
_V8_HEAP_OPTION_RE = re.compile(
    r"(?:^|\s)--max[-_]old[-_]space[-_]size(?:=|\s)",
    re.IGNORECASE,
)


def read_cgroup_memory_limit() -> int | None:
    """Return the active cgroup memory ceiling, if it is finite."""
    for path in _CGROUP_MEMORY_LIMIT_PATHS:
        try:
            raw = path.read_text(encoding="utf-8-sig").strip()
        except (OSError, UnicodeError):
            continue
        if raw == "max":
            return None
        if not raw:
            continue
        try:
            limit = int(raw)
        except ValueError:
            continue
        if limit >= _UNLIMITED_MEMORY_THRESHOLD:
            return None
        if limit > 0:
            return limit
    return None


def read_physical_memory() -> int | None:
    """Return physical RAM in bytes using only the standard library."""
    try:
        pages = int(os.sysconf("SC_PHYS_PAGES"))
        page_size = int(os.sysconf("SC_PAGE_SIZE"))
        if pages > 0 and page_size > 0:
            return pages * page_size
    except (AttributeError, OSError, TypeError, ValueError):
        pass

    if sys.platform == "win32":
        try:
            import ctypes

            class MemoryStatus(ctypes.Structure):
                _fields_ = [
                    ("length", ctypes.c_ulong),
                    ("memory_load", ctypes.c_ulong),
                    ("total_physical", ctypes.c_ulonglong),
                    ("available_physical", ctypes.c_ulonglong),
                    ("total_page_file", ctypes.c_ulonglong),
                    ("available_page_file", ctypes.c_ulonglong),
                    ("total_virtual", ctypes.c_ulonglong),
                    ("available_virtual", ctypes.c_ulonglong),
                    ("available_extended_virtual", ctypes.c_ulonglong),
                ]

            status = MemoryStatus()
            status.length = ctypes.sizeof(status)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return int(status.total_physical)
        except (AttributeError, OSError, TypeError, ValueError):
            pass
    return None


def effective_memory_mb() -> Optional[int]:
    """The machine's memory ceiling in MB — the smaller of the cgroup limit and
    physical RAM — or None when neither could be read."""
    limits = [
        value
        for value in (read_cgroup_memory_limit(), read_physical_memory())
        if value and 0 < value < _UNLIMITED_MEMORY_THRESHOLD
    ]
    return min(limits) // (1024 * 1024) if limits else None


def resolve_dkg_heap_mb(default_mb: int = 8192) -> int:
    """Choose a V8 heap cap that fits both the host and its cgroup.

    DKG snapshot recovery retains complete RDF phases in memory. Node's
    roughly 4 GiB default old-space cap is too small for the Blackbox graph,
    while an unconditional 8 GiB cap is unsafe in a smaller container. The cap
    is HALF the effective memory, never more than ``default_mb``: the node's
    Oxigraph store is a second process on the same machine that grows to
    2–2.5 GB during a first sync, and a 4 GB bench whose node was allowed 75%
    was killed by the kernel twice before the sync finished (2026-10-22).
    """
    if default_mb <= 0:
        raise ProcessLimitsError("default DKG heap must be positive")
    limit_mb = effective_memory_mb()
    if limit_mb is None:
        return default_mb
    sized = limit_mb // 2
    if sized <= 0:
        raise ProcessLimitsError("effective memory limit is too small for DKG")
    return min(default_mb, sized)


#: Sync transfers the node runs at once and its queue: the node's own defaults (10, 20)
#: from SMALL_MACHINE_MB up; below that (4, 8) — every transfer in flight is store work,
#: and on a 4 GB machine the store's peak at 10 slots was what the kernel killed.
SYNC_SLOTS_FULL = (10, 20)
SYNC_SLOTS_SMALL = (4, 8)
SMALL_MACHINE_MB = 8192


def sync_slots(memory_mb: Optional[int] = None) -> tuple[int, int]:
    """``(max_inflight, queue_limit)`` for a machine with *memory_mb* (default:
    this machine; unknown memory gets the node's own defaults)."""
    limit = effective_memory_mb() if memory_mb is None else memory_mb
    if limit is None or limit >= SMALL_MACHINE_MB:
        return SYNC_SLOTS_FULL
    return SYNC_SLOTS_SMALL


def merge_node_options(node_options: str, heap_mb: int) -> str:
    """Add a DKG heap cap while preserving explicit Node options."""
    existing = str(node_options or "").strip()
    if _V8_HEAP_OPTION_RE.search(existing):
        return existing
    heap = int(heap_mb)
    if heap <= 0:
        raise ProcessLimitsError("DKG heap must be positive")
    option = f"--max-old-space-size={heap}"
    return f"{existing} {option}".strip()


#: The installer's queue limit for the store (DKG's own default is lower).
DEFAULT_STORE_QUEUE_LIMIT = 512
#: The installer's default heap ceiling, in MB, before host/cgroup sizing.
DEFAULT_HEAP_CEILING_MB = 8192
#: The record of the limits the installer chose, inside the node's home.
PROFILE_NAME = "blackbox-process-limits.json"
_PROFILE_VERSION = 2   # 2: the projection switch left the record (install-time only)
_MAX_PROFILE_BYTES = 4096
_MAX_SETTING = 2_147_483_647
_EXPLICIT_HEAP_RE = re.compile(r"--max[-_]old[-_]space[-_]size(?:=|\s+)([0-9]+)", re.IGNORECASE)


@dataclass(frozen=True)
class ProcessLimits:
    """The node's environment-only limits.

    ``heap_mb`` — V8 old-space cap in MB; ``store_queue_limit`` — the store's
    common queue limit. Both positive integers; build through
    :func:`default_process_limits` or :func:`read_process_limits`.
    """

    heap_mb: int
    store_queue_limit: int


def _bounded_positive(value: object) -> bool:
    return type(value) is int and 0 < value <= _MAX_SETTING


def explicit_heap_mb(node_options: str) -> Optional[int]:
    """The heap cap an operator already set in *node_options*, if any."""
    match = _EXPLICIT_HEAP_RE.search(str(node_options or ""))
    value = int(match.group(1)) if match else None
    return value if value is not None and _bounded_positive(value) else None


def default_process_limits(node_options: str = "") -> ProcessLimits:
    """The installer's limits for this host: an explicit heap in *node_options*
    wins, else 75% of RAM / cgroup capped at 8 GB; queue 512."""
    heap = explicit_heap_mb(node_options) or resolve_dkg_heap_mb(DEFAULT_HEAP_CEILING_MB)
    return ProcessLimits(heap, DEFAULT_STORE_QUEUE_LIMIT)


def write_process_limits(dkg_home: str, limits: ProcessLimits) -> Path:
    """Record *limits* in the node's home (atomic tmp + rename); returns the path."""
    if not (_bounded_positive(limits.heap_mb) and _bounded_positive(limits.store_queue_limit)):
        raise ProcessLimitsError("process limits must be positive integers")
    home = Path(dkg_home).expanduser()
    home.mkdir(parents=True, exist_ok=True)
    path = home / PROFILE_NAME
    descriptor, temporary = tempfile.mkstemp(prefix=PROFILE_NAME + ".tmp-", dir=home)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump({"version": _PROFILE_VERSION, "limits": asdict(limits)}, handle, sort_keys=True)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return path


def read_process_limits(dkg_home: str) -> Optional[ProcessLimits]:
    """The recorded limits, or None when absent or not exactly well-formed
    (callers then use :func:`default_process_limits`)."""
    path = Path(dkg_home).expanduser() / PROFILE_NAME
    try:
        with path.open("rb") as handle:
            raw = handle.read(_MAX_PROFILE_BYTES + 1)
        if len(raw) > _MAX_PROFILE_BYTES:
            return None
        data = json.loads(raw)
    except (OSError, ValueError):
        return None
    if type(data) is not dict or data.get("version") != _PROFILE_VERSION:
        return None
    limits = data.get("limits")
    if type(limits) is not dict or set(limits) != set(ProcessLimits.__dataclass_fields__):
        return None
    if not (_bounded_positive(limits["heap_mb"]) and _bounded_positive(limits["store_queue_limit"])):
        return None
    return ProcessLimits(**limits)


def apply_process_limits(env: dict[str, str], limits: ProcessLimits) -> None:
    """Put *limits* into the launch environment *env* (in place). A value the
    environment already carries wins: an explicit heap in ``NODE_OPTIONS`` or an
    explicit queue limit. The install-time projection switch is removed: the
    running node must list the graphs it is subscribed to (see module doc)."""
    env["NODE_OPTIONS"] = merge_node_options(env.get("NODE_OPTIONS", ""), limits.heap_mb)
    env.setdefault("DKG_STORE_QUEUE_LIMIT", str(limits.store_queue_limit))
    env.pop("DKG_LIST_CONTEXT_GRAPHS_PROJECTION", None)
