"""System status: this machine's CPU, memory, disks and network interfaces, live.

One cheap reading (psutil, no subprocess — a few milliseconds) for Network Shield's "System
status": CPU in total and per core, load average, memory and swap, disk space (``/`` and macOS's
data volume) and disk throughput, each network interface's counters with their rates, uptime,
how many processes run and the battery when there is one. Rates (bytes per second) are worked
out against the previous reading, kept in this process; the first reading's rates are 0.

CPU percentages come from ``psutil.cpu_percent(interval=None)`` — the use since the previous
call, never a blocking wait — so the first reading of a fresh process is primed and reads 0.

Usage::

    status = reading()        # plain JSON: {"cpu": {...}, "memory": {...}, "interfaces": [...], ...}
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any, Optional

import psutil

#: Disk volumes shown: the system volume and, on macOS, where the person's data lives.
VOLUMES = ("/", "/System/Volumes/Data")
MAX_INTERFACES = 24
MAX_CORES = 128
_MEMORY_FIELDS = ("total", "available", "used", "free", "active", "inactive", "wired")

_lock = threading.Lock()
_previous: dict[str, Any] = {"at": 0.0, "disk": None, "net": {}}
_primed = {"cpu": False}


def _rate(now_value: int, before: Optional[int], elapsed: float) -> int:
    if before is None or elapsed <= 0:
        return 0
    return max(0, int((now_value - before) / elapsed))


def _cpu() -> dict[str, Any]:
    if not _primed["cpu"]:   # the first call only starts the clock (it would read 0.0 anyway)
        psutil.cpu_percent(interval=None)
        psutil.cpu_percent(interval=None, percpu=True)
        _primed["cpu"] = True
    total = psutil.cpu_percent(interval=None)
    cores = psutil.cpu_percent(interval=None, percpu=True)[:MAX_CORES]
    try:
        load = [round(value, 2) for value in os.getloadavg()]
    except OSError:
        load = []
    return {"percent": round(total, 1), "cores": [round(value, 1) for value in cores], "load": load,
            "logical": psutil.cpu_count() or len(cores), "physical": psutil.cpu_count(logical=False) or 0}


def _memory() -> dict[str, Any]:
    memory = psutil.virtual_memory()
    out = {name: int(getattr(memory, name)) for name in _MEMORY_FIELDS if hasattr(memory, name)}
    out["percent"] = round(memory.percent, 1)
    swap = psutil.swap_memory()
    return {**out, "swap": {"total": int(swap.total), "used": int(swap.used), "percent": round(swap.percent, 1)}}


def _disks() -> list[dict[str, Any]]:
    found, seen = [], set()
    for volume in VOLUMES:
        try:
            usage = psutil.disk_usage(volume)
        except OSError:
            continue
        key = (usage.total, usage.used)
        if key in seen:   # one volume mounted twice reads the same
            continue
        seen.add(key)
        found.append({"mount": volume, "total": int(usage.total), "used": int(usage.used), "free": int(usage.free),
                      "percent": round(usage.percent, 1)})
    return found


def _interfaces(counters: dict[str, Any], stats: dict[str, Any], before: dict[str, Any], elapsed: float) -> list[dict[str, Any]]:
    found = []
    for name, now_counts in list(counters.items())[:MAX_INTERFACES]:
        stat = stats.get(name)
        was = before.get(name)
        if not (stat and stat.isup) and not (now_counts.bytes_recv or now_counts.bytes_sent):
            continue
        found.append({
            "name": name, "up": bool(stat and stat.isup), "speed_mbps": int(getattr(stat, "speed", 0) or 0),
            "loopback": name.startswith("lo"),
            "bytes_in": int(now_counts.bytes_recv), "bytes_out": int(now_counts.bytes_sent),
            "packets_in": int(now_counts.packets_recv), "packets_out": int(now_counts.packets_sent),
            "errors": int(now_counts.errin + now_counts.errout), "drops": int(now_counts.dropin + now_counts.dropout),
            "rate_in": _rate(now_counts.bytes_recv, was.bytes_recv if was else None, elapsed),
            "rate_out": _rate(now_counts.bytes_sent, was.bytes_sent if was else None, elapsed),
        })
    found.sort(key=lambda item: (item["loopback"], -(item["rate_in"] + item["rate_out"]), -(item["bytes_in"] + item["bytes_out"])))
    return found


def _battery() -> Optional[dict[str, Any]]:
    try:
        battery = psutil.sensors_battery()
    except (AttributeError, NotImplementedError, OSError):
        return None
    if battery is None:
        return None
    left = battery.secsleft if isinstance(battery.secsleft, int) and battery.secsleft >= 0 else None
    return {"percent": round(float(battery.percent), 1), "plugged": bool(battery.power_plugged), "seconds_left": left}


def reading(now: Optional[float] = None) -> dict[str, Any]:
    """One reading of the whole machine (see the module doc), plain JSON."""
    now = now or time.time()
    disk_io = psutil.disk_io_counters()
    net = psutil.net_io_counters(pernic=True)
    with _lock:
        elapsed = now - float(_previous["at"]) if _previous["at"] else 0.0
        before_disk, before_net = _previous["disk"], _previous["net"]
        _previous.update(at=now, disk=disk_io, net=net)
    disk_rates = {"read": _rate(disk_io.read_bytes, before_disk.read_bytes if before_disk else None, elapsed),
                  "write": _rate(disk_io.write_bytes, before_disk.write_bytes if before_disk else None, elapsed)} if disk_io else {"read": 0, "write": 0}
    boot = psutil.boot_time()
    return {
        "taken_at": now, "cpu": _cpu(), "memory": _memory(), "disks": _disks(), "disk_io": disk_rates,
        "interfaces": _interfaces(net, psutil.net_if_stats(), before_net, elapsed),
        "uptime_seconds": int(now - boot), "boot_time": boot, "processes": len(psutil.pids()), "battery": _battery(),
    }
