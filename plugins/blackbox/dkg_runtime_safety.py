"""Preserve only typed safety settings from Blackbox's own DKG runtime.

The daemon environment is never persisted or replayed. A profile belongs to
one canonical home and CLI installation, and contains no loader options or
credentials. Current caller settings take precedence over captured settings.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import json
import math
import os
from pathlib import Path
import re
import shlex
import tempfile
from typing import Dict, Mapping, Optional, Sequence

import psutil


PROFILE_NAME = ".blackbox-runtime-safety.json"
_MAX_PROFILE_BYTES = 4096
_MAX_SETTING = 2_147_483_647
_MAX_PROCESS_SCAN = 2048
_QUEUE_FIELDS = {
    "store_queue_limit": "DKG_STORE_QUEUE_LIMIT",
    "store_ack_queue_limit": "DKG_STORE_ACK_QUEUE_LIMIT",
    "store_health_queue_limit": "DKG_STORE_HEALTH_QUEUE_LIMIT",
    "store_normal_queue_limit": "DKG_STORE_NORMAL_QUEUE_LIMIT",
    "store_background_queue_limit": "DKG_STORE_BACKGROUND_QUEUE_LIMIT",
}
_PROJECTION_ENV = "DKG_LIST_CONTEXT_GRAPHS_PROJECTION"
_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}
_NODE_VALUE_FLAGS = {
    "--max-old-space-size", "--max-old-space-size-percentage", "--max-semi-space-size", "--require", "-r",
    "--import", "--loader", "--experimental-loader", "--conditions", "-C",
    "--openssl-config", "--icu-data-dir", "--env-file", "--env-file-if-exists",
}


class RuntimeSafetyError(ValueError):
    """A caller setting or profile cannot be used safely before a restart."""


@dataclass(frozen=True)
class RuntimeSafetyProfile:
    max_old_space_size_mb: Optional[int]
    store_queue_limit: int
    store_ack_queue_limit: int
    store_health_queue_limit: int
    store_normal_queue_limit: int
    store_background_queue_limit: int
    list_context_graphs_projection: bool


def _positive_integer(value: object) -> int:
    if type(value) is int and 0 < value <= _MAX_SETTING:
        return value
    if type(value) is str and re.fullmatch(r"[0-9]+", value.strip()):
        parsed = int(value)
        if 0 < parsed <= _MAX_SETTING:
            return parsed
    raise RuntimeSafetyError("DKG runtime safety limits must be positive bounded integers")


def _validate_profile(value: object) -> Optional[RuntimeSafetyProfile]:
    if type(value) is not dict or set(value) != set(RuntimeSafetyProfile.__dataclass_fields__):
        return None
    if type(value["list_context_graphs_projection"]) is not bool:
        return None
    try:
        for field in _QUEUE_FIELDS:
            if type(value[field]) is not int:
                return None
            _positive_integer(value[field])
        heap = value["max_old_space_size_mb"]
        if heap is not None and (type(heap) is not int or _positive_integer(heap) != heap):
            return None
        return RuntimeSafetyProfile(**value)
    except (TypeError, ValueError):
        return None


def heap_limit_mb(node_options: str, node_arguments: Sequence[str] = ()) -> Optional[int]:
    """Extract just the numeric memory option; Node arguments override env."""
    try:
        options = shlex.split(node_options)
    except ValueError as exc:
        raise RuntimeSafetyError("Could not parse Node memory options safely") from exc
    result = None
    for tokens in (options, list(node_arguments)):
        index = 0
        while index < len(tokens):
            token = tokens[index]
            flag, separator, value = token.partition("=")
            normalized = flag.replace("_", "-")
            if normalized == "--max-old-space-size":
                if not separator:
                    index += 1
                    if index >= len(tokens):
                        raise RuntimeSafetyError("Node memory limit is missing its numeric value")
                    value = tokens[index]
                result = _positive_integer(value)
            elif normalized == "--max-old-space-size-percentage":
                raise RuntimeSafetyError("Use a numeric Node old-space size for managed DKG restarts")
            elif normalized in _NODE_VALUE_FLAGS and not separator:
                index += 1
            index += 1
    return result


def _live_integer(value: Optional[str], fallback: int) -> int:
    # Match DKG's Number(raw) positive-integer resolver for ordinary env inputs.
    try:
        parsed = float(value.strip()) if value and value.strip() else float(fallback)
        if math.isfinite(parsed) and parsed.is_integer() and 0 < parsed <= _MAX_SETTING:
            return int(parsed)
    except (TypeError, ValueError):
        pass
    return fallback


def _process_profile(process: psutil.Process, home: str, cli: str):
    started = process.create_time()
    command = process.cmdline()
    executable = process.exe()
    if not process.is_running() or Path(executable).name.lower() not in {"node", "node.exe"}:
        return None
    index = 1
    # Only the actual entrypoint is authoritative. A foreign script can carry
    # our CLI path and daemon command as ordinary arguments.
    while index < len(command) and command[index].startswith("-"):
        flag, separator, _ = command[index].partition("=")
        if flag in {"-e", "--eval", "-p", "--print", "-c", "--check"}:
            return None
        if flag == "--":
            index += 1
            break
        index += 2 if flag.replace("_", "-") in _NODE_VALUE_FLAGS and not separator else 1
    if index < len(command) - 1:
        argument = command[index]
        if str(Path(argument).expanduser().resolve()) != cli:
            return None
        kind = command[index + 1]
        if kind not in {"daemon-worker", "daemon-supervisor"}:
            return None
        environment = process.environ()
        if not environment.get("DKG_HOME") or str(Path(environment["DKG_HOME"]).expanduser().resolve()) != home:
            return None
        common = _live_integer(environment.get("DKG_STORE_QUEUE_LIMIT"), 64)
        try:
            heap = heap_limit_mb(environment.get("NODE_OPTIONS", ""), command[1:index])
        except RuntimeSafetyError:
            # Unsupported V8 sizing flags are never replayed. Preserve the
            # independent guards and use saved/bounded numeric sizing instead.
            heap = None
        profile = RuntimeSafetyProfile(
            max_old_space_size_mb=heap,
            **{
                field: common if field == "store_queue_limit" else _live_integer(environment.get(name), common)
                for field, name in _QUEUE_FIELDS.items()
            },
            list_context_graphs_projection=environment.get(_PROJECTION_ENV, "").strip().lower() in _TRUE,
        )
        # psutil objects cache creation times. A fresh lookup also rejects a
        # PID reused while its environment was being read.
        current = psutil.Process(process.pid)
        if (
            not process.is_running() or current.create_time() != started
            or current.cmdline() != command or current.exe() != executable
            or str(Path(current.environ().get("DKG_HOME", "")).expanduser().resolve()) != home
        ):
            return None
        return kind, profile
    return None


def capture_runtime_safety(dkg_home: str, dkg_bin: str) -> Optional[RuntimeSafetyProfile]:
    """Read one exact local worker, never an unrelated PID or installation."""
    home, cli = str(Path(dkg_home).expanduser().resolve()), str(Path(dkg_bin).expanduser().resolve())
    candidates = []
    try:
        candidates.append(psutil.Process(int((Path(home) / "daemon.pid").read_text(encoding="utf-8").strip())))
    except (OSError, ValueError, psutil.Error):
        pass
    seen = set()
    supervisor = None
    try:
        processes = iter(psutil.process_iter(["pid", "cmdline"]))
        for index in range(_MAX_PROCESS_SCAN + len(candidates)):
            process = candidates[index] if index < len(candidates) else next(processes)
            pid = getattr(process, "pid", None)
            if type(pid) is not int or pid in seen:
                continue
            seen.add(pid)
            try:
                captured = _process_profile(process, home, cli)
            except (OSError, ValueError, psutil.Error):
                continue
            if captured is not None:
                kind, profile = captured
                if kind == "daemon-worker":
                    return profile
                supervisor = profile
    except (StopIteration, OSError, psutil.Error):
        pass
    return supervisor


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate profile field")
        result[key] = value
    return result


def read_runtime_safety(dkg_home: str, dkg_bin: str) -> Optional[RuntimeSafetyProfile]:
    path = Path(dkg_home).expanduser() / PROFILE_NAME
    try:
        if path.is_symlink():
            return None
        with path.open("rb") as handle:
            raw = handle.read(_MAX_PROFILE_BYTES + 1)
        if len(raw) > _MAX_PROFILE_BYTES:
            return None
        value = json.loads(raw, object_pairs_hook=_unique_json_object)
        if type(value) is not dict or set(value) != {"version", "dkg_home", "dkg_bin", "settings"}:
            return None
        if type(value["version"]) is not int or value["version"] != 1:
            return None
        if value["dkg_home"] != str(Path(dkg_home).expanduser().resolve()) or value["dkg_bin"] != str(Path(dkg_bin).expanduser().resolve()):
            return None
        return _validate_profile(value["settings"])
    except (OSError, ValueError, TypeError):
        return None


def write_runtime_safety(profile: RuntimeSafetyProfile, dkg_home: str, dkg_bin: str) -> None:
    if _validate_profile(asdict(profile)) is None:
        raise RuntimeSafetyError("Invalid DKG runtime safety profile")
    home = Path(dkg_home).expanduser().resolve()
    home.mkdir(parents=True, exist_ok=True)
    path = home / PROFILE_NAME
    if path.is_symlink():
        raise RuntimeSafetyError("DKG runtime safety profile must be a regular local file")
    value = {
        "version": 1, "dkg_home": str(home),
        "dkg_bin": str(Path(dkg_bin).expanduser().resolve()), "settings": asdict(profile),
    }
    descriptor, temporary = tempfile.mkstemp(prefix=PROFILE_NAME + ".tmp-", dir=home)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def default_heap_mb() -> int:
    """Use the installer's bounded RAM/cgroup sizing policy for cold starts."""
    limits = []
    try:
        limits.append(int(psutil.virtual_memory().total))
    except (OSError, ValueError, psutil.Error):
        pass
    for path in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        try:
            limits.append(int(Path(path).read_text(encoding="utf-8").strip()))
        except (OSError, ValueError):
            pass
    finite = [value for value in limits if 0 < value < 1 << 50]
    if not finite:
        return 8192
    sized = (min(finite) // (1024 * 1024)) * 3 // 4
    if sized <= 0:
        raise RuntimeSafetyError("Effective memory limit is too small for managed DKG")
    return min(8192, sized)


def prepare_restart_environment(environment: Dict[str, str], dkg_home: str, dkg_bin: str) -> None:
    """Persist resolved typed settings before stop, then apply caller overrides."""
    saved = read_runtime_safety(dkg_home, dkg_bin)
    live = capture_runtime_safety(dkg_home, dkg_bin)
    profile = live or saved or RuntimeSafetyProfile(default_heap_mb(), 512, 512, 512, 512, 512, True)
    if profile.max_old_space_size_mb is None:
        profile = replace(profile, max_old_space_size_mb=(saved.max_old_space_size_mb if saved else None) or default_heap_mb())
    settings = asdict(profile)
    caller_heap = heap_limit_mb(environment.get("NODE_OPTIONS", ""))
    if caller_heap is not None:
        settings["max_old_space_size_mb"] = caller_heap
    if "DKG_STORE_QUEUE_LIMIT" in environment:
        common = _positive_integer(environment["DKG_STORE_QUEUE_LIMIT"])
        prior_common = settings["store_queue_limit"]
        for field in _QUEUE_FIELDS:
            # A common option supplies defaults; it must not widen captured
            # per-lane guards. Only an explicit caller lane replaces those.
            if field == "store_queue_limit" or settings[field] == prior_common:
                settings[field] = common
    for field, name in _QUEUE_FIELDS.items():
        if name in environment:
            settings[field] = _positive_integer(environment[name])
    if _PROJECTION_ENV in environment:
        raw = environment[_PROJECTION_ENV].strip().lower()
        if raw not in _TRUE | _FALSE:
            raise RuntimeSafetyError("DKG graph-list projection setting must be a boolean")
        settings["list_context_graphs_projection"] = raw in _TRUE
    resolved = RuntimeSafetyProfile(**settings)
    write_runtime_safety(resolved, dkg_home, dkg_bin)
    if caller_heap is None:
        option = f"--max-old-space-size={resolved.max_old_space_size_mb}"
        environment["NODE_OPTIONS"] = (environment.get("NODE_OPTIONS", "").strip() + " " + option).strip()
    for field, name in _QUEUE_FIELDS.items():
        environment[name] = str(getattr(resolved, field))
    environment[_PROJECTION_ENV] = "1" if resolved.list_context_graphs_projection else "0"
