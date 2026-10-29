"""The managed local DKG node: its sync settings, process and restarts.

Decides whether Blackbox manages the node, keeps its sync environment at the
installer's settings, and restarts it safely — through the service manager
when one supervises it (FIX-0014: never stop/start behind systemd's back).
"""

from __future__ import annotations

import argparse
import logging
from contextlib import contextmanager
import os
import psutil
import shutil
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional
from ..kernel import constants
from ..kernel.config import BlackboxConfig
from ..kernel.dkg_client import DkgClient, DkgError
from . import node_process, node_service, process_limits
# The node's sync profile lives in node_profile. These names stay reachable as
# managed_node.<name>: sync/command.py calls them through this module and tests
# patch them here.
from .node_profile import (
    _DKG_CONFIG_SYNC_SETTINGS,
    _DKG_ENV_ONLY_SETTINGS,
    _DKG_RECOVERY_SPEEDUPS,
    _DKG_STEADY_SYNC_SETTINGS,
    _managed_dkg_sync_mode_matches,
    _persisted_dkg_sync_settings,
    _set_persisted_dkg_sync_state,
    node_sync_settings,
)
from ..kernel.bounded_files import atomic_write

logger = logging.getLogger(__name__)

def _uses_managed_dkg(cfg: BlackboxConfig, args: argparse.Namespace) -> bool:
    """Return whether this is a blocking sync for Blackbox's managed DKG."""
    return bool(
        getattr(args, "wait", False)
        and cfg.context_graph_id == constants.DEFAULT_CONTEXT_GRAPH_ID
        and cfg.graph_peer_id
        and Path(cfg.dkg_bin).is_file()
        and Path(cfg.dkg_home).is_dir()
    )


@contextmanager
def _managed_sync_lock():
    """Hold the one cross-process slot used by dashboard and manual syncs."""
    path = constants.blackbox_home() / "sync-window.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+b")
    acquired = False
    try:
        if os.name == "nt":  # pragma: no cover - exercised on Windows
            import msvcrt

            if path.stat().st_size == 0:
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                acquired = True
            except OSError:
                pass
        else:
            import fcntl

            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except BlockingIOError:
                pass
        yield acquired
    finally:
        if acquired:
            if os.name == "nt":  # pragma: no cover - exercised on Windows
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def _dkg_sync_environment(cfg: BlackboxConfig) -> dict[str, str]:
    env = os.environ.copy()
    sync_settings = node_sync_settings(cfg)
    sync_settings.update(_persisted_dkg_sync_settings(cfg))
    env.update(sync_settings)
    env["DKG_HOME"] = str(cfg.dkg_home)
    env.setdefault("DKG_CATCHUP_MAX_CONCURRENT_PEERS", "1")
    env.setdefault("DKG_STORE_QUEUE_WAIT_TIMEOUT_MS", "300000")
    # No effect: the node reads neither of the next two (DKG 10.0.25 has its sync
    # round and durable-sync limits built in).
    env.setdefault("DKG_SYNC_TOTAL_TIMEOUT_MS", "1800000")
    env.setdefault("DKG_SWM_RECOVERY_TIMEOUT_MS", "3600000")
    _apply_process_limits(cfg, env)
    # Native DKG dependencies are tied to the Node ABI used at installation.
    # A dashboard launched from another runtime can have a different ``node``
    # first on PATH, so preserve the executable of the currently managed node.
    node_executable = _managed_dkg_node_executable(cfg)
    if node_executable is not None:
        env["PATH"] = str(node_executable.parent) + os.pathsep + env.get("PATH", "")
    return env


def _apply_process_limits(cfg: BlackboxConfig, env: dict[str, str]) -> None:
    """Give a restarted node the heap / queue / projection limits the installer
    chose (PR #21 runtime-safety gap): the recorded ones, else the installer's
    defaults for this host. Fail-open: an unsizeable host keeps Node's default."""
    try:
        limits = process_limits.read_process_limits(cfg.dkg_home)
        limits = limits or process_limits.default_process_limits(env.get("NODE_OPTIONS", ""))
    except process_limits.ProcessLimitsError as exc:
        logger.warning("blackbox: DKG process limits unavailable, node keeps its defaults: %s", exc)
        return
    process_limits.apply_process_limits(env, limits)


def _managed_dkg_node_executable(cfg: BlackboxConfig) -> Optional[Path]:
    """Find the Node executable whose ABI matches the installed DKG runtime."""
    candidates: list[Path] = []

    def _candidate(value: object) -> None:
        if value:
            path = Path(str(value)).expanduser()
            if path not in candidates:
                candidates.append(path)

    # Only a process running this exact installation, never another DKG node
    # (daemon.pid alone can name a dead auto-spawned daemon, KI-312).
    for process in node_process.managed_daemons(cfg):
        try:
            _candidate((getattr(process, "info", None) or {}).get("exe") or process.exe())
        except (OSError, psutil.Error):
            continue

    marker = Path(cfg.dkg_home) / ".blackbox-node-path"
    try:
        _candidate(marker.read_text(encoding="utf-8-sig").strip())
    except OSError:
        pass
    nvm_bin = os.environ.get("NVM_BIN")
    if nvm_bin:
        _candidate(Path(nvm_bin) / ("node.exe" if os.name == "nt" else "node"))
    _candidate(shutil.which("node"))

    for executable in candidates:
        if not executable.is_file() or not _node_runtime_matches_dkg(executable, cfg):
            continue
        try:
            marker.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(marker, str(executable.resolve()) + "\n")
        except OSError:
            pass
        return executable
    return None


def _node_runtime_matches_dkg(executable: Path, cfg: BlackboxConfig) -> bool:
    """Load the installed native SQLite binding before trusting a Node path."""
    dkg_bin = Path(cfg.dkg_bin).expanduser()
    native_package = dkg_bin.parent.parent / "better-sqlite3"
    if not native_package.is_dir():
        return False
    probe = (
        "const DB=require(process.argv[1]);"
        "const db=new DB(':memory:');db.close();"
    )
    try:
        result = subprocess.run(
            [str(executable), "-e", probe, str(native_package)],
            stdin=subprocess.DEVNULL, capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def _systemd_unit_of(pid: int, proc_root: Path = Path("/proc")) -> Optional[str]:
    """Return the systemd ``.service`` unit supervising *pid*, if any.

    Reads the process's cgroup (Linux only; ``None`` elsewhere or when the
    process is not inside a service unit, e.g. a detached daemon or a user
    shell). Example cgroup-v2 line: ``0::/system.slice/blackbox-dkg.service``.
    """
    try:
        lines = (proc_root / str(pid) / "cgroup").read_text(encoding="utf-8-sig").splitlines()
    except OSError:
        return None
    for line in lines:
        leaf = line.rsplit("/", 1)[-1].strip()
        if leaf.endswith(".service"):
            return leaf
    return None


def expected_node_settings(cfg: BlackboxConfig) -> dict[str, str]:
    """The settings a running node must have for a sync to skip the restart.

    A node supervised by a service manager is restarted through it, with the
    unit's own environment, so an environment-only switch the unit lacks can
    never be added by a restart. Counting it would restart that node on every
    hourly sync (the KI-059/KI-065 loop), so it is left out here and logged;
    re-running the installer writes it into the unit.
    """
    expected = node_sync_settings(cfg)
    if not _runs_under_a_service(cfg, _daemon_pid(cfg)):
        return expected
    missing = sorted(name for name in _DKG_ENV_ONLY_SETTINGS if name in expected)
    if missing:
        logger.warning(
            "blackbox: the DKG node runs under a service unit; %s can only be set in the unit's "
            "environment — re-run the Blackbox installer to update the unit", ", ".join(missing))
    return {name: value for name, value in expected.items() if name not in _DKG_ENV_ONLY_SETTINGS}


def _runs_under_a_service(cfg: BlackboxConfig, pid: Optional[int]) -> bool:
    """Whether the running node *pid* was started by a service (so it has the service's environment)."""
    if pid is None:
        return False
    if _systemd_unit_of(pid) is not None:
        return True
    service = node_service.registered(cfg)
    return service is not None and service.owns(pid)


def _daemon_pid(cfg: BlackboxConfig) -> Optional[int]:
    """The managed node's live daemon pid (never a stale daemon.pid, KI-312), or None."""
    return node_process.managed_daemon_pid(cfg)


def _restart_managed_dkg(cfg: BlackboxConfig) -> None:
    """Restart the managed node with bounded native reconciliation enabled.

    A node supervised by a systemd unit is restarted THROUGH systemd. Running
    ``dkg stop``/``dkg start`` behind the unit's back kills the unit's main
    process (systemd records a failure and restarts it), and the unit's
    ``ExecStartPre`` ``dkg stop`` then kills the detached daemon this function
    just started, so the node flaps and in-flight syncs hit a dead API
    (KI-059/KI-065). When a service is REGISTERED for this install's node (the
    macOS LaunchAgent, or an enabled unit while no node runs under it), the
    restart goes through it too — a node started here instead is one the service
    cannot supervise, and launchd's copy then fails "Daemon already running" for
    ever (KI-426). See :func:`_restart_through_service`.
    """
    env = _dkg_sync_environment(cfg)
    command = str(cfg.dkg_bin)
    old_pid = _daemon_pid(cfg)
    unit = _systemd_unit_of(old_pid) if old_pid is not None else None
    service = node_service.systemd_unit(unit) if unit is not None else node_service.registered(cfg)
    if service is not None:
        # a node in the unit's cgroup is the unit's own: nothing stray to stop first
        _restart_through_service(cfg, service, None if unit is not None else old_pid, env, command)
        return
    try:
        _stop_managed_dkg(cfg, old_pid, env, command)
        started = subprocess.run(
            [command, "start"],
            env=env,
            stdin=subprocess.DEVNULL, capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"could not restart the managed DKG node: {exc}") from exc

    if started.returncode != 0:
        detail = (started.stderr or started.stdout or "").strip()
        raise RuntimeError(
            "could not start the managed DKG node"
            + (f": {detail[-500:]}" if detail else "")
        )
    _wait_for_managed_dkg_ready(cfg, (started.stderr or started.stdout or "").strip())


def _restart_through_service(cfg: BlackboxConfig, service: node_service.NodeService, stray_pid: Optional[int],
                             env: dict[str, str], command: str) -> None:
    """Restart the node through *service* and wait until it answers.

    *stray_pid*: a running node that may have been started OUTSIDE the service (by an install or an
    older Blackbox), or None. Such a node is stopped first: the service's ``dkg start --foreground``
    refuses while it lives.
    """
    try:
        if stray_pid is not None and not service.owns(stray_pid):
            _stop_managed_dkg(cfg, stray_pid, env, command)
        restarted = service.restart()
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"could not restart {service.name}: {exc}") from exc
    if restarted.returncode != 0:
        detail = (restarted.stderr or restarted.stdout or "").strip()
        raise RuntimeError(f"could not restart {service.name}" + (f": {detail[-500:]}" if detail else ""))
    _wait_for_managed_dkg_ready(cfg, "")


def _stop_managed_dkg(cfg: BlackboxConfig, old_pid: Optional[int], env: dict[str, str], command: str) -> None:
    """Stop the node with ``dkg stop`` and wait until its process and API are gone (≤ 45 s).

    Raises RuntimeError when it does not finish stopping; OSError / SubprocessError from the
    stop command pass through to the caller.
    """
    subprocess.run(
        [command, "stop"],
        env=env,
        stdin=subprocess.DEVNULL, capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    # ``dkg stop`` can return after its ten-second API wait while the
    # worker is still draining sync jobs. Starting immediately then sees
    # the old PID and refuses with "Daemon already running". Wait for the
    # exact managed worker and API listener to disappear first.
    stopped = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home, config=cfg)
    stop_deadline = time.monotonic() + 45
    while time.monotonic() < stop_deadline:
        pid_running = old_pid is not None and node_process.is_managed_daemon(cfg, old_pid)
        if not pid_running and not stopped.reachable(timeout=0.5):
            break
        time.sleep(0.5)
    else:
        raise RuntimeError("managed DKG node did not finish stopping")

    # A forced worker exit can leave its PID file behind. Remove it only
    # after proving that exact managed process is no longer alive.
    if old_pid is not None:
        if not node_process.is_managed_daemon(cfg, old_pid):
            try:
                (Path(cfg.dkg_home) / "daemon.pid").unlink()
            except FileNotFoundError:
                pass


def _wait_for_managed_dkg_ready(cfg: BlackboxConfig, detail: str) -> None:
    """Block until the node API answers ``status`` (90s), else RuntimeError.

    *detail* is the start command's output, appended to the error for context.
    """
    from .bootstrap import wait_for_native_bootstrap
    wait_for_native_bootstrap(cfg)
    client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home, config=cfg)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            client.status(timeout=2)
            return
        except DkgError:
            time.sleep(1)
    raise RuntimeError(
        "managed DKG node did not become ready"
        + (f": {detail[-500:]}" if detail else "")
    )
