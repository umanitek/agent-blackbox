"""Getting Blackbox ready from Hermes Desktop: where this machine is, from plugin install to synced.

A plugin-catalog install copies the plugin only; ``hermes blackbox setup`` then installs the local
DKG node, starts the dashboard and begins the first sync of Umanitek's verified threat graph. The
Desktop page shows that journey live instead of empty cards, and can start setup itself.

Three parts, each in one place:

- :func:`stage_of` — the ONE decision of which stage the machine is in (State pattern, a pure
  function over :class:`ReadinessFacts`, table-tested). Stages, in order:
  ``setup-needed`` → ``installing`` (or ``setup-failed``) → ``starting`` → ``syncing`` → ``ready``.
  ``syncing`` is the FIRST sync only (no verified rules yet); later catch-ups are ``ready``.
- :class:`SetupRun` — the one setup run Desktop starts: ``hermes blackbox setup`` in this Hermes, as
  a child process this module owns, its output kept in ``<blackbox home>/desktop_setup/setup.log``.
  It refuses a second run while one is going and never kills anything. A Hermes restart mid-run
  leaves the run going (own session); the record then reads its end from the log.
- :func:`readiness_payload` — what the page polls: the stage, setup's steps (from the installer's
  section headings), the last log lines, the node and dashboard, and the sync meter the dashboard
  serves (``/api/verified-sync``, read through :func:`.dashboard_link` — the page and the dashboard
  show one reading).

A probe that fails is "could not tell", never "down" (LES-011): an unreachable dashboard leaves the
sync unknown, it does not turn a synced machine back into "syncing".

Usage::

    from plugins.blackbox.desktop import readiness
    readiness.readiness_payload()   # {"stage": "syncing", "steps": [...], "sync": {...}, ...}
    readiness.start_setup()         # {"started": True, ...} or {"started": False, "reason": "..."}
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, TypedDict

from ..kernel import constants, health
from ..kernel.bounded_files import atomic_write, read_json_object
from ..kernel.config import load_blackbox_config
from ..kernel.dkg_client import DkgClient
from ..kernel.host_command import hermes_argv

logger = logging.getLogger(__name__)

STAGES = ("setup-needed", "installing", "setup-failed", "starting", "syncing", "ready")
#: Setup's own last line on success (``heading "Blackbox is ready ($mode mode)."``).
READY_MARK = "Blackbox is ready"
#: A run with no live process whose log has not moved for this long has ended (its Hermes restarted).
STALE_LOG_SECONDS = 600
LOG_TAIL_LINES = 14
MAX_LINE_CHARS = 240
NODE_PROBE_SECONDS = 1.5
#: The page polls every 2 s during setup; one reading is shared for this long.
CACHE_SECONDS = 1.5
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


class SetupStep(TypedDict):
    """One step of setup as the page lists it; ``state`` is done | active | waiting | failed."""

    id: str
    label: str
    state: str


#: Setup's steps, each with the installer section headings (``heading "…"`` in
#: setup/blackbox-install.sh) that belong to it, in the order setup runs them.
STEPS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("check", "Check disk space and network", ("Checking your system", "Checking this machine")),
    ("hermes", "Link Blackbox into your Hermes", ("Using your Hermes", "Installing Blackbox plugin copy", "Hermes API setup",
                                     "Moving Blackbox onto your Hermes")),
    ("node", "Install the local threat-graph node", ("Setting up the OriginTrail DKG node",)),
    ("protect", "Switch on protection for your agents", ("Enabling and configuring Blackbox", "Blackbox mode", "Protecting your agents",
                                       "LLM reviewer", "Threat graph")),
    ("dashboard", "Start the Blackbox dashboard", ("Starting Blackbox dashboard",)),
    ("service", "Run the node in the background", ("Registering the DKG node to start on boot",)),
    ("verify", "Check that everything answers", ("Checking the install",)),
)


@dataclass(frozen=True)
class ReadinessFacts:
    """What :func:`stage_of` decides from.

    ``setup_state``: none | running | failed | done (the Desktop run; ``none`` when setup ran in a
    terminal or never ran). ``node_reachable``: None = could not tell. ``rules``: compiled verified
    rules, None = could not read.
    """

    setup_state: str
    node_installed: bool
    node_reachable: Optional[bool]
    rules: Optional[int]


def stage_of(facts: ReadinessFacts) -> str:
    """The stage this machine is in (one of :data:`STAGES`)."""
    if facts.setup_state == "running":
        return "installing"
    if not facts.node_installed:
        return "setup-failed" if facts.setup_state == "failed" else "setup-needed"
    if facts.node_reachable is False:
        return "starting"
    return "ready" if (facts.rules or 0) > 0 else "syncing"


def step_states(log_lines: list[str], run_state: str, node_installed: bool) -> list[SetupStep]:
    """Each step's state, read from the installer's section headings in *log_lines*.

    A step is done once a later step's heading appears; the newest is active while the run goes,
    failed when it failed, done when it finished. With no Desktop run (setup ran in a terminal),
    every step is done when the node is installed, else waiting."""
    reached = -1
    for line in log_lines:
        text = line.strip()
        for index, (_, _, headings) in enumerate(STEPS):
            if index > reached and any(text.startswith(heading) for heading in headings):
                reached = index
    if run_state == "none":
        reached, run_state = (len(STEPS), "done") if node_installed else (-1, "none")
    steps: list[SetupStep] = []
    for index, (step_id, label, _) in enumerate(STEPS):
        if index < reached or (index == reached and run_state == "done"):
            state = "done"
        elif index == reached:
            state = "failed" if run_state == "failed" else "active"
        else:
            state = "waiting"
        steps.append(SetupStep(id=step_id, label=label, state=state))
    return steps


def _clean(line: str) -> str:
    return _ANSI.sub("", line).rstrip()[:MAX_LINE_CHARS]


class SetupRun:
    """The one setup run Desktop starts, and its record (``run.json`` + ``setup.log`` in *folder*).

    One lock guards the start and the record. ``spawn`` is injectable for tests; it takes
    (command, log file, working folder) and returns a ``subprocess.Popen``-like object with ``pid``,
    ``poll()`` and ``wait()``. Setup runs in *folder*, never in the folder of the process that starts
    it: Hermes runs in its own checkout, whose ``.npmrc`` (``min-release-age=14``) made npm refuse the
    pinned DKG release for its first two weeks, and setup rolled back.
    """

    def __init__(self, folder: Callable[[], Path], spawn: Optional[Callable[[list[str], Any, Path], Any]] = None,
                 clock: Callable[[], float] = time.time) -> None:
        self._folder = folder
        self._spawn = spawn or _spawn_detached
        self._clock = clock
        self._lock = threading.Lock()
        self._process: Any = None

    @property
    def log_path(self) -> Path:
        return self._folder() / "setup.log"

    def _record_path(self) -> Path:
        return self._folder() / "run.json"

    def _read_record(self) -> dict[str, Any]:
        return read_json_object(self._record_path()) or {}

    def _write_record(self, record: dict[str, Any]) -> None:
        atomic_write(self._record_path(), json.dumps(record))

    def log_lines(self) -> list[str]:
        try:
            return [_clean(line) for line in self.log_path.read_text(encoding="utf-8-sig", errors="replace").splitlines()]
        except OSError:
            return []

    def state(self) -> dict[str, Any]:
        """``{"state": none|running|failed|done, "started", "finished", "exitCode"}``."""
        with self._lock:
            return self._state_locked()

    def _state_locked(self) -> dict[str, Any]:
        record = self._read_record()
        if not record.get("started"):
            return {"state": "none", "started": None, "finished": None, "exitCode": None}
        if record.get("finished") is None and not self._still_running():
            record = self._settle(record)
        exit_code = record.get("exitCode")
        state = "running" if record.get("finished") is None else ("done" if exit_code == 0 else "failed")
        return {"state": state, "started": record.get("started"), "finished": record.get("finished"),
                "exitCode": exit_code}

    def _still_running(self) -> bool:
        if self._process is not None:
            return self._process.poll() is None
        # No handle: this Hermes restarted mid-run. The run is going while its log keeps moving.
        try:
            return self._clock() - self.log_path.stat().st_mtime < STALE_LOG_SECONDS
        except OSError:
            return False

    def _settle(self, record: dict[str, Any]) -> dict[str, Any]:
        """Close a run that has ended but is not recorded yet: with its own exit code when this
        process holds it (the waiter may not have written it yet), else — its Hermes restarted —
        success when the log ends with setup's ready line."""
        if self._process is not None:
            code = int(self._process.poll())
        else:
            code = 0 if any(line.strip().startswith(READY_MARK) for line in self.log_lines()[-40:]) else -1
        record = {**record, "finished": self._clock(), "exitCode": code}
        self._write_record(record)
        return record

    def start(self, command: list[str]) -> dict[str, Any]:
        """Start setup unless a run is going. Returns ``{"started": bool, "reason"?: str}``."""
        with self._lock:
            if self._state_locked()["state"] == "running":
                return {"started": False, "reason": "setup is already running"}
            self._folder().mkdir(parents=True, exist_ok=True)
            with open(self.log_path, "w", encoding="utf-8") as log:
                log.write("Blackbox setup, started from Hermes Desktop\n")
                log.flush()
                self._process = self._spawn(command, log, self._folder())
            self._write_record({"started": self._clock(), "finished": None, "exitCode": None, "pid": self._process.pid})
            threading.Thread(target=self._wait, args=(self._process,), name="blackbox-desktop-setup", daemon=True).start()
            return {"started": True}

    def _wait(self, process: Any) -> None:
        code = process.wait()
        with self._lock:
            self._write_record({**self._read_record(), "finished": self._clock(), "exitCode": int(code)})


def _spawn_detached(command: list[str], log: Any, cwd: Path) -> subprocess.Popen:
    """Run *command* in *cwd* and its own session (a Hermes restart does not stop it), output to *log*.
    stdin is closed: the installer asks on the terminal itself and takes its defaults without one."""
    return subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                            cwd=str(cwd), start_new_session=True)


def setup_command() -> list[str]:
    """``hermes blackbox setup`` in the Hermes this process runs in (the same Python, so the same profile)."""
    return hermes_argv("blackbox", "setup")


RUN = SetupRun(folder=lambda: constants.blackbox_home() / "desktop_setup")


def _node_reachable(cfg: Any) -> Optional[bool]:
    try:
        return DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home, config=cfg).reachable(timeout=NODE_PROBE_SECONDS)
    except Exception as exc:   # health: allow BLE001 -- a probe that cannot run is "could not tell" (LES-011)
        logger.debug("blackbox: node probe for Desktop could not run: %s", exc)
        return None


def _sync_reading(link: Any) -> tuple[bool, Optional[dict[str, Any]]]:
    """(dashboard answered, the sync meter's reading or None)."""
    try:
        answer = link.forward("GET", "api/verified-sync")
    except Exception as exc:   # health: allow BLE001 -- no reading is "could not tell", never an error
        logger.debug("blackbox: sync meter unreadable for Desktop: %s", exc)
        return False, None
    if answer.status != 200 or not isinstance(answer.body, dict):
        return False, None
    meter = answer.body
    percent = meter.get("percent_compiled")
    if not isinstance(percent, (int, float)):
        percent = meter.get("percent_downloaded")
    return True, {
        "state": str(meter.get("state") or ""),
        "phase": str(meter.get("phase") or ""),
        "phaseText": str(meter.get("phase_text") or ""),
        "percent": float(percent) if isinstance(percent, (int, float)) else None,
        "downloaded": meter.get("downloaded_assets"),
        "total": meter.get("graph_assets"),
        "rules": meter.get("verified_rules"),
        "runningSince": meter.get("running_since"),
        "lastProgress": meter.get("last_progress"),
    }


class _Cache:
    """One shared reading for :data:`CACHE_SECONDS` (several Desktop windows poll at once)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._at = -1e9
        self._body: Optional[dict[str, Any]] = None

    def get(self, build: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        with self._lock:
            if self._body is None or time.monotonic() - self._at >= CACHE_SECONDS:
                self._body, self._at = build(), time.monotonic()
            return dict(self._body)

    def clear(self) -> None:
        with self._lock:
            self._body = None


_cache = _Cache()


def _build(rules: Optional[int], link: Any, run: SetupRun) -> dict[str, Any]:
    cfg = load_blackbox_config()
    run_state = run.state()
    reachable = _node_reachable(cfg)
    installed = health.node_installed(cfg, bool(reachable))
    dashboard_up, sync = _sync_reading(link) if installed else (False, None)
    stage = stage_of(ReadinessFacts(run_state["state"], installed, reachable, rules))
    lines = run.log_lines()
    errors = [line for line in lines if line.lstrip().startswith("✗")]
    return {
        "stage": stage,
        "steps": step_states(lines, run_state["state"], installed),
        "setup": {**run_state, "logTail": lines[-LOG_TAIL_LINES:], "error": errors[-1].lstrip("✗ ").strip() if errors else ""},
        "node": {"installed": installed, "reachable": reachable, "url": str(cfg.dkg_url)},
        "dashboard": {"up": dashboard_up, "url": f"http://127.0.0.1:{cfg.dashboard_port}/"},
        "sync": sync,
        "rules": rules,
        "checkedAt": time.time(),
    }


def readiness_payload(rules: Optional[int], link: Any, run: SetupRun = RUN) -> dict[str, Any]:
    """Where this machine is (see the module doc); *rules* is the compiled verified-rule count
    (None = unreadable) and *link* the :class:`~.dashboard_link.DashboardLink` to read the sync meter through."""
    return _cache.get(lambda: _build(rules, link, run))


def start_setup(run: SetupRun = RUN) -> dict[str, Any]:
    """Start ``hermes blackbox setup`` from Desktop (see :class:`SetupRun`); refuses a second run."""
    answer = run.start(setup_command())
    _cache.clear()
    return answer
