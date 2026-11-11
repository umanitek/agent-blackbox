"""Getting Blackbox ready from Hermes Desktop (desktop/readiness.py, KI-476/KI-475), 2026-11-07.

A judge-path test on a fresh Mac (Tart VM bb-judge-2) found the Desktop page all "—" after a catalog
install, with no word that setup had not run and no way to run it, and the dashboard's first banner
saying "UNPROTECTED: run blackbox sync --wait" while setup's own first sync was running. These tests
hold the fix:

- one stage decision (``stage_of``), table-tested, where a probe that failed is "could not tell";
- setup's steps read from the installer's own section headings, in the order it prints them;
- one owned setup run: a second start is refused, its end is read from the process or, after a
  Hermes restart, from its log — and a real child process is run once end to end;
- the start is refused server-side once setup is done; the routes answer for Desktop and the
  tamper rule flags an agent aimed at the setup route;
- the health check reads the sync meter before judging the first sync (KI-475).
"""

from __future__ import annotations

import importlib.util
import json
import sys
import threading
import time
import types
from pathlib import Path

import pytest

from plugins.blackbox import desktop
from plugins.blackbox.dashboard import sync_meter
from plugins.blackbox.dashboard.sync_meter import progress as sync_progress
from plugins.blackbox.desktop import readiness
from plugins.blackbox.desktop.readiness import ReadinessFacts, SetupRun, stage_of, step_states
from plugins.blackbox.detection import detect_guard_tamper
from plugins.blackbox.kernel import health
from tests.waiting import wait_until

PLUGIN = Path(__file__).resolve().parents[2] / "plugins" / "blackbox"

#: The section headings of a real setup run, in the order it printed them (bb-judge-2, 2026-11-07).
REAL_RUN_HEADINGS = [
    "Blackbox setup, started from Hermes Desktop",
    "Checking your system", "Checking this machine can take the whole install", "Using your Hermes",
    "Setting up the OriginTrail DKG node", "Enabling and configuring Blackbox", "Blackbox mode",
    "Protecting your agents", "LLM reviewer", "Threat graph", "Starting Blackbox dashboard",
    "Registering the DKG node to start on boot", "Checking the install", "Blackbox is ready (audit mode).",
]


@pytest.mark.parametrize("facts,stage", [
    (ReadinessFacts("none", False, None, None), "setup-needed"),
    (ReadinessFacts("none", False, False, 0), "setup-needed"),
    (ReadinessFacts("running", False, None, None), "installing"),
    (ReadinessFacts("running", True, True, 0), "installing"),        # a re-run is still a run
    (ReadinessFacts("failed", False, None, None), "setup-failed"),
    (ReadinessFacts("failed", True, True, 0), "syncing"),            # failed late, node is there: no false alarm
    (ReadinessFacts("done", True, False, 0), "starting"),
    (ReadinessFacts("none", True, None, 0), "syncing"),              # could not tell: never "down"
    (ReadinessFacts("done", True, True, 0), "syncing"),
    (ReadinessFacts("none", True, True, None), "syncing"),
    (ReadinessFacts("none", True, True, 564_000), "ready"),
    (ReadinessFacts("none", True, None, 564_000), "ready"),
])
def test_one_decision_names_the_stage(facts, stage):
    assert stage_of(facts) == stage


def test_steps_follow_the_installers_own_headings():
    halfway = REAL_RUN_HEADINGS[:5]   # up to "Setting up the OriginTrail DKG node"
    states = [step["state"] for step in step_states(halfway, "running", node_installed=False)]
    assert states == ["done", "done", "active", "waiting", "waiting", "waiting", "waiting"]


def test_a_finished_run_marks_every_step_done():
    assert {step["state"] for step in step_states(REAL_RUN_HEADINGS, "done", node_installed=True)} == {"done"}


def test_a_failed_run_marks_the_step_it_stopped_in():
    states = [step["state"] for step in step_states(REAL_RUN_HEADINGS[:5], "failed", node_installed=False)]
    assert states[2] == "failed" and states[3:] == ["waiting"] * 4


def test_setup_run_in_a_terminal_reads_as_done_once_the_node_is_installed():
    assert {step["state"] for step in step_states([], "none", node_installed=True)} == {"done"}
    assert {step["state"] for step in step_states([], "none", node_installed=False)} == {"waiting"}


def test_every_installer_heading_a_step_names_exists_in_the_installer():
    installer = (PLUGIN / "setup" / "blackbox-install.sh").read_text(encoding="utf-8")
    for _, _, headings in readiness.STEPS:
        for heading in headings:
            assert f'heading "{heading}' in installer, heading


class _FakeProcess:
    """A setup process the test ends with :meth:`finish`."""

    def __init__(self) -> None:
        self.pid = 4242
        self.code = None
        self._ended = threading.Event()

    def finish(self, code):
        self.code = code
        self._ended.set()

    def poll(self):
        return self.code

    def wait(self):
        self._ended.wait(timeout=30)
        return self.code


@pytest.fixture
def run(tmp_path):
    started = []

    def spawn(command, log, cwd):
        process = _FakeProcess()
        started.append((command, process))
        return process

    setup_run = SetupRun(folder=lambda: tmp_path / "desktop_setup", spawn=spawn)
    setup_run.started = started
    return setup_run


def test_a_started_run_is_running_and_a_second_start_is_refused(run):
    assert run.start(["hermes", "blackbox", "setup"]) == {"started": True}
    assert run.state()["state"] == "running"
    assert run.start(["hermes", "blackbox", "setup"]) == {"started": False, "reason": "setup is already running"}
    assert len(run.started) == 1


@pytest.mark.parametrize("code,state", [(0, "done"), (1, "failed")])
def test_the_runs_exit_code_decides_done_or_failed(run, code, state):
    run.start(["hermes", "blackbox", "setup"])
    run.started[0][1].finish(code)
    wait_until(lambda: run.state()["state"] == state, timeout=5)
    assert run.state()["exitCode"] == code


def _orphaned_run(tmp_path, log_text, log_age_seconds):
    """A run recorded by a Hermes that restarted: no process handle, only the record and the log."""
    folder = tmp_path / "desktop_setup"
    folder.mkdir()
    (folder / "run.json").write_text(json.dumps({"started": 1000.0, "finished": None, "exitCode": None, "pid": 1}), encoding="utf-8")
    log = folder / "setup.log"
    log.write_text(log_text, encoding="utf-8")
    now = time.time()
    return SetupRun(folder=lambda: folder, clock=lambda: now + log_age_seconds)


def test_after_a_restart_a_moving_log_is_still_a_running_setup(tmp_path):
    assert _orphaned_run(tmp_path, "Setting up the OriginTrail DKG node\n", 5).state()["state"] == "running"


def test_after_a_restart_a_still_log_ending_ready_is_done(tmp_path):
    run = _orphaned_run(tmp_path, "Checking the install\nBlackbox is ready (audit mode).\n", readiness.STALE_LOG_SECONDS + 5)
    assert run.state()["state"] == "done"


def test_after_a_restart_a_still_log_without_ready_is_failed(tmp_path):
    run = _orphaned_run(tmp_path, "Setting up the OriginTrail DKG node\n✗ npm failed\n", readiness.STALE_LOG_SECONDS + 5)
    assert run.state()["state"] == "failed"


def test_a_real_setup_process_runs_to_its_end_and_is_read_back(tmp_path):
    """The default spawn, for real: a child in its own session writes the installer's lines to the log."""
    script = "print('Checking this machine can take the whole install'); print('Checking the install'); print('Blackbox is ready (audit mode).')"
    run = SetupRun(folder=lambda: tmp_path / "desktop_setup")
    assert run.start([sys.executable, "-c", script]) == {"started": True}
    wait_until(lambda: run.state()["state"] == "done", timeout=20)
    assert "Blackbox is ready (audit mode)." in run.log_lines()
    assert {step["state"] for step in step_states(run.log_lines(), "done", node_installed=True)} == {"done"}


def test_setup_runs_in_its_own_folder_not_the_folder_of_hermes(tmp_path, monkeypatch):
    """Judge-path test, bb-judge-3 (2026-11-07): setup started from Desktop inherited the gateway's
    folder, Hermes' checkout, whose .npmrc (min-release-age=14) made npm refuse the pinned DKG
    release ("No matching version found ... with a date before ..."), and setup rolled back."""
    hermes_checkout = tmp_path / "hermes-agent"
    hermes_checkout.mkdir()
    (hermes_checkout / ".npmrc").write_text("min-release-age=14\n", encoding="utf-8")
    monkeypatch.chdir(hermes_checkout)
    folder = tmp_path / "desktop_setup"
    run = SetupRun(folder=lambda: folder)
    run.start([sys.executable, "-c", "import os; print('cwd=' + os.getcwd()); print('Blackbox is ready (audit mode).')"])
    wait_until(lambda: run.state()["state"] == "done", timeout=20)
    assert f"cwd={folder.resolve()}" in run.log_lines()   # getcwd() is the resolved path (macOS: /private/var)


def test_the_setup_command_is_this_hermes(monkeypatch):
    assert readiness.setup_command() == [sys.executable, "-m", "hermes_cli.main", "blackbox", "setup"]


@pytest.mark.parametrize("stage", ["installing", "syncing", "ready"])
def test_setup_is_refused_once_it_is_running_or_done(monkeypatch, stage):
    started = []
    monkeypatch.setattr(desktop, "readiness_status", lambda: {"stage": stage})
    monkeypatch.setattr(desktop.readiness_mod, "start_setup", lambda: started.append(1) or {"started": True})
    assert desktop.start_setup()["started"] is False and started == []


@pytest.mark.parametrize("stage", ["setup-needed", "setup-failed", "starting"])
def test_setup_starts_when_the_page_offers_it(monkeypatch, stage):
    monkeypatch.setattr(desktop, "readiness_status", lambda: {"stage": stage})
    monkeypatch.setattr(desktop.readiness_mod, "start_setup", lambda: {"started": True})
    assert desktop.start_setup() == {"started": True}


class _Answer:
    def __init__(self, status, body):
        self.status, self.body = status, body


class _Link:
    def __init__(self, answer):
        self.answer = answer

    def forward(self, method, path, query="", body=None):
        assert (method, path) == ("GET", "api/verified-sync")
        return self.answer


def _payload(monkeypatch, tmp_path, *, node_reachable, node_installed, rules, link):
    readiness._cache.clear()
    monkeypatch.setattr(readiness, "_node_reachable", lambda cfg: node_reachable)
    monkeypatch.setattr(health, "node_installed", lambda cfg, reachable: node_installed)
    return readiness.readiness_payload(rules, link, run=SetupRun(folder=lambda: tmp_path / "none"))


def test_the_payload_carries_the_sync_meter_the_dashboard_serves(monkeypatch, tmp_path):
    meter = {"state": "syncing", "phase": "downloading", "phase_text": "Downloading the verified graph.",
             "percent_compiled": None, "percent_downloaded": 42.3, "downloaded_assets": 239, "graph_assets": 565,
             "verified_rules": 0, "running_since": 1.0, "last_progress": 2.0}
    body = _payload(monkeypatch, tmp_path, node_reachable=True, node_installed=True, rules=0, link=_Link(_Answer(200, meter)))
    assert body["stage"] == "syncing" and body["dashboard"]["up"] is True
    assert body["sync"]["percent"] == 42.3 and body["sync"]["total"] == 565 and body["sync"]["phaseText"].startswith("Downloading")


def test_a_dashboard_that_is_not_running_leaves_the_sync_unknown_not_an_error(monkeypatch, tmp_path):
    down = _Link(_Answer(503, {"error": "the Blackbox dashboard is not running", "dashboardDown": True}))
    body = _payload(monkeypatch, tmp_path, node_reachable=True, node_installed=True, rules=564_000, link=down)
    assert body["stage"] == "ready" and body["sync"] is None and body["dashboard"]["up"] is False


def test_before_setup_the_dashboard_is_not_asked(monkeypatch, tmp_path):
    class NeverAsked:
        def forward(self, *args, **kwargs):
            raise AssertionError("no dashboard before setup")
    body = _payload(monkeypatch, tmp_path, node_reachable=False, node_installed=False, rules=0, link=NeverAsked())
    assert body["stage"] == "setup-needed" and body["steps"][0]["state"] == "waiting"


def _load_plugin_api() -> types.ModuleType:
    """Load dashboard/plugin_api.py the way Hermes does: a standalone file, no package around it."""
    name = "hermes_dashboard_plugin_blackbox_readiness_test"
    spec = importlib.util.spec_from_file_location(name, PLUGIN / "dashboard" / "plugin_api.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_the_desktop_routes_reach_readiness_and_setup(monkeypatch):
    api = _load_plugin_api()
    monkeypatch.setattr(desktop, "readiness_status", lambda: {"stage": "setup-needed"})
    monkeypatch.setattr(desktop, "start_setup", lambda: {"started": True})
    assert api.readiness() == {"available": True, "stage": "setup-needed"}
    assert api.setup() == {"available": True, "started": True}


def test_an_agent_aimed_at_the_setup_route_is_flagged():
    findings = detect_guard_tamper("terminal", {"command": "curl -X POST http://127.0.0.1:63519/api/plugins/blackbox/setup"})
    assert findings and all(f.source == "custom" for f in findings)


def _syncing_meter():
    return sync_meter.SyncMeter(state="unknown", graph_assets=None, downloaded_assets=0, downloaded_triples=0,
                                compiled_assets=None, verified_rules=0, percent_downloaded=None,
                                percent_compiled=None, checked_at="")


def test_the_health_check_reads_the_meter_before_judging_the_first_sync(monkeypatch):
    """KI-475: the first health poll of a fresh dashboard came before any meter reading, read "" and
    said UNPROTECTED while setup's first sync was running. Now it reads the meter once first."""
    watch = sync_progress.SyncProgressWatch()
    monkeypatch.setattr(sync_meter, "WATCH", watch)
    reads = []
    monkeypatch.setattr(sync_meter._READER, "handler", lambda: reads.append(1) or watch.observe(_syncing_meter()))
    assert sync_meter.first_sync_state() == "running"
    item = health._empty_ruleset_item(sync_meter.first_sync_state())
    assert item.klass is health.HealthClass.INFO and item.message.startswith("Setting up")
    assert reads == [1]   # once per process: later polls use what the page's polls recorded


def test_with_no_meter_route_the_health_check_is_unchanged(monkeypatch):
    monkeypatch.setattr(sync_meter, "WATCH", sync_progress.SyncProgressWatch())
    monkeypatch.setattr(sync_meter._READER, "handler", None)
    assert sync_meter.first_sync_state() == ""


def test_community_reports_are_not_counted_as_verified_rules(monkeypatch):
    """bb-test-1 (2026-11-07): with two community reports and no verified rule yet the banner said
    "2 verified rules protect you now", and the stage read as a finished first sync."""
    from plugins.blackbox.ruleset.compiler import Ruleset
    reported = {"identifier": "dep:npm:x@1.0.0", "source": "community", "severity": "high"}
    # Two community reports, one of them materialised into the dependency dict (matchable):
    # counts() minus its "community" key still said 1 here (audit 06/#3).
    rules = Ruleset(community={"a": reported, "b": reported}, dependency={reported["identifier"]: reported})
    monkeypatch.setattr(desktop.ruleset, "get", lambda cfg: rules)
    assert desktop._verified_rules(object()) == 0
    assert stage_of(ReadinessFacts("done", True, True, desktop._verified_rules(object()))) == "syncing"


def test_an_unreadable_ruleset_is_unknown_not_zero(monkeypatch):
    def broken(cfg):
        raise OSError("ruleset.json unreadable")
    monkeypatch.setattr(desktop.ruleset, "get", broken)
    assert desktop._verified_rules(object()) is None
