"""KI-455: once a service runs the dashboard, the installer starts it only through that service.

An update on bb-install-1022b (2026-10-27) launched its own dashboard beside the systemd unit's:
the copy stopped the unit's dashboard, ``enable --now`` started the unit again, the unit's
dashboard replaced the copy, and the final check — one try, 10 s — caught it mid-start and rolled
a healthy update back, leaving the old plugin copy beside the new checkout. These tests run the
REAL installer functions in bash against stubs (systemctl / launchctl / curl / uname record or
answer; nothing on the machine is touched).
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

INSTALLER = Path(__file__).resolve().parents[2] / "scripts" / "blackbox-install.sh"

pytestmark = [
    pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash"),
    # every script runs against stub systemctl/launchctl/curl in a temp HOME; the live-system
    # guard only sees the installer text ("hermes", "update", "restart") inside it
    pytest.mark.live_system_guard_bypass,
]


def _src() -> str:
    return INSTALLER.read_text(encoding="utf-8")


def _function(name: str) -> str:
    """The text of one top-level shell function of the installer."""
    src = _src()
    start = src.index(f"\n{name}() {{\n") + 1
    return src[start:src.index("\n}\n", start) + 3]


def _constant(name: str) -> str:
    """The installer's own `NAME=value` line, so the sandbox cannot drift from it."""
    match = re.search(rf"^{name}=\S+", _src(), re.MULTILINE)
    assert match is not None, name
    return match.group(0)


class Machine:
    """A throwaway HOME with stub tools; ``run`` executes installer functions in bash.

    ``unit`` puts an enabled systemd user unit in place (the dashboard is supervised);
    ``loaded`` makes launchctl report the dashboard's LaunchAgent as loaded; ``answers``
    is how many curl calls fail before the dashboard answers (None = never answers).
    """

    def __init__(self, tmp_path: Path, *, system: str = "Linux", unit: bool = False,
                 loaded: bool = False, answers: int | None = 0, bootstrap_fails: bool = False) -> None:
        self.home = tmp_path
        self.calls = tmp_path / "calls"
        self.launched = tmp_path / "launched"
        stubs = tmp_path / "bin"
        stubs.mkdir()
        self.stubs = stubs
        counter = tmp_path / "curl-count"
        curl = "exit 7" if answers is None else (
            f'n=$(cat "{counter}" 2>/dev/null || echo 0); echo $((n+1)) > "{counter}"; '
            f'[ "$n" -ge {answers} ] || exit 7; exit 0')
        launchctl_print = "exit 0" if loaded else "exit 113"
        bodies = {
            "systemctl": f'echo "systemctl $*" >> "{self.calls}"; exit 0',
            "launchctl": (f'echo "launchctl $*" >> "{self.calls}"; [ "$1" = print ] && {launchctl_print}; '
                          + ('[ "$1" = bootstrap ] && exit 5; ' if bootstrap_fails else "") + "exit 0"),
            "curl": curl,
            "uname": f"echo {system}",
            "node": "exit 0",
            "hermes": "exit 0",
        }
        for name, body in bodies.items():
            (stubs / name).write_text(f"#!/bin/sh\n{body}\n")
            (stubs / name).chmod(0o755)
        if unit:
            path = tmp_path / ".config" / "systemd" / "user" / "blackbox-dashboard.service"
            path.parent.mkdir(parents=True)
            path.write_text("old unit\n")
        self.repo = tmp_path / "repo"
        self.repo.mkdir()
        for args in (["init", "-q", "-b", "main"], ["add", "."],
                     ["-c", "user.name=T", "-c", "user.email=t@example.com", "commit", "-qm", "v", "--allow-empty"]):
            subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True)
        (tmp_path / ".hermes" / "blackbox").mkdir(parents=True)
        (tmp_path / ".hermes" / "blackbox" / ".dashboard-revision").write_text("0" * 40 + "\n")  # older code runs

    def run(self, *lines: str) -> subprocess.CompletedProcess[str]:
        script = "\n".join([
            "set -euo pipefail",
            "ok() { echo \"OK $*\"; }", "warn() { echo \"WARN $*\"; }", "step() { :; }", "heading() { :; }",
            "sleep() { :; }", "id() { echo 1000; }", "xml_escape() { printf '%s' \"$1\"; }",
            f'run_detached() {{ echo launched >> "{self.launched}"; }}',
            f"HOME={self.home}", f"HERMES_HOME={self.home}/.hermes", f"HERMES_BIN={self.stubs}/hermes",
            f"REPO_DIR={self.repo}", f"BLACKBOX_SYSTEMD_DIR={self.home}/etc-systemd",
            "BLACKBOX_AUTO_DASHBOARD=1",
            _constant("BLACKBOX_SERVICE_SYSTEM_PATH"),
            _constant("BLACKBOX_DASHBOARD_LAUNCHD_LABEL"),
            _constant("BLACKBOX_DASHBOARD_ANSWER_WAIT_SECONDS"),
            _constant("BLACKBOX_DASHBOARD_RESTART_PENDING"),
            *(_function(name) for name in ("blackbox_dashboard_supervisor", "blackbox_dashboard_control",
                                           "blackbox_dashboard_answers_within", "start_dashboard",
                                           "register_dashboard_service", "rollback_restart_dashboard")),
            *lines,
        ])
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False,
                              env={"PATH": f"{self.stubs}:/usr/bin:/bin"})

    def recorded(self) -> list[str]:
        return self.calls.read_text().splitlines() if self.calls.exists() else []


def test_an_update_restarts_a_supervised_dashboard_only_through_systemd(tmp_path):
    machine = Machine(tmp_path, unit=True)
    result = machine.run("start_dashboard", "register_dashboard_service")
    assert result.returncode == 0, result.stderr
    assert not machine.launched.exists(), "a copy was launched beside the unit's dashboard"
    assert "systemctl --user restart blackbox-dashboard" in machine.recorded()


def test_a_current_unit_and_dashboard_are_only_started_not_restarted(tmp_path):
    machine = Machine(tmp_path, unit=True)
    first = machine.run("start_dashboard", "register_dashboard_service")   # writes the current unit
    assert first.returncode == 0, first.stderr
    machine.calls.unlink()
    again = machine.run("register_dashboard_service")                      # nothing changed since
    assert again.returncode == 0, again.stderr
    assert "systemctl --user start blackbox-dashboard" in machine.recorded()
    assert not any(" restart " in call for call in machine.recorded())


def test_a_first_install_launches_the_dashboard_then_hands_it_to_systemd(tmp_path):
    machine = Machine(tmp_path, answers=None)   # nothing answers yet: no service, nothing running
    result = machine.run("start_dashboard", "register_dashboard_service")
    assert result.returncode == 0, result.stderr
    assert machine.launched.exists()
    assert "systemctl --user enable blackbox-dashboard" in machine.recorded()


def test_a_slow_starting_dashboard_passes_the_bounded_check(tmp_path):
    machine = Machine(tmp_path, answers=6)   # the 7th try answers (~12 s at the 2 s poll)
    result = machine.run('blackbox_dashboard_answers_within http://127.0.0.1:9700/ 60 && echo ANSWERED')
    assert "ANSWERED" in result.stdout, result.stderr


def test_a_dashboard_that_never_answers_still_fails(tmp_path):
    machine = Machine(tmp_path, answers=None)
    result = machine.run('blackbox_dashboard_answers_within http://127.0.0.1:9700/ 10 || echo BROKEN')
    assert "BROKEN" in result.stdout, result.stderr


def test_the_final_check_waits_for_the_dashboard_and_a_failure_still_rolls_back():
    """verify_install asks through the bounded wait; a part that never answers still sets
    failed=true, which the installer turns into the rollback (test_blackbox_install_all_or_nothing)."""
    body = _function("verify_install")
    assert 'blackbox_dashboard_answers_within "$dashboard_url" "$BLACKBOX_DASHBOARD_ANSWER_WAIT_SECONDS"' in body
    assert "failed=true" in body
    assert int(_constant("BLACKBOX_DASHBOARD_ANSWER_WAIT_SECONDS").split(":-")[1].rstrip("}\"")) >= 30


def test_a_rollback_restarts_the_supervised_dashboard_on_the_restored_code(tmp_path):
    machine = Machine(tmp_path, unit=True)
    result = machine.run("rollback_restart_dashboard")
    assert result.returncode == 0, result.stderr
    assert machine.recorded()[-2:] == ["systemctl --user daemon-reload", "systemctl --user restart blackbox-dashboard"]


def test_a_rollback_without_a_dashboard_service_restarts_nothing(tmp_path):
    machine = Machine(tmp_path)
    result = machine.run("rollback_restart_dashboard")
    assert result.returncode == 0, result.stderr
    assert not any("restart" in call for call in machine.recorded())


def test_a_loaded_launch_agent_is_reloaded_through_launchd_on_update(tmp_path):
    machine = Machine(tmp_path, system="Darwin", loaded=True)
    result = machine.run("start_dashboard", "register_dashboard_service")
    assert result.returncode == 0, result.stderr
    assert not machine.launched.exists()
    calls = machine.recorded()
    assert any(call.startswith("launchctl bootout gui/1000/ai.umanitek.blackbox-dashboard") for call in calls)
    assert any(call.startswith("launchctl bootstrap gui/1000 ") for call in calls)


def test_a_first_install_on_a_mac_hands_the_dashboard_to_launchd_now(tmp_path):
    """LES-066 (2026-11-08, fresh Mac): the agent used to load only at the next login, so the
    installer's own dashboard ran unsupervised until then. It is loaded at once; launchd's copy
    takes the port over from the one the installer started."""
    machine = Machine(tmp_path, system="Darwin", loaded=False)
    result = machine.run("start_dashboard", "register_dashboard_service")
    assert result.returncode == 0, result.stderr
    assert machine.launched.exists()
    calls = machine.recorded()
    assert any(call.startswith("launchctl bootstrap gui/1000 ") and call.endswith("ai.umanitek.blackbox-dashboard.plist")
               for call in calls), calls
    assert not any(call.split()[1] in {"kickstart", "bootout"} for call in calls)
    assert "the dashboard runs under it" in result.stdout


def test_a_launch_agent_that_will_not_load_says_so_and_keeps_the_running_dashboard(tmp_path):
    machine = Machine(tmp_path, system="Darwin", loaded=False, bootstrap_fails=True)
    result = machine.run("start_dashboard", "register_dashboard_service")
    assert result.returncode == 0, result.stderr
    assert machine.launched.exists()
    assert "next login" in result.stdout and "launchctl bootstrap" in result.stdout


def test_the_rollback_restarts_the_dashboard_after_the_files_are_back():
    body = _function("rollback_install")
    assert body.index("rollback_files") < body.index("rollback_restart_dashboard")
