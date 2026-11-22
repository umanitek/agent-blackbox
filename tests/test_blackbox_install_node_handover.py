"""A first install hands the DKG node it started over to the node's boot service.

KI-426 (GitHub macOS runner, 2026-10-15): a first install has no service yet, so the installer
runs the node itself, then registers the LaunchAgent. launchd's copy found that node running,
exited "Daemon already running" and was relaunched for ever, while the installer's copy (on
install-only settings) served unsupervised until a reboot; systemd's unit was only enabled.
`hand_dkg_node_to_service` stops the installer's copy, starts the node through the service and
confirms the service's process is the one serving.

These tests run the real functions out of the script against a small simulated machine: fake
`launchctl`, `systemctl`, `ps` and `curl` read and write a state folder (the service's pid, the
node's daemon.pid, each process's parent, whether the node answers), and the DKG CLI is a shell
function that starts an unsupervised copy or stops whichever copy daemon.pid names.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
INSTALL_SH = REPO / "scripts" / "blackbox-install.sh"
LABEL = "ai.umanitek.blackbox-dkg"
FUNCTIONS = ("blackbox_dkg_supervisor", "blackbox_dkg_control", "blackbox_dkg_service_pid",
             "blackbox_dkg_serving_pid", "blackbox_dkg_descends_from", "blackbox_dkg_node_pid", "blackbox_dkg_stray",
             "blackbox_dkg_owned_by", "blackbox_dkg_answers", "blackbox_dkg_launchd_error_log",
             "blackbox_dkg_stop_and_wait", "hand_dkg_node_to_service")

# Pids of the simulated machine: the installer's unsupervised copy, and the copy a service starts
# (`dkg start --foreground` = the CLI's supervisor; the node daemon is its child).
ORPHAN_SUPERVISOR, ORPHAN_NODE = "4500", "4527"
SERVICE_SUPERVISOR, SERVICE_NODE = "7000", "7001"
SERVICE_MIDDLE = "7002"


def _body(text: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{\s*\n(?P<body>.*?)^\}}", text, re.MULTILINE | re.DOTALL)
    assert match is not None, f"{name}() not found"
    return match["body"]


def _fake(bin_dir: Path, name: str, script: str) -> None:
    path = bin_dir / name
    path.write_text("#!/bin/sh\n" + script, encoding="utf-8")
    path.chmod(0o755)


def _set(folder: Path, **values: str) -> None:
    for name, value in values.items():
        (folder / name).write_text(value, encoding="utf-8")


class Machine:
    """A sandbox with one node and one boot service; `run()` calls hand_dkg_node_to_service."""

    def __init__(self, tmp_path: Path, supervisor: str) -> None:
        self.home, self.bin, self.state = tmp_path / "home", tmp_path / "bin", tmp_path / "state"
        self.dkg_home, self.calls = tmp_path / "dkg", tmp_path / "calls"
        for folder in (self.home, self.bin, self.state, self.dkg_home):
            folder.mkdir(parents=True)
        self.calls.write_text("", encoding="utf-8")
        self.supervisor = supervisor
        self._fakes()

    # ── the simulated machine's state ─────────────────────────────────────────
    def orphan_running(self) -> None:
        """The node the installer started itself: no service runs it."""
        (self.dkg_home / "daemon.pid").write_text(ORPHAN_NODE + "\n", encoding="utf-8")
        _set(self.state, **{f"ppid_{ORPHAN_NODE}": ORPHAN_SUPERVISOR, "answers": "1", "listener": ORPHAN_NODE})

    def service_running(self) -> None:
        (self.dkg_home / "daemon.pid").write_text(SERVICE_NODE + "\n", encoding="utf-8")
        _set(self.state, **{"service_pid": SERVICE_SUPERVISOR, f"ppid_{SERVICE_NODE}": SERVICE_SUPERVISOR, "answers": "1",
                            "listener": SERVICE_NODE})

    def service_takes_over(self, yes: bool) -> None:
        """Whether a (re)start through the service brings the node up under it."""
        _set(self.state, takeover="1" if yes else "0")

    def service_takes_over_writing_its_pid_late(self) -> None:
        """The service's node serves before it writes daemon.pid, as a grandchild (KI-533)."""
        _set(self.state, takeover="late_pid")

    # ── fakes ────────────────────────────────────────────────────────────────
    def _fakes(self) -> None:
        state, calls, pid_file = (shlex.quote(str(p)) for p in (self.state, self.calls, self.dkg_home / "daemon.pid"))
        log = f'echo "$(basename "$0") $*" >> {calls}\n'
        # A sync racing the handover (KI-529): the first start through the service finds a stray copy
        # already started behind it, so the service's own copy cannot start that time.
        stray = (f'if [ -f {state}/stray_once ]; then rm -f {state}/stray_once; echo {ORPHAN_NODE} > {pid_file}; '
                 f'echo {ORPHAN_SUPERVISOR} > {state}/ppid_{ORPHAN_NODE}; echo 1 > {state}/answers; echo {ORPHAN_NODE} > {state}/listener; exit 0; fi\n')
        takeover = (f'[ "$(cat {state}/takeover 2>/dev/null)" = 1 ] && {{ echo {SERVICE_SUPERVISOR} > {state}/service_pid; '
                    f'echo {SERVICE_NODE} > {pid_file}; echo {SERVICE_SUPERVISOR} > {state}/ppid_{SERVICE_NODE}; '
                    f'echo 1 > {state}/answers; echo {SERVICE_NODE} > {state}/listener; }}\n'
                    # KI-533 (E2E full4): the service's node serves BEFORE it writes daemon.pid, and runs
                    # as a grandchild of the process launchd started (dkg start --foreground -> daemon).
                    f'[ "$(cat {state}/takeover 2>/dev/null)" = late_pid ] && {{ echo {SERVICE_SUPERVISOR} > {state}/service_pid; '
                    f'rm -f {pid_file}; echo {SERVICE_MIDDLE} > {state}/ppid_{SERVICE_NODE}; '
                    f'echo {SERVICE_SUPERVISOR} > {state}/ppid_{SERVICE_MIDDLE}; echo 1 > {state}/answers; '
                    f'echo {SERVICE_NODE} > {state}/listener; }}\n')
        service_pid = f'cat {state}/service_pid 2>/dev/null || echo 0'
        _fake(self.bin, "uname", f'echo {"Darwin" if self.supervisor == "launchd" else "Linux"}\n')
        _fake(self.bin, "launchctl", f'case "$1" in\n'
              f'  print) echo "{LABEL} = {{"; echo "	pid = $({service_pid})"; exit 0;;\n'
              f'  kickstart|bootstrap) {log}{stray}{takeover}exit 0;;\n'
              f'  bootout) {log}rm -f {state}/service_pid; exit 0;;\n'
              f'esac\nexit 0\n')
        _fake(self.bin, "systemctl", f'case "$*" in\n'
              f'  *is-enabled*) exit 0;;\n'
              f'  *show*) {service_pid}; exit 0;;\n'
              f'  *restart*|*start*) {log}{takeover}exit 0;;\n'
              f'  *stop*) {log}rm -f {state}/service_pid; exit 0;;\n'
              f'esac\nexit 0\n')
        _fake(self.bin, "ps", f'pid=""; for a in "$@"; do pid="$a"; done\ncat {state}/ppid_$pid 2>/dev/null\n')
        _fake(self.bin, "curl", f'[ -f {state}/answers ]\n')
        _fake(self.bin, "lsof", f'[ -f {state}/answers ] && cat {state}/listener 2>/dev/null\nexit 0\n')
        _fake(self.bin, "sleep", "exit 0\n")

    def orphan_lingers(self, checks: int) -> None:
        """`dkg stop` returns while the stopped node still runs for *checks* more liveness checks."""
        _set(self.state, **{f"alive_{ORPHAN_NODE}": str(checks)})

    def stray_on_first_start(self) -> None:
        """Something starts the node behind the service just as the handover starts it (KI-529)."""
        _set(self.state, stray_once="1")

    def run(self, wait_seconds: int = 3) -> tuple[list[str], str]:
        """Run the handover; return (every recorded start/stop call in order, its output)."""
        text = INSTALL_SH.read_text(encoding="utf-8")
        state, calls, pid_file = (shlex.quote(str(p)) for p in (self.state, self.calls, self.dkg_home / "daemon.pid"))
        unit_dir = self.home / "systemd"
        unit_dir.mkdir(exist_ok=True)
        if self.supervisor == "systemd":
            (unit_dir / "blackbox-dkg.service").write_text("[Service]\n", encoding="utf-8")
        if self.supervisor == "launchd":
            (self.home / "Library" / "LaunchAgents").mkdir(parents=True, exist_ok=True)
            (self.home / "Library" / "LaunchAgents" / f"{LABEL}.plist").write_text("<plist/>", encoding="utf-8")
        functions = "\n".join(f"{name}() {{\n{_body(text, name)}\n}}" for name in FUNCTIONS)
        script = f"""
BLACKBOX_SYSTEMD_DIR={shlex.quote(str(unit_dir))}
BLACKBOX_DKG_LAUNCHD_LABEL={LABEL}
BLACKBOX_DKG_HOME={shlex.quote(str(self.dkg_home))}
BLACKBOX_DKG_DAEMON_URL=http://127.0.0.1:9320
BLACKBOX_DKG_HANDOVER_WAIT_SECONDS={wait_seconds}
BLACKBOX_DKG_HANDOVER_STRAY_GRACE_SECONDS=2
BLACKBOX_DKG_HANDOVER_STRAY_STOPS=3
HOME={shlex.quote(str(self.home))}
PATH={shlex.quote(str(self.bin))}:/usr/bin:/bin
ok() {{ echo "OK $*"; }}
warn() {{ echo "WARN $*"; }}
step() {{ echo "STEP $*"; }}
blackbox_dkg() {{
    echo "dkg $*" >> {calls}
    case "$1" in
        stop) rm -f {pid_file} {state}/answers {state}/listener ;;
        start) echo {ORPHAN_NODE} > {pid_file}; echo {ORPHAN_SUPERVISOR} > {state}/ppid_{ORPHAN_NODE}; echo 1 > {state}/answers; echo {ORPHAN_NODE} > {state}/listener ;;
    esac
}}
kill() {{
    local pid="${{2:-$1}}" left
    left="$(cat {state}/alive_$pid 2>/dev/null || echo 0)"
    if [ "$left" -gt 0 ]; then echo $((left - 1)) > {state}/alive_$pid; return 0; fi
    [ -f {state}/alive_$pid ] && {{ rm -f {state}/alive_$pid; echo "gone $pid" >> {calls}; }}
    return 1
}}
BLACKBOX_DKG_STOP_WAIT_SECONDS=30
{functions}
hand_dkg_node_to_service
"""
        env = {k: v for k, v in os.environ.items() if k not in ("HOME", "PATH")}
        result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False, env=env)
        assert result.returncode == 0, result.stderr
        return self.calls.read_text(encoding="utf-8").splitlines(), result.stdout

    def node_pid(self) -> str:
        return (self.dkg_home / "daemon.pid").read_text(encoding="utf-8").strip()


def test_launchd_takes_the_node_the_installer_started(tmp_path):
    machine = Machine(tmp_path, "launchd")
    machine.orphan_running()
    machine.service_takes_over(True)
    calls, output = machine.run()
    assert calls == ["dkg stop", f"launchctl kickstart -k gui/{os.getuid()}/{LABEL}"]   # stop the copy, then the service
    assert machine.node_pid() == SERVICE_NODE
    assert "OK The DKG node now runs under its launchd service" in output
    assert "WARN" not in output


def test_systemd_takes_the_node_the_installer_started(tmp_path):
    """systemctl enable does not start a unit: without the handover the installer's copy serves until reboot."""
    machine = Machine(tmp_path, "systemd")
    machine.orphan_running()
    machine.service_takes_over(True)
    calls, output = machine.run()
    assert calls == ["dkg stop", "systemctl restart blackbox-dkg"]
    assert machine.node_pid() == SERVICE_NODE
    assert "OK The DKG node now runs under its systemd service" in output


def test_a_node_already_under_its_service_is_left_alone(tmp_path):
    """A re-run over a supervised node: nothing is stopped or restarted."""
    machine = Machine(tmp_path, "launchd")
    machine.service_running()
    calls, output = machine.run()
    assert calls == []
    assert "OK The DKG node already runs under its launchd service" in output


def test_a_service_running_some_other_copy_does_not_count_as_owning_the_node(tmp_path):
    """launchd's relaunch loop has a pid of its own while the installer's copy serves (the CI evidence)."""
    machine = Machine(tmp_path, "launchd")
    machine.orphan_running()
    _set(machine.state, service_pid="6001")
    machine.service_takes_over(True)
    calls, _ = machine.run()
    assert calls[0] == "dkg stop"
    assert machine.node_pid() == SERVICE_NODE


def test_a_stray_copy_started_behind_the_service_during_the_handover_is_stopped_and_the_service_takes_the_node(tmp_path):
    """KI-529 (E2E recheck 2, 2026-11-22): the dashboard's first sync restarted the node behind the
    LaunchAgent while the installer handed it over; launchd's copy then failed "Daemon already
    running" until the 300 s wait ran out and the install rolled back. A node that answers but is not
    the service's is this install's stray copy: it is stopped and the service starts the node."""
    machine = Machine(tmp_path, "launchd")
    machine.orphan_running()
    machine.service_takes_over(True)
    machine.stray_on_first_start()
    calls, output = machine.run(wait_seconds=10)
    kickstart = f"launchctl kickstart -k gui/{os.getuid()}/{LABEL}"
    assert calls == ["dkg stop", kickstart, "dkg stop", kickstart]
    assert machine.node_pid() == SERVICE_NODE
    assert "OK The DKG node now runs under its launchd service" in output
    assert "did not take over" not in output


def test_when_the_service_does_not_take_the_node_it_is_started_directly_and_the_run_warns(tmp_path):
    """Fail-safe: protection never drops, and the run never claims a supervised node."""
    machine = Machine(tmp_path, "launchd")
    machine.orphan_running()
    machine.service_takes_over(False)
    calls, output = machine.run()
    assert calls == ["dkg stop", f"launchctl kickstart -k gui/{os.getuid()}/{LABEL}",
                     f"launchctl bootout gui/{os.getuid()}/{LABEL}", "dkg start"]
    assert machine.node_pid() == ORPHAN_NODE   # the node runs again
    assert "did not take over the DKG node" in output
    assert "now runs under" not in output


def test_a_failed_launchd_handover_shows_the_service_s_last_errors(tmp_path):
    """launchd keeps no journal: the warning shows what the LaunchAgent's node wrote to stderr."""
    machine = Machine(tmp_path, "launchd")
    machine.orphan_running()
    machine.service_takes_over(False)
    (machine.dkg_home / "launchd-errors.log").write_text("Daemon already running (PID 4527).\n", encoding="utf-8")
    _, output = machine.run()
    assert "launchd-errors.log" in output and "Daemon already running (PID 4527)." in output


def test_without_a_service_nothing_is_handed_over(tmp_path):
    machine = Machine(tmp_path, "none")
    machine.orphan_running()
    calls, output = machine.run()
    assert calls == []
    assert output == ""


def test_the_handover_runs_when_the_boot_service_is_registered():
    body = _body(INSTALL_SH.read_text(encoding="utf-8"), "register_boot_service")
    assert body.rstrip().endswith("hand_dkg_node_to_service")


def test_the_service_starts_its_node_only_after_the_stopped_copy_is_gone(tmp_path):
    """KI-533 (E2E full3, 2026-11-22): `dkg stop` returns before the daemon exits, so the service's
    copy started in that window exited "Daemon already running" and launchd relaunched it."""
    machine = Machine(tmp_path, "launchd")
    machine.orphan_running()
    machine.orphan_lingers(3)
    machine.service_takes_over(True)
    calls, output = machine.run()
    assert f"gone {ORPHAN_NODE}" in calls, calls
    first_start = next(i for i, call in enumerate(calls) if call.startswith("launchctl kickstart"))
    assert calls.index(f"gone {ORPHAN_NODE}") < first_start, calls
    assert "OK The DKG node now runs under its launchd service" in output


def test_the_services_own_node_is_never_stopped_as_a_stray_while_it_writes_its_pid_late(tmp_path):
    """KI-533 (E2E full4, fresh install): the node answered before it wrote daemon.pid, so the
    handover took the service's own copy for a stray and stopped it three times — launchd started
    the node 4x in a minute. Ownership is now judged by the process serving the API port."""
    machine = Machine(tmp_path, "launchd")
    machine.orphan_running()
    machine.service_takes_over_writing_its_pid_late()
    calls, out = machine.run(wait_seconds=20)
    assert "OK The DKG node now runs under its launchd service" in out, out
    assert "Another copy of the DKG node" not in out, out
    assert [call for call in calls if call.startswith("launchctl kickstart")].__len__() == 1, calls
