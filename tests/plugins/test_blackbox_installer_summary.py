"""What the installer says at the end is true for THIS operating system (installer audit 2026-11-23,
KI-609's lesson: every check mark is a check, never an assumption).

Only macOS has platform code for the root helper, the kernel sandbox and Network Shield's
enforcement (per-OS structure, 2026-11-21). On Linux the summary must name each as not available
yet and never imply it; on macOS it says what this run really did with the helper. ``uname`` is
simulated: the installer's own ``detect_os`` and ``protection_summary`` run under a stand-in.

Also here: an unsupported processor stops before any change (Hermes's setup has tools for x86_64
and arm64 only), and a rollback says "nothing was left behind" only after looking.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

INSTALL_SH = Path(__file__).resolve().parents[2] / "scripts" / "blackbox-install.sh"
NOT_YET = "not available on this OS yet"


def _run(call: str, functions: tuple[str, ...], prelude: str = "") -> subprocess.CompletedProcess:
    text = INSTALL_SH.read_text(encoding="utf-8")
    bodies = []
    for name in functions:
        found = re.search(rf"^{name}\(\)\s*\{{.*?^\}}\n|^{name}\(\)\s*\{{[^\n]*\}}\n", text, re.MULTILINE | re.DOTALL)
        assert found is not None, name
        bodies.append(found.group(0))
    constant = re.search(r"^BLACKBOX_NOT_YET=.*$", text, re.MULTILINE)
    assert constant is not None
    script = "\n".join(["GREEN= YELLOW= CYAN= RED= NC=", constant.group(0), *bodies, prelude, call])
    return subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, timeout=60, check=False)


def _uname(system: str, machine: str = "x86_64") -> str:
    return f'uname() {{ case "$1" in -s) echo {system} ;; -m) echo {machine} ;; *) echo {system} ;; esac; }}'


SUMMARY = ("ok", "err", "detect_os", "protection_summary")


def test_on_linux_the_macos_only_protections_are_named_as_not_available():
    done = _run("detect_os; BLACKBOX_SYSTEM_PROTECTION_STATE=unsupported; protection_summary", SUMMARY,
                _uname("Linux"))
    assert done.returncode == 0, done.stderr
    out = done.stdout
    assert "Protection on this machine (Linux):" in out
    for name in ("Root system-protection helper", "Kernel sandbox for agents", "Network Shield enforcement"):
        line = next(line for line in out.splitlines() if name in line)
        assert line.rstrip().endswith(NOT_YET), line
    assert "Agent hooks" in out and "Threat detection + dependency checks:    on" in out
    assert "installed" not in out.split("Dashboard")[1] and "File Shield" not in out and "DNS Shield" not in out


@pytest.mark.parametrize("state, helper, network", [
    ("installed", "installed", "available"),
    ("declined", "not installed", "needs the helper"),
    ("failed", "not installed (it failed", "needs the helper"),
])
def test_on_macos_the_summary_says_what_this_run_did_with_the_helper(state, helper, network):
    done = _run(f"detect_os; BLACKBOX_SYSTEM_PROTECTION_STATE={state}; protection_summary", SUMMARY, _uname("Darwin", "arm64"))
    assert done.returncode == 0, done.stderr
    lines = done.stdout.splitlines()
    assert "Protection on this machine (macOS):" in done.stdout and NOT_YET not in done.stdout
    assert helper in next(line for line in lines if "Root system-protection helper" in line)
    assert network in next(line for line in lines if "Network Shield enforcement" in line)


def test_a_dashboard_left_off_is_not_reported_as_running():
    done = _run("detect_os; BLACKBOX_AUTO_DASHBOARD=0; protection_summary", SUMMARY, _uname("Linux"))
    assert "running" not in next(line for line in done.stdout.splitlines() if "Dashboard" in line)


@pytest.mark.parametrize("machine", ["riscv64", "armv7l", "i686"])
def test_an_unsupported_processor_stops_before_anything_changes(machine):
    done = _run("detect_os; echo GOT-PAST", ("ok", "err", "detect_os"), _uname("Linux", machine))
    assert done.returncode == 1 and "GOT-PAST" not in done.stdout
    assert f"Unsupported processor: {machine}" in done.stdout


ROLLBACK = ("ok", "warn", "install_path_exists", "install_path_removable", "system_package_installed",
            "system_package_removal", "rollback_leftovers")


def test_a_rollback_that_could_not_remove_something_names_it(tmp_path):
    """"Nothing from this install attempt was left behind" was printed without looking."""
    record = tmp_path / "record"
    record.mkdir()
    stuck = tmp_path / "home" / "agent-blackbox"
    stuck.mkdir(parents=True)
    (record / "absent").write_text(f"{stuck}\n{tmp_path}/home/gone\n", encoding="utf-8")
    (record / "saved").write_text("", encoding="utf-8")
    prelude = (f'HOME="{tmp_path}/home"; BLACKBOX_PROTECTED_ROOTS="/Users /home"; INSTALL_RECORD_DIR="{record}"; '
               f'BLACKBOX_INSTALL_ROOT="{tmp_path}/none"')
    done = _run("rollback_leftovers", ROLLBACK, prelude)
    assert done.returncode == 0, done.stderr
    assert done.stdout.splitlines() == [str(stuck)]
    stuck.rmdir()
    assert _run("rollback_leftovers", ROLLBACK, prelude).stdout == ""


def test_a_rollback_names_a_system_package_this_attempt_installed(tmp_path):
    """KI-651 (security round 7, Linux check 5): the rollback said "Nothing … was left behind" while
    the apt package libatomic1 (installed with sudo for nvm's Node) stayed. It stays — other
    programs may use it — but it is named, with the command that removes it."""
    record = tmp_path / "record"
    record.mkdir()
    (record / "absent").write_text("", encoding="utf-8")
    (record / "saved").write_text("", encoding="utf-8")
    (record / "packages-absent").write_text("libatomic1\nlibatomic\n", encoding="utf-8")
    fake = ('dpkg-query() { for a; do :; done; [ "$a" = libatomic1 ] && printf "install ok installed"; }; rpm() { return 1; }; '
            'apt-get() { :; }')
    prelude = (f'HOME="{tmp_path}/home"; BLACKBOX_PROTECTED_ROOTS="/Users /home"; INSTALL_RECORD_DIR="{record}"; '
               f'BLACKBOX_INSTALL_ROOT="{tmp_path}/none"; {fake}')
    done = _run("rollback_leftovers", ROLLBACK, prelude)
    assert done.returncode == 0, done.stderr
    [line] = done.stdout.splitlines()
    assert line.startswith("libatomic1 (a system package installed during this attempt; kept")
    assert line.endswith("remove it with: sudo apt-get remove libatomic1)")


def test_the_caches_an_install_creates_are_rolled_back_and_listed_with_the_host(tmp_path):
    """KI-651 / KI-650: ~/.npm (the DKG package's npm) and ~/.cache/uv (Hermes's setup) were left
    by a rollback and by uninstall; made by this run, they are this run's to take away."""
    prelude = f'HOME="{tmp_path}"; BLACKBOX_INSTALL_ROOT=r; HERMES_HOME=h; BLACKBOX_HOME=b'
    created = _run("install_created_paths", ("install_created_paths",), prelude).stdout.splitlines()
    host = _run("install_host_paths", ("install_host_paths",), prelude).stdout.splitlines()
    for cache in (f"{tmp_path}/.npm", f"{tmp_path}/.cache/uv"):
        assert cache in created and cache in host
