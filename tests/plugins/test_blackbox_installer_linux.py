"""The installer on Linux says plainly what this machine can take (installer audit 2026-11-23, fix wave 7).

Contracts, each red on the base ffaf359e56:

* KI-625 — an install as root (under sudo, or from a root shell) is refused before anything
  changes, naming the user to run it as; BLACKBOX_ALLOW_ROOT=1 lets a machine meant to run
  Blackbox as root go on, said as such. Before, the system units ran the node and dashboard as root.
* KI-626 — a Linux with the systemctl command but no running systemd (a container, WSL2 without
  systemd=true) gets no unit files, a plain "not started at boot" and the command that starts the
  node and the dashboard by hand; the end summary says so too.
* KI-627 — the distribution is named as supported (Debian / Ubuntu and their derivatives),
  untested (another glibc Linux) or unsupported (a musl Linux such as Alpine, which stops before
  any change unless BLACKBOX_ALLOW_UNSUPPORTED_DISTRO=1).

The installer's own functions run in a throwaway bash with stand-ins for ``id`` and ``systemctl``.
"""

from __future__ import annotations

import shlex
import subprocess
from pathlib import Path

import pytest

from tests.plugins._blackbox_installer_shell import functions_with_callees, installer_functions

INSTALL_SH = Path(__file__).resolve().parents[2] / "scripts" / "blackbox-install.sh"
TEXT = INSTALL_SH.read_text(encoding="utf-8")
PROVIDED = ("step", "ok", "warn", "err", "heading", "BLACKBOX_SYSTEMD_RUNTIME_DIR", "BLACKBOX_SYSTEMD_DIR")


def _run(tmp_path: Path, names: list[str], call: str, *, uid: int = 1000, env: str = "",
         systemctl: str | None = "exit 0", runtime: bool = True) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / "id").write_text(f'#!/bin/sh\n[ "$1" = -u ] && echo {uid} && exit 0\nexec /usr/bin/id "$@"\n', encoding="utf-8")
    (bin_dir / "id").chmod(0o755)
    (bin_dir / "systemctl").unlink(missing_ok=True)
    if systemctl is not None:
        (bin_dir / "systemctl").write_text(f'#!/bin/sh\necho "systemctl $*" >>{shlex.quote(str(tmp_path / "calls"))}\n{systemctl}\n',
                                           encoding="utf-8")
        (bin_dir / "systemctl").chmod(0o755)
    runtime_dir = tmp_path / "run-systemd"
    if runtime:
        runtime_dir.mkdir(exist_ok=True)
    script = f"""
set -euo pipefail
PATH={shlex.quote(str(bin_dir))}:/usr/bin:/bin
step() {{ echo "step: $*"; }}
ok() {{ echo "ok: $*"; }}
warn() {{ echo "warn: $*"; }}
err() {{ echo "err: $*"; }}
heading() {{ :; }}
BLACKBOX_SYSTEMD_RUNTIME_DIR={shlex.quote(str(runtime_dir))}
BLACKBOX_SYSTEMD_DIR={shlex.quote(str(tmp_path / "no-such-units"))}
{env}
{functions_with_callees(TEXT, names, provided=PROVIDED)}
{call}
"""
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60, check=False)


# ── KI-625: root ─────────────────────────────────────────────────────────────────────────────

def test_a_sudo_install_is_refused_and_names_the_user_to_run_it_as(tmp_path):
    done = _run(tmp_path, ["check_install_user"], "check_install_user; echo GO-ON", uid=0, env="SUDO_USER=amos")
    assert done.returncode == 1 and "GO-ON" not in done.stdout
    assert "Run the installer as amos, without sudo" in done.stdout


def test_a_root_shell_install_is_refused_with_the_way_forward(tmp_path):
    done = _run(tmp_path, ["check_install_user"], "unset SUDO_USER; check_install_user; echo GO-ON", uid=0)
    assert done.returncode == 1 and "BLACKBOX_ALLOW_ROOT=1" in done.stdout and "adduser" in done.stdout


def test_root_goes_on_only_when_the_machine_says_so_and_a_user_always_does(tmp_path):
    allowed = _run(tmp_path, ["check_install_user"], "check_install_user; echo GO-ON", uid=0, env="BLACKBOX_ALLOW_ROOT=1")
    assert allowed.returncode == 0 and "GO-ON" in allowed.stdout and "run as root" in allowed.stdout
    user = _run(tmp_path, ["check_install_user"], "check_install_user; echo GO-ON", uid=1000)
    assert user.returncode == 0 and user.stdout.strip() == "GO-ON"


def test_the_root_check_runs_before_anything_changes():
    main = installer_functions(TEXT)["main"]
    assert main.index("check_install_user") < main.index("install_record_begin")


# ── KI-626: no running systemd ──────────────────────────────────────────────────────────────

def test_no_running_systemd_is_named_with_its_reason(tmp_path):
    names = ["linux_services_unavailable"]
    stopped = _run(tmp_path, names, "linux_services_unavailable", runtime=False)
    assert stopped.returncode == 0 and "systemd is not running" in stopped.stdout and "wsl.conf" in stopped.stdout
    missing = _run(tmp_path, names, "linux_services_unavailable", systemctl=None)
    assert missing.returncode == 0 and "not installed" in missing.stdout
    no_user_manager = _run(tmp_path, names, "linux_services_unavailable", systemctl="exit 1")
    assert no_user_manager.returncode == 0 and "does not answer" in no_user_manager.stdout
    running = _run(tmp_path, names, "linux_services_unavailable")
    assert running.returncode == 1 and running.stdout == ""


def test_without_a_running_systemd_no_unit_is_written_and_the_manual_start_is_said(tmp_path):
    dkg = tmp_path / "dkg"
    dkg.write_text("#!/bin/sh\n", encoding="utf-8")
    dkg.chmod(0o755)
    env = (f"BLACKBOX_DKG_BIN={shlex.quote(str(dkg))}\nBLACKBOX_DKG_HOME={shlex.quote(str(tmp_path / '.dkg'))}\n"
           f"HOME={shlex.quote(str(tmp_path))}\nHERMES_BIN=\nuname() {{ echo Linux; }}\nsecure_dkg_token_perms() {{ :; }}")
    done = _run(tmp_path, ["register_boot_service"], 'register_boot_service; echo "BOOT=$BLACKBOX_BOOT_SERVICES"',
                env=env, runtime=False)
    assert done.returncode == 0, done.stderr
    assert "will NOT start at boot" in done.stdout and f'DKG_HOME="{tmp_path / ".dkg"}" "{dkg}" start' in done.stdout
    assert "BOOT=none" in done.stdout
    assert not (tmp_path / ".config" / "systemd").exists() and not (tmp_path / "calls").exists()


def test_the_summary_says_the_services_do_not_start_at_boot(tmp_path):
    env = 'OS=linux\nBLACKBOX_AUTO_DASHBOARD=1\nBLACKBOX_SYSTEM_PROTECTION_STATE=""\nBLACKBOX_BOOT_SERVICES=none'
    done = _run(tmp_path, ["protection_summary"], "protection_summary", env=env)
    assert done.returncode == 0, done.stderr
    assert "Start at boot (node, dashboard):         not set up" in done.stdout


# ── KI-627: which Linux ─────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("release, musl, level", [
    ('NAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\nPRETTY_NAME="Ubuntu 24.04 LTS"\n', False, "supported"),
    ('ID=linuxmint\nID_LIKE="ubuntu debian"\nPRETTY_NAME="Linux Mint 22"\n', False, "supported"),
    ('ID=debian\nPRETTY_NAME="Debian GNU/Linux 12"\n', False, "supported"),
    ('ID=fedora\nPRETTY_NAME="Fedora Linux 41"\n', False, "untested"),
    ('ID=arch\nPRETTY_NAME="Arch Linux"\n', False, "untested"),
    ('ID=alpine\nPRETTY_NAME="Alpine Linux v3.20"\n', True, "unsupported"),
])
def test_each_linux_is_named_supported_untested_or_unsupported(tmp_path, release, musl, level):
    (tmp_path / "os-release").write_text(release, encoding="utf-8")
    lib = tmp_path / "lib"
    lib.mkdir()
    if musl:
        (lib / "ld-musl-x86_64.so.1").write_text("", encoding="utf-8")
    done = _run(tmp_path, ["linux_distro_support"], f'linux_distro_support {shlex.quote(str(tmp_path / "os-release"))} {shlex.quote(str(lib))}')
    assert done.returncode == 0, done.stderr
    assert done.stdout.split("\t")[0] == level


def test_an_unsupported_linux_stops_before_any_change_unless_told_to_try(tmp_path):
    stub = "linux_distro_support() { printf 'unsupported\\tAlpine Linux v3.20\\n'; }"
    names = ["check_linux_distro"]
    provided = (*PROVIDED, "linux_distro_support")
    script = functions_with_callees(TEXT, names, provided=provided)
    for env, code in (("", 1), ("BLACKBOX_ALLOW_UNSUPPORTED_DISTRO=1", 0)):
        done = subprocess.run(["bash", "-c", "\n".join(["set -euo pipefail", 'step() { echo "step: $*"; }', 'ok() { :; }',
                                                       'warn() { echo "warn: $*"; }', 'err() { echo "err: $*"; }', env, stub,
                                                       script, "check_linux_distro; echo GO-ON"])],
                              capture_output=True, text=True, timeout=60, check=False)
        assert done.returncode == code, done.stderr
        assert ("GO-ON" in done.stdout) == (code == 0)
        assert "Alpine Linux v3.20 is not supported" in done.stdout


def test_an_untested_linux_is_said_and_the_install_goes_on(tmp_path):
    stub = "linux_distro_support() { printf 'untested\\tFedora Linux 41\\n'; }"
    script = functions_with_callees(TEXT, ["check_linux_distro"], provided=(*PROVIDED, "linux_distro_support"))
    done = subprocess.run(["bash", "-c", "\n".join(["set -euo pipefail", 'step() { echo "step: $*"; }', 'ok() { :; }',
                                                   'warn() { echo "warn: $*"; }', 'err() { :; }', stub, script,
                                                   "check_linux_distro; echo GO-ON"])],
                          capture_output=True, text=True, timeout=60, check=False)
    assert done.returncode == 0 and "GO-ON" in done.stdout
    assert "Fedora Linux 41 has not been tested" in done.stdout and "put back" in done.stdout
