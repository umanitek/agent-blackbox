"""The installer run from another folder installs into the checkout that is already here (KI-577).

Found in security round 2 (test VM, 2026-11-22): Blackbox was installed at ~/agent-blackbox; the
installer script, saved as ~/r2/blackbox-install.sh and run from ~/r2, cloned a SECOND checkout
into ~/r2/agent-blackbox. Hermes's setup then refused to hand the hermes command to that copy and
the install ended with "hermes: launcher publication failed" — an error that named Hermes, not the
cause. Now the checkout the hermes command runs is the install location wherever the script runs
from, and an install that would still make a second copy stops before anything changes, saying why.

The script's own configuration block and functions run under /bin/bash with a fake hermes launcher
and a temporary home; nothing here touches the real machine.
"""

from __future__ import annotations

import re
import shlex
import subprocess
from pathlib import Path

import pytest

INSTALL_SH = Path(__file__).resolve().parents[1] / "scripts" / "blackbox-install.sh"
TEXT = INSTALL_SH.read_text(encoding="utf-8")
#: The script's configuration block: everything from its strict mode to the first network setting.
PRELUDE = TEXT[TEXT.index("set -euo pipefail"):TEXT.index("DKG_NETWORK=")]


def _function(name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{.*?^\}}", TEXT, re.MULTILINE | re.DOTALL)
    assert match is not None, f"{name}() not found"
    return match.group(0)


@pytest.fixture()
def machine(tmp_path):
    """A home with Blackbox installed at ~/agent-blackbox behind ~/.local/bin/hermes, and the
    installer saved in ~/r2 (not a checkout)."""
    home = tmp_path / "home"
    checkout = home / "agent-blackbox"
    (checkout / "plugins" / "blackbox").mkdir(parents=True)
    (checkout / "plugins" / "blackbox" / "plugin.yaml").write_text("name: blackbox\n", encoding="utf-8")
    (checkout / "pyproject.toml").write_text("[project]\nname='hermes-agent'\n", encoding="utf-8")
    launcher = home / ".local" / "bin" / "hermes"
    launcher.parent.mkdir(parents=True)
    launcher.write_text(f'#!/bin/sh\n[ "$1" = --version ] && echo "Hermes Agent v0.22.7" && '
                        f'echo "Install directory: {checkout}"\nexit 0\n', encoding="utf-8")
    launcher.chmod(0o755)
    elsewhere = home / "r2"
    elsewhere.mkdir()
    return {"home": home, "checkout": checkout, "launcher": launcher, "r2": elsewhere}


def _install_root(machine: dict, extra: str = "") -> subprocess.CompletedProcess:
    script = machine["r2"] / "blackbox-install.sh"
    script.write_text(f"#!/usr/bin/env bash\n{extra}\n{PRELUDE}\nprintf '%s\\n' \"$BLACKBOX_INSTALL_ROOT\"\n", encoding="utf-8")
    env = {"HOME": str(machine["home"]), "PATH": "/usr/bin:/bin"}
    return subprocess.run(["/bin/bash", str(script)], cwd=machine["r2"], env=env, capture_output=True, text=True, check=False)


def test_run_from_another_folder_it_installs_into_the_checkout_already_here(machine):
    result = _install_root(machine)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(machine["checkout"])


def test_a_first_install_still_goes_where_the_person_runs_it(machine):
    machine["launcher"].unlink()
    assert _install_root(machine).stdout.strip() == str(machine["r2"] / "agent-blackbox")


def _preflight(machine: dict, root: Path) -> subprocess.CompletedProcess:
    script = f"""
set -euo pipefail
step() {{ printf 'step: %s\\n' "$*"; }}
err() {{ printf 'error: %s\\n' "$*"; }}
BLACKBOX_SETUP_ONLY=false
BLACKBOX_INSTALLED_CHECKOUT={shlex.quote(str(machine["checkout"]))}
BLACKBOX_INSTALL_ROOT={shlex.quote(str(root))}
{_function("preflight_one_checkout")}
preflight_one_checkout
echo passed
"""
    return subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, check=False)


def test_an_install_that_would_make_a_second_copy_stops_first_and_says_why(machine):
    second = machine["r2"] / "agent-blackbox"
    result = _preflight(machine, second)
    assert result.returncode == 1
    assert f"Blackbox is already installed from {machine['checkout']}" in result.stdout
    assert f"a second copy at {second}" in result.stdout
    assert "launcher" not in result.stdout   # the real cause, not Hermes's symptom
    assert not second.exists()


def test_the_installed_checkout_itself_passes(machine):
    assert _preflight(machine, machine["checkout"]).stdout.strip().endswith("passed")
