"""Setup never writes into an app bundle that carries the Hermes it runs in.

A bundled engine runs `blackbox setup` with HERMES_BIN inside `/Applications/<App>.app/Contents/
Resources/engine/bin`. The installer put its `blackbox` shortcut beside that `hermes`, which broke
the app's signature seal ("a sealed resource is missing or invalid", clean-Mac install 2026-11-26)
and fails outright in a read-only, translocated copy. These tests run the real function.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from tests.plugins._blackbox_installer_shell import functions_with_callees

INSTALLER = Path(__file__).resolve().parents[2] / "scripts" / "blackbox-install.sh"
STUBS = ("heading", "step", "ok", "warn", "err")


def _run(tmp_path: Path, bin_dir: Path) -> subprocess.CompletedProcess[str]:
    bin_dir.mkdir(parents=True)
    hermes = bin_dir / "hermes"
    hermes.write_text("#!/bin/sh\n", encoding="utf-8")
    hermes.chmod(0o755)
    venv = tmp_path / "venv"
    (venv / "bin").mkdir(parents=True)
    (venv / "bin" / "python").symlink_to(sys.executable)
    home = tmp_path / "home"
    home.mkdir()
    functions = functions_with_callees(INSTALLER.read_text(encoding="utf-8"), ["use_running_hermes"], provided=STUBS)
    script = "\n".join([
        "heading() { :; }; ok() { echo \"ok: $*\"; }; warn() { echo \"warn: $*\"; }; step() { echo \"step: $*\"; }; err() { echo \"err: $*\"; }",
        functions,
        "use_running_hermes",
    ])
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(home), "HERMES_BIN": str(hermes), "VENV_DIR": str(venv)}
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, timeout=60, check=False)


def test_the_shortcut_is_never_written_into_an_app_bundle(tmp_path):
    bin_dir = tmp_path / "Blackbox App.app" / "Contents" / "Resources" / "engine" / "bin"
    result = _run(tmp_path, bin_dir)
    assert result.returncode == 0, result.stderr
    assert not (bin_dir / "blackbox").exists(), result.stdout
    assert "hermes blackbox" in result.stdout


def test_a_plain_folder_still_gets_the_shortcut(tmp_path):
    bin_dir = tmp_path / "opt" / "hermes" / "bin"
    result = _run(tmp_path, bin_dir)
    assert result.returncode == 0, result.stderr
    assert (bin_dir / "blackbox").is_file(), result.stdout
    assert os.access(bin_dir / "blackbox", os.X_OK)


def test_the_plugins_installer_is_the_same_file_as_the_one_line_installer():
    """`blackbox setup` runs the plugin's copy (ARCHITECTURE.md: "byte-identical copy"). The quoted
    store path fix (FIX-PENDING-d8707c) reached only scripts/ at first, so a catalog install kept the
    bug; one file changed without the other is a split install path."""
    plugin_copy = INSTALLER.parents[1] / "plugins" / "blackbox" / "setup" / "blackbox-install.sh"
    assert plugin_copy.read_bytes() == INSTALLER.read_bytes()
