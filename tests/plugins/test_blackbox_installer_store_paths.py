"""The installer's store step works when its Python lives under a folder with a space.

A bundled engine runs the installer with ``VENV_DIR`` inside an app bundle
(``/Applications/<Name With Space>.app/…``). ``provision_blackbox_store`` ran
``$VENV_DIR/bin/python`` unquoted inside a command substitution, so bash split the path at the
space ("line 1159: /Applications/Blackbox: No such file or directory", clean-VM install
2026-11-26): the existing node's store settings read back empty, and the store namespace became
the empty string. These tests run the real function with such a path (FIX-PENDING-d8707c).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from tests.plugins._blackbox_installer_shell import functions_with_callees

INSTALLER = Path(__file__).resolve().parents[2] / "scripts" / "blackbox-install.sh"
STUBS = ("step", "ok", "warn", "err", "use_blackbox_oxigraph", "blackbox_helper")


def _run_store_step(tmp_path: Path, config: dict) -> subprocess.CompletedProcess[str]:
    venv = tmp_path / "Folder With Space.app" / "venv"
    (venv / "bin").mkdir(parents=True)
    (venv / "bin" / "python").symlink_to(sys.executable)
    dkg_home = tmp_path / "dkg home"
    dkg_home.mkdir()
    (dkg_home / "config.json").write_text(json.dumps(config), encoding="utf-8")
    functions = functions_with_callees(
        INSTALLER.read_text(encoding="utf-8"), ["provision_blackbox_store"], provided=STUBS
    )
    script = "\n".join([
        "set -u",
        "step() { :; }; ok() { :; }; warn() { :; }; err() { echo \"err: $*\" >&2; }",
        "blackbox_helper() { printf '%s' /nonexistent/helper; }",
        'use_blackbox_oxigraph() { echo "oxigraph namespace=$BLACKBOX_DKG_STORE_NAMESPACE"; }',
        functions,
        "BLACKBOX_DKG_STORE_BACKEND=auto",
        "BLACKBOX_DKG_STORE_URL_EXPLICIT=false",
        "provision_blackbox_store",
    ])
    env = {"PATH": "/usr/bin:/bin", "VENV_DIR": str(venv), "BLACKBOX_DKG_HOME": str(dkg_home)}
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, timeout=60, check=False)


def test_existing_store_settings_are_read_when_the_python_path_has_a_space(tmp_path):
    result = _run_store_step(tmp_path, {"name": "my-graph", "store": {"backend": "oxigraph-server"}})
    assert "No such file or directory" not in result.stderr, result.stderr
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "oxigraph namespace=my-graph"


def test_a_missing_name_falls_back_to_the_default_namespace_not_an_empty_one(tmp_path):
    result = _run_store_step(tmp_path, {"store": {"backend": "oxigraph-server"}})
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "oxigraph namespace=agent-blackbox"
