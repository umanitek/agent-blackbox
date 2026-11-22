"""The installer uses a Node.js already on the machine before installing another.

KI-418: a Node that nvm installed on an earlier run. E2E recheck 2026-11-21: Homebrew's keg-only
node@24, which a non-login shell (an update over SSH) does not have on PATH — the update installed
a second Node with nvm and the node's service then failed on it.

nvm puts Node under ~/.nvm/versions, which a fresh, non-interactive shell does not have on PATH.
Every re-run therefore announced "Node.js 22+ not found — installing it automatically" and ran
`nvm install` again (seen on the trader bench, 2026-10-15). ensure_node now asks nvm first.
"""

from __future__ import annotations

import re
import shlex
import subprocess
from pathlib import Path

INSTALL_SH = Path(__file__).resolve().parents[1] / "scripts" / "blackbox-install.sh"


def _body(name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{\s*\n(?P<body>.*?)^\}}", INSTALL_SH.read_text(encoding="utf-8"),
                      re.MULTILINE | re.DOTALL)
    assert match is not None, f"{name}() not found"
    return match["body"]


def _fake_node(folder: Path, major: int) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    for name, version in (("node", f"v{major}.3.0"), ("npm", "10.9.0")):
        (folder / name).write_text(f"#!/bin/sh\necho {version}\n", encoding="utf-8")
        (folder / name).chmod(0o755)


def _ensure_node(tmp_path: Path, *, installed_major: int, keg_major: int = 0) -> tuple[subprocess.CompletedProcess, str]:
    nvm_dir, node_bin, calls = tmp_path / "nvm", tmp_path / "nvm-node" / "bin", tmp_path / "calls"
    nvm_dir.mkdir(); node_bin.mkdir(parents=True); calls.write_text("", encoding="utf-8")
    places, kegs = tmp_path / "places", tmp_path / "opt"      # stand-ins for /opt/homebrew/bin and /opt/homebrew/opt
    places.mkdir(); kegs.mkdir()
    if keg_major:
        _fake_node(kegs / f"node@{keg_major}" / "bin", keg_major)
    for name, version in (("node", f"v{installed_major}.3.0"), ("npm", "10.9.0")):
        (node_bin / name).write_text(f"#!/bin/sh\necho {version}\n", encoding="utf-8")
        (node_bin / name).chmod(0o755)
    # A stand-in nvm: `use` puts its Node on PATH (as the real one does); every call is recorded.
    (nvm_dir / "nvm.sh").write_text(
        f'nvm() {{ echo "nvm $*" >> {shlex.quote(str(calls))}; '
        f'if [ "$1" = use ]; then PATH={shlex.quote(str(node_bin))}:$PATH; fi; }}\n', encoding="utf-8")
    script = f"""
set -euo pipefail
ok() {{ echo "OK $*"; }}
warn() {{ echo "WARN $*"; }}
step() {{ :; }}
_node_manual_hint() {{ :; }}
curl() {{ echo "curl $*" >> {shlex.quote(str(calls))}; return 1; }}
NODE_MAJOR=22
SKIP_DKG=false
NVM_DIR={shlex.quote(str(nvm_dir))}
PATH=/usr/bin:/bin
BLACKBOX_NODE_PLACES={shlex.quote(str(places))}
BLACKBOX_NODE_KEG_ROOTS={shlex.quote(str(kegs))}
_node_ok() {{
{_body("_node_ok")}
}}
_installed_node_dirs() {{
{_body("_installed_node_dirs")}
}}
_use_installed_node() {{
{_body("_use_installed_node")}
}}
ensure_node() {{
{_body("ensure_node")}
}}
ensure_node
echo "HAS_NODE=$HAS_NODE"
"""
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)
    return result, calls.read_text(encoding="utf-8")


def test_a_node_nvm_installed_earlier_is_used_without_a_second_install(tmp_path):
    result, calls = _ensure_node(tmp_path, installed_major=22)

    assert result.returncode == 0, result.stderr
    assert "HAS_NODE=true" in result.stdout and "installed earlier with nvm" in result.stdout
    assert "not found" not in result.stdout and "nvm install" not in calls


def test_an_older_nvm_node_still_triggers_the_install(tmp_path):
    result, calls = _ensure_node(tmp_path, installed_major=18)

    assert "not found" in result.stdout and "nvm install 22" in calls


def test_a_keg_only_homebrew_node_is_used_before_installing_another(tmp_path):
    result, calls = _ensure_node(tmp_path, installed_major=18, keg_major=24)

    assert result.returncode == 0, result.stderr
    assert "HAS_NODE=true" in result.stdout and "already on this machine" in result.stdout and "node@24" in result.stdout
    assert "not found" not in result.stdout and "nvm install" not in calls


def test_a_keg_node_older_than_needed_is_not_used(tmp_path):
    result, calls = _ensure_node(tmp_path, installed_major=18, keg_major=20)

    assert "not found" in result.stdout and "nvm install 22" in calls
