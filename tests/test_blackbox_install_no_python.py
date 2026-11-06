"""A machine with no Python 3.11–3.13 and no uv installs without any manual step.

A user's Mac (2026-10-29) stopped at the pre-flight with "Python 3.11–3.13 not found (and uv
isn't installed). Easiest fix: brew install python@3.12" — yet Hermes's own setup
(setup-hermes.sh, which the installer runs) downloads a pinned, sha256-verified uv and has it
install Python, so the stop was for a step the installer does itself. `check_python` now
continues; only the old-Hermes fallback (`minimal_python_env`, used when there is no such setup)
still needs a Python or uv, and gives the install guidance there.

These run the real functions out of the script with a PATH that holds only fakes.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
INSTALL_SH = REPO / "scripts" / "blackbox-install.sh"


def _body(text: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{\s*\n(?P<body>.*?)^\}}", text, re.MULTILINE | re.DOTALL)
    assert match is not None, f"{name}() not found"
    return match["body"]


def _bin(tmp_path: Path, *, python: dict[str, str], uv: bool) -> Path:
    """A folder of fakes: each python name answers the version check per *python*
    ("ok" passes the 3.11–3.13 check, "old" fails it), plus `uv` when asked."""
    folder = tmp_path / "bin"
    folder.mkdir()
    for name, kind in python.items():
        exit_code = 0 if kind == "ok" else 1
        script = f'#!/bin/sh\ncase "$1" in -V) echo "Python {"3.12.7" if kind == "ok" else "3.10.4"}" ;; *) exit {exit_code} ;; esac\n'
        (folder / name).write_text(script, encoding="utf-8")
        (folder / name).chmod(0o755)
    if uv:
        (folder / "uv").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        (folder / "uv").chmod(0o755)
    for tool in ("awk", "sed", "cat"):   # what the functions themselves call
        (folder / tool).symlink_to(shutil.which(tool))
    return folder


def _run(tmp_path: Path, function: str, *, python: dict[str, str], uv: bool, extra: str = "") -> subprocess.CompletedProcess:
    text = INSTALL_SH.read_text(encoding="utf-8")
    folder = _bin(tmp_path, python=python, uv=uv)
    script = f"""
OS=macos
ok() {{ echo "OK $*"; }}
warn() {{ echo "WARN $*"; }}
step() {{ echo "STEP $*"; }}
err() {{ echo "ERR $*"; }}
{extra}
{function}() {{
{_body(text, function)}
}}
{function}
echo "CONTINUED PY=[$PY]"
"""
    return subprocess.run([shutil.which("bash"), "-c", script], capture_output=True, text=True, check=False,
                          env={"PATH": str(folder), "HOME": str(tmp_path)})


def test_no_suitable_python_and_no_uv_no_longer_stops_the_install(tmp_path):
    result = _run(tmp_path, "check_python", python={"python3": "old"}, uv=False)   # the user's Mac
    assert result.returncode == 0, result.stdout + result.stderr
    assert "CONTINUED PY=[]" in result.stdout
    assert "will download a pinned, checksum-verified uv and Python" in result.stdout
    assert "brew install" not in result.stdout and "ERR" not in result.stdout


def test_a_suitable_python_is_still_found_and_used(tmp_path):
    result = _run(tmp_path, "check_python", python={"python3.12": "ok", "python3": "old"}, uv=False)
    assert "OK Python 3.12.7 (python3.12)" in result.stdout and "CONTINUED PY=[python3.12]" in result.stdout


def test_uv_without_a_suitable_python_is_still_accepted(tmp_path):
    result = _run(tmp_path, "check_python", python={"python3": "old"}, uv=True)
    assert "uv will provide a compatible one" in result.stdout and "CONTINUED PY=[]" in result.stdout


def test_only_the_old_hermes_fallback_still_needs_python_or_uv_and_says_how(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    extra = f"REPO_DIR={shlex.quote(str(repo))}\nPY=\nfind_uv() {{ return 1; }}"
    result = _run(tmp_path, "minimal_python_env", python={"python3": "old"}, uv=False, extra=extra)
    assert result.returncode == 1 and "CONTINUED" not in result.stdout
    assert "ERR Need Python 3.11–3.13 or uv" in result.stdout and "brew install uv" in result.stdout


def test_the_plugin_ships_the_same_installer():
    shipped = (REPO / "plugins" / "blackbox" / "setup" / "blackbox-install.sh").read_bytes()
    assert shipped == INSTALL_SH.read_bytes()


def test_hermes_setup_stages_its_own_checksum_verified_uv():
    """The reason check_python may continue: Hermes's setup fetches uv itself and checks it."""
    setup = (REPO / "setup-hermes.sh").read_text(encoding="utf-8")
    assert "Staging pinned uv" in setup and "sha256 mismatch for uv" in setup
    assert re.search(r"bash \"\$REPO_DIR/setup-hermes\.sh\"", INSTALL_SH.read_text(encoding="utf-8"))
