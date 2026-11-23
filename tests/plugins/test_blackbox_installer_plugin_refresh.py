"""An upgrade over a RUNNING install swaps the plugin copy whole, and a rollback puts it back whole (KI-644).

Security round 7 (bb-sec-r7, the real installer at 96b24d43b1 over 53c4864b with the dashboard, the
companion app and the hooks running): "Refreshing ~/.hermes/plugins/blackbox" died in
``shutil.rmtree`` with OSError 66 "Directory not empty" — the running dashboard and hooks wrote
fresh ``__pycache__`` folders into the copy while it was being deleted — and the rollback's
``rm -rf`` + ``cp`` then left "~/.hermes/plugins/blackbox (not restored)": a copy mixing files of
both commits.

Here a folder that can not be emptied stands in for the racing writer (deterministic: a read-only
sub-folder holding a file, so a delete in place fails exactly as it did), and the installer's own
code is run: the refresh block (``refresh_blackbox_plugin_copy``'s Python) and the rollback's
``rollback_put_back``, extracted from ``scripts/blackbox-install.sh``.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALL_SH = REPO_ROOT / "scripts" / "blackbox-install.sh"


def _refresh_script(tmp_path: Path) -> Path:
    block = re.search(r"refresh_blackbox_plugin_copy\(\) \{.*?<<'PYEOF'\n(.*?)\nPYEOF", INSTALL_SH.read_text(encoding="utf-8"), re.DOTALL)
    assert block, "the installer's plugin refresh block"
    script = tmp_path / "refresh.py"
    script.write_text(block.group(1), encoding="utf-8")
    return script


def _plugin(root: Path, version: str) -> None:
    plugin = root / "plugins" / "blackbox"
    (plugin / "kernel" / "os_layout").mkdir(parents=True, exist_ok=True)
    (plugin / "kernel" / "os_layout" / "__init__.py").write_text(
        "def other_os_entries(folder, names):\n    return []\n", encoding="utf-8")
    (plugin / "plugin.yaml").write_text(f"version: {version}\n", encoding="utf-8")
    (plugin / f"only_in_{version}.py").write_text("x = 1\n", encoding="utf-8")


@pytest.fixture
def stuck(tmp_path):
    """An installed copy with a sub-folder that can not be emptied (the running dashboard's stand-in)."""
    home = tmp_path / "home"
    dest = home / "plugins" / "blackbox"
    _plugin(home, "old")
    busy = dest / "__pycache__"
    busy.mkdir()
    (busy / "kernel.cpython-314.pyc").write_bytes(b"\0")
    busy.chmod(0o500)
    yield home, dest, busy
    for folder in (busy, *home.rglob("__pycache__")):
        try:
            folder.chmod(0o700)
        except OSError:
            pass


@pytest.mark.skipif(os.geteuid() == 0, reason="root deletes a read-only folder anyway")
def test_the_refresh_swaps_in_the_new_copy_while_the_old_one_is_in_use(tmp_path, stuck):
    home, dest, _busy = stuck
    repo = tmp_path / "repo"
    _plugin(repo, "new")
    done = subprocess.run([sys.executable, "-I", str(_refresh_script(tmp_path)), str(repo), str(home)],
                          capture_output=True, text=True, timeout=60, check=False)
    assert done.returncode == 0, done.stderr
    assert (dest / "plugin.yaml").read_text(encoding="utf-8") == "version: new\n"
    assert (dest / "only_in_new.py").exists() and not (dest / "only_in_old.py").exists(), "one commit's files only"
    assert sorted(path.name for path in (home / "plugins").iterdir()) == ["blackbox"], "nothing else in plugins/"


def test_a_refresh_that_fails_before_the_swap_leaves_the_old_copy_whole(tmp_path):
    home = tmp_path / "home"
    _plugin(home, "old")
    repo = tmp_path / "repo"
    _plugin(repo, "new")
    (repo / "plugins" / "blackbox" / "kernel" / "os_layout" / "__init__.py").write_text("raise SystemExit(3)\n", encoding="utf-8")
    done = subprocess.run([sys.executable, "-I", str(_refresh_script(tmp_path)), str(repo), str(home)],
                          capture_output=True, text=True, timeout=60, check=False)
    assert done.returncode != 0
    dest = home / "plugins" / "blackbox"
    assert (dest / "plugin.yaml").read_text(encoding="utf-8") == "version: old\n" and (dest / "only_in_old.py").exists()


@pytest.mark.skipif(os.geteuid() == 0, reason="root deletes a read-only folder anyway")
def test_the_rollback_puts_the_saved_copy_back_whole_while_the_new_one_is_in_use(tmp_path, stuck):
    home, dest, _busy = stuck
    saved = tmp_path / "saved"
    _plugin(saved, "before")
    function = re.search(r"^rollback_put_back\(\) \{.*?^\}", INSTALL_SH.read_text(encoding="utf-8"), re.DOTALL | re.MULTILINE)
    assert function, "the rollback's put-back"
    script = f"warn() {{ printf '%s\\n' \"$*\" >&2; }}\n{function.group(0)}\nrollback_put_back \"$1\" \"$2\"\n"
    done = subprocess.run(["/bin/bash", "-c", script, "bash", str(dest), str(saved / "plugins" / "blackbox")],
                          capture_output=True, text=True, timeout=60, check=False)
    assert done.returncode == 0, done.stderr
    assert subprocess.run(["diff", "-rq", str(saved / "plugins" / "blackbox"), str(dest)], capture_output=True, check=False).returncode == 0
    assert sorted(path.name for path in (home / "plugins").iterdir()) == ["blackbox"], "nothing else in plugins/"
