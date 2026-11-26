"""A copy of the plugin carries only this machine's operating-system modules (per-OS structure,
Amos 2026-11-21): ``kernel.os_layout`` and the two copies that use it — ``blackbox attach``
(``attach/plugin_copy.py``) and the installer's plugin refresh (``scripts/blackbox-install.sh``)."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

from plugins.blackbox.attach import plugin_copy
from plugins.blackbox.kernel import os_layout

REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALL_SH = REPO_ROOT / "scripts" / "blackbox-install.sh"
ENTRIES = ["__init__.py", "macos.py", "windows.py", "linux", "unsupported.py", "mod.rs", "macos"]


def test_each_os_keeps_only_its_own_platform_entries():
    assert os_layout.other_os_entries("a/platform", ENTRIES, "darwin") == ["windows.py", "linux"]
    assert os_layout.other_os_entries("a/platform", ENTRIES, "win32") == ["macos.py", "linux", "macos"]
    assert os_layout.other_os_entries("a/platform", ENTRIES, "linux") == ["macos.py", "windows.py", "macos"]
    assert os_layout.other_os_entries("a/monitor", ENTRIES, "darwin") == [], "only a platform/ folder is sorted by OS"
    assert os_layout.os_folder("freebsd14") == "" and os_layout.other_os_entries("platform", ["macos.py"], "freebsd14") == ["macos.py"]


def _plugin_tree(root: Path) -> Path:
    """A small plugin tree with a platform/ folder for every OS (and the real rule file)."""
    plugin = root / "plugins" / "blackbox"
    platform = plugin / "shields" / "network" / "monitor" / "platform"
    for name in ("__init__.py", "macos.py", "windows.py", "unsupported.py", "linux/__init__.py"):
        (platform / name).parent.mkdir(parents=True, exist_ok=True)
        (platform / name).write_text("# test\n", encoding="utf-8")
    rule = plugin / "kernel" / "os_layout" / "__init__.py"
    rule.parent.mkdir(parents=True)
    shutil.copy(REPO_ROOT / "plugins" / "blackbox" / "kernel" / "os_layout" / "__init__.py", rule)
    return plugin


def _copied(dest: Path) -> list[str]:
    return sorted(p.relative_to(dest / "shields" / "network" / "monitor" / "platform").as_posix()
                  for p in (dest / "shields" / "network" / "monitor" / "platform").rglob("*") if p.is_file())


def _this_os_only() -> list[str]:
    here = os_layout.os_folder()
    everything = ["__init__.py", "linux/__init__.py", "macos.py", "unsupported.py", "windows.py"]
    others = {name for name in ("macos", "windows", "linux") if name != here}
    return [path for path in everything if path.split("/")[0].removesuffix(".py") not in others]


def test_blackbox_attach_copies_only_this_machines_platform_modules(tmp_path):
    src = _plugin_tree(tmp_path / "repo")
    dest = tmp_path / "home" / "plugins" / "blackbox"
    plugin_copy.copy_plugin_tree(src, dest)
    assert _copied(dest) == _this_os_only()
    if sys.platform == "darwin":
        assert _copied(dest) == ["__init__.py", "macos.py", "unsupported.py"]


def test_the_installers_plugin_refresh_copies_only_this_machines_platform_modules(tmp_path):
    text = INSTALL_SH.read_text(encoding="utf-8")
    block = re.search(r"refresh_blackbox_plugin_copy\(\) \{.*?<<'PYEOF'\n(.*?)\nPYEOF", text, re.DOTALL)
    assert block, "the installer's plugin refresh block"
    script = tmp_path / "refresh.py"
    script.write_text(block.group(1), encoding="utf-8")
    repo, home = tmp_path / "repo", tmp_path / "home"
    _plugin_tree(repo)
    subprocess.run([sys.executable, "-I", str(script), str(repo), str(home)], check=True, capture_output=True, timeout=60)
    assert _copied(home / "plugins" / "blackbox") == _this_os_only()
