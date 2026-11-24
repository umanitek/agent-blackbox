"""Where the system protection helper lives is ONE definition per OS, and the helper, the plugin
and the installer agree on it (Linux deep layers step 9).

``kernel/system_helper/platform/<os>.py`` names the helper's folder, program, service definition
and receipt; the helper's own install writes exactly those (``helper/src/platform/<os>/``), and
the installer's helper variables for that OS are the same — otherwise Network Shield would call an
installed helper missing, or ``blackbox uninstall`` would miss it.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
PLATFORM = REPO / "plugins" / "blackbox" / "kernel" / "system_helper" / "platform"
INSTALLER = (REPO / "scripts" / "blackbox-install.sh").read_text(encoding="utf-8")


def _places(system: str):
    spec = importlib.util.spec_from_file_location(f"system_helper_{system}", PLATFORM / f"{system}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _installer(case: str) -> dict[str, str]:
    block = re.search(rf"^    {re.escape(case)}\)\n(.*?);;", INSTALLER.split("Where the helper lives, per OS", 1)[1], re.MULTILINE | re.DOTALL).group(1)
    return dict(re.findall(r'BLACKBOX_(HELPER_\w+)="([^"]*)"', block))


def test_linux_places_are_the_ones_the_linux_helper_installs():
    linux = _places("linux")
    rust = (REPO / "plugins/blackbox/helper/src/platform/linux/mod.rs").read_text(encoding="utf-8")
    install = (REPO / "plugins/blackbox/helper/src/platform/linux/install.rs").read_text(encoding="utf-8")
    assert f'pub const HOME: &str = "{linux.HOME}";' in rust and f'pub const UNIT: &str = "{linux.SERVICE}";' in rust
    assert f'pub const BINARY: &str = "{linux.BINARY}";' in rust and f'pub const RECEIPT_PATH: &str = "{linux.RECEIPT}";' in install
    assert "pub const SUPPORTED: bool = true;" in rust
    shell = _installer("Linux*")
    assert (shell["HELPER_HOME"], shell["HELPER_PROGRAM"], shell["HELPER_DAEMON"], shell["HELPER_RECEIPT"]) == \
           (str(linux.HOME), str(linux.BINARY), str(linux.SERVICE), str(linux.RECEIPT))


def test_macos_places_are_unchanged_and_the_installers():
    macos = _places("macos")
    assert str(macos.SERVICE) == "/Library/LaunchDaemons/ai.umanitek.blackbox.netd.plist"
    shell = _installer("*")
    assert (shell["HELPER_HOME"], shell["HELPER_DAEMON"], shell["HELPER_RECEIPT"]) == (str(macos.HOME), str(macos.SERVICE), str(macos.RECEIPT))


@pytest.mark.parametrize("config, expected", [("", ".config/blackbox/helper"), ("/x/cfg", "/x/cfg/blackbox/helper")])
def test_the_persons_linux_key_folder_follows_xdg(monkeypatch, tmp_path, config, expected):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", config)
    folder = _places("linux").user_key_folder()
    assert str(folder) == (expected if config else str(tmp_path / expected))
