"""The install manifest per operating system (``setup/install_manifest.py``; the installers'
``install_manifest_begin`` / ``install_manifest_write`` and ``Start-InstallManifest`` /
``Write-InstallManifest``): everything an install creates on the machine besides Blackbox is
listed, so ``blackbox uninstall`` removes exactly that (KI-610, KI-611; installer audit 2026-11-23).

Gaps closed here, each red on the base:

* macOS / Linux: the Node ``ensure_node`` installs with nvm (``~/.nvm``) was never listed, so an
  uninstall with "remove the host" left it;
* Linux: systemd lingering the installer turns on (``loginctl enable-linger``) is a system setting
  that stayed on after uninstall;
* Windows: the folder the installer adds to the user PATH stayed (read here through a fake
  ``platform``; the registry code itself needs a Windows machine).
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from plugins.blackbox.setup import install_manifest
from plugins.blackbox.setup.platform import linux as linux_platform

INSTALL_SH = Path(__file__).resolve().parents[2] / "scripts" / "blackbox-install.sh"
FUNCTIONS = ("install_path_exists", "install_host_paths", "install_own_dirs", "install_startup_files",
             "install_manifest_begin", "install_manifest_write")


def _shell(home: Path, record: Path, linger_dir: Path, fake_bin: Path, call: str) -> None:
    text = INSTALL_SH.read_text(encoding="utf-8")
    bodies = []
    for name in FUNCTIONS:
        found = re.search(rf"^{name}\(\)\s*\{{.*?^\}}\n", text, re.MULTILINE | re.DOTALL)
        assert found is not None, name
        bodies.append(found.group(0))
    script = "\n".join([f'export PATH="{fake_bin}:$PATH"', f'HOME="{home}"', f'HERMES_HOME="{home}/.hermes"',
                        f'BLACKBOX_HOME="{home}/.hermes/blackbox"', f'BLACKBOX_INSTALL_ROOT="{home}/agent-blackbox"',
                        f'INSTALL_RECORD_DIR="{record}"', f'BLACKBOX_LINGER_DIR="{linger_dir}"', *bodies, call])
    done = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, timeout=60, check=False)
    assert done.returncode == 0, done.stderr


@pytest.fixture
def machine(tmp_path):
    """A clean home, a linger folder standing in for /var/lib/systemd/linger, and a loginctl on PATH."""
    home = (tmp_path / "home").resolve()
    home.mkdir()
    linger_dir = tmp_path / "linger"
    linger_dir.mkdir()
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "loginctl").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (fake_bin / "loginctl").chmod(0o755)
    record = tmp_path / "record"
    record.mkdir()
    return home, record, linger_dir, fake_bin


def _user() -> str:
    return subprocess.run(["id", "-un"], capture_output=True, text=True, check=True).stdout.strip()


def test_the_node_installed_with_nvm_is_listed_with_the_host(machine):
    home, record, linger_dir, fake_bin = machine
    _shell(home, record, linger_dir, fake_bin, "install_manifest_begin")
    (home / ".nvm" / "versions" / "node").mkdir(parents=True)
    (home / ".hermes" / "blackbox").mkdir(parents=True)
    _shell(home, record, linger_dir, fake_bin, "install_manifest_write")
    manifest = install_manifest.read(home / ".hermes" / "blackbox", home=home)
    assert home / ".nvm" in manifest.host
    report: list[str] = []
    install_manifest.remove_host(manifest, report)
    assert not (home / ".nvm").exists()


def test_linux_lingering_the_installer_turned_on_is_turned_off_by_uninstall(machine, monkeypatch):
    home, record, linger_dir, fake_bin = machine
    user = _user()
    _shell(home, record, linger_dir, fake_bin, "install_manifest_begin")
    (linger_dir / user).write_text("", encoding="utf-8")       # ensure_user_lingering turned it on
    (home / ".hermes" / "blackbox").mkdir(parents=True)
    _shell(home, record, linger_dir, fake_bin, "install_manifest_write")
    monkeypatch.setattr(install_manifest, "LINGER_DIR", linger_dir)
    monkeypatch.setattr(install_manifest, "platform", linux_platform)   # the Linux module, on any machine
    manifest = install_manifest.read(home / ".hermes" / "blackbox", home=home, user=user)
    assert manifest.linger_user == user
    ran: list[list[str]] = []
    report: list[str] = []
    install_manifest.restore_system_settings(manifest, lambda argv: ran.append(list(argv)) or 0, report)
    assert ran == [["loginctl", "disable-linger", user]]
    assert any("turned lingering off" in line for line in report)


def test_lingering_that_was_on_before_the_install_is_left_alone(machine, monkeypatch):
    home, record, linger_dir, fake_bin = machine
    user = _user()
    (linger_dir / user).write_text("", encoding="utf-8")       # the person had it on already
    _shell(home, record, linger_dir, fake_bin, "install_manifest_begin")
    (home / ".hermes" / "blackbox").mkdir(parents=True)
    _shell(home, record, linger_dir, fake_bin, "install_manifest_write")
    monkeypatch.setattr(install_manifest, "LINGER_DIR", linger_dir)
    assert install_manifest.read(home / ".hermes" / "blackbox", home=home, user=user).linger_user == ""


def test_a_linger_entry_for_another_user_or_folder_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(install_manifest, "LINGER_DIR", Path("/var/lib/systemd/linger"))
    folder = tmp_path / "bb" / install_manifest.FOLDER
    folder.mkdir(parents=True)
    (folder / install_manifest.MANIFEST).write_text(
        "own-linger\t/var/lib/systemd/linger/root\nown-linger\t/etc/linger/alice\n", encoding="utf-8")
    assert install_manifest.read(tmp_path / "bb", home=tmp_path, user="alice").linger_user == ""


def test_windows_the_user_path_entry_is_taken_off_on_every_uninstall(tmp_path, monkeypatch):
    home = tmp_path.resolve()
    folder = home / "bb" / install_manifest.FOLDER
    folder.mkdir(parents=True)
    shim_dir = home / ".local" / "bin"
    (folder / install_manifest.MANIFEST).write_text(f"user-path\t{shim_dir}\nuser-path\t/elsewhere/bin\n",
                                                    encoding="utf-8")
    manifest = install_manifest.read(home / "bb", home=home, user="alice")
    assert manifest.user_path == (shim_dir,)            # outside the home: refused
    taken: list[str] = []

    class FakeWindows:
        @staticmethod
        def disable_linger(_user, _run):
            return False

        @staticmethod
        def remove_user_path_entry(entry):
            taken.append(entry)
            return True

    monkeypatch.setattr(install_manifest, "platform", FakeWindows)
    report: list[str] = []
    install_manifest.restore_system_settings(manifest, lambda argv: 0, report)
    assert taken == [str(shim_dir)] and any("off your PATH" in line for line in report)


def test_on_macos_restoring_system_settings_changes_nothing(tmp_path):
    """macOS has neither: the facade's macOS answers are False and nothing runs."""
    from plugins.blackbox.setup.platform import macos
    assert macos.disable_linger("alice", lambda argv: 0) is False
    assert macos.remove_user_path_entry("/x") is False
