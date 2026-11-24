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
  ``platform``; the registry code itself needs a Windows machine);
* KI-654 (security round 7, Linux): ``--remove-host`` deleted ``~/.nvm`` with the Claude Code the
  person had installed into the installer's Node afterwards. Only what the installer created and
  the person has not added to goes (``setup/host_removal``).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from plugins.blackbox.setup import install_manifest
from plugins.blackbox.setup.platform import linux as linux_platform

INSTALL_SH = Path(__file__).resolve().parents[2] / "scripts" / "blackbox-install.sh"
FUNCTIONS = ("install_path_exists", "system_package_installed", "system_packages_absent", "install_host_paths", "install_own_dirs", "install_startup_files",
             "install_manifest_begin", "install_manifest_write")


def _shell(home: Path, record: Path, linger_dir: Path, fake_bin: Path, call: str) -> None:
    text = INSTALL_SH.read_text(encoding="utf-8")
    bodies = []
    for name in FUNCTIONS:
        found = re.search(rf"^{name}\(\)\s*\{{.*?^\}}\n", text, re.MULTILINE | re.DOTALL)
        assert found is not None, name
        bodies.append(found.group(0))
    script = "\n".join([f'export PATH="{fake_bin}:$PATH"', f'HOME="{home}"', f'HERMES_HOME="{home}/.hermes"',
                        f'BLACKBOX_HELPER_DAEMON="{home}/LaunchDaemons/netd.plist"',
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


def test_the_helper_and_the_notifier_this_install_added_are_in_the_manifest(machine, monkeypatch):
    """KI-629: the optional components are in the one list `blackbox uninstall` reads: the helper
    (accepted only as the helper's own LaunchDaemon) and the notifier, which uninstall removes."""
    from plugins.blackbox.kernel import system_helper
    home, record, linger_dir, fake_bin = machine
    _shell(home, record, linger_dir, fake_bin, "install_manifest_begin")
    (home / "LaunchDaemons").mkdir()
    (home / "LaunchDaemons" / "netd.plist").write_text("plist", encoding="utf-8")
    (home / ".hermes" / "blackbox" / "notifier" / "Blackbox.app").mkdir(parents=True)
    _shell(home, record, linger_dir, fake_bin, "install_manifest_write")
    text = (home / ".hermes" / "blackbox" / install_manifest.FOLDER / install_manifest.MANIFEST).read_text(encoding="utf-8")
    assert f"system-helper\t{home}/LaunchDaemons/netd.plist" in text
    assert f"notifier\t{home}/.hermes/blackbox/notifier" in text
    monkeypatch.setattr(system_helper, "SERVICE", home / "LaunchDaemons" / "netd.plist")
    manifest = install_manifest.read(home / ".hermes" / "blackbox", home=home)
    assert manifest.system_helper and manifest.notifier == (home / ".hermes" / "blackbox" / "notifier",)
    report: list[str] = []
    install_manifest.remove_components(manifest, report)
    assert not (home / ".hermes" / "blackbox" / "notifier").exists() and any("notifier" in line for line in report)


def test_a_system_helper_entry_names_only_the_helpers_own_launch_daemon(tmp_path):
    folder = tmp_path / "bb" / install_manifest.FOLDER
    folder.mkdir(parents=True)
    (folder / install_manifest.MANIFEST).write_text("system-helper\t/Library/LaunchDaemons/evil.plist\n", encoding="utf-8")
    assert install_manifest.read(tmp_path / "bb", home=tmp_path, user="alice").system_helper is False


def test_components_that_were_there_before_the_install_are_not_listed(machine):
    home, record, linger_dir, fake_bin = machine
    (home / "LaunchDaemons").mkdir()
    (home / "LaunchDaemons" / "netd.plist").write_text("theirs", encoding="utf-8")
    (home / ".hermes" / "blackbox" / "notifier").mkdir(parents=True)
    _shell(home, record, linger_dir, fake_bin, "install_manifest_begin")
    _shell(home, record, linger_dir, fake_bin, "install_manifest_write")
    text = (home / ".hermes" / "blackbox" / install_manifest.FOLDER / install_manifest.MANIFEST).read_text(encoding="utf-8")
    assert "system-helper" not in text and "notifier" not in text


def test_removing_the_host_takes_hermes_commands_that_lead_into_it_even_unlisted(tmp_path):
    """Security round 6 (variant B): Hermes republishes ``~/.local/bin/hermes-agent`` when it starts,
    so the uninstall's own Hermes rewrote it after the install manifest was written; removing the
    host left it pointing into the deleted checkout. A Hermes command that leads into a removed host
    folder goes with it; one that leads elsewhere (another Hermes) stays."""
    home = tmp_path.resolve()
    checkout = home / "agent-blackbox"
    (checkout / ".hermes" / "bin").mkdir(parents=True)
    bin_dir = home / ".local" / "bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "hermes-agent").write_text(f'#!/bin/sh\nexec "{checkout}/.hermes/bin/hermes" --run-module run_agent "$@"\n',
                                         encoding="utf-8")
    (bin_dir / "hermes-acp").symlink_to(checkout / ".hermes" / "bin" / "hermes-acp")
    (bin_dir / "hermes").write_text("#!/bin/sh\nexec /Applications/Hermes.app/Contents/MacOS/hermes \"$@\"\n", encoding="utf-8")
    manifest = install_manifest.InstallManifest(host=(checkout,))
    report: list[str] = []
    install_manifest.remove_host(manifest, report, home=home)
    assert not checkout.exists()
    assert not (bin_dir / "hermes-agent").exists() and not (bin_dir / "hermes-acp").is_symlink()
    assert (bin_dir / "hermes").exists()                       # another Hermes's command stays
    assert any("hermes-agent" in line and "just removed" in line for line in report)


@pytest.mark.skipif(not (os.environ.get("BLACKBOX_TEST_PWSH") or shutil.which("pwsh")), reason="PowerShell (pwsh) is not installed")
def test_windows_the_printed_commands_remove_a_kept_host_and_leave_a_filled_folder(tmp_path):
    """KI-630 on Windows: the PowerShell spelling of the commands printed for a kept host removes
    each listed path (a quote in its name included) and a listed folder only when it is empty."""
    from plugins.blackbox.setup.platform import windows as windows_platform
    odd = tmp_path / "it's a folder"
    (odd / "inside").mkdir(parents=True)
    filled, empty = tmp_path / "config", tmp_path / "config" / "openui"
    empty.mkdir(parents=True)
    (filled / "mine.txt").write_text("mine", encoding="utf-8")
    script = "\n".join(windows_platform.manual_removal([odd], [empty, filled]))
    pwsh = os.environ.get("BLACKBOX_TEST_PWSH") or shutil.which("pwsh")
    done = subprocess.run([pwsh, "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True,
                          timeout=120, check=False)
    assert done.returncode == 0, done.stderr
    assert not odd.exists() and not empty.exists() and (filled / "mine.txt").exists()


# -- KI-654: never the person's own tools --------------------------------------------------------

NODE = "versions/node/v22.21.1"
NVM_BLOCK = 'export NVM_DIR="$HOME/.nvm"\n[ -s "$NVM_DIR/nvm.sh" ] && \\. "$NVM_DIR/nvm.sh"\n'


def _installed_nvm(machine) -> Path:
    """An install that had to add nvm + Node 22 (and nvm's lines in ~/.bashrc), manifest written."""
    home, record, linger_dir, fake_bin = machine
    (home / ".bashrc").write_text("# mine\n", encoding="utf-8")
    _shell(home, record, linger_dir, fake_bin, "install_manifest_begin")
    (home / ".nvm" / NODE / "lib" / "node_modules" / "npm").mkdir(parents=True)
    (home / ".nvm" / "nvm.sh").write_text("# nvm\n", encoding="utf-8")
    with (home / ".bashrc").open("a", encoding="utf-8") as rc:
        rc.write(NVM_BLOCK)
    (home / ".hermes" / "blackbox").mkdir(parents=True)
    _shell(home, record, linger_dir, fake_bin, "install_manifest_write")
    assert (home / ".hermes" / "blackbox" / install_manifest.FOLDER / install_manifest.STAMP).is_file()
    return home


def test_nvm_holding_a_tool_the_person_installed_later_is_kept_with_its_startup_lines(machine):
    home = _installed_nvm(machine)
    claude = home / ".nvm" / NODE / "lib" / "node_modules" / "@anthropic-ai" / "claude-code"
    claude.mkdir(parents=True)                         # npm install -g @anthropic-ai/claude-code, after the install
    (claude / "cli.js").write_text("// the person's", encoding="utf-8")
    manifest = install_manifest.read(home / ".hermes" / "blackbox", home=home)
    assert home / ".nvm" in manifest.host
    report: list[str] = []
    install_manifest.remove_host(manifest, report, home=home)
    assert (claude / "cli.js").is_file() and (home / ".nvm" / "nvm.sh").is_file()
    assert NVM_BLOCK in (home / ".bashrc").read_text(encoding="utf-8")   # `claude` still on the person's PATH
    assert any(f"kept {home / '.nvm'}" in line and "@anthropic-ai" in line for line in report), report
    assert not (home / "agent-blackbox").exists()     # the rest of the host still goes
    kept = install_manifest.kept_host(manifest, home=home)
    assert home / ".nvm" not in kept.paths and not kept.appended   # no printed command deletes it either


def test_only_the_installers_node_goes_when_the_persons_tools_are_in_another_version(machine):
    home = _installed_nvm(machine)
    theirs = home / ".nvm" / "versions" / "node" / "v20.18.0" / "lib" / "node_modules" / "typescript"
    theirs.mkdir(parents=True)                         # nvm install 20 && npm install -g typescript, after
    manifest = install_manifest.read(home / ".hermes" / "blackbox", home=home)
    report: list[str] = []
    install_manifest.remove_host(manifest, report, home=home)
    assert not (home / ".nvm" / NODE).exists()        # the installer's Node 22, holding nothing of theirs
    assert theirs.is_dir() and (home / ".nvm" / "nvm.sh").is_file()
    assert any(f"removed {home / '.nvm' / NODE}" == line for line in report), report


def test_nvm_nobody_added_to_goes_whole_with_its_lines(machine):
    home = _installed_nvm(machine)
    manifest = install_manifest.read(home / ".hermes" / "blackbox", home=home)
    install_manifest.remove_host(manifest, [], home=home)
    assert not (home / ".nvm").exists()
    assert (home / ".bashrc").read_text(encoding="utf-8") == "# mine\n"


def test_nvm_the_person_had_before_the_install_is_never_listed(machine):
    home, record, linger_dir, fake_bin = machine
    (home / ".nvm" / NODE).mkdir(parents=True)
    _shell(home, record, linger_dir, fake_bin, "install_manifest_begin")
    (home / ".hermes" / "blackbox").mkdir(parents=True)
    _shell(home, record, linger_dir, fake_bin, "install_manifest_write")
    assert home / ".nvm" not in install_manifest.read(home / ".hermes" / "blackbox", home=home).host


def test_a_system_package_the_install_added_is_named_by_every_uninstall_never_removed(machine, monkeypatch):
    """KI-651 / KI-654 (security round 7, Linux): libatomic1 stayed after uninstall and nothing said
    so. It is not removed (other programs may need it; removal needs an administrator) — it is
    listed in the manifest and named with the command that removes it."""
    home, record, linger_dir, fake_bin = machine
    state = home.parent / "dpkg-installed"
    (fake_bin / "dpkg-query").write_text(f'#!/bin/sh\nfor a; do :; done; [ "$a" = libatomic1 ] && [ -e "{state}" ] && printf "install ok installed"\n',
                                         encoding="utf-8")
    (fake_bin / "dpkg-query").chmod(0o755)
    packages = re.search(r"^BLACKBOX_SYSTEM_PACKAGES=.*$", INSTALL_SH.read_text(encoding="utf-8"), re.MULTILINE)
    assert packages is not None   # the installer's own list
    _shell(home, record, linger_dir, fake_bin, f"{packages.group(0)}; install_manifest_begin")
    state.write_text("", encoding="utf-8")                      # Hermes's setup installed it with sudo
    (home / ".hermes" / "blackbox").mkdir(parents=True)
    _shell(home, record, linger_dir, fake_bin, f"{packages.group(0)}; install_manifest_write")
    manifest = install_manifest.read(home / ".hermes" / "blackbox", home=home)
    assert manifest.system_packages == ("libatomic1",)
    monkeypatch.setattr(install_manifest, "platform", linux_platform)
    monkeypatch.setattr(linux_platform.shutil, "which", lambda name: "/usr/bin/apt-get" if name == "apt-get" else None)
    ran: list[list[str]] = []
    report: list[str] = []
    install_manifest.restore_system_settings(manifest, lambda argv: ran.append(list(argv)) or 0, report)
    assert ran == []
    assert any("kept the system package libatomic1" in line and "sudo apt-get remove libatomic1" in line for line in report)


def test_a_planted_system_package_name_is_refused(tmp_path):
    folder = tmp_path / "bb" / install_manifest.FOLDER
    folder.mkdir(parents=True)
    (folder / install_manifest.MANIFEST).write_text("system-package\tlibatomic1; rm -rf ~\nsystem-package\tLIBX\n", encoding="utf-8")
    assert install_manifest.read(tmp_path / "bb", home=tmp_path, user="alice").system_packages == ()
