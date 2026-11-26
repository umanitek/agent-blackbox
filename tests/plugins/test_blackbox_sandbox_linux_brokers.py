"""The Linux sandbox's words and brokers (design "Linux deep layers" §1.6 and §4, build step 16,
local-only): what an agent sees when Linux's sandbox refuses something, what the permissions
page says on Linux, and the openers and package managers the broker reaches there.

Contracts (the shell stand-ins run on any OS; the catalogue's Linux view is checked on Linux, the
Blackbox CI lane):
* Linux's refusals read as the sandbox's: a read-only place (EROFS), a pinned folder (EBUSY), a
  protected file in home (EACCES — outside home an ordinary permission says the same, so not
  counted), sudo under no new privileges, the hidden session bus, the hidden display;
* the machine is "this computer" on Linux, "this Mac" on macOS;
* on Linux the camera and microphone are controllable, the keychain is blocked (F4) and the
  clipboard's refusal kind includes the display;
* ``xdg-open`` / ``sensible-browser`` / ``gio open`` hand one web link to the broker,
  ``gio launch <app> <files>`` a file in a named app; anything else is refused with the reason;
  ``gio``'s other subcommands run the real ``gio``;
* the broker finds Linuxbrew and the person's package managers in Linux's places.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from plugins.blackbox.agent_hooks.protect import sandbox_errors
from plugins.blackbox.kernel.os_layout import machine_words
from plugins.blackbox.shields.files.sandbox.platform.linux import shims


@pytest.fixture
def linux_words(monkeypatch, tmp_path):
    monkeypatch.setattr(sandbox_errors, "LINUX", True)
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def test_linux_refusals_read_as_the_sandboxs(linux_words):
    home = linux_words
    cases = {
        f"touch: cannot touch '{home}/.hermes/blackbox/x': Read-only file system": sandbox_errors.FILE,
        f"bash: {home}/.config/systemd/user/evil.service: Read-only file system": sandbox_errors.PERSISTENCE,
        f"mv: cannot move '{home}/Documents' to '{home}/D2': Device or resource busy": sandbox_errors.FILE,
        f"cat: {home}/Documents/Taxes/2025.pdf: Permission denied": sandbox_errors.FILE,
        f"PermissionError: [Errno 13] Permission denied: '{home}/Documents/Taxes/a b.pdf'": sandbox_errors.FILE,
        'sudo: The "no new privileges" flag is set, which prevents sudo from running as root.': sandbox_errors.SETUID,
        "Failed to connect to bus: Permission denied": sandbox_errors.SYSTEM_SERVICES,
        "Error: Can't open display: :0": sandbox_errors.DISPLAY,
    }
    for output, kind in cases.items():
        found = sandbox_errors.refusals(output)
        assert [each.kind for each in found] == [kind], output
        assert sandbox_errors.note(found).startswith("Blackbox's sandbox refused this ("), output
    assert sandbox_errors.refusals(f"bash: {home}/.bashrc: Read-only file system")[0].kind == sandbox_errors.STARTUP
    assert sandbox_errors.refusals("cat: /root/secret: Permission denied") == [], "outside home: an ordinary permission"


def test_macos_reads_none_of_linuxs_words(monkeypatch, tmp_path):
    monkeypatch.setattr(sandbox_errors, "LINUX", False)
    monkeypatch.setenv("HOME", str(tmp_path))
    assert sandbox_errors.refusals(f"cat: {tmp_path}/Taxes/x: Permission denied") == []
    assert sandbox_errors.refusals("Failed to connect to bus: Permission denied") == []


def test_the_machine_is_named_as_a_person_does_on_it():
    assert machine_words("darwin") == "this Mac"
    assert machine_words("linux") == "this computer"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the catalogue's Linux view is built on Linux")
def test_on_linux_the_camera_is_controllable_the_keychain_blocked_and_the_display_is_the_clipboard():
    from plugins.blackbox.shields.files.sandbox.permissions import catalogue
    assert catalogue.BY_ID["camera-mic"].controllable is True
    assert catalogue.BY_ID["keychain"].controllable is False and "session bus" in catalogue.BY_ID["keychain"].note
    assert catalogue.KIND_DISPLAY in catalogue.BY_ID["clipboard"].refusal_kinds
    assert catalogue.BY_ID["local-ports"].name == "Services on this computer"
    assert any(each.name == "ssh into this computer" for each in catalogue.NEVER)


def _client(tmp_path: Path) -> tuple[Path, Path]:
    """A stand-in for the broker's client: records its argv."""
    called = tmp_path / "called"
    fake = tmp_path / "python"
    fake.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > {called}\n', encoding="utf-8")
    fake.chmod(0o755)
    return fake, called


def _run(script: str, tmp_path: Path, *argv: str) -> subprocess.CompletedProcess[str]:
    path = tmp_path / "shim"
    path.write_text(script, encoding="utf-8")
    path.chmod(0o755)
    return subprocess.run([str(path), *argv], capture_output=True, text=True, encoding="utf-8", check=False,
                          env={"PATH": "/usr/bin:/bin"})


def test_link_openers_hand_one_web_link_to_the_broker_and_refuse_the_rest(tmp_path):
    python, called = _client(tmp_path)
    tools = str(tmp_path)
    all_shims = shims.broker_shims(tools, str(python), "http://127.0.0.1:9700")
    assert set(all_shims) == {*shims.LINK_OPENERS, "gio"}
    done = _run(all_shims["xdg-open"], tmp_path, "https://github.com/login/device")
    assert done.returncode == 0
    assert called.read_text(encoding="utf-8").splitlines()[2:] == ["http://127.0.0.1:9700", "--action", "open-link",
                                                                     "https://github.com/login/device"]
    refused = _run(all_shims["xdg-open"], tmp_path, "/home/me/Taxes/x.pdf")
    assert refused.returncode == 126 and "Blackbox's sandbox refused this (xdg-open)" in refused.stderr
    assert _run(all_shims["sensible-browser"], tmp_path, "file:///etc/passwd").returncode == 126


def test_gio_brokers_open_and_launch_and_runs_its_other_subcommands(tmp_path):
    python, called = _client(tmp_path)
    gio = shims.broker_shims(str(tmp_path), str(python), "http://x")["gio"]
    assert _run(gio, tmp_path, "open", "https://example.com").returncode == 0
    assert called.read_text(encoding="utf-8").splitlines()[-2:] == ["open-link", "https://example.com"]
    assert _run(gio, tmp_path, "launch", "org.gnome.Evince.desktop", "/home/me/a.pdf").returncode == 0
    assert called.read_text(encoding="utf-8").splitlines()[-5:] == ["--action", "open-app", "-a", "org.gnome.Evince.desktop",
                                                                      "/home/me/a.pdf"]
    assert _run(gio, tmp_path, "open", "/home/me/Taxes").returncode == 126
    other = _run(gio, tmp_path, "info", "/")
    assert "Blackbox's sandbox refused" not in other.stderr, "gio info is not an opener"


def test_the_broker_looks_for_linuxbrew_and_the_persons_managers_in_linuxs_places():
    assert "/home/linuxbrew/.linuxbrew/bin" in shims.MANAGER_FOLDERS and "{home}/.local/bin" in shims.MANAGER_FOLDERS
    assert shims.BREW_PATHS == ("/home/linuxbrew/.linuxbrew/bin/brew", "{home}/.linuxbrew/bin/brew")
    assert shims.osascript_shim("/t", "/py", "http://x") == ""
