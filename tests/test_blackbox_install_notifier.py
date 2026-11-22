"""The installer's native-notifier step (Amos 2026-11-22: Blackbox itself connects to the
system's notifications when installed).

Runs the real shell function from scripts/blackbox-install.sh with a fake ``hermes`` that only
records what it was asked. Contracts: a locally named archive is handed to ``blackbox
notifications setup`` with its checksum; with no archive nothing is run and the person is told
the system's own notifier is used; a failing set-up never fails the install; other systems skip it.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = REPO_ROOT / "scripts" / "blackbox-install.sh"
PLUGIN_COPY = REPO_ROOT / "plugins" / "blackbox" / "setup" / "blackbox-install.sh"
FUNCTIONS = ("helper_manifest_file", "helper_manifest_version", "helper_manifest_sha256", "install_native_notifier")


def _function(name: str) -> str:
    text = INSTALL_SH.read_text(encoding="utf-8")
    one_line = re.search(rf"^{name}\(\) \{{ .*\}}$", text, re.MULTILINE)
    if one_line:
        return one_line.group(0) + "\n"
    match = re.search(rf"^{name}\(\)\s*\{{.*?^\}}\n", text, re.MULTILINE | re.DOTALL)
    assert match is not None, f"{name}() not found"
    return match.group(0)


def _run(tmp_path: Path, *, archive: str = "", sha: str = "", os_name: str = "macos", setup_fails: bool = False,
         manifest: str | None = None) -> tuple[str, list[str], int]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "hermes-calls"
    hermes = bin_dir / "hermes"
    hermes.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{calls}"\nexit {1 if setup_fails else 0}\n', encoding="utf-8")
    hermes.chmod(0o755)
    for tool in ("awk", "mktemp", "rm", "tr"):
        for folder in ("/bin", "/usr/bin"):
            if Path(folder, tool).exists():
                (bin_dir / tool).symlink_to(Path(folder, tool))
                break
    repo = tmp_path / "repo"
    if manifest is not None:
        (repo / "plugins" / "blackbox" / "helper").mkdir(parents=True)
        (repo / "plugins" / "blackbox" / "helper" / "release-manifest.txt").write_text(manifest, encoding="utf-8")
    script = "\n".join([
        "set -e",
        'step() { printf -- "-> %s\\n" "$1"; }', 'ok() { printf "OK %s\\n" "$1"; }', 'warn() { printf "WARN %s\\n" "$1"; }',
        f'OS="{os_name}"', f'HERMES_BIN="{hermes}"', f'BLACKBOX_NOTIFIER_PATH="{archive}"', f'BLACKBOX_NOTIFIER_SHA256="{sha}"',
        f'REPO_DIR="{repo}"', f'HERMES_HOME="{tmp_path}/hermes-home"', f'TMPDIR="{tmp_path}"', 'REPO_URL="https://example.invalid/x.git"',
        *(_function(name) for name in FUNCTIONS),
        "install_native_notifier", 'printf "AFTER\\n"',
    ])
    done = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, timeout=30,
                          env={"PATH": str(bin_dir), "HOME": str(tmp_path)}, start_new_session=True,
                          stdin=subprocess.DEVNULL, check=False)
    ran = calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []
    return done.stdout + done.stderr, ran, done.returncode


def test_a_named_archive_is_handed_to_the_plugin_with_its_checksum(tmp_path):
    archive = tmp_path / "blackbox-notify-darwin.zip"
    archive.write_bytes(b"zip")
    out, ran, code = _run(tmp_path, archive=str(archive), sha="AB" * 32)
    assert code == 0 and "AFTER" in out
    assert ran == [f"blackbox notifications setup --from {archive} --sha256 {'ab' * 32}"]
    assert "OK Blackbox's notifications are set up" in out


def test_without_an_archive_only_the_installed_mark_is_set_and_the_person_is_told(tmp_path):
    out, ran, code = _run(tmp_path)
    assert code == 0 and ran == ["blackbox notifications setup"]   # marks the installed Blackbox; nothing downloaded
    assert "macOS's own notifier" in out and "AFTER" in out


def test_a_manifest_that_does_not_list_the_notifier_downloads_nothing(tmp_path):
    out, ran, code = _run(tmp_path, manifest="version 0.1.0\n" + "a" * 64 + "  blackbox-netd-darwin-arm64\n")
    assert code == 0 and ran == ["blackbox notifications setup"] and "macOS's own notifier" in out


def test_a_failing_set_up_never_fails_the_install(tmp_path):
    archive = tmp_path / "blackbox-notify-darwin.zip"
    archive.write_bytes(b"zip")
    out, ran, code = _run(tmp_path, archive=str(archive), sha="cd" * 32, setup_fails=True)
    assert code == 0 and "AFTER" in out and len(ran) == 1
    assert "WARN Blackbox's own notifier was not installed" in out


def test_another_system_only_marks_the_installed_blackbox(tmp_path):
    out, ran, code = _run(tmp_path, os_name="linux")
    assert code == 0 and ran == ["blackbox notifications setup"] and out.strip() == "AFTER"


def test_the_plugin_copy_of_the_installer_is_identical():
    assert INSTALL_SH.read_bytes() == PLUGIN_COPY.read_bytes()
