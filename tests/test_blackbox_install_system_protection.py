"""The installer's opt-in system protection step (the root helper ``blackbox-netd``, 2026-11-21).

Runs the real shell functions from scripts/blackbox-install.sh with a fake ``sudo`` that only
records what it was asked to run — so the contract is checked without root: a declined or
unattended install runs nothing as root, a binary whose checksum does not match is never run as
root, and a matching one is handed to the helper's own verified ``install`` with the plan-key
hand-off. Detached from any terminal so nothing can prompt.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = REPO_ROOT / "scripts" / "blackbox-install.sh"
PLUGIN_COPY = REPO_ROOT / "plugins" / "blackbox" / "setup" / "blackbox-install.sh"
FUNCTIONS = (
    "helper_manifest_file", "helper_asset_name", "helper_manifest_version", "helper_manifest_sha256",
    "sha256_of", "want_system_protection", "fetch_helper_binary", "sudo_with_tty",
    "install_system_protection", "offer_system_protection",
)


def _function(name: str) -> str:
    text = INSTALL_SH.read_text(encoding="utf-8")
    one_line = re.search(rf"^{name}\(\) \{{ .*\}}$", text, re.MULTILINE)
    if one_line:
        return one_line.group(0) + "\n"
    match = re.search(rf"^{name}\(\)\s*\{{.*?^\}}\n", text, re.MULTILINE | re.DOTALL)
    assert match is not None, f"{name}() not found"
    return match.group(0)


def _run(tmp_path: Path, *, choice: str, helper: bytes | None = None, sha: str = "", os_name: str = "macos",
         manifest: str | None = None) -> tuple[str, list[str]]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "sudo-calls"
    sudo = bin_dir / "sudo"
    sudo.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{calls}"\nexit 0\n', encoding="utf-8")
    sudo.chmod(0o755)
    for tool in ("awk", "cat", "chmod", "cp", "grep", "id", "mktemp", "rm", "shasum", "tr", "uname"):
        for folder in ("/bin", "/usr/bin"):
            if Path(folder, tool).exists():
                (bin_dir / tool).symlink_to(Path(folder, tool))
                break
    helper_path = ""
    if helper is not None:
        helper_path = str(tmp_path / "downloaded-netd")
        Path(helper_path).write_bytes(helper)
    repo = tmp_path / "repo"
    if manifest is not None:
        (repo / "plugins" / "blackbox" / "helper").mkdir(parents=True)
        (repo / "plugins" / "blackbox" / "helper" / "release-manifest.txt").write_text(manifest, encoding="utf-8")
    script = "\n".join([
        'heading() { printf "== %s\\n" "$1"; }', 'step() { printf -- "-> %s\\n" "$1"; }',
        'ok() { printf "OK %s\\n" "$1"; }', 'warn() { printf "WARN %s\\n" "$1"; }', 'err() { printf "ERR %s\\n" "$1"; }',
        f'OS="{os_name}"', f'BLACKBOX_SYSTEM_PROTECTION="{choice}"', "BLACKBOX_SYSTEM_PROTECTION_PROMPT_SECONDS=1",
        f'BLACKBOX_HELPER_PATH="{helper_path}"', f'BLACKBOX_HELPER_SHA256="{sha}"',
        f'BLACKBOX_HELPER_DAEMON="{tmp_path}/no-such.plist"', f'BLACKBOX_HELPER_KEY_DIR="{tmp_path}/keys"',
        f'REPO_DIR="{repo}"', f'HERMES_HOME="{tmp_path}/hermes"', f'TMPDIR="{tmp_path}"',
        *(_function(name) for name in FUNCTIONS),
        'offer_system_protection', 'printf "STATE=%s\\n" "$BLACKBOX_SYSTEM_PROTECTION_STATE"',
    ])
    done = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, timeout=30,
                          env={"PATH": str(bin_dir), "HOME": str(tmp_path)}, start_new_session=True,
                          stdin=subprocess.DEVNULL, check=False)
    assert done.returncode == 0, done.stderr
    ran = calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []
    return done.stdout + done.stderr, ran


def test_declined_or_unattended_runs_nothing_as_root(tmp_path):
    # "ask" with no terminal (curl | bash in CI, a script): no — a root install never happens unattended.
    for choice in ("no", "ask"):
        folder = tmp_path / choice
        folder.mkdir()
        out, ran = _run(folder, choice=choice)
        assert ran == [] and "STATE=declined" in out, choice


def test_a_binary_whose_checksum_does_not_match_is_never_run_as_root(tmp_path):
    out, ran = _run(tmp_path, choice="yes", helper=b"tampered", sha="0" * 64)
    assert ran == [], "nothing ran as root"
    assert "does not match" in out and "STATE=failed" in out


def test_a_matching_binary_goes_to_the_helpers_own_verified_install(tmp_path):
    binary = b"the helper"
    sha = hashlib.sha256(binary).hexdigest()
    out, ran = _run(tmp_path, choice="yes", helper=binary, sha=sha)
    assert "STATE=installed" in out, out
    assert len(ran) == 1
    command = ran[0]
    assert re.search(rf"blackbox-netd install --from \S+/blackbox-netd --sha256 {sha} ", command)
    assert f"--key-for {tmp_path}/keys --owner {os.getuid()}" in command
    assert command.startswith("-n "), "no terminal: only an already-cached sudo, never a hanging prompt"


def test_the_download_is_checked_against_the_manifest_committed_in_the_checkout(tmp_path):
    manifest = "# test\nversion 0.1.0\n" + "a" * 64 + "  blackbox-netd-darwin-arm64\n" + "b" * 64 + "  blackbox-netd-darwin-x86_64\n"
    script = "\n".join([*(_function(n) for n in ("helper_manifest_version", "helper_manifest_sha256")),
                        f"m={tmp_path}/m", "helper_manifest_version $m", "helper_manifest_sha256 $m blackbox-netd-darwin-x86_64",
                        "helper_manifest_sha256 $m blackbox-netd-linux"])
    (tmp_path / "m").write_text(manifest, encoding="utf-8")
    done = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, timeout=30, check=True)
    assert done.stdout.splitlines() == ["0.1.0", "b" * 64]


def test_linux_is_never_offered_it(tmp_path):
    out, ran = _run(tmp_path, choice="yes", os_name="linux")
    assert ran == [] and "STATE=unsupported" in out and "System protection" not in out.replace("STATE", "")


def test_the_plugin_copy_matches_the_installer():
    assert PLUGIN_COPY.read_text(encoding="utf-8") == INSTALL_SH.read_text(encoding="utf-8")
