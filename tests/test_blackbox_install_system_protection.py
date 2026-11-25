"""The installer's opt-in system protection step (the root helper ``blackbox-netd``, 2026-11-21).

Runs the real shell functions from scripts/blackbox-install.sh with a fake ``sudo`` that only
records what it was asked to run — so the contract is checked without root: a declined or
unattended install runs nothing as root, a binary whose checksum does not match is never run as
root, and a matching one is handed to the helper's own verified ``install`` with the plan-key
hand-off. Detached from any terminal so nothing can prompt.

Upgrades (E2E 2026-11-21, KI-PENDING-11e14b): re-running the installer over an installed helper
upgrades it only when it differs from the one this install carries (the helper's public receipt),
and a failed upgrade never removes the helper the person already had.
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
    "install_system_protection", "offer_system_protection", "helper_installed_sha", "helper_expected_sha",
    "upgrade_system_protection", "forget_sudo", "helper_release_exists", "sandbox_default_after_helper",
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
         manifest: str | None = None, installed_sha: str | None = None, root_fails: bool = False,
         ) -> tuple[str, list[str]]:
    """*installed_sha*: a helper is installed (its LaunchDaemon exists) with this receipt ("" = an
    installed helper from before receipts). *root_fails*: every command run as root fails."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "sudo-calls"
    sudo = bin_dir / "sudo"
    sudo.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{calls}"\nexit {1 if root_fails else 0}\n', encoding="utf-8")
    sudo.chmod(0o755)
    hermes = bin_dir / "hermes"
    hermes.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{tmp_path}/hermes-calls"\n', encoding="utf-8")
    hermes.chmod(0o755)
    for tool in ("awk", "cat", "chmod", "cp", "grep", "id", "mktemp", "rm", "shasum", "tr", "uname"):
        for folder in ("/bin", "/usr/bin"):
            if Path(folder, tool).exists():
                (bin_dir / tool).symlink_to(Path(folder, tool))
                break
    helper_path = ""
    if helper is not None:
        helper_path = str(tmp_path / "downloaded-netd")
        Path(helper_path).write_bytes(helper)
    daemon = tmp_path / "no-such.plist"
    receipt = tmp_path / "netd-installed"
    if installed_sha is not None:
        daemon = tmp_path / "netd.plist"
        daemon.write_text("<plist/>", encoding="utf-8")
        if installed_sha:
            receipt.write_text(f"sha256 {installed_sha}\n", encoding="utf-8")
    repo = tmp_path / "repo"
    if manifest is not None:
        (repo / "plugins" / "blackbox" / "helper").mkdir(parents=True)
        (repo / "plugins" / "blackbox" / "helper" / "release-manifest.txt").write_text(manifest, encoding="utf-8")
    script = "\n".join([
        'heading() { printf "== %s\\n" "$1"; }', 'step() { printf -- "-> %s\\n" "$1"; }',
        'ok() { printf "OK %s\\n" "$1"; }', 'warn() { printf "WARN %s\\n" "$1"; }', 'err() { printf "ERR %s\\n" "$1"; }',
        f'OS="{os_name}"', f'BLACKBOX_SYSTEM_PROTECTION="{choice}"', "BLACKBOX_SYSTEM_PROTECTION_PROMPT_SECONDS=1",
        f'BLACKBOX_HELPER_PATH="{helper_path}"', f'BLACKBOX_HELPER_SHA256="{sha}"',
        f'BLACKBOX_HELPER_DAEMON="{daemon}"', f'BLACKBOX_HELPER_RECEIPT="{receipt}"',
        f'BLACKBOX_HELPER_KEY_DIR="{tmp_path}/keys"',
        f'REPO_DIR="{repo}"', f'HERMES_HOME="{tmp_path}/hermes"', f'TMPDIR="{tmp_path}"', f'HERMES_BIN="{hermes}"',
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
    assert len(ran) == 2 and ran[1] == "-k", "the password sudo took is forgotten at once (an agent started next must not inherit it)"
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


def test_the_helper_download_names_only_this_machines_own_os_and_architecture():
    """Per-OS structure (2026-11-21): the installer fetches the one binary built for this machine's
    OS and chip — never another's — and none for a chip it has no build for."""
    def asset(system: str, machine: str) -> subprocess.CompletedProcess[str]:
        script = (f"uname() {{ case \"$1\" in -s) echo {system} ;; *) echo {machine} ;; esac; }}\n"
                  f"{_function('helper_asset_name')}\nhelper_asset_name")
        return subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, timeout=30, check=False)
    assert asset("Darwin", "arm64").stdout.strip() == "blackbox-netd-darwin-arm64"
    assert asset("Darwin", "x86_64").stdout.strip() == "blackbox-netd-darwin-x86_64"
    assert asset("Linux", "aarch64").stdout.strip() == "blackbox-netd-linux-arm64"
    assert asset("Linux", "x86_64").stdout.strip() == "blackbox-netd-linux-x86_64"
    unknown = asset("Linux", "riscv64")
    assert unknown.returncode != 0 and unknown.stdout == ""


def test_on_linux_it_is_offered_and_says_so_when_the_release_has_no_helper_for_it(tmp_path):
    out, ran = _run(tmp_path, choice="yes", os_name="linux", manifest="version 0.1.0\n")
    assert ran == [] and "STATE=unavailable" in out and "no published system protection helper" in out, out


def test_on_linux_a_checked_helper_is_installed_through_its_own_install_then_sudo_forgets(tmp_path):
    binary = b"the linux helper"
    out, ran = _run(tmp_path, choice="yes", os_name="linux", helper=binary, sha=hashlib.sha256(binary).hexdigest())
    assert "STATE=installed" in out and len(ran) == 2 and " install --from " in ran[0] and ran[1] == "-k", (out, ran)


def test_the_plugin_copy_matches_the_installer():
    assert PLUGIN_COPY.read_text(encoding="utf-8") == INSTALL_SH.read_text(encoding="utf-8")


def test_an_installed_helper_that_is_the_one_this_install_carries_is_left_alone(tmp_path):
    binary = b"the helper"
    sha = hashlib.sha256(binary).hexdigest()
    out, ran = _run(tmp_path, choice="ask", helper=binary, sha=sha, installed_sha=sha)
    assert ran == [] and "up to date" in out and "STATE=installed" in out, out


def test_an_installed_helper_that_differs_is_upgraded_without_asking_again(tmp_path):
    """The release path used to skip any installed helper, so an old binary was never replaced."""
    manifest = "version 0.2.0\n" + "".join(f"{'c' * 64}  blackbox-netd-darwin-{arch}\n" for arch in ("arm64", "x86_64"))
    for name, installed in (("older", "a" * 64), ("before-receipts", "")):
        folder = tmp_path / name
        folder.mkdir()
        out, ran = _run(folder, choice="ask", manifest=manifest, installed_sha=installed)
        # The download is the step that runs before root (there is no network here): reaching it
        # means the upgrade was started; nothing installed is touched when it fails.
        assert "newer system protection helper" in out and "Downloading the system protection helper" in out, out
        assert ran == [] and "STATE=kept" in out, out


def test_a_failed_upgrade_never_removes_the_helper_the_person_already_had(tmp_path):
    """E2E 2026-11-21: launchd refused the new helper and the rollback uninstalled the old one."""
    binary = b"the new helper"
    sha = hashlib.sha256(binary).hexdigest()
    out, ran = _run(tmp_path, choice="ask", helper=binary, sha=sha, installed_sha="a" * 64, root_fails=True)
    assert any(" install --from " in command for command in ran), ran
    assert not any(command.rstrip().endswith(" uninstall") for command in ran), f"the old helper was removed: {ran}"
    assert "still installed and running" in out and "STATE=kept" in out, out


def test_a_first_install_that_fails_is_cleaned_up(tmp_path):
    binary = b"the helper"
    out, ran = _run(tmp_path, choice="yes", helper=binary, sha=hashlib.sha256(binary).hexdigest(), root_fails=True)
    assert ran[-2].rstrip().endswith(" uninstall") and ran[-1] == "-k" and "STATE=failed" in out, ran


def test_saying_no_leaves_an_installed_helper_as_it_is(tmp_path):
    out, ran = _run(tmp_path, choice="no", helper=b"x", sha=hashlib.sha256(b"x").hexdigest(), installed_sha="a" * 64)
    assert ran == [] and "STATE=installed" in out, out


def _hermes_calls(tmp_path: Path) -> list[str]:
    calls = tmp_path / "hermes-calls"
    return calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []


def test_on_linux_a_helper_installed_now_puts_the_agents_in_the_sandbox_it_brought(tmp_path):
    """KI-671 (Linux round L2): the attach step's "every agent in the sandbox" ran before the helper
    (and with it the sandbox's launcher) was installed, so a fresh Linux install left every agent
    hooks-only until the person ran `blackbox attach`. Once the helper is in, it runs again."""
    binary = b"the helper"
    out, _ran = _run(tmp_path, choice="yes", os_name="linux", helper=binary, sha=hashlib.sha256(binary).hexdigest())
    assert "STATE=installed" in out, out
    assert _hermes_calls(tmp_path) == [f"blackbox attach {tmp_path}/hermes"], out


def test_the_sandbox_default_is_not_run_again_without_a_new_linux_helper(tmp_path):
    binary = b"the helper"
    for os_name, choice in (("macos", "yes"), ("linux", "no")):
        folder = tmp_path / f"{os_name}-{choice}"
        folder.mkdir()
        out, _ran = _run(folder, choice=choice, os_name=os_name, helper=binary, sha=hashlib.sha256(binary).hexdigest())
        assert _hermes_calls(folder) == [], (os_name, choice, out)
