"""A per-user node service keeps running after logout and starts at boot (lingering, KI-428).

On the Linux test droplet (2026-10-16) a non-root install put the node under a systemd user unit
and the handover confirmed it — then the SSH session ended, systemd stopped that user's services,
and the node died; every later login started a fresh user manager that started it again. Without
lingering a user unit runs only while its user is logged in, so on a server nobody logs in to the
node never runs. These tests run the installer's real `ensure_user_lingering` with fake
`loginctl`, `sudo` and `id` that record what they are asked.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
INSTALL_SH = REPO / "scripts" / "blackbox-install.sh"


def _body(name: str) -> str:
    text = INSTALL_SH.read_text(encoding="utf-8")
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{\s*\n(?P<body>.*?)^\}}", text, re.MULTILINE | re.DOTALL)
    assert match is not None, f"{name}() not found"
    return match["body"]


def _fake(bin_dir: Path, name: str, script: str) -> None:
    path = bin_dir / name
    path.write_text("#!/bin/sh\n" + script, encoding="utf-8")
    path.chmod(0o755)


def _run(tmp_path: Path, *, lingering: bool = False, self_allowed: bool = True, sudo_allowed: bool = False,
         loginctl: bool = True) -> tuple[list[str], str]:
    bin_dir, linger_dir, calls = tmp_path / "bin", tmp_path / "linger", tmp_path / "calls"
    bin_dir.mkdir()
    linger_dir.mkdir()
    calls.write_text("", encoding="utf-8")
    if lingering:
        (linger_dir / "trader").write_text("", encoding="utf-8")
    log = f'echo "${{0##*/}} $*" >> {shlex.quote(str(calls))}\n'
    _fake(bin_dir, "id", 'echo trader\n')
    if loginctl:
        _fake(bin_dir, "loginctl", log + f"exit {0 if self_allowed else 1}\n")
    _fake(bin_dir, "sudo", log + f"exit {0 if sudo_allowed else 1}\n")
    # PATH is the fakes' folder ALONE: the function and the fakes need only shell builtins, and a
    # host with a real `loginctl` in /usr/bin (GitHub's Ubuntu runners) must not answer for a
    # missing one.
    script = f"""
BLACKBOX_LINGER_DIR={shlex.quote(str(linger_dir))}
PATH={shlex.quote(str(bin_dir))}
ok() {{ echo "OK $*"; }}
warn() {{ echo "WARN $*"; }}
ensure_user_lingering() {{
{_body("ensure_user_lingering")}
}}
ensure_user_lingering
"""
    env = {k: v for k, v in os.environ.items() if k != "PATH"}
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False, env=env)
    assert result.returncode == 0, result.stderr
    return calls.read_text(encoding="utf-8").splitlines(), result.stdout


def test_a_user_switches_lingering_on_for_themselves(tmp_path):
    calls, output = _run(tmp_path)
    assert calls == ["loginctl enable-linger trader"]
    assert "OK Lingering on for trader" in output


def test_when_the_user_may_not_it_asks_sudo_without_a_prompt(tmp_path):
    calls, output = _run(tmp_path, self_allowed=False, sudo_allowed=True)
    assert calls == ["loginctl enable-linger trader", "sudo -n loginctl enable-linger trader"]
    assert "OK Lingering on for trader" in output


def test_when_nothing_may_it_says_what_will_happen_and_how_to_fix_it(tmp_path):
    _, output = _run(tmp_path, self_allowed=False, sudo_allowed=False)
    assert "WARN Blackbox's services stop when trader logs out" in output
    assert "sudo loginctl enable-linger trader" in output
    assert "OK" not in output


def test_a_user_already_lingering_is_left_alone(tmp_path):
    calls, output = _run(tmp_path, lingering=True)
    assert calls == [] and output == ""


def test_without_logind_there_is_nothing_to_do(tmp_path):
    calls, output = _run(tmp_path, loginctl=False)
    assert calls == [] and output == ""


def test_lingering_follows_a_registered_user_unit():
    body = _body("register_boot_service")
    user_branch = body.split('systemctl --user daemon-reload && systemctl --user enable blackbox-dkg', 1)[1]
    assert user_branch.index("ensure_user_lingering") < user_branch.index("else")
