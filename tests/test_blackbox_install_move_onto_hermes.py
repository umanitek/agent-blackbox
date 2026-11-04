"""Blackbox installed first, Hermes Desktop installed after: the one-liner moves Blackbox onto it.

Found 2026-11-03 on a Mac: after the standalone one-liner (Blackbox with its own Hermes, an Agent
Blackbox checkout behind ~/.local/bin/hermes) the user installed Hermes Desktop, which put its own
Hermes in ~/.hermes/hermes-agent. Two Hermes programs then shared one ~/.hermes: the hermes command
ran ours (0.22.2 fork), the app ran Desktop's (0.22.7). Re-running the one-liner saw only "our
Hermes" and updated the fork. Now it moves Blackbox onto Desktop's Hermes: the node (identity, keys,
graph) moves to where `hermes blackbox setup` keeps it, the hermes command runs Desktop's Hermes,
Blackbox is installed and set up there, and only after that succeeds is our checkout retired with
its environment record. Also KI-467: a fresh clone at a path whose checkout is gone inherited that
checkout's environment record and Hermes refused to start; the stale record is now removed.

The real functions run under macOS bash 3.2 with fakes for Hermes, the service helpers, lsof and ps.
"""

from __future__ import annotations

import hashlib
import re
import shlex
import subprocess
from pathlib import Path

import pytest

INSTALL_SH = Path(__file__).resolve().parents[1] / "scripts" / "blackbox-install.sh"
TEXT = INSTALL_SH.read_text(encoding="utf-8")
FUNCTIONS = ("install_into_existing_hermes", "hermes_install_key", "drop_stale_hermes_install_record",
             "other_hermes_in_home", "our_installed_hermes_dir", "stop_blackbox_dashboard",
             "move_onto_existing_hermes")


def _body(name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{\s*\n(?P<body>.*?)^\}}", TEXT, re.MULTILINE | re.DOTALL)
    assert match is not None, f"{name}() not found"
    return match["body"]


def _hermes(path: Path, *, install_dir: Path, calls: Path, setup_ok: bool = True) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"""#!/bin/sh
if [ "$1" = --version ]; then echo "Hermes Agent v0.22.7"; echo "Install directory: {install_dir}"; exit 0; fi
echo "{path.parent.parent.parent.name}: $*" >> {shlex.quote(str(calls))}
if [ "$1 $2" = "blackbox setup" ]; then exit {0 if setup_ok else 1}; fi
exit 0
""", encoding="utf-8")
    path.chmod(0o755)
    return path


@pytest.fixture()
def mac(tmp_path):
    """Blackbox installed first (our checkout + node), Hermes Desktop installed after."""
    home = tmp_path / "home"
    hermes_home = home / ".hermes"
    ours = home / "agent-blackbox"
    desktop = hermes_home / "hermes-agent"
    calls = tmp_path / "calls"
    (ours / "plugins" / "blackbox").mkdir(parents=True)
    (ours / "plugins" / "blackbox" / "plugin.yaml").write_text("name: blackbox\n", encoding="utf-8")
    (ours / ".dkg").mkdir()
    (ours / ".dkg" / "wallets.key").write_text("node key", encoding="utf-8")
    _hermes(ours / ".hermes" / "bin" / "hermes", install_dir=ours, calls=calls)
    (desktop / "hermes_cli").mkdir(parents=True)
    _hermes(desktop / ".hermes" / "bin" / "hermes", install_dir=desktop, calls=calls)
    (hermes_home / "plugins" / "blackbox").mkdir(parents=True)               # the copy attach placed
    key = hashlib.sha256(str(ours.resolve()).encode()).hexdigest()[:16]
    (hermes_home / "installs" / key).mkdir(parents=True)                     # our checkout's record
    (home / ".local" / "bin").mkdir(parents=True)
    launcher = home / ".local" / "bin" / "hermes"
    launcher.write_text(f'#!/bin/sh\nexec {ours}/.hermes/bin/hermes "$@"\n', encoding="utf-8")
    launcher.chmod(0o755)
    return {"home": home, "hermes_home": hermes_home, "ours": ours, "desktop": desktop, "calls": calls,
            "launcher": launcher, "record": hermes_home / "installs" / key, "tmp": tmp_path}


def _run(mac: dict, call: str, *, extra: str = "") -> subprocess.CompletedProcess:
    fake_bin = mac["tmp"] / "fakebin"
    fake_bin.mkdir(exist_ok=True)
    for tool in ("lsof", "ps"):
        if not (fake_bin / tool).exists():
            (fake_bin / tool).write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            (fake_bin / tool).chmod(0o755)
    functions = "\n".join(f"{name}() {{\n{_body(name)}\n}}" for name in FUNCTIONS)
    script = f"""set -euo pipefail
ok() {{ echo "OK $*"; }}; warn() {{ echo "WARN $*"; }}; step() {{ echo "STEP $*"; }}
err() {{ echo "ERR $*"; }}; heading() {{ echo "== $*"; }}
blackbox_dashboard_supervisor() {{ :; }}
blackbox_dkg_control() {{ echo "dkg-control $*" >> {shlex.quote(str(mac['calls']))}; }}
{functions}
HOME={shlex.quote(str(mac['home']))}
HERMES_HOME={shlex.quote(str(mac['hermes_home']))}
PATH={shlex.quote(str(fake_bin))}:/usr/bin:/bin
BLACKBOX_DKG_STORE_BACKEND=auto
SKIP_DKG=false
{extra}
{call}
"""
    run = mac["tmp"] / "run.sh"
    run.write_text(script, encoding="utf-8")
    return subprocess.run(["/bin/bash", str(run)], capture_output=True, text=True, check=False)


def _calls(mac: dict) -> list[str]:
    return mac["calls"].read_text(encoding="utf-8").splitlines() if mac["calls"].exists() else []


def test_the_install_key_is_hermess_own(mac):
    """pm/environments.py install_key: sha256 of the resolved checkout path, first 16 hex."""
    result = _run(mac, f"hermes_install_key {shlex.quote(str(mac['ours']))}")
    assert result.stdout.strip() == mac["record"].name


def test_desktops_hermes_and_ours_are_both_found(mac):
    assert _run(mac, "other_hermes_in_home").stdout.strip() == str(mac["desktop"] / ".hermes" / "bin" / "hermes")
    assert _run(mac, "our_installed_hermes_dir").stdout.strip() == str(mac["ours"])
    assert _run(mac, "other_hermes_in_home", extra="BLACKBOX_USE_EXISTING_HERMES=0").returncode != 0


def test_blackbox_moves_onto_desktops_hermes_and_the_old_one_is_retired(mac):
    desktop_bin = mac["desktop"] / ".hermes" / "bin" / "hermes"
    result = _run(mac, f"move_onto_existing_hermes {shlex.quote(str(desktop_bin))} {shlex.quote(str(mac['ours']))}")
    assert result.returncode == 0, result.stdout + result.stderr
    node = mac["hermes_home"] / "blackbox" / "node" / ".dkg"
    assert (node / "wallets.key").read_text(encoding="utf-8") == "node key"          # same node, same keys
    assert mac["launcher"].read_text(encoding="utf-8") == f'#!/bin/sh\nexec "{desktop_bin}" "$@"\n'
    assert _calls(mac)[0] == "dkg-control stop"                                     # stopped before the move
    assert [c for c in _calls(mac) if c.startswith("hermes-agent:")] == [
        "hermes-agent: plugins list", "hermes-agent: plugins install blackbox --yes-deps --enable",
        "hermes-agent: blackbox setup"]
    assert not mac["ours"].exists() and not mac["record"].exists()                   # retired after success
    assert "there is one Hermes again" in result.stdout


def test_a_failed_setup_keeps_the_old_hermes(mac):
    desktop_bin = _hermes(mac["desktop"] / ".hermes" / "bin" / "hermes", install_dir=mac["desktop"],
                          calls=mac["calls"], setup_ok=False)
    result = _run(mac, f"move_onto_existing_hermes {shlex.quote(str(desktop_bin))} {shlex.quote(str(mac['ours']))}")
    assert result.returncode == 1
    assert mac["ours"].exists() and mac["record"].exists()
    assert "is kept at" in result.stdout


def test_a_fresh_clone_drops_the_record_a_gone_checkout_left_ki467(mac):
    extra = f"REPO_DIR={shlex.quote(str(mac['ours']))}"
    _run(mac, "drop_stale_hermes_install_record", extra=extra)                      # an update: kept
    assert mac["record"].exists()
    result = _run(mac, "drop_stale_hermes_install_record", extra=extra + "\nBLACKBOX_FRESH_CLONE=true")
    assert result.returncode == 0 and not mac["record"].exists()


def test_only_a_blackbox_dashboard_on_the_port_is_stopped(mac, tmp_path):
    fake_bin = mac["tmp"] / "fakebin"
    fake_bin.mkdir(exist_ok=True)
    killed = tmp_path / "killed"
    _run(mac, ":")                                   # writes the default fakes first
    (fake_bin / "lsof").write_text("#!/bin/sh\necho 101\necho 202\n", encoding="utf-8")
    (fake_bin / "ps").write_text('#!/bin/sh\ncase "$4" in 101) echo "/x/python3 -I -c ... blackbox dashboard";; '
                                 '*) echo "/usr/bin/other-server --port 9700";; esac\n', encoding="utf-8")
    result = _run(mac, "stop_blackbox_dashboard",
                  extra=f'kill() {{ echo "$*" >> {shlex.quote(str(killed))}; }}')
    assert result.returncode == 0, result.stderr
    assert killed.read_text(encoding="utf-8").split() == ["-TERM", "101"]


def test_the_two_hermes_case_is_checked_before_anything_is_installed():
    main = _body("main")
    move = main.index('move_onto_existing_hermes "$existing_hermes" "$ours_dir"')
    assert main.index("existing_foreign_hermes") < move < main.index("install_record_begin")
    assert main.index("resolve_repo") < main.index("drop_stale_hermes_install_record") < main.index("install_python_env")


def test_the_windows_hand_over_carries_the_node_across_and_retires_the_checkout():
    """Windows publishes no hermes command of its own, so a later Hermes Desktop's is the one found
    and the existing hand-over runs; it now moves the node and retires the checkout too (LES-029)."""
    ps1 = INSTALL_SH.with_suffix(".ps1").read_text(encoding="utf-8")
    hand_over = ps1[ps1.index("function Install-IntoExistingHermes"):ps1.index("function Main {")]
    assert 'Move-Item -Path $DkgHome -Destination $nodeHome' in hand_over
    assert hand_over.index("Move-Item -Path $DkgHome") < hand_over.index("& $Hermes plugins")
    assert "if ($setupExit -eq 0) {" in hand_over and "Remove-Item $ourCheckout -Recurse -Force" in hand_over
    shipped = INSTALL_SH.parents[1] / "plugins" / "blackbox" / "setup" / "blackbox-install.ps1"
    assert shipped.read_bytes() == INSTALL_SH.with_suffix(".ps1").read_bytes()
