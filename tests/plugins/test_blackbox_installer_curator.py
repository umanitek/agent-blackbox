"""The installer's opt-in node service units (Community Curation C9; trust-and-threat-lab I1).

Curator nodes and benches run their own services — the curator beat (with
``--publisher`` on the wallet holder only), the curate watcher, the lab tunnel
and the key console. The installer registers each ONLY behind its own flag,
and these tests RUN the installer's functions (extracted from the script, with
``uname`` / ``systemctl`` / ``id`` / ``useradd`` stood in for) and read the
units they write.
"""

from __future__ import annotations

import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Mapping, Optional

import pytest

INSTALLER = Path(__file__).resolve().parents[2] / "scripts" / "blackbox-install.sh"
HELPERS = ("have_systemd", "systemd_unavailable", "can_write_system_units", "install_node_unit", "valid_service_port")
REGISTRARS = ("register_curator_service", "register_curate_watch", "register_lab_tunnel", "register_key_console")
UNITS = ("blackbox-curator", "blackbox-curate-watch", "blackbox-lab-tunnel", "blackbox-console")
CONSOLE_HARDENING = ("User=blackbox-console", "Group=blackbox-console", "NoNewPrivileges=yes", "ProtectSystem=strict",
                     "MemoryDenyWriteExecute=yes", "LimitCORE=0")


def _function(name: str = "register_curator_service") -> str:
    source = INSTALLER.read_text(encoding="utf-8")
    start = source.index(f"\n{name}() {{") + 1
    return source[start:source.index("\n}\n", start) + 3]


@dataclass
class Installed:
    """What one installer run did: its stdout, every unit it wrote (name → text,
    system and user folders alike), and the systemctl / useradd calls it made."""

    out: str
    units: dict[str, str]
    system_units: dict[str, str]
    calls: str
    useradd: str


def _install(tmp_path: Path, env: Mapping[str, str], *, call: str = "register_curator_service", system: str = "Linux",
             systemctl: bool = True, root: bool = False, autossh: bool = True, console_user: bool = True,
             ptrace: Optional[str] = None) -> Installed:
    """Run one registrar in a throwaway HOME (*root*: a writable system unit folder and uid 0)."""
    home, bin_dir, system_dir = tmp_path / "home", tmp_path / "bin", tmp_path / "system"
    for folder in (home, bin_dir):
        folder.mkdir(exist_ok=True)
    if root:
        system_dir.mkdir(exist_ok=True)
    if autossh:
        fake = bin_dir / "autossh"
        fake.write_text("#!/bin/sh\n", encoding="utf-8")
        fake.chmod(0o755)
    ptrace_file = tmp_path / "ptrace_scope"
    if ptrace is not None:
        ptrace_file.write_text(ptrace + "\n", encoding="utf-8")
    calls, useradd = tmp_path / "systemctl.log", tmp_path / "useradd.log"
    hidden = [name for name, present in (("systemctl", systemctl), ("autossh", autossh)) if not present]
    hide = ('command() { case "$2" in ' + "|".join(hidden) + ') return 1 ;; esac; builtin command "$@"; }') if hidden else ""
    script = f"""
set -u
heading() {{ echo "HEADING $1"; }}; ok() {{ echo "OK $1"; }}; warn() {{ echo "WARN $1"; }}; step() {{ echo "STEP $1"; }}
uname() {{ echo {system}; }}
id() {{ if [ "$1" = -u ]; then echo {0 if root else 1000}; else {"return 0" if console_user else "return 1"}; fi; }}
useradd() {{ echo "$*" >> "{useradd}"; }}
{f'systemctl() {{ echo "$*" >> "{calls}"; }}' if systemctl else ""}
{hide}
HERMES_HOME="$HOME/.hermes"; BLACKBOX_HOME="$HERMES_HOME/blackbox"; HERMES_BIN="/opt/venv/bin/hermes"
BLACKBOX_SYSTEMD_DIR="{system_dir}"; BLACKBOX_PTRACE_SCOPE_FILE="{ptrace_file}"
BLACKBOX_SYSTEMD_RUNTIME_DIR="{tmp_path}"   # systemd runs here (KI-626: the installer checks)
{"".join(_function(name) for name in HELPERS)}
{_function(call)}
{call}
"""
    done = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30,
                          env={"HOME": str(home), "PATH": f"{bin_dir}:/usr/bin:/bin", **env}, check=False)
    assert done.returncode == 0, done.stderr

    def read(folder: Path) -> dict[str, str]:
        return {name: (folder / f"{name}.service").read_text(encoding="utf-8")
                for name in UNITS if (folder / f"{name}.service").exists()}

    system_units = read(system_dir)
    return Installed(done.stdout, {**read(home / ".config/systemd/user"), **system_units}, system_units,
                     calls.read_text(encoding="utf-8") if calls.exists() else "",
                     useradd.read_text(encoding="utf-8") if useradd.exists() else "")


def _run(tmp_path, env, *, system="Linux", systemctl=True):
    """The curator registrar's (stdout, its unit text or None, the systemctl calls)."""
    done = _install(tmp_path, env, system=system, systemctl=systemctl)
    return done.out, done.units.get("blackbox-curator"), done.calls


def _exec_start(unit: str) -> str:
    return next(line for line in unit.splitlines() if line.startswith("ExecStart="))


def test_an_ordinary_install_registers_no_curator_service(tmp_path):
    for env in ({}, {"BLACKBOX_CURATOR_SERVICE": "0"}, {"BLACKBOX_CURATOR_PEERS": "peer-a"}):
        out, unit, calls = _run(tmp_path, env)
        assert (out, unit, calls) == ("", None, "")


def test_a_curator_node_gets_a_unit_that_runs_the_service_with_its_peers(tmp_path):
    out, unit, calls = _run(tmp_path, {"BLACKBOX_CURATOR_SERVICE": "1", "BLACKBOX_CURATOR_PEERS": "curator-b,12D3KooWabc:9"})
    assert "ExecStart=/opt/venv/bin/hermes blackbox curate run --peer curator-b --peer 12D3KooWabc:9\n" in unit
    assert "Restart=on-failure" in unit and "After=network-online.target blackbox-dkg.service" in unit
    assert f"Environment=BLACKBOX_HOME={tmp_path}/home/.hermes/blackbox" in unit
    assert calls.splitlines() == ["--user daemon-reload", "--user enable blackbox-curator", "--user restart blackbox-curator"]
    assert "OK curator user service registered" in out
    assert "signs nothing until you accept the automation policy" in out          # the operator is told what is still theirs to do


@pytest.mark.parametrize("peers", ["good-peer,bad peer", "good-peer,$(touch pwned)", "good-peer,a;b", "good-peer,,`id`"])
def test_a_peer_name_that_is_not_a_plain_token_never_reaches_the_unit(tmp_path, peers):
    out, unit, _ = _run(tmp_path, {"BLACKBOX_CURATOR_SERVICE": "1", "BLACKBOX_CURATOR_PEERS": peers})
    assert "ExecStart=/opt/venv/bin/hermes blackbox curate run --peer good-peer\n" in unit
    assert "WARN ignoring curator peer" in out and not (tmp_path / "home" / "pwned").exists()
    assert not list(Path(tmp_path).rglob("pwned"))


def test_without_peers_the_service_is_still_registered_and_says_so(tmp_path):
    out, unit, _ = _run(tmp_path, {"BLACKBOX_CURATOR_SERVICE": "1"})
    assert "ExecStart=/opt/venv/bin/hermes blackbox curate run\n" in unit and "WARN no curator peers given" in out


@pytest.mark.parametrize("system, systemctl", [("Darwin", True), ("Linux", False)])
def test_where_there_is_no_systemd_nothing_is_written_and_the_command_is_shown(tmp_path, system, systemctl):
    out, unit, calls = _run(tmp_path, {"BLACKBOX_CURATOR_SERVICE": "1", "BLACKBOX_CURATOR_PEERS": "curator-b"},
                            system=system, systemctl=systemctl)
    assert unit is None and calls == ""
    assert "blackbox curate run --peer curator-b" in out and "Linux with systemd only" in out


def test_the_installer_calls_it_after_the_node_service_and_documents_how_to_stop_it():
    source = INSTALLER.read_text(encoding="utf-8")
    main_body = source.split("main() {", 1)[1]
    assert main_body.index("register_boot_service") < main_body.index("register_curator_service") < main_body.index("next_steps")
    assert "systemctl disable --now blackbox-curator" in source and "BLACKBOX_CURATOR_SERVICE=1" in source
    assert _function().lstrip().split("\n")[1].strip() == '[ "${BLACKBOX_CURATOR_SERVICE:-0}" = 1 ] || return 0'    # opt-in is the first line


# -- trust-and-threat-lab I1: the publisher flag, the watcher, the lab tunnel, the key console --

SLACK = "https://hooks.slack.com/services/T000/B000/abcDEF123"


@pytest.mark.parametrize("call", REGISTRARS)
def test_no_flag_writes_no_unit_and_says_nothing(tmp_path, call):
    for env in ({}, {"BLACKBOX_KEY_CONSOLE": "0", "BLACKBOX_CURATOR_SERVICE": "0"},
                {"BLACKBOX_CURATOR_PUBLISHER": "1", "BLACKBOX_LAB_TUNNEL_PORT": "9000"}):
        done = _install(tmp_path, env, call=call, root=True)
        assert (done.out, done.units, done.calls, done.useradd) == ("", {}, "", "")
    assert not (tmp_path / "home" / ".hermes").exists()        # no sink, no curate home, nothing


@pytest.mark.parametrize("flag, expected", [("1", " --publisher"), ("0", ""), ("yes", ""), ("", "")])
def test_publisher_appears_only_with_the_flag(tmp_path, flag, expected):
    done = _install(tmp_path, {"BLACKBOX_CURATOR_SERVICE": "1", "BLACKBOX_CURATOR_PEERS": "curator-b",
                               "BLACKBOX_CURATOR_PUBLISHER": flag})
    assert _exec_start(done.units["blackbox-curator"]) == \
        f"ExecStart=/opt/venv/bin/hermes blackbox curate run --peer curator-b{expected}"
    assert ("wallet holder only" in done.out) == bool(expected)


def test_without_systemd_the_publisher_flag_is_in_the_command_shown(tmp_path):
    done = _install(tmp_path, {"BLACKBOX_CURATOR_SERVICE": "1", "BLACKBOX_CURATOR_PUBLISHER": "1"}, system="Darwin")
    assert done.units == {} and "blackbox curate run --publisher" in done.out


def test_a_bench_gets_a_long_running_watcher_and_the_url_only_in_a_private_sink(tmp_path):
    done = _install(tmp_path, {"BLACKBOX_CURATOR_WEBHOOK": SLACK}, call="register_curate_watch")
    unit = done.units["blackbox-curate-watch"]
    assert _exec_start(unit) == "ExecStart=/opt/venv/bin/hermes blackbox curate watch --interval 60"
    assert "--once" not in unit and SLACK not in unit and "Restart=on-failure" in unit
    sink = tmp_path / "home/.hermes/blackbox/curate/alarm_sink.json"
    assert sink.read_text(encoding="utf-8") == f'{{"kind": "slack", "url": "{SLACK}"}}\n'
    assert stat.S_IMODE(sink.stat().st_mode) == 0o600                          # node_sink refuses anything wider
    assert "--user restart blackbox-curate-watch" in done.calls


def test_the_sink_the_installer_writes_is_one_the_watcher_accepts(tmp_path):
    from plugins.blackbox.curate.watch.delivery import node_sink, WebhookSink

    for url, chat in ((SLACK, True), ("https://alerts.example/hook?token=a1&b=2", False)):
        root = tmp_path / ("slack" if chat else "plain")
        root.mkdir()
        _install(root, {"BLACKBOX_CURATOR_WEBHOOK": url}, call="register_curate_watch")
        sink = node_sink(root / "home/.hermes/blackbox/curate")
        assert isinstance(sink, WebhookSink) and sink._chat is chat          # Slack gets chat formatting


@pytest.mark.parametrize("url", ["http://hooks.slack.com/services/x", "https://", "https://a.example/x\"y",
                                 "https://a.example/$(touch pwned)", "https://a.example/a b", "https://a.example/a;b",
                                 "https://a.example/`id`", "https://a.example/a\\nb", "ftp://a.example"])
def test_a_webhook_that_is_not_a_plain_https_url_is_refused_and_nothing_is_written(tmp_path, url):
    done = _install(tmp_path, {"BLACKBOX_CURATOR_WEBHOOK": url}, call="register_curate_watch")
    assert "WARN refused BLACKBOX_CURATOR_WEBHOOK" in done.out and done.units == {}
    assert not (tmp_path / "home/.hermes").exists() and not list(tmp_path.rglob("pwned"))


def test_an_existing_sink_is_never_replaced(tmp_path):
    sink = tmp_path / "home/.hermes/blackbox/curate/alarm_sink.json"
    sink.parent.mkdir(parents=True)
    sink.write_text('{"kind": "telegram"}', encoding="utf-8")
    done = _install(tmp_path, {"BLACKBOX_CURATOR_WEBHOOK": SLACK}, call="register_curate_watch")
    assert sink.read_text(encoding="utf-8") == '{"kind": "telegram"}' and "kept the existing" in done.out
    assert "blackbox-curate-watch" in done.units


def test_on_a_curator_node_the_beat_watches_so_only_the_sink_is_written(tmp_path):
    done = _install(tmp_path, {"BLACKBOX_CURATOR_WEBHOOK": SLACK, "BLACKBOX_CURATOR_SERVICE": "1"},
                    call="register_curate_watch")
    assert done.units == {} and done.calls == ""
    assert (tmp_path / "home/.hermes/blackbox/curate/alarm_sink.json").exists()
    assert "beat posts this node's alarms" in done.out


def test_the_lab_tunnel_forwards_only_loopback_to_loopback_with_the_lab_key(tmp_path):
    done = _install(tmp_path, {"BLACKBOX_LAB_TUNNEL": "lab@lab-1.example"}, call="register_lab_tunnel")
    unit = done.units["blackbox-lab-tunnel"]
    key = f"{tmp_path}/home/.hermes/blackbox/curate/lab/tunnel_key"
    assert _exec_start(unit) == (
        f"ExecStart={tmp_path}/bin/autossh -M 0 -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 "
        f"-o ServerAliveCountMax=3 -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes "
        f"-i {key} -L 127.0.0.1:8790:127.0.0.1:8790 lab@lab-1.example")
    assert "Environment=AUTOSSH_GATETIME=0" in unit and "Restart=always" in unit
    assert "no lab-only key at" in done.out and "pin the lab host's key" in done.out


def test_the_lab_tunnel_ports_and_key_come_from_their_flags(tmp_path):
    done = _install(tmp_path, {"BLACKBOX_LAB_TUNNEL": "10.0.0.9", "BLACKBOX_LAB_TUNNEL_PORT": "18790",
                               "BLACKBOX_LAB_PORT": "8791", "BLACKBOX_LAB_TUNNEL_KEY": "/etc/blackbox/lab_key"},
                    call="register_lab_tunnel", root=True)
    assert _exec_start(done.system_units["blackbox-lab-tunnel"]).endswith(
        "-i /etc/blackbox/lab_key -L 127.0.0.1:18790:127.0.0.1:8791 10.0.0.9")


@pytest.mark.parametrize("env", [
    {"BLACKBOX_LAB_TUNNEL": "-oProxyCommand=touch_pwned"}, {"BLACKBOX_LAB_TUNNEL": "-F.evil"}, {"BLACKBOX_LAB_TUNNEL": "a b"},
    {"BLACKBOX_LAB_TUNNEL": "a@b@c"}, {"BLACKBOX_LAB_TUNNEL": "@host"}, {"BLACKBOX_LAB_TUNNEL": "host;id"},
    {"BLACKBOX_LAB_TUNNEL": "lab", "BLACKBOX_LAB_TUNNEL_PORT": "80"},
    {"BLACKBOX_LAB_TUNNEL": "lab", "BLACKBOX_LAB_PORT": "70000"},
    {"BLACKBOX_LAB_TUNNEL": "lab", "BLACKBOX_LAB_PORT": "8790 -R x"},
    # bash's `[ " 8790" -ge 1024 ]` is true: only the digits-only rule keeps a padded port out of the unit
    {"BLACKBOX_LAB_TUNNEL": "lab", "BLACKBOX_LAB_TUNNEL_PORT": " 8790"},
    {"BLACKBOX_LAB_TUNNEL": "lab", "BLACKBOX_LAB_PORT": "8790 "},
    {"BLACKBOX_LAB_TUNNEL": "lab", "BLACKBOX_LAB_TUNNEL_KEY": "relative/key"},
    {"BLACKBOX_LAB_TUNNEL": "lab", "BLACKBOX_LAB_TUNNEL_KEY": "/k -o ProxyCommand=x"},
    # '%' is a systemd specifier and '$' a systemd variable inside ExecStart
    {"BLACKBOX_LAB_TUNNEL": "lab", "BLACKBOX_LAB_TUNNEL_KEY": "/etc/blackbox/%h_key"},
    {"BLACKBOX_LAB_TUNNEL": "lab", "BLACKBOX_LAB_TUNNEL_KEY": "/etc/blackbox/$HOME"},
])
def test_a_lab_tunnel_setting_that_could_become_an_ssh_option_is_refused(tmp_path, env):
    done = _install(tmp_path, env, call="register_lab_tunnel")
    assert "WARN refused" in done.out and done.units == {} and done.calls == ""


def test_without_autossh_no_tunnel_unit_is_written(tmp_path):
    done = _install(tmp_path, {"BLACKBOX_LAB_TUNNEL": "lab"}, call="register_lab_tunnel", autossh=False)
    assert done.units == {} and "apt-get install autossh" in done.out


def test_the_key_console_runs_as_its_own_hardened_system_user(tmp_path):
    done = _install(tmp_path, {"BLACKBOX_KEY_CONSOLE": "1"}, call="register_key_console", root=True,
                    console_user=False, ptrace="2")
    unit = done.system_units["blackbox-console"]
    assert _exec_start(unit) == "ExecStart=/opt/venv/bin/hermes blackbox curate console --port 9710"
    for directive in CONSOLE_HARDENING:
        assert f"\n{directive}\n" in unit, directive
    assert f"ReadWritePaths={tmp_path}/home/.hermes/blackbox/curate\n" in unit
    assert "--system" in done.useradd and "blackbox-console" in done.useradd and "nologin" in done.useradd
    assert done.calls.splitlines() == ["daemon-reload", "enable blackbox-console", "restart blackbox-console"]
    assert "OK kernel.yama.ptrace_scope is 2" in done.out
    assert "tailscale serve --bg http://127.0.0.1:9710" in done.out and "never Funnel" in done.out


@pytest.mark.parametrize("scope", [None, "0", "1"])
def test_the_console_names_the_ptrace_host_step_when_the_host_lacks_it(tmp_path, scope):
    done = _install(tmp_path, {"BLACKBOX_KEY_CONSOLE": "1"}, call="register_key_console", root=True, ptrace=scope)
    assert "blackbox-console" in done.system_units and done.useradd == ""          # the user already exists
    assert "WARN kernel.yama.ptrace_scope is" in done.out
    assert "set kernel.yama.ptrace_scope = 2 in a file under /etc/sysctl.d/" in done.out


@pytest.mark.parametrize("system, root", [("Linux", False), ("Darwin", True)])
def test_the_console_is_never_a_user_unit(tmp_path, system, root):
    done = _install(tmp_path, {"BLACKBOX_KEY_CONSOLE": "1"}, call="register_key_console", system=system, root=root)
    assert done.units == {} and done.calls == "" and done.useradd == ""
    assert "SYSTEM unit" in done.out and "Nothing was registered" in done.out


def test_every_node_unit_is_registered_in_order_and_documents_how_to_stop_it():
    source = INSTALLER.read_text(encoding="utf-8")
    main_body = source.split("main() {", 1)[1]
    positions = [main_body.index(f"    {name}\n") for name in ("register_boot_service", *REGISTRARS, "next_steps")]
    assert positions == sorted(positions)
    for unit in UNITS:
        assert f"systemctl disable --now {unit}" in source
    assert "blackbox-install.ps1 has no mirror on purpose" in source
    for name, flag in zip(REGISTRARS[1:], ("BLACKBOX_CURATOR_WEBHOOK", "BLACKBOX_LAB_TUNNEL", "BLACKBOX_KEY_CONSOLE")):
        first = _function(name).split("\n")[1].strip()
        assert flag in first and "return 0" in _function(name).split("\n")[2 if "local" in first else 1], name


def test_a_rerun_that_adds_a_flag_restarts_the_running_unit(tmp_path):
    """KI-317: `enable --now` leaves a running unit on its old ExecStart; the writer restarts it."""
    _install(tmp_path, {"BLACKBOX_CURATOR_SERVICE": "1"})
    again = _install(tmp_path, {"BLACKBOX_CURATOR_SERVICE": "1", "BLACKBOX_CURATOR_PUBLISHER": "1"})
    assert _exec_start(again.units["blackbox-curator"]).endswith("curate run --publisher")
    assert again.calls.count("--user restart blackbox-curator") == 2 and "--now" not in again.calls
