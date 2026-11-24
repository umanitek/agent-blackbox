"""The agent sandbox's Linux port in Python (shields/files/sandbox/platform/linux; design "Linux deep
layers" §1.2, build step 13, local-only). Everything here runs on any OS: the modules are imported
by path, the launcher runs with a stand-in for ``blackbox-sandbox`` that records how it was called.
The real launcher is proven on a Linux kernel by helper/tests/sandbox_linux.rs.

Contracts:
* the policy names every place the way the launcher reads it: protected items and keys hidden, the
  canary, Blackbox's own places / startup files / startup places read-only, the folders above an
  item pinned, the buses hidden — the never-list after its mark, the permissions above it;
* each refused permission adds its lines (Docker's sockets, local ports with the allowed ports and
  the dashboard's, the display for the clipboard, the camera and microphone);
* the launcher starts the real agent through ``blackbox-sandbox run --policy <profile> --`` with the
  stand-ins first on the sandboxed PATH; without the launcher installed it says the hooks-only line;
* stand-ins say why for the tools that raise privileges; placeholders are made only for missing
  startup folders and no-op files (never ``.bash_profile``) and recorded;
* ``unavailable()`` comes from the probe; a stopped process is described from /proc.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from plugins.blackbox.shields.files.sandbox.permissions import Allowances
from plugins.blackbox.shields.files.sandbox.places import build
from plugins.blackbox.shields.files.sandbox.platform.linux import launchers, placeholders, probe, processes, profile, tools


@pytest.fixture
def places(tmp_path):
    home = tmp_path / "home"
    (home / "Documents" / "Taxes").mkdir(parents=True)
    (home / ".hermes" / "blackbox").mkdir(parents=True)
    return build([str(home / "Documents" / "Taxes"), str(home / "id_rsa")], [str(home / ".hermes/blackbox/*.pem")],
                 [str(home / ".hermes" / "blackbox")], str(home / ".hermes/blackbox/canary"),
                 is_folder=lambda path: path.endswith("Taxes"), startup_files=[str(home / ".bashrc")],
                 startup=([str(home / ".config/systemd/user")], [str(home / ".xprofile")], [str(home / ".local/share/gem/ruby/*/bin")]))


def _lines(text: str) -> list[str]:
    return text.splitlines()


def test_the_policy_names_every_place_the_way_the_launcher_reads_it(places, tmp_path):
    text = profile.render(places, "sha256:abc123", home=str(tmp_path / "home"), runtime="/run/user/1000")
    lines = _lines(text)
    assert lines[0] == "# blackbox-sandbox policy 1"
    assert lines[1] == "# Blackbox agent sandbox — generated, do not edit. sha256:abc123"
    home = os.path.realpath(tmp_path / "home")
    expected = [f"hide-dir {home}/Documents/Taxes", f"hide-file {home}/id_rsa", f"hide-glob {home}/.hermes/blackbox/*.pem",
                f"canary {home}/.hermes/blackbox/canary", f"ro {home}/.hermes/blackbox", f"ro-file {home}/.bashrc",
                f"startup-ro {home}/.config/systemd/user", f"startup-ro {home}/.xprofile",
                f"startup-ro-glob {home}/.local/share/gem/ruby/*/bin", f"pin {home}/Documents", "bus refuse",
                "hide-socket /run/user/1000/bus", "hide-socket /run/dbus/system_bus_socket"]
    for line in expected:
        assert line in lines, line
    never = lines.index(profile.NEVER_MARK)
    assert all(lines.index(line) > never for line in expected), "the never-list comes last"
    directives = {line.split(" ", 1)[0] for line in lines[2:] if not line.startswith("#")}
    assert directives <= {"hide-dir", "hide-file", "hide-glob", "canary", "ro", "ro-file", "ro-glob", "pin", "startup-ro",
                          "startup-ro-glob", "hide-socket", "hide-socket-glob", "display", "bus", "docker", "devices",
                          "local-ports", "allow-port", "dashboard-port"}


def test_a_path_with_a_backslash_or_a_newline_is_escaped_for_the_line_format(tmp_path):
    odd = build([str(tmp_path / "a\\b\nc")], [], [], str(tmp_path / "canary"), is_folder=lambda _path: True)
    text = profile.render(odd, home=str(tmp_path), runtime="/run/user/1")
    assert f"hide-dir {os.path.realpath(tmp_path)}/a\\\\b\\nc" in _lines(text)


def test_each_refused_permission_adds_its_lines_and_an_allowed_one_adds_none(places, tmp_path):
    refused = Allowances(refused=frozenset({"docker", "local-ports", "clipboard", "camera-mic"}), ports=(5432, 3000),
                         dashboard_port=9700, tool_folders=("/h/.local/bin",), hidden=("/h/work/secret",))
    lines = _lines(profile.render(places, allowances=refused, home="/h", runtime="/run/user/7"))
    for line in ["docker refuse", "hide-socket /run/docker.sock", "hide-socket /run/user/7/docker.sock",
                 "hide-socket-glob /h/.colima/*/docker.sock", "local-ports block", "allow-port 3000", "allow-port 5432",
                 "dashboard-port 9700", "display refuse", "hide-socket-glob /tmp/.X11-unix/*",
                 "hide-socket-glob /run/user/7/wayland-*", "devices refuse", "hide-socket-glob /dev/video*",
                 "hide-socket /dev/snd", "hide-socket /run/user/7/pipewire-0", "ro /h/.local/bin", "hide-dir /h/work/secret"]:
        assert line in lines, line
    assert lines.index("docker refuse") < lines.index(profile.NEVER_MARK)
    allowed = _lines(profile.render(places, home="/h", runtime="/run/user/7"))
    assert "display allow" in allowed
    assert not [line for line in allowed if line.startswith(("docker", "local-ports", "devices", "allow-port"))]


def _fake_sandbox(tmp_path: Path) -> Path:
    fake = tmp_path / "blackbox-sandbox"
    fake.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$BB_CALLED"; printf "%s\\n" "$PATH" >> "$BB_CALLED"\n', encoding="utf-8")
    fake.chmod(0o755)
    return fake


def test_the_launcher_runs_the_agent_through_blackbox_sandbox_with_the_tools_first(tmp_path, monkeypatch):
    fake = _fake_sandbox(tmp_path)
    monkeypatch.setattr(launchers, "RUNNER", f'{launchers.quote_shell(str(fake))} run --policy "$profile" --')
    monkeypatch.setattr(launchers, "READY", f"[ -x {launchers.quote_shell(str(fake))} ]")
    here, real_bin = tmp_path / "agent-bin", tmp_path / "real"
    here.mkdir()
    real_bin.mkdir()
    (real_bin / "claude").write_text("#!/bin/sh\necho real\n", encoding="utf-8")
    (real_bin / "claude").chmod(0o755)
    policy = tmp_path / "claude-code.policy"
    policy.write_text("# blackbox-sandbox policy 1\n# x sha256:00ff\n", encoding="utf-8")
    (here / "claude").write_text(launchers.launcher_script("claude", str(here), str(policy)), encoding="utf-8")
    (here / "claude").chmod(0o755)
    called = tmp_path / "called"
    env = {"PATH": f"{here}:{real_bin}:/usr/bin:/bin", "BB_CALLED": str(called), "HOME": str(tmp_path)}
    subprocess.run([str(here / "claude"), "--print", "hi"], env=env, check=True, cwd=tmp_path)
    words = called.read_text(encoding="utf-8").splitlines()
    assert words[:5] == ["run", "--policy", str(policy), "--", str(real_bin / "claude")]
    assert words[5:7] == ["--print", "hi"]
    assert not words[7].startswith(str(here / tools.TOOLS_FOLDER)), "no sandbox-tools folder yet: nothing put first"
    (here / tools.TOOLS_FOLDER).mkdir()
    subprocess.run([str(here / "claude")], env=env, check=True, cwd=tmp_path)
    assert called.read_text(encoding="utf-8").splitlines()[-1].startswith(str(here / tools.TOOLS_FOLDER) + ":")


def test_without_the_launcher_installed_the_agent_runs_with_the_hooks_only_line(tmp_path, monkeypatch):
    monkeypatch.setattr(launchers, "READY", f"[ -x {launchers.quote_shell(str(tmp_path / 'missing'))} ]")
    here, real_bin = tmp_path / "agent-bin", tmp_path / "real"
    here.mkdir()
    real_bin.mkdir()
    (real_bin / "codex").write_text("#!/bin/sh\necho real codex\n", encoding="utf-8")
    (real_bin / "codex").chmod(0o755)
    policy = tmp_path / "codex.policy"
    policy.write_text("# blackbox-sandbox policy 1\n", encoding="utf-8")
    (here / "codex").write_text(launchers.launcher_script("codex", str(here), str(policy)), encoding="utf-8")
    (here / "codex").chmod(0o755)
    done = subprocess.run([str(here / "codex")], env={"PATH": f"{here}:{real_bin}:/usr/bin:/bin"}, capture_output=True,
                          text=True, encoding="utf-8", check=True, cwd=tmp_path)
    assert done.stdout.strip() == "real codex"
    assert "blackbox: no sandbox profile — codex runs with Blackbox's hooks only" in done.stderr


def test_stand_ins_say_why_for_the_tools_that_raise_privileges(tmp_path, monkeypatch):
    fake_sudo = tmp_path / "sudo"
    fake_sudo.write_text("", encoding="utf-8")
    monkeypatch.setattr(tools, "SETUID_TOOLS", (str(fake_sudo), str(tmp_path / "not-here")))
    assert tools.refresh_tools(str(tmp_path)) is True
    assert tools.refresh_tools(str(tmp_path)) is False, "made again only when the set changes"
    standin = Path(tools.tools_dir(str(tmp_path))) / "sudo"
    assert standin.stat().st_mode & stat.S_IXUSR
    assert not (Path(tools.tools_dir(str(tmp_path))) / "not-here").exists()
    done = subprocess.run([str(standin), "-i"], capture_output=True, text=True, encoding="utf-8", check=False)
    assert done.returncode == 126 and "no new privileges" in done.stderr
    tools.refresh_tools(str(tmp_path), wanted=False)
    assert not Path(tools.tools_dir(str(tmp_path))).exists()


def test_placeholders_only_for_missing_startup_folders_and_no_op_files_and_recorded(tmp_path):
    home = tmp_path / "home"
    (home / ".config" / "autostart").mkdir(parents=True)
    rules = build([], [], [], str(home / "canary"), is_folder=lambda _path: True,
                  startup_files=[str(home / ".bashrc"), str(home / ".bash_profile"), str(home / ".zshrc")],
                  startup=([str(home / ".config/systemd/user"), str(home / ".config/autostart"), "/etc/systemd/user"],
                           [str(home / ".xinitrc"), str(home / ".xprofile")], []))
    manifest = tmp_path / "state" / placeholders.MANIFEST
    manifest.parent.mkdir()
    made = placeholders.ensure(rules, os.path.realpath(home), manifest)
    real = os.path.realpath(home)
    assert set(made) == {f"{real}/.config/systemd/user", f"{real}/.bashrc", f"{real}/.zshrc", f"{real}/.xprofile"}
    assert not (home / ".bash_profile").exists(), "never .bash_profile: bash would stop reading .profile"
    assert not (home / ".xinitrc").exists(), "an empty .xinitrc is not a no-op"
    assert json.loads(manifest.read_text(encoding="utf-8")) == made
    assert placeholders.ensure(rules, real, manifest) == [], "nothing made twice"


def test_unavailable_comes_from_the_probe(tmp_path):
    assert probe.unavailable(str(tmp_path / "missing")) == probe.NOT_INSTALLED
    fake = tmp_path / "blackbox-sandbox"
    fake.write_text('#!/bin/sh\necho \'{"format":1,"userns":false,"why":"Ubuntu\\u2019s AppArmor restricts it"}\'\n',
                    encoding="utf-8")
    fake.chmod(0o755)
    assert "AppArmor" in probe.unavailable(str(fake))
    fake.write_text('#!/bin/sh\necho \'{"format":1,"userns":true,"seccomp":true,"signals":"none","helper_rules":false}\'\n',
                    encoding="utf-8")
    os.utime(fake, ns=(1, 2))   # another file version: probed again
    assert probe.unavailable(str(fake)) is None
    rows = {row["layer"]: row for row in probe.layers(str(fake))}
    assert rows["files"]["enforced"] == "yes" and rows["signals"]["enforced"] == "no"
    assert "6.12" in rows["signals"]["note"]


def test_a_process_is_described_from_proc(tmp_path):
    entry = tmp_path / "4242"
    entry.mkdir()
    (entry / "status").write_text("Name:\tnode\nUid:\t1000\t1000\t1000\t1000\n", encoding="utf-8")
    (entry / "cmdline").write_bytes(b"node\0server.js\0")
    os.symlink("/usr/bin/node", entry / "exe")
    facts = processes.describe(4242, proc=str(tmp_path))
    assert facts == processes.ProcessFacts(1000, "/usr/bin/node", "node server.js")
    assert processes.describe(4243, proc=str(tmp_path)) is None
    assert processes.is_system("/usr/lib/systemd/systemd") and not processes.is_system("/usr/bin/node")
