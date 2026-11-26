"""The Linux sandbox's per-agent network rules (design "Linux deep layers" §1.3 and §1.5, build step
17, local-only): Linux's unprivileged launcher can not refuse a TCP port, so the root helper does,
per agent's cgroup scope, from File Shield's watch plan.

Contracts:
* a rendered policy says which network rules its agent gets, keyed by its digest — local ports
  (with the listed ports and the dashboard's), Docker's TCP ports; an unsigned render says none;
* the watch plan carries every rendered profile's rules as ``agents`` (one per digest), and none
  where no profile asks for them (macOS: Seatbelt refuses them itself);
* Hermes' execute_code RPC listens on a unix socket (a path, never a local TCP port), in a folder
  the Linux policy neither hides nor makes read-only — so the local-ports block can not cut
  Hermes' own tools off (§1.5).
"""

from __future__ import annotations

import os
import socket
import sys

import pytest

from plugins.blackbox.shields.files.sandbox import profiles
from plugins.blackbox.shields.files.sandbox.permissions import Allowances
from plugins.blackbox.shields.files.sandbox.places import build
from plugins.blackbox.shields.files.sandbox.platform.linux import network, profile


def _rendered(allowances: Allowances, tmp_path) -> str:
    places = build([], [], [str(tmp_path / "own")], str(tmp_path / "canary"), is_folder=lambda _path: True)
    text = profile.render(places, allowances=allowances, home=str(tmp_path), runtime="/run/user/1000")
    return profile.render(places, f"sha256:{profiles.digest(text)}", allowances, home=str(tmp_path), runtime="/run/user/1000")


def test_a_policy_says_its_network_rules_keyed_by_its_digest(tmp_path):
    text = _rendered(Allowances(refused=frozenset({"local-ports", "docker"}), ports=(5432,), dashboard_port=9700), tmp_path)
    rules = network.network_rules(text)
    assert rules is not None and len(rules.digest) == profiles.DIGEST_CHARS
    assert (rules.local_ports, rules.allow, rules.docker_tcp) == (True, (5432, 9700), True)
    assert rules.plan() == {"digest": rules.digest[:network.SCOPE_DIGEST_CHARS], "local_ports": True, "allow": [5432, 9700],
                            "docker_tcp": True}
    open_rules = network.network_rules(_rendered(Allowances(), tmp_path))
    assert (open_rules.local_ports, open_rules.allow, open_rules.docker_tcp) == (False, (), False)
    assert network.network_rules("# blackbox-sandbox policy 1\n# no digest\nlocal-ports block\n") is None


def test_the_watch_plan_carries_every_profiles_rules_once(tmp_path, monkeypatch):
    folder = tmp_path / "profiles"
    (folder / "claude-code").mkdir(parents=True)
    blocked = _rendered(Allowances(refused=frozenset({"local-ports"}), ports=(3000,)), tmp_path)
    (folder / "claude-code.policy").write_text(blocked, encoding="utf-8")
    (folder / "claude-code" / "abc.policy").write_text(blocked, encoding="utf-8")   # same digest: once
    (tmp_path / "agents.policy").write_text(_rendered(Allowances(), tmp_path), encoding="utf-8")
    monkeypatch.setattr(profiles, "profiles_dir", lambda: folder)
    monkeypatch.setattr(profiles, "profile_path", lambda: tmp_path / "agents.policy")
    monkeypatch.setattr(profiles.platform, "PROFILE_SUFFIX", ".policy")
    monkeypatch.setattr(profiles.platform, "network_rules", network.network_rules)
    rules = profiles.network_rules()
    assert len(rules) == 2, "one entry per digest"
    [blocking] = [rule for rule in rules if rule["local_ports"]]
    assert blocking["allow"] == [3000] and blocking["docker_tcp"] is False


@pytest.mark.skipif(sys.platform == "win32", reason="Hermes uses loopback TCP on Windows")
def test_hermes_execute_code_rpc_is_a_unix_socket_the_policy_leaves_usable(tmp_path):
    from tools import code_kernel
    kernel = code_kernel.SessionKernel(("test", "rpc"))
    endpoint = code_kernel._bind_rpc_socket(kernel)
    try:
        assert not endpoint.startswith("tcp://"), "a path socket, never a local port the local-ports block would cut"
        assert kernel.server_sock.family == socket.AF_UNIX
        folder = os.path.dirname(endpoint)
        places = build([], [], [str(tmp_path / "own")], str(tmp_path / "canary"), is_folder=lambda _path: True)
        text = profile.render(places, allowances=Allowances(refused=frozenset({"local-ports", "docker", "clipboard"})),
                              home=str(tmp_path), runtime="/run/user/1000")
        closed = [line.split(" ", 1)[1] for line in text.splitlines()
                  if line.split(" ", 1)[0] in ("hide-dir", "hide-file", "ro", "ro-file", "startup-ro", "pin")]
        assert not any(folder == place or folder.startswith(place.rstrip("/") + "/") for place in closed), (folder, closed)
    finally:
        kernel.server_sock.close()
        if kernel.sock_path:
            os.unlink(kernel.sock_path)
