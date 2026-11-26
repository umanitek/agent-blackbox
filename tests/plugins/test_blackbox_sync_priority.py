"""The first graph sync yields the machine to the person's work — and nothing on the guard path
is lowered (``dashboard.network_sync``, the DKG node's boot unit, ``kernel.config_values.saved_entry``).

Linux round L7 (BB-LINUX-PENDING-88f30f, Medium): after an install the first graph sync, the DKG
node, its store and the dashboard held 2 of 4 cores for 1-3 hours. Profiled on the VM (py-spy,
25 s): the dashboard spent about a tenth of a core deep-copying Hermes's WHOLE config on each
settings read, and the sync child ran at full priority. The node itself stays at normal priority:
it runs the DKG-managed Oxigraph store, which every hook's graph lookup asks with a 2 s limit.
"""

from __future__ import annotations

from _blackbox_loader import load_blackbox

from test_blackbox_installer_boot import _register_boot_service

network_sync = load_blackbox("dashboard.network_sync")
saved_entry = load_blackbox("kernel.config_values.saved_entry")


def test_the_sync_child_runs_lowered_where_the_tools_exist(monkeypatch):
    tools = {"nice": "/usr/bin/nice", "ionice": "/usr/bin/ionice"}
    monkeypatch.setattr(network_sync.shutil, "which", tools.get)
    argv = network_sync.network_sync_argv(60)
    assert argv[:7] == ["/usr/bin/ionice", "-c", "2", "-n", "7", "/usr/bin/nice", "-n"] and argv[7] == "10"
    assert argv[-5:] == ["sync", "--wait", "--timeout", "60", "--require-rules"]
    monkeypatch.setattr(network_sync.shutil, "which", lambda name: None)
    plain = network_sync.network_sync_argv(60)
    assert plain[0] != "/usr/bin/nice" and plain[-5:] == ["sync", "--wait", "--timeout", "60", "--require-rules"]


def test_the_node_is_not_lowered_and_survives_a_slow_start(tmp_path):
    """Its store answers the hooks' lookups, so no Nice/CPUWeight; under load its start-pre overran
    systemd's 90 s and it restart-looped, so its start may take 300 s."""
    _register_boot_service(tmp_path, "Linux")
    unit = (tmp_path / ".config" / "systemd" / "user" / "blackbox-dkg.service").read_text(encoding="utf-8")
    lines = {line.split("=", 1)[0] for line in unit.splitlines() if "=" in line and not line.startswith("#")}
    assert not lines & {"Nice", "CPUWeight", "IOWeight", "CPUSchedulingPolicy"}
    assert "TimeoutStartSec=300" in unit.splitlines()


def test_a_settings_read_never_copies_or_changes_hermess_cached_config(monkeypatch):
    from hermes_cli import config as hermes_config

    cached = {"plugins": {"entries": {"blackbox": {"mode": "block", "protected_paths": ["~/.ssh/*"]}}}, "big": list(range(10))}
    monkeypatch.setattr(hermes_config, "load_config_readonly", lambda: cached)
    monkeypatch.setattr(hermes_config, "load_config", lambda: (_ for _ in ()).throw(AssertionError("whole-config copy")))
    monkeypatch.setattr(saved_entry.constants, "hermes_root", saved_entry.constants.hermes_home)
    saved_entry.forget()
    entry = saved_entry.read()
    assert entry["mode"] == "block"
    entry["protected_paths"].append("x")
    entry["mode"] = "audit"
    assert cached["plugins"]["entries"]["blackbox"] == {"mode": "block", "protected_paths": ["~/.ssh/*"]}
    saved_entry.forget()
