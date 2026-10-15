"""Status preserves setup guidance and backend-specific verified progress."""

import argparse
from types import SimpleNamespace

import pytest
from _blackbox_loader import load_blackbox

cli = load_blackbox("cli")
config = load_blackbox("kernel.config")


@pytest.mark.parametrize("backend", ["legacy-cache", "dkg"])
@pytest.mark.parametrize("installed", [False, True])
def test_empty_graph_status_distinguishes_setup_and_compilation(
    tmp_path, monkeypatch, capsys, backend, installed,
):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "blackbox"))
    command = tmp_path / "dkg"
    if installed:
        command.write_text("#!/bin/sh\n", encoding="utf-8")
    cfg = config.BlackboxConfig(dkg_bin=str(command), detection_backend=backend)
    counts = dict.fromkeys(["injection", "escalation", "dependency", "fileaccess", "skill", "ioc"], 0)
    monkeypatch.setattr(cli, "load_blackbox_config", lambda: cfg)
    monkeypatch.setattr(cli, "DkgClient", lambda **kwargs: SimpleNamespace(reachable=lambda: False))
    monkeypatch.setattr(cli.ruleset, "get", lambda cfg: SimpleNamespace(counts=lambda: counts))
    monkeypatch.setattr(cli.ruleset, "verified_progress", lambda graph: {
        "assets_total": 10, "assets_compiled": 3,
    })
    monkeypatch.setattr(cli, "_print_health", lambda *args: None)
    monkeypatch.setattr(cli, "_print_attached_targets", lambda: None)
    monkeypatch.setattr(cli, "print_community_status", lambda cfg: None)
    monkeypatch.setattr(cli.audit, "count_findings", lambda: 0)

    assert cli._cmd_status(argparse.Namespace()) == 0

    out = capsys.readouterr().out
    assert ("SETUP NEEDED" in out) is (not installed)
    assert ("hermes blackbox setup" in out) is (not installed)
    assert ("UNPROTECTED" in out) is installed
    assert ("blackbox sync --wait" in out) is installed
    assert ("3 of 10 assets compiled into rules" in out) is (backend == "legacy-cache")
    assert ("live local graph queries" in out) is (backend == "dkg")
