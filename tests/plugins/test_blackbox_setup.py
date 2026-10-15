"""`blackbox setup` — the full install after a Hermes plugin-catalog install.

The plugin carries byte-identical copies of the installer the curl one-liner runs
(scripts/ stays where blackbox.umanitek.ai points) and runs them in setup-only mode
in the Hermes it is installed in, with the DKG release pinned by checksum.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

import pytest
from _blackbox_loader import load_blackbox

setup = load_blackbox("setup")
cli_mod = load_blackbox("cli")

REPO = Path(__file__).resolve().parents[2]
COPIES = ["blackbox-install.sh", "blackbox-install.ps1", "blackbox-blazegraph.mjs", "blackbox-dkg-runtime-fingerprint.py"]


@pytest.mark.parametrize("name", COPIES)
def test_the_plugin_carries_the_installer_curl_runs_byte_for_byte(name):
    """When this fails, the original in scripts/ changed: copy it over —
    cp scripts/<name> plugins/blackbox/setup/<name>"""
    assert (setup.HERE / name).read_bytes() == (REPO / "scripts" / name).read_bytes()


def test_the_environment_selects_setup_only_mode_in_this_hermes_with_the_pinned_dkg(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("BLACKBOX_DKG_PACKAGE", "@origintrail-official/dkg@latest")   # a caller's value never wins

    env = setup.setup_environment()

    assert env["BLACKBOX_SETUP_ONLY"] == "true"
    assert env["VENV_DIR"] == sys.prefix
    assert env["BLACKBOX_HELPER_DIR"] == str(setup.HERE)
    assert env["BLACKBOX_PLUGIN_DIR"] == str(setup.PLUGIN_DIR)
    assert env["BLACKBOX_DKG_PACKAGE"] == "@origintrail-official/dkg@10.0.23"
    assert env["BLACKBOX_DKG_INTEGRITY"].startswith("sha512-")
    assert env["BLACKBOX_INSTALL_DIR"].endswith("node") and env["HERMES_HOME"] == str(tmp_path / "home")


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig"])
def test_the_revision_is_the_catalogs_pinned_commit(tmp_path, monkeypatch, encoding):
    plugin = tmp_path / "blackbox"
    plugin.mkdir()
    (plugin / ".hermes-catalog.json").write_text('{"sha": "cfe788d212383113929e2f10011816966f6cc0b2"}', encoding=encoding)
    monkeypatch.setattr(setup, "PLUGIN_DIR", plugin)

    assert setup._revision() == "cfe788d212383113929e2f10011816966f6cc0b2"


def test_setup_runs_the_bundled_installer_and_returns_its_exit_code(monkeypatch):
    ran = {}

    def fake_run(command, env, stdin, check):
        ran.update(command=command, env=env, stdin=stdin)
        return subprocess.CompletedProcess(command, 3)

    monkeypatch.setattr(setup, "_hermes_bin", lambda: "/usr/local/bin/hermes")
    monkeypatch.setattr(setup.subprocess, "run", fake_run)
    monkeypatch.setattr(setup.os, "name", "posix")

    assert setup.cmd_setup(argparse.Namespace(store="oxigraph")) == 3
    assert ran["command"] == ["bash", str(setup.HERE / "blackbox-install.sh"), "--store", "oxigraph"]
    assert ran["env"]["BLACKBOX_SETUP_ONLY"] == "true" and ran["stdin"] is subprocess.DEVNULL


def test_setup_without_a_hermes_command_says_so(monkeypatch, capsys):
    monkeypatch.setattr(setup, "_hermes_bin", lambda: "")

    assert setup.cmd_setup(argparse.Namespace(store=None)) == 1
    assert "hermes" in capsys.readouterr().out


def test_blackbox_setup_is_a_blackbox_command():
    parser = argparse.ArgumentParser()
    cli_mod.setup_cli(parser)

    args = parser.parse_args(["setup", "--store", "blazegraph"])

    assert args.func is setup.cmd_setup and args.store == "blazegraph"
