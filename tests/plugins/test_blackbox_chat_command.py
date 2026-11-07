"""How ``blackbox chat`` (and the dashboard's assistant) re-runs Hermes under Blackbox's profile.

Moved out of test_blackbox_plugin.py (size cap) on 2026-11-07 with the KI-459 regression tests:
Hermes 0.23's launcher runs ``python -I -c <script>``, so ``sys.argv[0]`` is "-c" and must never be
the program the chat command execs.
"""

from __future__ import annotations

import sys

from plugins.blackbox.chat import command as chat_command


def test_blackbox_chat_wraps_bare_prompt(monkeypatch):
    from hermes_cli import relaunch

    monkeypatch.setattr(relaunch, "resolve_hermes_bin", lambda: "/opt/bin/hermes")
    assert chat_command._blackbox_chat_argv(["who", "are", "you?"]) == [
        "/opt/bin/hermes",
        "--profile",
        "agent-blackbox",
        "chat",
        "--query",
        "who are you?",
    ]
    assert chat_command._blackbox_chat_argv(["--tui"]) == [
        "/opt/bin/hermes",
        "--profile",
        "agent-blackbox",
        "chat",
        "--tui",
    ]


def test_blackbox_chat_under_the_published_c_launcher_runs_the_real_hermes(tmp_path, monkeypatch):
    """KI-459: Hermes' launcher is ``python -I -c <script>``, so sys.argv[0] is "-c".

    The chat command must exec the real ``hermes`` on PATH, never the string "-c".
    """
    shim = tmp_path / "hermes"
    shim.write_text('#!/bin/sh\nexec true "$@"\n', encoding="utf-8")
    shim.chmod(0o755)
    monkeypatch.setattr(sys, "argv", ["-c", "blackbox", "chat"])
    monkeypatch.setenv("PATH", str(tmp_path))

    argv = chat_command._blackbox_chat_argv(["hi"])

    assert argv[0] == str(shim)
    assert argv[1:] == ["--profile", "agent-blackbox", "chat", "--query", "hi"]


def test_blackbox_chat_without_a_hermes_program_runs_the_module(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["-c"])
    monkeypatch.setenv("PATH", str(tmp_path))

    argv = chat_command._blackbox_chat_argv(["--tui"])

    assert argv == [sys.executable, "-m", "hermes_cli.main", "--profile", "agent-blackbox", "chat", "--tui"]
