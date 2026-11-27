"""The person's question never shows on a command line (review 2026-11-26, LOW).

The dashboard's assistant ran ``hermes blackbox chat --query=<question + state brief>``: any local
process could read both with ``ps``. The question now travels on the child's standard input
(``--query-file=-``, which Hermes' own chat reads), and ``blackbox chat`` passes that option on to
Hermes unchanged. Contracts:

- the assistant's command line carries neither the question nor the state brief; its input does;
- ``blackbox chat --query-file=-`` hands Hermes ``--query-file=-`` (and no bare-prompt query).
"""

from __future__ import annotations

import argparse
import subprocess

from plugins.blackbox import cli as cli_mod
from plugins.blackbox.chat import command as chat_command
from plugins.blackbox.dashboard.assistant import runner

QUESTION = "is my private-project-name folder safe?"


def test_the_question_goes_on_stdin_never_on_the_command_line(monkeypatch):
    seen: dict = {}

    def fake_run(argv, **kwargs):
        seen.update(argv=argv, input=kwargs.get("input"), stdin=kwargs.get("stdin"))
        return subprocess.CompletedProcess(argv, 0, stdout="Fine.", stderr="")

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    runner.ask(QUESTION)
    assert not any(QUESTION in str(part) for part in seen["argv"])
    assert "--query-file=-" in seen["argv"]
    assert QUESTION in (seen["input"] or "") and seen["stdin"] is None


def test_blackbox_chat_passes_the_query_file_on_to_hermes():
    parser = argparse.ArgumentParser()
    cli_mod.setup_cli(parser)
    args = parser.parse_args(["chat", "--query-file=-", "--quiet"])
    assert chat_command._blackbox_chat_args(args) == ["--query-file=-", "--quiet"]
