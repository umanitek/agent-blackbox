"""An agent may not switch Blackbox off by what a command says: the switch-off commands, the
control API, Blackbox's environment and the startup files (``detection/paths/guard_commands.py``).

Split from test_blackbox_self_protection.py (KI-691): the red-team catalogue's cases of the
surfaces below, each in Audit AND Block mode. Nothing is executed: the cases are text handed to
the judgement (``guard.tool_call_verdict``).
"""

from __future__ import annotations

import pytest

from _blackbox_self_protection_machine import attack_cases, make_machine, refused_in_every_mode


@pytest.fixture
def machine(monkeypatch, tmp_path):
    """The shared machine (:func:`_blackbox_self_protection_machine.make_machine`); returns ``use(mode)``."""
    return make_machine(monkeypatch, tmp_path)


@pytest.mark.parametrize("mode", ["audit", "block"])
@pytest.mark.parametrize("tool,args", attack_cases('switch-off commands', 'control api', 'environment and startup'))
def test_an_attack_on_blackbox_itself_is_refused_in_every_mode(machine, mode, tool, args):
    refused_in_every_mode(machine, mode, tool, args)
