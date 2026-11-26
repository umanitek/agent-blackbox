"""An attack delayed or disguised — encoded, pieced together, wrapped, written first and run later —
and the second round written after the rule passed the first (``detection/paths/shell_scripts.py``,
``guard_settings.py``'s whole reading).

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
@pytest.mark.parametrize("tool,args", attack_cases('delayed and disguised', 'second round'))
def test_an_attack_on_blackbox_itself_is_refused_in_every_mode(machine, mode, tool, args):
    refused_in_every_mode(machine, mode, tool, args)
