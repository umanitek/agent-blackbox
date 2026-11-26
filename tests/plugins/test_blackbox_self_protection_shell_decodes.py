"""Blackbox's own protection reads a command the way the shell will run it — no more, no less
(``detection/paths/guard_settings.py`` ``_read_closely``, ``guard_paths._without_a_run_folder``).

Linux round L8 (BB-LINUX-PENDING-8cb925, MEDIUM, false block): every string literal of inline
code is also read as a command line, so ``node -e "console.log('/')"`` gave the line ``/`` — a
"command" whose program is the root folder, which holds every guarded place — and was refused as
"Change to Blackbox's own settings" on real Cline and Hermes dev days. A folder cannot be run
(the shell answers "is a directory"), so its name in the program's position reaches nothing.

Found while fixing it (L-W5): the rule judged only a line as written when that line handed text
on (``-c``/``eval``), so a decode the SHELL does — ``~/$'.\\x68ermes'``, ``$(printf '…')``,
``printf '\\x2f' | xargs rm -rf``, ``rm -rf \\/`` — reached Blackbox's own folder unrefused. The
commands a line hides are now judged on every closely read line. Nothing is executed: the cases
are text handed to the judgement (``guard.tool_call_verdict``), in Audit and Block mode.
"""

from __future__ import annotations

import pytest

from _blackbox_self_protection_machine import guard, make_machine, own_findings, refused_in_every_mode


@pytest.fixture
def machine(monkeypatch, tmp_path):
    """The shared machine (:func:`_blackbox_self_protection_machine.make_machine`); returns ``use(mode)``."""
    return make_machine(monkeypatch, tmp_path)


#: Inline code that only names the root or home folder in a literal: everyday work, never a change.
ROOT_IN_CODE = [
    """node -e "console.log('/')\"""",
    """python3 -c "print('/')\"""",
    """python3 -c "import os; print(os.listdir('/'))\"""",
    """node -p "require('path').join('/', 'tmp')\"""",
    """python3 -c "print('~')\"""",
    """ruby -e "puts '/'\"""",
    """perl -e "print '/'\"""",
]

#: The same family, written so the shell (not the words) names Blackbox or the folders above it.
SHELL_DECODED = [
    r"rm -rf ~/$'.\x68ermes'",
    r"rm -rf ~/$(printf '.\x68ermes')",
    r"printf '.\x68ermes' | xargs -I{} rm -rf ~/{}",
    r"rm -rf $(printf '\x2f')",
    r"rm -rf $'\x2f'",
    r"printf '\x2f' | xargs rm -rf",
    r"rm -rf \/",
    # A folder in the program's position is dropped; what follows it on the line is still judged.
    "/ ; rm -rf ~/.hermes",
    "~ && rm -rf ~/.hermes/plugins/blackbox",
    # The root literal handed to code that deletes is still the root folder deleted.
    """python3 -c "import shutil; shutil.rmtree('/')\"""",
    """python3 -c "import shutil; shutil.rmtree('\\x2f')\"""",
    """node -e "require('fs').rmSync('/', {recursive: true})\"""",
    """python3 -c "import subprocess; subprocess.run(['rm', '-rf', '/'])\"""",
    # A wildcard in the program's position runs the first FILE it matches: never dropped.
    "~/.hermes/*",
]


@pytest.mark.parametrize("command", ROOT_IN_CODE)
def test_inline_code_naming_the_root_folder_is_not_a_change_to_blackbox(machine, command):
    machine("block")
    verdict = guard.tool_call_verdict("terminal", {"command": command})
    assert own_findings(verdict) == [], verdict


@pytest.mark.parametrize("mode", ["audit", "block"])
@pytest.mark.parametrize("command", SHELL_DECODED)
def test_a_command_the_shell_decodes_onto_blackbox_is_refused_in_every_mode(machine, mode, command):
    refused_in_every_mode(machine, mode, "terminal", {"command": command})
