"""A long command is checked like a short one.

The shell command of a call was read up to its first 8,000 characters only, so
anything after that — a protected file read, a keychain read, an edit of
Blackbox's own settings — was outside every command check. A command is now read
whole up to 100,000 characters, and beyond that by its first and last 50,000 (the
rule the secret scanners already follow). Each case goes through the hook's real
check list; nothing is executed.
"""

from __future__ import annotations

import pytest

from plugins.blackbox import shields
from plugins.blackbox.detection import shell_shapes
from plugins.blackbox.guard import hooks
from plugins.blackbox.kernel import constants
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.ruleset import Ruleset

#: What each command must be recognised as, however much harmless text surrounds it.
PROTECTED = [
    ("cat ~/.ssh/id_rsa", "fileaccess:terminal:user-protected"),
    ("sed -i 's/mode: block/mode: audit/' {hermes_home}/config.yaml", "fileaccess:terminal:blackbox-settings"),
    ("security find-generic-password -a me -w", "fileaccess:terminal:macos-keychain"),
]


def _identifiers(command: str) -> set[str]:
    found = hooks._raw_findings(BlackboxConfig(mode="block"), Ruleset(), "terminal", {"command": command},
                                shields.ShieldsSnapshot())
    return {finding.identifier for finding in found}


def _padding(characters: int) -> str:
    return "echo " + "a " * (characters // 2) + "; "


@pytest.mark.parametrize("command, identifier", PROTECTED)
@pytest.mark.parametrize("before, after", [(0, 0), (8_100, 0), (60_000, 0), (0, 60_000), (150_000, 0), (0, 150_000)])
def test_a_protected_action_is_found_with_harmless_text_around_it(monkeypatch, tmp_path, command, identifier,
                                                                   before, after):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path))
    command = command.format(hermes_home=constants.hermes_home())   # the suite runs with its own Hermes home
    text = _padding(before) + command + (" ; " + _padding(after) if after else "")
    assert identifier in _identifiers(text)


@pytest.mark.parametrize("characters", [0, 8_100, 60_000, 250_000])
def test_a_long_harmless_command_raises_nothing(monkeypatch, tmp_path, characters):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path))
    assert _identifiers(_padding(characters) + "ls -la") == set()


def test_the_command_read_is_whole_when_short_and_head_plus_tail_when_long():
    short = "x" * shell_shapes.COMMAND_SCAN_WINDOW * 2
    assert shell_shapes.command_from_args("terminal", {"command": short}) == short
    long = "h" * shell_shapes.COMMAND_SCAN_WINDOW + "m" * 10 + "t" * shell_shapes.COMMAND_SCAN_WINDOW
    read = shell_shapes.command_from_args("terminal", {"command": long})
    assert read == "h" * shell_shapes.COMMAND_SCAN_WINDOW + "\n" + "t" * shell_shapes.COMMAND_SCAN_WINDOW
    assert shell_shapes.command_from_args("terminal", long) == read


def test_one_check_splits_and_walks_a_command_once_however_many_checks_ask(monkeypatch, tmp_path):
    """Protected paths, the keychain rule and the guard-settings rule all read the same command.
    Its word split and its path arguments are worked out once, so reading the whole command
    (not 8,000 characters of it) does not multiply the cost by the number of checks."""
    from plugins.blackbox.detection.paths import shell_files

    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path))
    shell_files._split.cache_clear()
    shell_files._file_args.cache_clear()
    command = _padding(120_000) + "cat ~/.ssh/id_rsa"
    assert "fileaccess:terminal:user-protected" in _identifiers(command)
    assert shell_files._file_args.cache_info().misses == 1 and shell_files._file_args.cache_info().hits >= 1
    read = shell_shapes.command_from_args("terminal", {"command": command})
    assert len(read) == 2 * shell_shapes.COMMAND_SCAN_WINDOW + 1          # bounded whatever the length


def test_a_remembered_answer_is_a_fresh_list_each_time():
    from plugins.blackbox.detection.paths import shell_files

    first = shell_files.shell_file_args("cat ~/.ssh/id_rsa")
    first.clear()
    assert [arg.path for arg in shell_files.shell_file_args("cat ~/.ssh/id_rsa")] == ["~/.ssh/id_rsa"]
    words = shell_files._words("cat a b")
    words.clear()
    assert shell_files._words("cat a b") == ["cat", "a", "b"]


# --- one reader for "the command of this call" -------------------------------------------------

READS = [
    # (tool, args, the command a shell check reads, the text an install check reads)
    ("terminal", {"command": "pip install a==1"}, "pip install a==1", "pip install a==1"),
    ("terminal", "npm i b@2", "npm i b@2", "npm i b@2"),
    ("terminal", {"note": "x", "other": "pip install c==3"}, "x pip install c==3", "x pip install c==3"),
    ("run_python", {"code": "pip install d==4"}, "", "pip install d==4"),   # not a shell tool
    ("run_python", {"cmd": "pip install e==5"}, "pip install e==5", "pip install e==5"),
    ("write_file", {"path": "a", "content": 7}, "", "a"),
    ("terminal", None, "", ""),
    ("terminal", ["pip", "install"], "", ""),
]


@pytest.mark.parametrize("tool, args, shell_read, install_read", READS)
def test_one_reader_gives_each_check_the_text_it_always_read(tool, args, shell_read, install_read):
    """Shell checks read the command, falling back to all string arguments for shell tools only;
    install checks fall back for every tool (a package can be installed through any tool that
    runs text). Both now come from ``command_from_args``."""
    assert shell_shapes.command_from_args(tool, args) == shell_read
    assert shell_shapes.command_from_args(tool, args, any_tool=True) == install_read


def test_an_install_through_a_tool_that_is_not_a_shell_is_still_seen():
    from plugins.blackbox.detection import ioc_detection

    assert ioc_detection.ioc_context("run_python", {"code": "pip install requests==2.31.0"}) == "in-dependency"
