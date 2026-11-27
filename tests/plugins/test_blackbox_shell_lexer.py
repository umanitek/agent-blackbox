"""The ONE shell lexer (``detection/command_line/lexer``) reads every spelling of a path as the shell does.

Review 2026-11-26 (findings 1, 2 and 13), each probed red on the base:

* finding 1 (Critical): one Windows path ANYWHERE on a line switched quote handling off for every
  other word, so ``echo C:\\x; cat ~/.s"s"h/id_rsa`` read ``~/.s"s"h/id_rsa`` and matched nothing;
* finding 2 (High): brace expansion, ``${HOME:-x}``, ``$(echo ~)`` / backticks and ``( … )``
  subshells were read as written, so the same protected file passed under each spelling;
  what can not be expanded is marked undecidable (File Shield's flag);
* finding 13: PowerShell tool calls are shell commands, split with per-word Windows paths.
"""

from __future__ import annotations

import pytest

from plugins.blackbox.detection import SHELL_TOOLS, builds_hidden_command, detect_persistence_write, protected_path_touches
from plugins.blackbox.detection.paths.shell_words import _words as words

SSH = ["~/.ssh/*"]


@pytest.mark.parametrize("command", [
    'echo C:\\x; cat ~/.s"s"h/id_rsa',            # finding 1: a Windows word elsewhere on the line
    "type C:\\notes.txt & cat ~/.ss''h/id_rsa",
    "cat ~/.s{s,}h/id_rsa",                        # finding 2: brace alternatives
    "cat ~/.{ssh,x}/id_rsa",
    "cat ${HOME:-x}/.ssh/id_rsa",                  # a default on the home variable
    "cat ${NOPE:-~}/.ssh/id_rsa",                  # an unset variable's default
    "cat $(echo ~)/.ssh/id_rsa",                   # a substitution that prints the home folder
    "cat `echo $HOME`/.ssh/id_rsa",
    "(cd ~ && cat .ssh/id_rsa)",                   # a subshell
    "echo a#b; cat ~/.ssh/id_rsa",                 # ``#`` inside a word is no comment
])
def test_every_spelling_of_a_protected_file_is_the_file(command):
    assert protected_path_touches("terminal", {"command": command}, SSH)


@pytest.mark.parametrize("command", [
    "echo k >> ~/.s{s,}h/authorized_keys",
    "echo C:\\x; echo k >> ~/.ss''h/authorized_keys",
])
def test_a_persistence_write_is_found_under_any_spelling(command):
    assert detect_persistence_write("terminal", {"command": command})


def test_windows_paths_keep_their_backslashes_and_posix_words_their_quoting():
    assert words('type C:\\Users\\a\\x.txt "C:\\Program Files\\y" ~/a\\ b \'q\'"r"') == [
        "type", "C:\\Users\\a\\x.txt", "C:\\Program Files\\y", "~/a b", "qr"]
    assert words(r"cp f{,.bak} && find . -exec cat {} \;") == ["cp", "f", "f.bak", "&&", "find", ".", "-exec", "cat", "{}", ";"]


def test_what_can_not_be_expanded_is_undecidable_and_what_can_is_not():
    assert builds_hidden_command("cat ${HOME%/*}/me/.ssh/id_rsa")
    assert builds_hidden_command("cat ~/.ssh/id_{1..100000}")
    assert not builds_hidden_command("cat ${HOME:-x}/.ssh/id_rsa")
    assert not builds_hidden_command("cat $(echo ~)/.ssh/id_rsa")


def test_powershell_calls_are_shell_commands():
    assert {"powershell", "pwsh"} <= SHELL_TOOLS
    assert protected_path_touches("pwsh", {"command": "Get-Content ~/.ssh/id_rsa"}, SSH)


def test_one_huge_word_is_read_in_linear_time():
    """CI, 2026-11-27 (1.7.0 PR): a 900,000-character call of nested JSON — one word with 300,000
    quotes and 150,000 braces — hung the hook past CI's 300 s limit. The Windows-path checks re-joined
    the whole word at every quote, and brace expansion rescanned to its end for every ``{``. Both now
    read a bounded tail / pair the braces in one pass. Bound generous: the quadratic version took minutes."""
    import time

    from plugins.blackbox.detection.command_line import lexer

    word = '{"a":' * 150_000 + "1" + "}" * 150_000
    started = time.monotonic()
    lexer.split_words("echo " + word)
    assert time.monotonic() - started < 20


@pytest.mark.parametrize(("command", "word"), [
    ('cat "C:\\Program Files\\x"', "C:\\Program Files\\x"),        # a Windows path inside quotes keeps its backslashes
    ("cat " + "a" * 600 + '-"C:\\x"', "a" * 600 + "-C:\\x"),         # after a long stretch of the same word (the cut tail)
    ('cat "a\\"b"', 'a"b'),                                          # elsewhere, the shell's own escapes
])
def test_windows_paths_are_still_told_from_shell_escapes(command, word):
    from plugins.blackbox.detection.command_line import lexer

    assert lexer.split_words(command)[1] == word
