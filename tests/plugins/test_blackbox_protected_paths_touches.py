"""The one protected-path mechanism: does this action touch any of these protected paths, and which.

``detection.paths.protected.touches`` answers for every list of protected places — the person's
own (``detect_custom_fileaccess``), Blackbox's keys (``guard_secrets``) and, next, File Shield's
protected files. Each access form an agent could use is a case here, and every spelling is judged
by the canonical path (LES-105). E2E 2026-11-21 (bb-final-1121) found the gap that made this one
function: Blackbox's helper key was reachable from the shell.
"""

from __future__ import annotations

import os
import sys

import pytest

from _blackbox_loader import load_blackbox

protected = load_blackbox("detection.paths.protected")


@pytest.fixture
def home(monkeypatch, tmp_path):
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "secret.key").write_text("k", encoding="utf-8")
    (vault / "notes.md").write_text("n", encoding="utf-8")
    (tmp_path / "work").mkdir()
    os.symlink(vault, tmp_path / "work" / "shortcut")
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


PATTERN = "~/vault"


def _hit(tool, args, pattern=PATTERN, **kw):
    return protected.touches(tool, args, [pattern], **kw)


@pytest.mark.parametrize("tool,args", [
    ("read_file", {"path": "~/vault/secret.key"}),                                   # a file tool
    ("Read", {"file_path": "$HOME/vault/secret.key"}),
    ("terminal", {"command": "cat ~/vault/secret.key"}),                             # shell readers
    ("terminal", {"command": "head -c 32 \"$HOME/vault/secret.key\""}),
    ("terminal", {"command": "xxd ~/vault/secret.key"}),
    ("terminal", {"command": "base64 < ~/vault/secret.key"}),                         # a redirect
    ("terminal", {"command": "cp ~/vault/secret.key /tmp/k"}),                        # copiers, movers, archivers
    ("terminal", {"command": "mv ~/vault/secret.key /tmp/k"}),
    ("terminal", {"command": "tar czf /tmp/v.tgz ~/vault"}),
    ("terminal", {"command": "zip -r /tmp/v.zip ~/vault"}),
    ("terminal", {"command": "rsync -a ~/vault/ /tmp/v/"}),
    ("terminal", {"command": "tar czf /tmp/home.tgz ~"}),                              # a folder holding it
    ("terminal", {"command": "find ~ -name '*.key' -exec cat {} +"}),
    ("terminal", {"command": "cat ~/vault/*"}),                                       # a wildcard
    ("terminal", {"command": "cd ~/vault && cat secret.key"}),                         # cd + relative
    ("terminal", {"command": "cat ~/work/../vault/secret.key"}),                       # ../
    ("terminal", {"command": "cat ~/work/shortcut/secret.key"}),                       # a link along the way
    ("terminal", {"command": "bash -c 'cat ~/vault/secret.key'"}),                     # a nested shell
    ("terminal", {"command": "python3 -c \"print(open('" + "~/vault/secret.key" + "').read())\""}),
    ("execute_code", {"code": "print(open('/tmp/../' + '" + "x" + "') or open('~/vault/secret.key').read())"}),
    ("mcp__fs__read_text_file", {"path": "~/vault/secret.key"}),                       # an MCP tool's arguments
    ("process", {"action": "start", "command": "cat ~/vault/secret.key"}),             # a shell by another name
])
def test_every_access_form_is_seen(home, tool, args):
    found = _hit(tool, args)
    assert found and found[0].pattern == PATTERN, (tool, args)


def test_case_is_ignored_where_folders_ignore_it(home):
    if sys.platform not in ("darwin", "win32"):
        pytest.skip("folders here are case-sensitive: the other spelling names another folder")
    assert _hit("terminal", {"command": "cat ~/VAULT/Secret.key"})


@pytest.mark.parametrize("tool,args", [
    ("terminal", {"command": "ls ~/vault"}),                                           # a listing reads no file
    ("terminal", {"command": "find ~ -name '*.txt' -exec cat {} +"}),                  # picks no file there
    ("terminal", {"command": "cat ~/work/readme.md"}),
    ("terminal", {"command": "cp ~/work/a.txt ~/vault/"}),                             # writing INTO it is not a read
    ("web_search", {"query": "~/vault/secret.key"}),                                   # a query, not a file access
])
def test_what_does_not_read_a_protected_path(home, tool, args):
    assert _hit(tool, args) == []


def test_it_says_which_paths_and_patterns(home):
    found = protected.touches("terminal", {"command": "cat ~/vault/secret.key ~/.ssh/id_rsa"}, ["~/.ssh/*", PATTERN])
    assert {(touch.path, touch.pattern) for touch in found} == {("~/vault/secret.key", PATTERN), ("~/.ssh/id_rsa", "~/.ssh/*")}
    assert all(touch.mode == "read" for touch in found)


def test_whole_reads_a_long_command_past_the_window(home):
    padding = "echo " + "a" * 70_000
    command = f"{padding}; cat ~/vault/secret.key; {padding}"
    assert _hit("terminal", {"command": command}, whole=True)
