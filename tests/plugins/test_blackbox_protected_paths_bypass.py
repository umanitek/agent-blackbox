"""KI-470/471/472: routes around the protected-path rule found by a text-only probe (2026-11-06).

In block mode, with a canary ``server.key`` protected by ``*.key``, three reads went through:

- KI-470: Hermes's ``execute_code`` tool running Python that opens the key (the rule read only file
  tools and terminal commands; the same code through ``python3 -c`` was already caught);
- KI-471: a wildcard (``cd ~/folder && cat server.k*``) — the pattern was matched against the word
  as written, never the files it expands to;
- KI-472: a link (``ln -s KEY /tmp/y && cat /tmp/y``) — creating the link was not access, and the
  link's own name matches nothing.
"""

from __future__ import annotations

import os

import pytest

from plugins.blackbox.detection import detect_custom_fileaccess
from plugins.blackbox.kernel.config import DEFAULT_PROTECTED_PATHS


@pytest.fixture
def key_folder(tmp_path):
    folder = tmp_path / "canary"
    folder.mkdir()
    (folder / "server.key").write_text("not a real key\n", encoding="utf-8")
    (folder / "notes.txt").write_text("plain notes\n", encoding="utf-8")
    return folder


def _found(tool, args):
    return bool(detect_custom_fileaccess(tool, args, DEFAULT_PROTECTED_PATHS))


def test_ki470_execute_code_opening_a_protected_file_is_found(key_folder):
    assert _found("execute_code", {"code": f"print(open('{key_folder}/server.key').read())"})


def test_ki470_execute_code_on_an_ordinary_file_is_left_alone(key_folder):
    assert not _found("execute_code", {"code": f"print(open('{key_folder}/notes.txt').read())"})


@pytest.mark.parametrize("command", [
    "cd {folder} && cat server.k*",
    "cat {folder}/server.?ey",
    "cat {folder}/*",
])
def test_ki471_a_wildcard_is_checked_against_the_files_it_expands_to(key_folder, command):
    assert _found("terminal", {"command": command.format(folder=key_folder)})


def test_ki471_a_wildcard_matching_only_ordinary_files_is_left_alone(key_folder):
    assert not _found("terminal", {"command": f"cat {key_folder}/notes.*"})


def test_ki471_a_wildcard_naming_a_protected_name_is_found_without_the_disk():
    """``.env*`` reaches ``.env`` wherever the agent is; nothing on disk needs to exist."""
    assert _found("terminal", {"command": "cat .env*"})


def test_ki472_making_a_link_to_a_protected_file_is_found(key_folder):
    assert _found("terminal", {"command": f"ln -s {key_folder}/server.key /tmp/y && cat /tmp/y"})


def test_ki472_reading_an_existing_link_is_checked_against_where_it_points(key_folder, tmp_path):
    link = tmp_path / "innocent-name"
    os.symlink(key_folder / "server.key", link)
    assert _found("terminal", {"command": f"cat {link}"})
    assert _found("read_file", {"path": str(link)})


def test_ki472_a_link_to_an_ordinary_file_is_left_alone(key_folder, tmp_path):
    link = tmp_path / "notes-link"
    os.symlink(key_folder / "notes.txt", link)
    assert not _found("terminal", {"command": f"cat {link}"})
    assert not _found("terminal", {"command": f"ln -s {key_folder}/notes.txt /tmp/n"})
