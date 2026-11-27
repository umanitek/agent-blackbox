"""A sensitive path is sensitive in every spelling (review 2026-11-26, finding 8, Medium).

``sensitive_path_category`` matched the path as written, so a Windows path, a doubled slash, a
``/./`` and macOS's ``/private`` alias of ``/etc`` all fell through; it now reads the canonical
path (LES-105) and keeps the template exclusions.
"""

from __future__ import annotations

import pytest

from plugins.blackbox.detection.action_parsing import sensitive_path_category


@pytest.mark.parametrize("path, category", [
    ("C:\\Users\\a\\.ssh\\id_rsa", "ssh-private-key"),
    ("C:\\proj\\.env", "env-file"),
    ("/etc//shadow", "system-shadow"),
    ("/etc/./shadow", "system-shadow"),
    ("/private/etc/sudoers", "system-shadow"),
    ("~/.aws//credentials", "credentials"),
])
def test_every_spelling_has_its_category(path, category):
    assert (sensitive_path_category(path) or {}).get("category") == category


@pytest.mark.parametrize("path", ["C:\\proj\\.env.example", "~/.ssh//config", "/private/tmp/notes.txt"])
def test_templates_and_ordinary_files_stay_unflagged(path):
    assert sensitive_path_category(path) is None
