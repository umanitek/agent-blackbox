"""Hermes homes are found where Hermes keeps them, not only under ``~/.hermes`` (review 2026-11-26, MED).

Discovery listed the profiles of ``~/.hermes`` only, so a custom or Docker root
(``HERMES_HOME=<root>/profiles/<name>``) and a ``HERMES_DATA_DIR_SUFFIX`` layout lost every other
profile, and a profile Hermes deleted (its tombstone in ``profiles/.deleted/``) was still offered for
protection. These contracts hold:

- under a custom root, the root and each of its profiles are found;
- a profile Hermes marked deleted is never listed, and neither is the tombstone folder itself.
"""

from __future__ import annotations

from pathlib import Path

from plugins.blackbox import attach


def _profile(root: Path, name: str) -> Path:
    home = root / "profiles" / name
    home.mkdir(parents=True)
    (home / "config.yaml").write_text("plugins:\n  enabled: []\n", encoding="utf-8")
    return home


def test_a_custom_root_lists_the_root_and_every_profile(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "person")
    root = tmp_path / "opt" / "data"
    root.mkdir(parents=True)
    (root / "config.yaml").write_text("plugins:\n  enabled: []\n", encoding="utf-8")
    coder, writer = _profile(root, "coder"), _profile(root, "writer")
    monkeypatch.setenv("HERMES_HOME", str(coder))
    homes = attach.discover_hermes_homes()
    assert root in homes and coder in homes and writer in homes


def test_a_profile_hermes_deleted_is_not_listed(tmp_path, monkeypatch):
    person = tmp_path / "person"
    monkeypatch.setattr(Path, "home", lambda: person)
    root = person / ".hermes"
    root.mkdir(parents=True)
    (root / "config.yaml").write_text("plugins:\n  enabled: []\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(root))
    kept, gone = _profile(root, "kept"), _profile(root, "gone")
    (root / "profiles" / ".deleted").mkdir()
    (root / "profiles" / ".deleted" / "gone").write_text("deleted\n", encoding="utf-8")
    homes = attach.discover_hermes_homes()
    assert kept in homes
    assert gone not in homes and root / "profiles" / ".deleted" not in homes
