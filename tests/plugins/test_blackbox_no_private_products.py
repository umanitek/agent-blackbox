"""The public core names no private product (LES-121, the project's Safety rule, 2026-11-22).

Blackbox's own tracked files — the plugin, its tests, the Blackbox installers, the OpenClaw
bridge, Blackbox's README and docs — speak only of generic "add-ons" (registered beside the
plugin through the extension point) and "companion apps". They never name a private product,
its package or link scheme, its download page, its private documents or how it works inside.
Hermes-owned paths (the Hermes host this repository forks, ``apps/desktop`` among them) are not
Blackbox's and are not read.

WHY the patterns are built from pieces: the repository is public, so this file must not carry
the very words it keeps out. Each forbidden form is assembled at import time.

Contracts:
- no forbidden form appears in any of Blackbox's own tracked files;
- each forbidden form is caught (a sample of each, assembled the same way, matches);
- the forms that are fine — the public Hermes Desktop app, Docker Desktop, Remote Desktop, a
  wallet's "Desktop app" label, the ``~/Desktop`` folder, a "desktop session" — do not match.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

#: Blackbox's own files (git pathspecs). Everything else in the repository is the Hermes host.
OWN_PATHS = (
    "plugins/blackbox",
    "tests/plugins/test_blackbox_*",
    "tests/plugins/fixtures/shields_api_payload.json",
    "tests/plugins/architecture_baseline.json",
    "tests/test_blackbox_*",
    "scripts/blackbox-install.sh",
    "scripts/blackbox-install.ps1",
    "scripts/blackbox-readme-inventory.py",
    "integrations/openclaw",
    "README.md",
    "docs",
)
#: Folders never read when the tree is walked without git (build output, caches).
SKIPPED_FOLDERS = frozenset({"__pycache__", "node_modules", "target", ".venv", ".pytest_cache"})

# The pieces. Joined, they spell what the public files must not.
_BRAND = "black" + "box"
_PRODUCTS = ("desk" + "top", "enter" + "prise", "fle" + "et")
_APP = "Desk" + "top"

#: (name, pattern) — each one form that names a private product or describes its insides.
FORBIDDEN: tuple[tuple[str, re.Pattern[str]], ...] = (
    # the product names, their package names and their link scheme (brand + separator + product)
    ("product name", re.compile(_BRAND + r"[ _-]?(?:" + "|".join(_PRODUCTS) + ")", re.IGNORECASE)),
    # the private servers' names
    ("private server", re.compile(r"\b(?:" + _PRODUCTS[1] + "|" + _PRODUCTS[2] + r")[ _-]core\b", re.IGNORECASE)),
    # the app's add-on, named by the app
    ("named add-on", re.compile(_PRODUCTS[0] + r"[ -]add-?on", re.IGNORECASE)),
    # the app's download page
    ("download page", re.compile(r"command\.com/" + _PRODUCTS[0], re.IGNORECASE)),
    # a private document's path
    ("private document", re.compile(r"docs/security/" + "appro" + r"vals\.md", re.IGNORECASE)),
    # how the app's collector works inside
    ("collector internals", re.compile(r"250\s?ms[^\n]{0,40}collector|collector[^\n]{0,40}250\s?ms", re.IGNORECASE)),
    # the app by its short name: a capitalised word that is not one of the public apps of that
    # name, not a wallet's "<word> app" label (a quoted or "·"-joined label) and not a folder path
    ("short name", re.compile(r"(?<![\w~/.])(?<!Hermes )(?<!Docker )(?<!Remote )(?<!Jump )(?<!Windows )"
                              r"(?<!\")(?<!· )" + _APP + r"\b(?!/)")),
)


def _own_files() -> list[Path]:
    """Blackbox's own tracked files (git), or the same paths walked when there is no git."""
    try:
        listed = subprocess.run(["git", "ls-files", "-z", "--", *OWN_PATHS], cwd=ROOT, capture_output=True,
                                check=True, timeout=60).stdout.decode("utf-8").split("\0")
        return [ROOT / name for name in listed if name]
    except (OSError, subprocess.SubprocessError):
        found: list[Path] = []
        for spec in OWN_PATHS:
            for top in ROOT.glob(spec):
                if top.is_file():
                    found.append(top)
                    continue
                for folder, subfolders, names in os.walk(top):
                    subfolders[:] = [name for name in subfolders if name not in SKIPPED_FOLDERS]
                    found += [Path(folder) / name for name in names]
        return found


def _mentions(text: str) -> list[tuple[int, str]]:
    return [(number, name) for number, line in enumerate(text.splitlines(), 1)
            for name, pattern in FORBIDDEN if pattern.search(line)]


def test_blackboxs_own_files_name_no_private_product():
    files = _own_files()
    assert len(files) > 500, "the file list is Blackbox's whole tree"
    offending = []
    for path in files:
        try:
            text = path.read_bytes().decode("utf-8", errors="ignore")
        except OSError:
            continue
        offending += [f"{path.relative_to(ROOT)}:{number}: {name}" for number, name in _mentions(text)]
    assert not offending, "the public core must name no private product:\n" + "\n".join(offending[:50])


@pytest.mark.parametrize("sample", [
    _BRAND.capitalize() + " " + _APP,
    _BRAND + "_" + _PRODUCTS[0],
    _BRAND + "-" + _PRODUCTS[0] + "://open",
    _BRAND.capitalize() + " " + _PRODUCTS[1].capitalize(),
    _BRAND.capitalize() + " " + _PRODUCTS[2].capitalize(),
    _PRODUCTS[1].capitalize() + " Core",
    _PRODUCTS[2] + " core",
    "the " + _APP + " add-on",
    "https://" + _BRAND + "command.com/" + _PRODUCTS[0] + "/download/macos",
    "see docs/security/" + "appro" + "vals.md",
    "its 2" + "50 ms live collector",
    "without " + _APP + " installed",
    _APP + "'s engine",
    "the " + _APP + " app's key",
])
def test_each_forbidden_form_is_caught(sample):
    assert _mentions(sample), sample


@pytest.mark.parametrize("sample", [
    "Blackbox inside Hermes " + _APP + ": the page it shows",
    "Hermes " + _APP + "'s 30 s request limit",
    "opening someone's Docker " + _APP,
    "Remote " + _APP + " and file sharing",
    "Chrome Remote" + _APP + "Host.app",
    '"label": "' + _APP + ' app"',
    "Electrum · " + _APP + " app",
    "cp notes.md ~/" + _APP,
    "the person's desktop session",
    "an add-on registered beside the plugin, or a companion app",
])
def test_the_public_forms_are_left_alone(sample):
    assert not _mentions(sample), sample
