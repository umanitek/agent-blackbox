"""Blackbox's release number and changelog stay one true story (plugins/blackbox/CHANGELOG.md).

Found 2026-11-04 while preparing the first Hermes plugin-catalog update: plugin.yaml had said 1.0.0
since the catalog took Blackbox in, while kernel/constants.py `__version__` (what the dashboard,
`attach` and setup show) had said 1.1.0 since 2026-09-21 — one build, two numbers, and a release
number that never moved with 108 changes. These tests hold the rules the changelog's "How a release
is made" section states:

- plugin.yaml `version` (what Hermes and its catalog show) equals `__version__`;
- the version is plain SemVer MAJOR.MINOR.PATCH (the catalog quotes it as a label);
- CHANGELOG.md keeps an [Unreleased] section first, then dated releases newest first with
  strictly falling numbers, and the current version is the newest release;
- every release heading has a link reference at the bottom (Keep a Changelog: linkable versions).

Stdlib only; reads source text, never imports the plugin.
"""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path

PLUGIN = Path(__file__).resolve().parents[2] / "plugins" / "blackbox"
CHANGELOG = (PLUGIN / "CHANGELOG.md").read_text(encoding="utf-8-sig")
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
# "## [Unreleased]" or "## [1.2.0] - 2026-11-04" (optionally " [YANKED]", per Keep a Changelog)
HEADING = re.compile(r"^## \[(?P<name>[^\]]+)\](?: - (?P<day>\d{4}-\d{2}-\d{2}))?(?P<yanked> \[YANKED\])?\s*$",
                     re.MULTILINE)


def _manifest_version() -> str:
    match = re.search(r'^version:\s*"([^"]+)"', (PLUGIN / "plugin.yaml").read_text(encoding="utf-8-sig"),
                      re.MULTILINE)
    assert match is not None, "plugin.yaml has no quoted `version:`"
    return match.group(1)


def _code_version() -> str:
    match = re.search(r'^__version__ = "([^"]+)"$', (PLUGIN / "kernel" / "constants.py").read_text(
        encoding="utf-8-sig"), re.MULTILINE)
    # attach/plugin_copy.py reads this line from installed copies as text: a plain one-line literal.
    assert match is not None, "kernel/constants.py has no plain `__version__ = \"X.Y.Z\"` line"
    return match.group(1)


def _releases() -> list[tuple[tuple[int, int, int], str]]:
    """``((major, minor, patch), day)`` for each release heading, in file order."""
    found = []
    for heading in HEADING.finditer(CHANGELOG):
        if heading["name"] == "Unreleased":
            continue
        version = SEMVER.match(heading["name"])
        assert version is not None, f"release heading is not MAJOR.MINOR.PATCH: {heading.group(0)}"
        assert heading["day"], f"release {heading['name']} has no date"
        found.append((tuple(int(part) for part in version.groups()), heading["day"]))
    return found


def test_the_plugin_has_one_version():
    assert _manifest_version() == _code_version()


def test_the_version_is_semver():
    assert SEMVER.match(_manifest_version()), _manifest_version()


def test_unreleased_comes_first():
    first = HEADING.search(CHANGELOG)
    assert first is not None and first["name"] == "Unreleased"


def test_releases_run_newest_first_with_real_dates():
    releases = _releases()
    assert releases, "CHANGELOG.md has no release"
    numbers = [number for number, _ in releases]
    assert numbers == sorted(numbers, reverse=True) and len(set(numbers)) == len(numbers), numbers
    days = [date.fromisoformat(day) for _, day in releases]
    assert days == sorted(days, reverse=True), days


def test_the_current_version_is_the_newest_release():
    newest, _ = _releases()[0]
    assert ".".join(map(str, newest)) == _manifest_version()


def test_every_release_is_linkable():
    for heading in HEADING.finditer(CHANGELOG):
        assert re.search(rf"^\[{re.escape(heading['name'])}\]: https://", CHANGELOG, re.MULTILINE), \
            f"no link reference for [{heading['name']}]"
