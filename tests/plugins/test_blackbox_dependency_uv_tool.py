"""``uv tool install pkg==ver`` (and ``uv tool run``) is read as the install it is, so the package
is checked like any other (KI-663, Linux round L1: REAL Claude Code's ``uv tool install
six==1.17.0`` was allowed with a verified rule listing it — only pip's PEP 668 error stopped it).
"""

from __future__ import annotations

import pytest

from plugins.blackbox.detection import action_parsing


@pytest.mark.parametrize("command, packages", [
    ("uv tool install six==1.17.0", [{"ecosystem": "pypi", "name": "six", "version": "1.17.0"}]),
    ("uv tool install --force ruff", [{"ecosystem": "pypi", "name": "ruff", "version": ""}]),
    ("cd x && uv tool install six==1.17.0 && echo ok", [{"ecosystem": "pypi", "name": "six", "version": "1.17.0"}]),
    ("uv tool run cowsay hello world", [{"ecosystem": "pypi", "name": "cowsay", "version": ""}]),
])
def test_uv_tool_installs_name_their_package(command, packages):
    assert action_parsing.parse_dependency_installs(command) == packages


@pytest.mark.parametrize("command", ["uv tool list", "uv tool uninstall six", "uv tool dir", "uv sync"])
def test_uv_tool_looks_and_removals_install_nothing(command):
    assert action_parsing.parse_dependency_installs(command) == []
