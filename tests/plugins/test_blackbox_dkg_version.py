"""Behavioral tests for the Blackbox DKG runtime gate."""

from __future__ import annotations

import pytest

from plugins.blackbox import dkg_version


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("10.0.8", False),
        ("10.0.9", True),
        ("10.0.9-rc.1", True),
        ("10.0.10", True),
        ("11.0.0", True),
        ("not-a-version", False),
        ("10.0", False),
    ],
)
def test_direct_vm_runtime_gate(version: str, expected: bool) -> None:
    assert dkg_version.supports_direct_vm_sync(version) is expected


def test_runtime_gate_cli_exit_status() -> None:
    assert dkg_version.main(["10.0.8"]) == 1
    assert dkg_version.main(["10.0.9"]) == 0
    assert dkg_version.main([]) == 2
