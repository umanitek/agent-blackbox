"""DKG runtime compatibility required by Blackbox recovery."""

from __future__ import annotations

import sys
from typing import Sequence


MINIMUM_DKG_VERSION = (10, 0, 9)
MINIMUM_DKG_VERSION_TEXT = ".".join(str(part) for part in MINIMUM_DKG_VERSION)


def parse_dkg_version(raw: str) -> tuple[int, int, int] | None:
    """Parse the numeric core of an npm semantic version."""
    core = str(raw or "").strip().split("-", 1)[0].split("+", 1)[0]
    parts = core.split(".")
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        return None
    return (int(parts[0]), int(parts[1]), int(parts[2]))


def supports_direct_vm_sync(raw: str) -> bool:
    """Return whether a DKG release contains direct chain-name verification."""
    parsed = parse_dkg_version(raw)
    return parsed is not None and parsed >= MINIMUM_DKG_VERSION


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        return 2
    return 0 if supports_direct_vm_sync(args[0]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
