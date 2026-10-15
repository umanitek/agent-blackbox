"""Merge operator-wallet findings without duplicating stronger detections."""
from typing import Any
from .. import detection, shields
from ..kernel import constants


def own_key_findings(raw: list[detection.Finding], tool_name: str, args: Any) -> list[detection.Finding]:
    """Raw keys of the operator's own listed addresses (Trader Shield), unless the
    labelled-key rule already raised the same finding at least as high."""
    found = detection.detect_own_wallet_keys(tool_name, args, lambda: shields.get("trader").mode().options["addresses"])
    rank = constants.SEVERITY_RANK
    have = max((rank.get(f.severity, -1) for f in raw if f.identifier == "secret:wallet-private-key"), default=-1)
    return [f for f in found if rank.get(f.severity, -1) > have]
