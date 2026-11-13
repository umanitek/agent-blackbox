"""Shadow phase (Refine R15): stages computed and logged on the real network, only MONITOR enforced.

With ``community_shadow: true`` the community tier keeps computing every
stage exactly as it would, records the enforcement it WOULD have applied
(``shadowEnforcement``) and then clamps every community rule to MONITOR, so
nothing community-derived reaches a protected agent; each refresh appends a
:class:`Snapshot` of the §12 metrics. The phase exits on measured data
(thresholds tuned from the log, a curator-labelled sample), never on guesses.

Public surface: :func:`clamp_to_monitor` (the tier applies it),
:func:`build_snapshot` / :func:`write_snapshot` / :func:`latest` /
:func:`read_all`, :func:`calibration_gap` (curator node).
"""

from __future__ import annotations

from typing import Any, Mapping

from .metrics import MAX_SNAPSHOTS, Snapshot, build_snapshot, calibration_gap, latest, read_all, write_snapshot

SHADOW_SUFFIX = " (shadow phase: monitor only)"


def clamp_to_monitor(community: Mapping[str, dict[str, Any]]) -> int:
    """Record the computed enforcement as ``shadowEnforcement`` and set every
    community rule to ``monitor`` (in place); returns how many were clamped
    from ``flag``. Idempotent."""
    clamped = 0
    for rule in community.values():
        computed = str(rule.get("shadowEnforcement") or rule.get("enforcement") or "monitor")
        rule["shadowEnforcement"] = computed
        if rule.get("enforcement") != "monitor":
            rule["enforcement"] = "monitor"
            if not str(rule.get("stageReason") or "").endswith(SHADOW_SUFFIX):
                rule["stageReason"] = f"{rule.get('stageReason') or ''}{SHADOW_SUFFIX}"
            clamped += 1
    return clamped


__all__ = ["MAX_SNAPSHOTS", "SHADOW_SUFFIX", "Snapshot", "build_snapshot", "calibration_gap", "clamp_to_monitor",
           "latest", "read_all", "write_snapshot"]
