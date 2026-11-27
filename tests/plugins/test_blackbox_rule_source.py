"""An unknown trust tier never blocks (review 2026-11-26, finding 9, Medium; LES-011).

``_rule_source`` read any tier it did not recognise as ``public`` — verified, blockable — so a rule
tagged with a misspelt or new tier gained the power to block. Unknown is now ``community`` (flag
only); an UNTAGGED rule stays ``public`` (rules built before tier tagging).
"""

from __future__ import annotations

from types import SimpleNamespace

from plugins.blackbox.detection import detect_escalation
from plugins.blackbox.detection.finding import _rule_source


def test_an_unknown_tier_is_community_and_untagged_stays_public():
    assert _rule_source({"source": "verified-ish"}) == "community"
    assert _rule_source({"source": "Public"}) == "public"
    assert _rule_source({}) == "public"


def test_a_match_on_an_unknown_tier_is_not_confirmed():
    rules = SimpleNamespace(escalation=[{"identifier": "esc:x", "toolName": "terminal", "argShape": "rm-rf-system-paths",
                                         "source": "partner"}])
    [finding] = detect_escalation("terminal", {"command": "rm -rf /etc"}, rules)
    assert finding.confirmed is False and finding.source == "community"
