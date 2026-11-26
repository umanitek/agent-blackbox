"""The refusal names what refused: the threat graph only for graph matches (E2E recheck 2026-11-21:
the person's own protected-path rule was reported as a threat-graph match)."""

from plugins.blackbox.detection import Finding
from plugins.blackbox.guard import reporting


def _finding(source: str, matched: str = "") -> Finding:
    return Finding(identifier=f"x:{source}:{matched}", category="fileaccess", severity="critical", title="t",
                   tool_name="terminal", matched=matched, evidence="e", confirmed=source == "public", source=source)


def test_a_graph_match_says_threat_graph():
    text = reporting.blackbox_block_message([_finding("public")])
    assert "it matched 1 known threat in the threat graph" in text


def test_the_persons_protected_path_rule_is_named_as_theirs():
    text = reporting.blackbox_block_message([_finding("custom", "user-protected")])
    assert "your protected-path rule" in text and "threat graph" not in text


def test_self_protection_is_named_and_mixed_reasons_are_both_said():
    alone = reporting.blackbox_block_message([_finding("custom", "blackbox-settings")])
    assert "Blackbox's self-protection" in alone and "threat graph" not in alone
    both = reporting.blackbox_block_message([_finding("public"), _finding("secret")])
    assert "1 known threat in the threat graph and Blackbox's built-in secret protection" in both
