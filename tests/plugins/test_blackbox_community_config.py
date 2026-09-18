"""B2 contract: the community graph gets an address and a real switch.

Covers the config layer of the community-graph build: precedence of the
``community_graph_id`` resolution (env → config entry → shipped default),
the ``community_enabled`` single-gate truth table, the live ``report`` /
``daily_report_limit`` keys (KI-002), the empty-default launch-safety rule
(KI-035), and the report-threshold severity edges.
"""

from __future__ import annotations

import pytest

from plugins.blackbox import config as bb_config
from plugins.blackbox import constants


DEV_GRAPH = "0x51E5dE758A45c8b64048E29918421F0bdD6D5d5C/agent-blackbox-community-dev"


@pytest.fixture
def clean_env(monkeypatch):
    """Blank every Blackbox env override so precedence tests start neutral."""
    for var in (
        "BLACKBOX_REPORT",
        "BLACKBOX_COMMUNITY_GRAPH_ID",
        "BLACKBOX_DAILY_REPORT_LIMIT",
        "BLACKBOX_REPORT_MIN_SEVERITY",
    ):
        monkeypatch.delenv(var, raising=False)
    return monkeypatch


def _load_with_entry(monkeypatch, entry):
    monkeypatch.setattr(bb_config, "_blackbox_entry", lambda: dict(entry))
    return bb_config.load_blackbox_config()


# ---------------------------------------------------------------------------
# community_graph_id precedence: env wins, entry second, default third
# ---------------------------------------------------------------------------


def test_env_override_wins_over_entry(clean_env):
    clean_env.setenv("BLACKBOX_COMMUNITY_GRAPH_ID", DEV_GRAPH)
    cfg = _load_with_entry(clean_env, {"community_graph_id": "0xother/graph"})
    assert cfg.community_graph_id == DEV_GRAPH


def test_entry_wins_over_default(clean_env):
    cfg = _load_with_entry(clean_env, {"community_graph_id": DEV_GRAPH})
    assert cfg.community_graph_id == DEV_GRAPH


def test_default_is_shipped_constant(clean_env):
    cfg = _load_with_entry(clean_env, {})
    assert cfg.community_graph_id == constants.DEFAULT_COMMUNITY_GRAPH_ID


def test_shipped_default_is_empty_until_production_graph_exists(clean_env):
    """KI-035 launch-safety rule: a release must never point the fleet at a
    dev graph. Until the production graph id lands here, the default MUST be
    empty — which keeps community_enabled False by construction."""
    assert constants.DEFAULT_COMMUNITY_GRAPH_ID == ""


# ---------------------------------------------------------------------------
# community_enabled truth table — the single gate every write path uses
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("report", "graph_id", "expected"),
    [
        (True, DEV_GRAPH, True),
        (True, "", False),  # no address → dormant, even with sharing on
        (True, "   ", False),  # whitespace is not an address
        (False, DEV_GRAPH, False),  # operator off-switch is absolute
        (False, "", False),
    ],
)
def test_community_enabled_truth_table(report, graph_id, expected):
    cfg = bb_config.BlackboxConfig(report=report, community_graph_id=graph_id)
    assert cfg.community_enabled is expected


# ---------------------------------------------------------------------------
# report + daily_report_limit are LIVE keys (KI-002 part 1)
# ---------------------------------------------------------------------------


def test_report_key_is_live_from_entry(clean_env):
    cfg = _load_with_entry(clean_env, {"report": True})
    assert cfg.report is True


def test_report_env_override_wins(clean_env):
    clean_env.setenv("BLACKBOX_REPORT", "true")
    cfg = _load_with_entry(clean_env, {"report": False})
    assert cfg.report is True


def test_report_defaults_off(clean_env):
    cfg = _load_with_entry(clean_env, {})
    assert cfg.report is False


def test_daily_report_limit_has_real_default(clean_env):
    cfg = _load_with_entry(clean_env, {})
    assert cfg.daily_report_limit == constants.DEFAULT_DAILY_REPORT_LIMIT
    assert cfg.daily_report_limit > 0


def test_daily_report_limit_configurable_and_never_negative(clean_env):
    assert _load_with_entry(clean_env, {"daily_report_limit": 5}).daily_report_limit == 5
    assert _load_with_entry(clean_env, {"daily_report_limit": -3}).daily_report_limit == 0


# ---------------------------------------------------------------------------
# report threshold severity edges
# ---------------------------------------------------------------------------


def test_report_threshold_exactly_at_floor():
    cfg = bb_config.BlackboxConfig(report_min_severity="high")
    assert cfg.meets_report_threshold("high") is True


def test_report_threshold_below_floor():
    cfg = bb_config.BlackboxConfig(report_min_severity="high")
    assert cfg.meets_report_threshold("medium") is False


def test_report_threshold_above_floor_and_unknown():
    cfg = bb_config.BlackboxConfig(report_min_severity="high")
    assert cfg.meets_report_threshold("critical") is True
    assert cfg.meets_report_threshold("nonsense") is False
