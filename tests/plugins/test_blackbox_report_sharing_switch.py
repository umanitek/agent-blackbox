"""Turning community sharing on and off from the command line and the dashboard (KI-299).

Sharing is OPT-IN (2026-10-16): off on a fresh install. `--enable-sharing` and the
dashboard toggle are the two ways in — each records the acceptance and sets
`report: true`; after an opt-out (`--withdraw-consent`) they are the opt-back-in.
`--disable-sharing` sets `report: false`. `--consent` records an acceptance and
says plainly whether the `report` switch is on.
"""

from __future__ import annotations

import argparse

from plugins.blackbox.community.report_cli import report_command, report_rights
from plugins.blackbox.kernel.config import load_blackbox_config


def _parse(*argv: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    report_command.add_report_parser(sub)
    return parser.parse_args(["report", *argv])


def test_enable_sharing_turns_report_on_when_consent_is_in_force(real_consent, capsys):
    real_consent.record()

    code = report_command.cmd_report(_parse("--enable-sharing"))

    assert code == 0 and load_blackbox_config().report is True
    assert "sharing is on" in capsys.readouterr().out.lower()


def test_enable_sharing_after_an_opt_out_opts_back_in(real_consent, capsys):
    real_consent.withdraw()

    code = report_command.cmd_report(_parse("--enable-sharing"))

    assert code == 0 and load_blackbox_config().report is True and real_consent.in_force()
    assert "sharing is on" in capsys.readouterr().out.lower()


def test_disable_sharing_turns_report_off(real_consent):
    real_consent.record()
    report_command.cmd_report(_parse("--enable-sharing"))

    code = report_command.cmd_report(_parse("--disable-sharing"))

    assert code == 0 and load_blackbox_config().report is False


def test_consent_says_plainly_that_sharing_is_still_off_and_how_to_turn_it_on(real_consent, capsys):
    report_command.cmd_report(_parse("--disable-sharing"))
    capsys.readouterr()

    code = report_rights.record_consent()

    out = capsys.readouterr().out
    assert code == 0
    assert "still off" in out.lower() and "blackbox report --enable-sharing" in out


def test_consent_when_sharing_is_already_on_says_so(real_consent, capsys):
    real_consent.record()
    report_command.cmd_report(_parse("--enable-sharing"))
    capsys.readouterr()

    report_rights.record_consent()

    assert "sharing is on" in capsys.readouterr().out.lower()


def test_the_new_options_are_not_stored_under_a_name_hermes_reads_first():
    """LES-035: Hermes reads version / yolo / oneshot / command before dispatch."""
    args = _parse("--enable-sharing", "--disable-sharing")
    assert args.enable_sharing is True and args.disable_sharing is True
    assert not {"version", "yolo", "oneshot", "command"} & set(vars(args))   # KI-276 fixed: no option uses them


# ---- the switch never reads "on" over a withdrawn consent (2026-10-15 dashboard audit) ----


def test_withdraw_consent_also_turns_the_sharing_switch_off(real_consent):
    real_consent.record()
    report_command.cmd_report(_parse("--enable-sharing"))

    code = report_command.cmd_report(_parse("--withdraw-consent"))

    assert code == 0 and not real_consent.in_force() and load_blackbox_config().report is False


def test_the_dashboard_shows_sharing_off_and_a_later_save_does_not_opt_back_in(real_consent, monkeypatch, tmp_path):
    # A machine opted out BEFORE this fix: consent withdrawn, but `report: true` still in config.
    import pytest
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from plugins.blackbox.dashboard import server

    real_consent.record()
    report_command.cmd_report(_parse("--enable-sharing"))
    real_consent.withdraw()                                  # the old --withdraw-consent left report on
    assert load_blackbox_config().report is True
    monkeypatch.setenv("HOME", str(tmp_path))                # agent discovery must not see the real ~/.hermes
    with TestClient(server.create_app(), base_url="http://127.0.0.1:9700") as client:
        view = client.get("/api/settings").json()
        token = {"X-Blackbox-Token": client.get("/api/session").json()["token"]}
        assert view["report"] is False                       # the toggle reads off
        saved = client.post("/api/settings", json={"mode": "block", "report": view["report"]}, headers=token)

    assert saved.status_code == 200
    assert not real_consent.in_force()                       # an unrelated save did not opt the operator back in


def test_the_threat_sharing_tile_reads_off_over_a_withdrawn_consent(real_consent, monkeypatch):
    import dataclasses
    from types import SimpleNamespace
    from plugins.blackbox import community
    from plugins.blackbox.dashboard import community_routes
    from plugins.blackbox.kernel import config as kernel_config

    cfg = dataclasses.replace(load_blackbox_config(), report=True, context_graph_id="0xowner/agent-blackbox-vm")
    assert cfg.community_enabled                             # the switch alone says "on"
    monkeypatch.setattr(kernel_config, "load_blackbox_config", lambda: cfg)
    monkeypatch.setattr(community, "read_join_state", lambda client, graph: None)   # no node in tests
    monkeypatch.setattr(community, "contributing_agent_count", lambda reports: 0)
    real_consent.withdraw()

    stats = community_routes.community_stats_payload(lambda cfg: SimpleNamespace())

    assert stats["sharing_enabled"] is False


def test_a_fresh_install_shares_nothing_until_enable_sharing(real_consent, capsys):
    assert load_blackbox_config().report is False and real_consent.current() is None   # the opt-in default

    code = report_command.cmd_report(_parse("--enable-sharing"))

    assert code == 0 and load_blackbox_config().report is True and real_consent.in_force()
    assert real_consent.current().accepted_at                                          # the acceptance is recorded


def test_the_dashboard_toggle_records_the_opt_in_and_other_saves_do_not(real_consent, monkeypatch, tmp_path):
    import pytest
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from plugins.blackbox.dashboard import server

    monkeypatch.setenv("HOME", str(tmp_path))                # agent discovery must not see the real ~/.hermes
    with TestClient(server.create_app(), base_url="http://127.0.0.1:9700") as client:
        token = {"X-Blackbox-Token": client.get("/api/session").json()["token"]}
        assert client.get("/api/settings").json()["report"] is False                   # a fresh install reads off
        assert client.post("/api/settings", json={"mode": "block"}, headers=token).status_code == 200
        assert real_consent.current() is None                                           # an unrelated save records nothing
        assert client.post("/api/settings", json={"report": True}, headers=token).status_code == 200
        assert client.get("/api/settings").json()["report"] is True

    assert real_consent.in_force() and load_blackbox_config().report is True            # the toggle is the opt-in
