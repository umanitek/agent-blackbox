"""The mode Blackbox reports is never a guess (KI-PENDING-b28f8f, agents campaign pass 3,
2026-11-22: a companion app's Overview said "Audit mode … nothing is blocked yet" while ``blackbox status``
said block and blocks were recorded — the settings could not be read during a dashboard restart,
and the defaults were served as the person's settings).

Contracts: before the saved settings were ever read in this process, every status answer says
``starting`` (``/api/settings`` with ``starting: true``, the Hermes Desktop status, the findings and audit
routes) — never "audit"; once they were read, a read that fails keeps the last good settings, so
Block stays Block (for the answers AND the guard); Hermes' stand-in for an unreadable file counts
as unread.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from plugins.blackbox import desktop
from plugins.blackbox.dashboard import server
from plugins.blackbox.kernel import config, settings
from plugins.blackbox.kernel.config_values import saved_entry


@pytest.fixture(autouse=True)
def _fresh():
    saved_entry.forget()
    yield
    saved_entry.forget()


def _reads(monkeypatch, *answers):
    queue = list(answers)
    monkeypatch.setattr(saved_entry, "_read_now", lambda: queue.pop(0) if len(queue) > 1 else queue[0])


def test_before_the_settings_were_read_every_status_answer_says_starting(monkeypatch):
    _reads(monkeypatch, None)                                     # the config cannot be read yet
    assert settings.read_settings()["mode"] == "starting" and settings.read_settings()["starting"] is True
    assert desktop.status_payload()["mode"] == "starting"
    client = TestClient(server.create_app(), base_url="http://127.0.0.1:9700")
    assert client.get("/api/settings").json()["mode"] == "starting"
    assert client.get("/api/findings").json()["mode"] == "starting"
    assert client.get("/api/audit").json()["mode"] == "starting"


def test_a_failed_read_after_a_good_one_keeps_block(monkeypatch):
    _reads(monkeypatch, {"mode": "block"}, None)
    assert config.load_blackbox_config().mode == "block"           # the good read
    assert config.load_blackbox_config().mode == "block"           # the file is being rewritten: still block
    assert settings.read_settings()["mode"] == "block" and settings.read_settings()["starting"] is False


def test_hermes_stand_in_for_an_unreadable_file_is_not_the_persons_settings(monkeypatch):
    import hermes_cli.config as hermes_config
    from hermes_cli.config_read_errors import FailedConfigRead

    monkeypatch.setattr(config.constants, "hermes_root", config.constants.hermes_home)
    monkeypatch.setattr(hermes_config, "load_config_readonly", lambda: FailedConfigRead({"plugins": {}}, error=ValueError("torn")))
    assert config.mode_answer(config.load_blackbox_config()) == "starting"
    last_good = {"plugins": {"entries": {"blackbox": {"mode": "block"}}}}   # Hermes' last-known-good copy
    monkeypatch.setattr(hermes_config, "load_config_readonly", lambda: FailedConfigRead(last_good, error=ValueError("torn")))
    assert config.mode_answer(config.load_blackbox_config()) == "block"


def test_a_page_never_writes_the_starting_word_as_a_mode():
    assert settings.write_settings({"mode": "starting"})["ok"] is False
