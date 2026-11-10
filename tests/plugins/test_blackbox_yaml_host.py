"""Blackbox reads and writes config.yaml through the host's YAML library.

Hermes 0.21.7 removed PyYAML and reads YAML through its own ruamel-backed
``hermes_yaml``. Blackbox's helper imported ``yaml`` behind a fail-open guard, so on the
new host every config read came back empty and Blackbox silently ran on its defaults —
block mode and Trader Shield settings ignored. These tests run the real helper against
the real host library.
"""

from __future__ import annotations

import pytest

from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.kernel import yaml_files


def test_the_helper_has_a_yaml_library():
    assert yaml_files.yaml is not None


def test_a_config_written_by_the_helper_reads_back_the_same(tmp_path):
    path = tmp_path / "config.yaml"
    data = {"plugins": {"entries": {"blackbox": {"mode": "block", "wallet_protection": True,
                                                  "protected_wallets": ["metamask", "solana-cli"],
                                                  "protected_paths": ["~/.ssh/*", ".env"]}}}}
    yaml_files.dump_yaml(path, data)
    assert yaml_files.load_yaml(path) == data


def test_yaml_1_1_booleans_in_a_hand_written_config_still_read(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("plugins:\n  entries:\n    blackbox:\n      mode: block\n      report: no\n      discover: yes\n",
                    encoding="utf-8")
    entry = yaml_files.load_yaml(path)["plugins"]["entries"]["blackbox"]
    assert entry == {"mode": "block", "report": False, "discover": True}


def test_block_mode_in_config_yaml_reaches_blackbox(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    yaml_files.dump_yaml(home / "config.yaml", {"plugins": {"entries": {"blackbox": {"mode": "block"}}}})
    monkeypatch.setenv("HERMES_HOME", str(home))
    assert config_mod.load_blackbox_config().block_enabled


# --- KI-493: a config that cannot be read is never written over ---

BROKEN = "plugins:\n  enabled: [hermes-achievements\nmodel: [unclosed\n"   # the user's file, with a typo


def _broken_home(tmp_path):
    (tmp_path / "config.yaml").write_text(BROKEN, encoding="utf-8")
    return tmp_path


def test_reading_an_unparseable_config_still_gives_an_empty_mapping(tmp_path):
    assert yaml_files.load_yaml(_broken_home(tmp_path) / "config.yaml") == {}


def test_reading_it_for_an_edit_refuses(tmp_path):
    with pytest.raises(yaml_files.UnreadableYaml, match="was not changed"):
        yaml_files.load_for_edit(_broken_home(tmp_path) / "config.yaml")


def test_a_missing_or_empty_config_is_an_empty_mapping_for_an_edit(tmp_path):
    assert yaml_files.load_for_edit(tmp_path / "config.yaml") == {}
    (tmp_path / "config.yaml").write_text("", encoding="utf-8")
    assert yaml_files.load_for_edit(tmp_path / "config.yaml") == {}


def test_a_config_that_is_a_list_is_refused_for_an_edit(tmp_path):
    (tmp_path / "config.yaml").write_text("- a\n- b\n", encoding="utf-8")
    with pytest.raises(yaml_files.UnreadableYaml):
        yaml_files.load_for_edit(tmp_path / "config.yaml")


def test_attach_reports_the_unreadable_config_and_leaves_it_alone(tmp_path):
    from plugins.blackbox.attach import hermes_homes
    home = _broken_home(tmp_path)

    report = hermes_homes.attach_hermes(home)

    assert (home / "config.yaml").read_text(encoding="utf-8") == BROKEN
    assert report["ok"] is False and "was not changed" in report["error"]


def test_detach_leaves_an_unreadable_config_alone(tmp_path):
    from plugins.blackbox.attach import hermes_homes
    home = _broken_home(tmp_path)

    hermes_homes.detach_hermes(home)

    assert (home / "config.yaml").read_text(encoding="utf-8") == BROKEN


def test_the_chat_profile_setup_leaves_an_unreadable_config_alone(tmp_path):
    from plugins.blackbox.chat import command
    home = _broken_home(tmp_path)

    command._ensure_blackbox_context_cap(home)

    assert (home / "config.yaml").read_text(encoding="utf-8") == BROKEN


def test_saving_settings_fails_and_leaves_an_unreadable_config_alone(tmp_path, monkeypatch):
    from plugins.blackbox.kernel import settings
    home = _broken_home(tmp_path)
    monkeypatch.setenv("HERMES_HOME", str(home))

    assert settings._persist_locked({"mode": "block"}) is False
    assert (home / "config.yaml").read_text(encoding="utf-8") == BROKEN
