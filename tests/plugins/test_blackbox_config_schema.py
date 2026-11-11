"""One schema for what a setting may hold, asked by both reading and saving.

Reading config.yaml (``kernel.config``) and saving a dashboard edit
(``kernel.settings``) used to carry their own lists of valid values. These tests
pin that both sides agree: whatever a save accepts, a read returns unchanged, and
a value a save refuses is one a read replaces with its default.
"""

from __future__ import annotations

import pytest

from plugins.blackbox.kernel import config, constants, settings
from plugins.blackbox.kernel.config_values import schema


def _read(entry: dict) -> config.BlackboxConfig:
    return config.load_blackbox_config(entry=entry)


@pytest.mark.parametrize("mode", [member.value for member in schema.Mode])
def test_every_mode_a_save_accepts_is_read_back_unchanged(mode):
    updates, errors = settings._validate({"mode": mode})
    assert errors == [] and _read(updates).mode == mode


@pytest.mark.parametrize("severity", list(constants.SEVERITY_RANK))
def test_every_severity_a_save_accepts_is_read_back_unchanged(severity):
    updates, errors = settings._validate({"block_severity": severity, "report_min_severity": severity})
    cfg = _read(updates)
    assert errors == [] and (cfg.block_severity, cfg.report_min_severity) == (severity, severity)


@pytest.mark.parametrize("provider", [member.value for member in schema.Provider] + [""])
def test_every_reviewer_provider_a_save_accepts_is_read_back_unchanged(provider, monkeypatch):
    monkeypatch.delenv("BLACKBOX_LLM_PROVIDER", raising=False)
    updates, errors = settings._validate({"llm": {"provider": provider}})
    assert errors == [] and _read(updates).llm_provider == provider


@pytest.mark.parametrize("payload, field, default", [
    ({"mode": "enforce"}, "mode", "audit"),
    ({"block_severity": "severe"}, "block_severity", "critical"),
    ({"report_min_severity": "severe"}, "report_min_severity", "high"),
])
def test_a_value_a_save_refuses_is_one_a_read_replaces_with_the_default(payload, field, default, monkeypatch):
    for name in ("BLACKBOX_MODE", "BLACKBOX_BLOCK_SEVERITY", "BLACKBOX_REPORT_MIN_SEVERITY"):
        monkeypatch.delenv(name, raising=False)
    updates, errors = settings._validate(payload)
    assert updates == {} and len(errors) == 1
    assert getattr(_read(payload), field) == default


def test_an_unknown_reviewer_provider_is_refused_on_save_and_empty_on_read(monkeypatch):
    monkeypatch.delenv("BLACKBOX_LLM_PROVIDER", raising=False)
    updates, errors = settings._validate({"llm": {"provider": "acme"}})
    assert updates == {} and len(errors) == 1
    assert _read({"llm": {"provider": "acme"}}).llm_provider == ""


def test_category_policy_is_one_rule_reading_skips_what_saving_reports():
    raw = {"dependency": {"enabled": "yes", "min_severity": "critical"},
           "fileaccess": {"enabled": False, "min_severity": "severe"},
           "made-up": {"enabled": False}, "skill": "off"}
    valid = {"dependency": {"min_severity": "critical"}, "fileaccess": {"enabled": False}}
    assert dict(_read({"detection": raw}).categories) == valid
    updates, errors = settings._validate({"categories": raw})
    assert updates == {"detection": valid}
    assert errors == ["dependency.enabled must be a boolean", "invalid fileaccess.min_severity: 'severe'"]


def test_protected_paths_are_cleaned_the_same_way_on_both_sides():
    raw = [" ~/.ssh/* ", "*.pem", "", None, "*.pem"]
    updates, errors = settings._validate({"protected_paths": raw})
    assert errors == [] and updates["protected_paths"] == ["~/.ssh/*", "*.pem"]
    assert _read({"protected_paths": raw}).protected_paths == ("~/.ssh/*", "*.pem")


def test_reading_keeps_the_first_hundred_paths_and_saving_refuses_more():
    many = [f"/p{number}" for number in range(schema.MAX_PROTECTED_PATHS + 1)]
    assert len(_read({"protected_paths": many}).protected_paths) == schema.MAX_PROTECTED_PATHS
    updates, errors = settings._validate({"protected_paths": many})
    assert updates == {} and len(errors) == 1


def test_a_value_written_with_stray_spaces_or_capitals_is_the_value(monkeypatch):
    monkeypatch.delenv("BLACKBOX_MODE", raising=False)
    monkeypatch.delenv("BLACKBOX_BLOCK_SEVERITY", raising=False)
    assert _read({"mode": " Block ", "block_severity": " High "}).block_severity == "high"
    assert _read({"mode": " Block "}).block_enabled is True
    assert settings._validate({"mode": " Block "}) == ({"mode": "block"}, [])


def test_the_enums_compare_equal_to_the_text_the_rest_of_the_plugin_uses():
    assert schema.Mode.BLOCK == "block" and schema.DetectionBackend.DKG == "dkg"
    assert config.BlackboxConfig().mode == "audit" and type(config.BlackboxConfig().mode) is str
    assert config.BlackboxConfig().detection_backend == "legacy-cache"
    assert config.DETECTION_CATEGORIES is schema.DETECTION_CATEGORIES
    assert settings.MAX_PROTECTED_PATHS == schema.MAX_PROTECTED_PATHS == 100
