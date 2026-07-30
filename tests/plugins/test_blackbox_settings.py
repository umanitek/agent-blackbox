"""Tests for the user-configurable Blackbox detection policy.

Covers the whole configurable-policy surface that ships together:

* :class:`config.BlackboxConfig` per-category policy (``category_setting`` /
  ``category_allows``) and how ``load_blackbox_config`` parses the new
  ``detection.<category>`` + ``protected_paths`` config keys (garbage tolerated).
* :func:`detection.detect_custom_fileaccess` — the user's local protected-path
  rules (``source="custom"``, always critical, never shared).
* :func:`hooks._flag_worthy` applying the per-category policy, with custom rules
  bypassing it; :func:`hooks.on_pre_tool_call` blocking on a custom rule in
  block mode; and :func:`hooks._report_and_audit` keeping custom findings local
  (no SWM sighting).
* :mod:`settings` write/read round-trip persisting to the tmpdir-isolated
  ``HERMES_HOME/config.yaml`` so a fresh ``load_blackbox_config`` sees it.

``HERMES_HOME``/``BLACKBOX_HOME`` are per-test tmpdirs (root conftest), so
config writes and audit logs never touch the real home.
"""

import os
from pathlib import Path

import pytest

from _blackbox_loader import load_blackbox


config_mod = load_blackbox("config")
constants = load_blackbox("constants")
detection = load_blackbox("detection")
hooks = load_blackbox("hooks")
ruleset_mod = load_blackbox("ruleset")
settings = load_blackbox("settings")


# ---------------------------------------------------------------------------
# 1. BlackboxConfig.category_setting / category_allows
# ---------------------------------------------------------------------------


def test_category_defaults_allow_everything():
    # No policy configured → every category enabled at the ``info`` floor, so
    # even the lowest severity is allowed to flag.
    cfg = config_mod.BlackboxConfig()
    setting = cfg.category_setting("dependency")
    assert setting == {"enabled": True, "min_severity": "info"}
    for sev in ("info", "low", "medium", "high", "critical"):
        assert cfg.category_allows("dependency", sev) is True


def test_category_min_severity_critical_rejects_below():
    cfg = config_mod.BlackboxConfig(categories={"dependency": {"min_severity": "critical"}})
    assert cfg.category_setting("dependency")["min_severity"] == "critical"
    assert cfg.category_allows("dependency", "high") is False
    assert cfg.category_allows("dependency", "critical") is True


def test_category_disabled_rejects_everything():
    cfg = config_mod.BlackboxConfig(categories={"fileaccess": {"enabled": False}})
    assert cfg.category_setting("fileaccess")["enabled"] is False
    for sev in ("info", "low", "medium", "high", "critical"):
        assert cfg.category_allows("fileaccess", sev) is False


def test_category_garbage_min_severity_falls_back_to_info():
    cfg = config_mod.BlackboxConfig(categories={"injection": {"min_severity": "banana"}})
    setting = cfg.category_setting("injection")
    assert setting["min_severity"] == "info"  # unknown ladder value → info floor
    assert cfg.category_allows("injection", "info") is True


def test_category_setting_ignores_non_mapping_entry():
    # A category whose value isn't a mapping (e.g. a bare string from a
    # hand-edited config) must not crash — it falls back to the defaults.
    cfg = config_mod.BlackboxConfig(categories={"skill": "enabled"})
    assert cfg.category_setting("skill") == {"enabled": True, "min_severity": "info"}


# ---------------------------------------------------------------------------
# 2. load_blackbox_config parses detection.<cat> + protected_paths
# ---------------------------------------------------------------------------


def test_load_config_parses_detection_and_protected_paths(monkeypatch):
    monkeypatch.setattr(
        config_mod,
        "_blackbox_entry",
        lambda: {
            "detection": {
                "dependency": {"min_severity": "critical"},
                "fileaccess": {"enabled": False},
            },
            "protected_paths": ["~/.ssh/*", "*.pem", "~/.ssh/*"],  # dupe collapses
        },
    )
    cfg = config_mod.load_blackbox_config()
    assert dict(cfg.categories) == {
        "dependency": {"min_severity": "critical"},
        "fileaccess": {"enabled": False},
    }
    assert cfg.protected_paths == ("~/.ssh/*", "*.pem")
    assert cfg.category_allows("dependency", "high") is False
    assert cfg.category_allows("fileaccess", "critical") is False


def test_load_config_drops_garbage_values(monkeypatch):
    monkeypatch.setattr(
        config_mod,
        "_blackbox_entry",
        lambda: {
            "detection": {
                # bad min_severity is dropped; enabled kept.
                "dependency": {"enabled": True, "min_severity": "wat"},
                # unknown category name is ignored entirely.
                "not_a_category": {"min_severity": "critical"},
            },
            "protected_paths": "not-a-list",  # non-list → ignored
        },
    )
    cfg = config_mod.load_blackbox_config()
    assert dict(cfg.categories) == {"dependency": {"enabled": True}}
    assert cfg.protected_paths == ()
    # With only enabled=True set, the min_severity floor stays at the default.
    assert cfg.category_setting("dependency") == {"enabled": True, "min_severity": "info"}


def test_load_config_ignores_non_dict_detection(monkeypatch):
    monkeypatch.setattr(
        config_mod,
        "_blackbox_entry",
        lambda: {"detection": "nope", "protected_paths": ["x"]},
    )
    cfg = config_mod.load_blackbox_config()
    assert dict(cfg.categories) == {}
    assert cfg.protected_paths == ("x",)


def test_load_config_defaults_to_isolated_blackbox_dkg(monkeypatch, tmp_path):
    hermes_home = tmp_path / "hermes"
    monkeypatch.delenv("BLACKBOX_DKG_DAEMON_URL", raising=False)
    monkeypatch.delenv("BLACKBOX_DKG_URL", raising=False)
    monkeypatch.delenv("BLACKBOX_DKG_PORT", raising=False)
    monkeypatch.delenv("BLACKBOX_DKG_HOME", raising=False)
    monkeypatch.delenv("BLACKBOX_DKG_BIN", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    monkeypatch.setenv("DKG_DAEMON_URL", "http://default-node:9200")
    monkeypatch.setenv("DKG_API_TOKEN", "default-token")
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: {})

    cfg = config_mod.load_blackbox_config()
    assert cfg.dkg_url == constants.DEFAULT_DKG_URL
    assert cfg.dkg_home == str(hermes_home / "blackbox" / "dkg")
    assert cfg.dkg_bin == str(hermes_home / "blackbox" / "dkg-cli" / "node_modules" / ".bin" / "dkg")


def test_load_config_accepts_blackbox_dkg_overrides(monkeypatch, tmp_path):
    dkg_home = tmp_path / "bb-dkg"
    dkg_bin = tmp_path / "bb-dkg-cli" / "dkg"
    monkeypatch.setenv("BLACKBOX_DKG_PORT", "9432")
    monkeypatch.setenv("BLACKBOX_DKG_HOME", str(dkg_home))
    monkeypatch.setenv("BLACKBOX_DKG_BIN", str(dkg_bin))
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: {})

    cfg = config_mod.load_blackbox_config()
    assert cfg.dkg_url == "http://127.0.0.1:9432"
    assert cfg.dkg_home == str(dkg_home)
    assert cfg.dkg_bin == str(dkg_bin)


def test_load_config_migrates_legacy_default_dkg_url(monkeypatch, tmp_path):
    hermes_home = tmp_path / "hermes"
    monkeypatch.delenv("BLACKBOX_DKG_DAEMON_URL", raising=False)
    monkeypatch.delenv("BLACKBOX_DKG_URL", raising=False)
    monkeypatch.delenv("BLACKBOX_DKG_PORT", raising=False)
    monkeypatch.delenv("BLACKBOX_DKG_HOME", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: {"dkg_url": "http://127.0.0.1:9200"})

    cfg = config_mod.load_blackbox_config()
    assert cfg.dkg_url == constants.DEFAULT_DKG_URL
    assert cfg.dkg_home == str(hermes_home / "blackbox" / "dkg")


def test_load_config_migrates_unpaired_shared_default_dkg_home(monkeypatch, tmp_path):
    hermes_home = tmp_path / "hermes"
    monkeypatch.delenv("BLACKBOX_DKG_DAEMON_URL", raising=False)
    monkeypatch.delenv("BLACKBOX_DKG_URL", raising=False)
    monkeypatch.delenv("BLACKBOX_DKG_HOME", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    monkeypatch.setattr(
        config_mod,
        "_blackbox_entry",
        lambda: {"dkg_home": str(Path.home() / ".dkg")},
    )

    cfg = config_mod.load_blackbox_config()
    assert cfg.dkg_url == constants.DEFAULT_DKG_URL
    assert cfg.dkg_home == str(hermes_home / "blackbox" / "dkg")


def test_load_config_migrates_explicit_shared_dkg_pair(monkeypatch, tmp_path):
    hermes_home = tmp_path / "hermes"
    monkeypatch.delenv("BLACKBOX_DKG_DAEMON_URL", raising=False)
    monkeypatch.delenv("BLACKBOX_DKG_URL", raising=False)
    monkeypatch.delenv("BLACKBOX_DKG_PORT", raising=False)
    monkeypatch.delenv("BLACKBOX_DKG_HOME", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    monkeypatch.setattr(
        config_mod,
        "_blackbox_entry",
        lambda: {"dkg_url": "http://127.0.0.1:9320", "dkg_home": str(Path.home() / ".dkg")},
    )

    cfg = config_mod.load_blackbox_config()
    assert cfg.dkg_url == constants.DEFAULT_DKG_URL
    assert cfg.dkg_home == str(hermes_home / "blackbox" / "dkg")


def test_configured_blackbox_node_wins_over_stale_environment(monkeypatch, tmp_path):
    configured_home = tmp_path / "agent-blackbox" / ".dkg"
    configured_bin = tmp_path / "agent-blackbox" / "dkg" / "dkg"
    monkeypatch.setenv("BLACKBOX_DKG_HOME", str(Path.home() / ".dkg"))
    monkeypatch.setenv("BLACKBOX_DKG_BIN", str(Path.home() / ".local" / "bin" / "dkg"))
    monkeypatch.setenv("BLACKBOX_DKG_DAEMON_URL", "http://127.0.0.1:9200")
    monkeypatch.setattr(
        config_mod,
        "_blackbox_entry",
        lambda: {
            "dkg_url": "http://127.0.0.1:9320",
            "dkg_home": str(configured_home),
            "dkg_bin": str(configured_bin),
        },
    )

    cfg = config_mod.load_blackbox_config()
    assert cfg.dkg_url == "http://127.0.0.1:9320"
    assert cfg.dkg_home == str(configured_home)
    assert cfg.dkg_bin == str(configured_bin)


def test_load_config_preserves_custom_dkg_url(monkeypatch, tmp_path):
    dkg_home = tmp_path / "custom-dkg"
    monkeypatch.delenv("BLACKBOX_DKG_DAEMON_URL", raising=False)
    monkeypatch.delenv("BLACKBOX_DKG_URL", raising=False)
    monkeypatch.delenv("BLACKBOX_DKG_PORT", raising=False)
    monkeypatch.delenv("BLACKBOX_DKG_HOME", raising=False)
    monkeypatch.setattr(
        config_mod,
        "_blackbox_entry",
        lambda: {"dkg_url": "http://127.0.0.1:9444", "dkg_home": str(dkg_home)},
    )

    cfg = config_mod.load_blackbox_config()
    assert cfg.dkg_url == "http://127.0.0.1:9444"
    assert cfg.dkg_home == str(dkg_home)


# ---------------------------------------------------------------------------
# 3. detect_custom_fileaccess
# ---------------------------------------------------------------------------

_HOME = os.path.expanduser("~")


def _sole_custom(findings):
    assert len(findings) == 1
    f = findings[0]
    assert f.source == "custom"
    assert f.severity == "critical"
    assert f.category == "fileaccess"
    return f


def test_custom_fileaccess_basename_glob():
    path = os.path.join(_HOME, "certs", "server.pem")
    _sole_custom(detection.detect_custom_fileaccess("read_file", {"path": path}, ["*.pem"]))


def test_custom_fileaccess_full_path_glob():
    path = os.path.join(_HOME, ".ssh", "id_rsa")
    _sole_custom(detection.detect_custom_fileaccess("read_file", {"path": path}, ["~/.ssh/*"]))


def test_custom_fileaccess_directory_prefix():
    # A glob-free pattern naming a directory protects everything under it.
    path = os.path.join(_HOME, "secrets", "db", "creds.txt")
    _sole_custom(detection.detect_custom_fileaccess("read_file", {"path": path}, ["~/secrets"]))


def test_custom_fileaccess_benign_path_no_finding():
    path = os.path.join(_HOME, "projects", "main.py")
    assert detection.detect_custom_fileaccess("read_file", {"path": path}, ["*.pem"]) == []


def test_custom_fileaccess_non_file_tool_no_finding():
    # A terminal call is not a file-access tool even if a pem path appears.
    args = {"command": "cat " + os.path.join(_HOME, "certs", "server.pem")}
    assert detection.detect_custom_fileaccess("terminal", args, ["*.pem"]) == []


def test_custom_fileaccess_empty_patterns_no_finding():
    path = os.path.join(_HOME, "certs", "server.pem")
    assert detection.detect_custom_fileaccess("read_file", {"path": path}, []) == []


# ---------------------------------------------------------------------------
# 4. hooks._flag_worthy applies per-category policy; custom bypasses it
# ---------------------------------------------------------------------------


def _finding(category, severity, source):
    return detection.Finding(
        identifier=f"{category}:x:{source}-{severity}",
        category=category,
        severity=severity,
        title="t",
        confirmed=source == "public",
        source=source,
    )


def test_flag_worthy_drops_category_below_min_severity():
    cfg = config_mod.BlackboxConfig(categories={"dependency": {"min_severity": "critical"}})
    kept = hooks._flag_worthy(cfg, [_finding("dependency", "high", "public")])
    assert kept == []  # high < the dependency critical floor


def test_flag_worthy_keeps_category_at_min_severity():
    cfg = config_mod.BlackboxConfig(categories={"dependency": {"min_severity": "critical"}})
    findings = [_finding("dependency", "critical", "public")]
    assert hooks._flag_worthy(cfg, findings) == findings


def test_flag_worthy_disabled_category_drops_public_confirmed():
    # A disabled category drops even a source=="public" confirmed finding —
    # the user explicitly turned this category off.
    cfg = config_mod.BlackboxConfig(categories={"dependency": {"enabled": False}})
    kept = hooks._flag_worthy(cfg, [_finding("dependency", "critical", "public")])
    assert kept == []


def test_flag_worthy_custom_bypasses_category_policy():
    # Custom (user-configured) rules are kept regardless of category policy —
    # even when the same category is disabled.
    cfg = config_mod.BlackboxConfig(categories={"fileaccess": {"enabled": False}})
    custom = detection.Finding(
        identifier="fileaccess:read_file:user-protected",
        category="fileaccess",
        severity="critical",
        title="Access to a user-protected path",
        confirmed=False,
        source="custom",
    )
    kept = hooks._flag_worthy(cfg, [custom])
    assert kept == [custom]


# ---------------------------------------------------------------------------
# 5. hooks.on_pre_tool_call blocks on a custom protected-path rule
# ---------------------------------------------------------------------------


def _empty_ruleset():
    rs = ruleset_mod.Ruleset()
    rs.synced_at = 9e18  # far future → no background refresh
    return rs


def test_on_pre_tool_call_blocks_custom_protected_path(monkeypatch):
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: _empty_ruleset())
    monkeypatch.setattr(hooks, "_report_and_audit", lambda *a, **k: None)
    monkeypatch.setattr(hooks, "_spawn_osv_discovery", lambda *a, **k: None)
    monkeypatch.setattr(
        config_mod,
        "load_blackbox_config",
        lambda: config_mod.BlackboxConfig(
            mode="block", block_severity="critical", protected_paths=("~/.ssh/*",)
        ),
    )
    path = os.path.join(_HOME, ".ssh", "id_rsa")
    out = hooks.on_pre_tool_call(tool_name="read_file", args={"path": path})
    assert isinstance(out, dict)
    assert out["action"] == "block"
    assert "Blackbox" in out["message"]


def test_on_pre_tool_call_benign_path_returns_none(monkeypatch):
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: _empty_ruleset())
    monkeypatch.setattr(hooks, "_report_and_audit", lambda *a, **k: None)
    monkeypatch.setattr(hooks, "_spawn_osv_discovery", lambda *a, **k: None)
    monkeypatch.setattr(
        config_mod,
        "load_blackbox_config",
        lambda: config_mod.BlackboxConfig(
            mode="block", block_severity="critical", protected_paths=("~/.ssh/*",)
        ),
    )
    path = os.path.join(_HOME, "projects", "main.py")
    assert hooks.on_pre_tool_call(tool_name="read_file", args={"path": path}) is None


# ---------------------------------------------------------------------------
# 6. _report_and_audit never shares a custom finding to SWM
# ---------------------------------------------------------------------------


def test_report_and_audit_never_shares_custom_finding(monkeypatch):
    # A custom finding is audited locally but must NEVER reach the community
    # graph — no share_knowledge_asset, no private-audit KA write.
    shared = {"called": False}
    private = {"called": False}

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def share_knowledge_asset(self, cg, name, q):
            shared["called"] = True
            return {}

    monkeypatch.setattr(hooks, "DkgClient", FakeClient)
    monkeypatch.setattr(
        hooks.audit,
        "write_private_audit_ka",
        lambda *a, **k: private.__setitem__("called", True),
    )
    # Do not let a real cooldown state gate the assertion.
    monkeypatch.setattr(hooks.audit, "recently_reported", lambda ident: False)
    monkeypatch.setattr(hooks.audit, "allow_report", lambda *a, **k: True)

    cfg = config_mod.BlackboxConfig(report=True)
    custom = detection.Finding(
        identifier="fileaccess:read_file:user-protected",
        category="fileaccess",
        severity="critical",
        title="Access to a user-protected path",
        confirmed=False,
        source="custom",
    )
    hooks._report_and_audit(cfg, "pre_tool_call", [custom], {"tool_name": "read_file"})
    assert shared["called"] is False
    assert private["called"] is False


@pytest.mark.skip(reason="outbound threat sharing is disabled until community SWM ships")
def test_report_and_audit_shares_non_custom_finding(monkeypatch):
    # Contrast: a community finding DOES reach share_knowledge_asset, proving
    # the custom-skip above is the discriminator (not a broken client).
    shared = {"called": False}

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def share_knowledge_asset(self, cg, name, q):
            shared["called"] = True
            return {}

    monkeypatch.setattr(hooks, "DkgClient", FakeClient)
    monkeypatch.setattr(hooks.audit, "write_private_audit_ka", lambda *a, **k: None)
    monkeypatch.setattr(hooks.audit, "recently_reported", lambda ident: False)
    monkeypatch.setattr(hooks.audit, "allow_report", lambda *a, **k: True)
    monkeypatch.setattr(hooks, "_reporter_address", lambda client: "0xabc")

    cfg = config_mod.BlackboxConfig(report=True)
    community = detection.Finding(
        identifier="escalation:terminal:remote-script-pipe",
        category="escalation",
        severity="critical",
        title="curl|sh",
        confirmed=False,
        source="community",
        fields={"tool_name": "terminal", "arg_shape": "remote-script-pipe"},
    )
    hooks._report_and_audit(cfg, "pre_tool_call", [community], {"tool_name": "terminal"})
    assert shared["called"] is True


# ---------------------------------------------------------------------------
# 7. settings.write_settings + read_settings round-trip (tmpdir persistence)
# ---------------------------------------------------------------------------


def test_settings_round_trip_persists_and_reloads():
    result = settings.write_settings(
        {"categories": {"dependency": {"min_severity": "critical"}}, "protected_paths": ["*.pem"]}
    )
    assert result["ok"] is True
    assert result["errors"] == []
    assert result["settings"]["categories"]["dependency"] == {
        "enabled": True,
        "min_severity": "critical",
    }
    assert result["settings"]["protected_paths"] == ["*.pem"]

    # read_settings reflects the persisted policy.
    read = settings.read_settings()
    assert read["categories"]["dependency"]["min_severity"] == "critical"
    assert read["protected_paths"] == ["*.pem"]

    # A fresh config load sees it too — the write reached HERMES_HOME/config.yaml.
    cfg = config_mod.load_blackbox_config()
    assert cfg.category_allows("dependency", "high") is False
    assert cfg.category_allows("dependency", "critical") is True
    assert cfg.protected_paths == ("*.pem",)


def test_settings_write_invalid_payload_reports_error():
    result = settings.write_settings({"mode": "nope"})
    assert result["ok"] is False
    assert any("mode" in e for e in result["errors"])
    # It still returns a complete settings view rather than crashing.
    assert "categories" in result["settings"]


def test_settings_write_deep_merges_categories():
    # Tuning one category must not drop another already persisted.
    first = settings.write_settings({"categories": {"dependency": {"min_severity": "critical"}}})
    assert first["ok"] is True
    second = settings.write_settings({"categories": {"fileaccess": {"enabled": False}}})
    assert second["ok"] is True
    read = settings.read_settings()
    assert read["categories"]["dependency"]["min_severity"] == "critical"
    assert read["categories"]["fileaccess"]["enabled"] is False
