"""The generated installer profile must remain usable with community protection."""
import os
import subprocess
import sys
from pathlib import Path

import hermes_yaml as yaml
import pytest

from tests.test_blackbox_install_llm_setup import INSTALL_PS1, _extract_unix_blackbox_config_writer

ROOT = Path(__file__).resolve().parents[3]
GRAPH = "0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox-vm"


def write_profile(tmp_path, platform, entry, *, plugin_root=ROOT, url="http://127.0.0.1:19999"):
    from copy import deepcopy
    entry = deepcopy(entry)
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({"model": "kept", "plugins": {"entries": {"blackbox": entry}}}))
    node_home, node_bin = str(tmp_path / "node"), str(tmp_path / "dkg")
    if platform == "unix":
        code = _extract_unix_blackbox_config_writer()
        args = [str(path), "mainnet-base", GRAPH, "discovery-hint", url,
                node_home, node_bin, "", "", str(plugin_root)]
    else:
        code = INSTALL_PS1.read_text(encoding="utf-8").split("$configWriter = @\'\n", 1)[1].split("\n\'@", 1)[0]
        args = [str(path), url, node_home, node_bin, GRAPH, "discovery-hint", str(plugin_root)]
    env = {k: v for k, v in os.environ.items() if not k.startswith("BLACKBOX_")}
    env.update(HERMES_HOME=str(tmp_path), BLACKBOX_DKG_NETWORK="mainnet-base", PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run([sys.executable, "-c", code, *args], capture_output=True, text=True, check=False, env=env)
    assert result.returncode == 0, result.stderr
    return path, env


@pytest.mark.parametrize("platform", ["unix", "windows"])
def test_fresh_profile_loads_real_defaults_and_passes_sync_preflight(tmp_path, platform):
    path, env = write_profile(tmp_path, platform, {})
    code = """from plugins.blackbox.kernel.config import load_blackbox_config
from plugins.blackbox.sync.direct_preflight import valid
cfg = load_blackbox_config()
assert cfg.community_graph_id, 'Community reads must remain enabled'
assert valid(cfg), 'The generated profile must pass the real sync preflight'
assert cfg.detection_backend == 'legacy-cache' and cfg.snapshot_sync is None
"""
    result = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert yaml.safe_load(path.read_text())["model"] == "kept"


@pytest.mark.parametrize("platform", ["unix", "windows"])
def test_upgrade_keeps_community_and_explicit_detection_settings(tmp_path, platform):
    entry = {"context_graph_id": GRAPH, "detection_backend": "legacy-cache", "community_graph_id": "owner/community",
             "community_shadow": True, "community_poll_interval": 37, "daily_report_limit": 73, "report": False}
    path, _ = write_profile(tmp_path, platform, entry)
    actual = yaml.safe_load(path.read_text())["plugins"]["entries"]["blackbox"]
    assert all(actual[key] == value for key, value in entry.items())
    assert "snapshot_sync" not in actual


@pytest.mark.parametrize("platform", ["unix", "windows"])
@pytest.mark.parametrize("available", [False, True])
@pytest.mark.parametrize("layout", ["checkout", "installed"])
def test_public_only_installer_requires_compatible_daemon_and_proven_cores(tmp_path, platform, available, layout):
    import shutil
    from tests.plugins.blackbox_sync_fixtures import replies, completed_job, QUERY_CAPABILITIES
    plugin_root = ROOT
    if layout == "installed":
        plugin_root = tmp_path / "installed-plugin"
        shutil.copytree(ROOT / "plugins" / "blackbox", plugin_root,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    job = completed_job() if available else {"state": "idle", "capabilities": {"sourcePolicies": ["DKG_Core_chain_cache"]}}
    with replies([job, QUERY_CAPABILITIES] if available else [job]) as (url, calls):
        path, _ = write_profile(tmp_path, platform, {"community_graph_id": ""}, url=url, plugin_root=plugin_root)
        data = yaml.safe_load(path.read_text())
        entry = data["plugins"]["entries"]["blackbox"]
        assert (entry.get("snapshot_sync", {}).get("DKG_Core_chain_cache") is True) is available
        assert entry["community_graph_id"] == ""
        # An upgrade preserves this decision, even when cores later disappear.
        before = {k: entry.get(k) for k in ("community_graph_id", "detection_backend", "snapshot_sync")}
        path, _ = write_profile(tmp_path, platform, entry, url=url, plugin_root=plugin_root)
        after = yaml.safe_load(path.read_text())["plugins"]["entries"]["blackbox"]
        assert {k: after.get(k) for k in before} == before
    assert [method for method, _, _ in calls] == (["GET", "GET"] if available else ["GET"])
