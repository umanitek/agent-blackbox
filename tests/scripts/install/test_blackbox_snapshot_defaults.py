"""Execute both installers' config writers against isolated fresh/custom profiles."""
import os
import subprocess
import sys

import hermes_yaml as yaml
import pytest

from tests.test_blackbox_install_llm_setup import (
    INSTALL_PS1,
    _extract_unix_blackbox_config_writer,
)

GRAPH = "0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox-vm"


@pytest.mark.parametrize("platform", ["unix", "windows"])
@pytest.mark.parametrize("existing", [False, True])
def test_installer_keeps_ordinary_sync_without_verified_compatibility(tmp_path, platform, existing):
    path = tmp_path / "config.yaml"
    before = {"context_graph_id": GRAPH, "detection_backend": "legacy-cache"} if existing else {}
    path.write_text(yaml.safe_dump({"model": "kept", "plugins": {"entries": {"blackbox": before}}}))
    node_home, node_bin = str(tmp_path / "node"), str(tmp_path / "dkg")
    if platform == "unix":
        code = _extract_unix_blackbox_config_writer()
        args = [str(path), "mainnet-base", GRAPH, "discovery-hint", "http://127.0.0.1:19999", node_home, node_bin]
    else:
        code = INSTALL_PS1.read_text(encoding="utf-8").split("$configWriter = @'\n", 1)[1].split("\n'@", 1)[0]
        args = [str(path), "http://127.0.0.1:19999", node_home, node_bin, GRAPH, "discovery-hint"]
    result = subprocess.run([sys.executable, "-c", code, *args], capture_output=True, text=True, check=False,
                            env={**os.environ, "HERMES_HOME": str(tmp_path), "BLACKBOX_DKG_NETWORK": "mainnet-base"})
    assert result.returncode == 0, result.stderr
    data = yaml.safe_load(path.read_text())
    entry = data["plugins"]["entries"]["blackbox"]
    assert data["model"] == "kept" and entry["report"] is False
    if existing:
        assert entry["detection_backend"] == "legacy-cache" and "snapshot_sync" not in entry
    else:
        assert entry.get("detection_backend", "legacy-cache") == "legacy-cache"
        assert "snapshot_sync" not in entry
