from __future__ import annotations

import importlib.util
import json
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "blackbox-curator-config.py"
SPEC = importlib.util.spec_from_file_location("blackbox_curator_config", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_ensures_graph_scoped_auto_approval_without_clobbering_config(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    original = {
        "name": "publisher",
        "contextGraphs": ["owner/existing"],
        "autoApproveJoinRequests": ["owner/existing"],
        "store": {"type": "blazegraph", "url": "http://127.0.0.1:9999"},
    }
    config_path.write_text(json.dumps(original), encoding="utf-8")
    config_path.chmod(0o640)

    assert MODULE.ensure_graph_auto_approval(config_path, "owner/agent-blackbox") is True

    updated = json.loads(config_path.read_text(encoding="utf-8"))
    assert updated["contextGraphs"] == ["owner/existing", "owner/agent-blackbox"]
    assert updated["autoApproveJoinRequests"] == ["owner/existing", "owner/agent-blackbox"]
    assert updated["syncOnConnectEnabled"] is False
    assert updated["syncReconcilerEnabled"] is False
    assert updated["promoteQueue"] == {"workerConcurrency": 1, "pollIntervalMs": 1000}
    assert updated["store"] == original["store"]
    assert config_path.stat().st_mode & 0o777 == 0o640


def test_is_idempotent(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "contextGraphs": ["owner/agent-blackbox"],
                "autoApproveJoinRequests": ["owner/agent-blackbox"],
                "syncOnConnectEnabled": False,
                "syncReconcilerEnabled": False,
                "promoteQueue": {"workerConcurrency": 1, "pollIntervalMs": 1000},
            }
        ),
        encoding="utf-8",
    )
    before = config_path.read_bytes()

    assert MODULE.ensure_graph_auto_approval(config_path, "owner/agent-blackbox") is False
    assert config_path.read_bytes() == before


def test_rejects_malformed_membership_fields(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({"contextGraphs": [], "autoApproveJoinRequests": "all"}),
        encoding="utf-8",
    )

    try:
        MODULE.ensure_graph_auto_approval(config_path, "owner/agent-blackbox")
    except ValueError as error:
        assert "autoApproveJoinRequests" in str(error)
    else:
        raise AssertionError("malformed config was accepted")
