"""The one-graph devnet trial (``scripts/blackbox-one-graph-trial.py``): the parts that run without a devnet.

* A devnet Edge node gets Blackbox's node settings from the checked-out code — the
  installer's own config writer and ``sync/node_profile.py``'s native profile —
  while the keys that make it a node of THAT network stay the devnet's.
* The trial's report never carries a secret-named field, whatever an actor returned.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))   # the trial's package sits in scripts/

from blackbox_one_graph_trial import actor_actions
from blackbox_one_graph_trial.report import PASS, StepResult, TrialReport

from plugins.blackbox.sync import node_profile

DEVNET_CONFIG = {
    "name": "devnet-node-7", "apiPort": 9207, "listenPort": 10007, "nodeRole": "edge", "networkConfig": "devnet",
    "relayPeers": ["/ip4/127.0.0.1/tcp/10001/p2p/12D3KooWRelay"],
    "chain": {"type": "evm", "rpcUrl": "http://127.0.0.1:8545", "chainId": "evm:31337"},
    "store": {"backend": "oxigraph-server", "options": {"port": 7887}}, "auth": {"enabled": True},
    "syncReconcilerEnabled": True,
}


def _settings(tmp_path: Path, monkeypatch) -> dict:
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "config.json").write_text(json.dumps(DEVNET_CONFIG), encoding="utf-8")
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "blackbox"))
    return actor_actions.node_settings({"staging_home": str(staging), "graph": "0xabc/bb-trial",
                                        "installer": str(REPO / "plugins/blackbox/setup/blackbox-install.sh")})


def test_edge_keeps_the_devnets_network_keys(tmp_path, monkeypatch):
    config = _settings(tmp_path, monkeypatch)["config"]

    for key in ("networkConfig", "chain", "relayPeers", "apiPort", "listenPort", "name", "store", "nodeRole"):
        assert config[key] == DEVNET_CONFIG[key], key


def test_edge_takes_the_native_profile_from_the_checked_out_code(tmp_path, monkeypatch):
    settings = _settings(tmp_path, monkeypatch)
    config, env = settings["config"], settings["env"]

    for env_name, value in node_profile._DKG_NATIVE_SYNC_SETTINGS.items():
        key = node_profile._DKG_CONFIG_SYNC_SETTINGS[env_name]
        expected = int(value) if key in node_profile._INTEGER_CONFIG_KEYS else value == "1"
        assert config[key] == expected, key
        assert env[env_name] == value, env_name
    for env_name in node_profile._DKG_ENV_ONLY_SETTINGS:
        assert env_name in env, env_name   # a launch-environment-only switch must reach the launch environment
    assert config["syncContextGraphPriorities"]["0xabc/bb-trial"] > 0


def test_report_drops_secret_named_fields(tmp_path):
    report = TrialReport(tmp_path, facts={"api_token": "t0ken", "network_id": "devnet"})
    report.add(StepResult("keys", "keys", PASS, evidence={"root_key": "ab" * 32, "private_key": "secret-pem",
                                                          "nested": {"authToken": "t0ken", "peer": "12D3"}}))

    written = "".join((tmp_path / name).read_text(encoding="utf-8-sig") for name in ("report.json", "report.md"))
    assert "t0ken" not in written and "secret-pem" not in written
    assert "ab" * 32 in written and "12D3" in written and "devnet" in written
