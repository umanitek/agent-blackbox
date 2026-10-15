#!/usr/bin/env python3
"""Opt-in local consumer probe against a prepared DKG node and public fixture graph.

Uses a temporary profile and the actual sync/read/detection functions. The node
must serve the snapshot-sync and bounded-query capabilities. Fixture graph must
contain a confirmed IocSignal for 1.fixture.invalid. No URL is visited or command
executed. Run only against an isolated disposable node; this starts a sync job.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tests" / "plugins")]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--graph", required=True)
    parser.add_argument("--on-chain-id", required=True)
    parser.add_argument("--core-peer", required=True)
    parser.add_argument("--dkg-home", required=True, help="Isolated receiver home containing its operator token")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="blackbox-core-cache-probe-") as home:
        os.environ["HERMES_HOME"] = home
        os.environ["BLACKBOX_HOME"] = str(Path(home) / "blackbox")
        from _blackbox_loader import load_blackbox
        config = load_blackbox("kernel.config")
        settings = load_blackbox("kernel.snapshot_config")
        sync = load_blackbox("sync.core_snapshot")
        reader = load_blackbox("ruleset.direct.reader")
        detection = load_blackbox("detection")
        cfg = config.BlackboxConfig(detection_backend="dkg", context_graph_id=args.graph,
            dkg_url=args.url, dkg_home=args.dkg_home, community_graph_id="",
            snapshot_sync=settings.SnapshotSyncConfig(args.on_chain_id, (args.core_peer,)))
        sync.POLL_SECONDS = 0.1
        outcome = sync.run(sync.SnapshotSyncClient(cfg), cfg,
                           argparse.Namespace(wait=True, require_rules=True, timeout=120))
        assert outcome == 0, "Snapshot job or usable-rule readiness failed"
        payload = {"url": "https://1.fixture.invalid/"}
        read = reader.read_for_action(cfg, "browser", payload)
        assert read.state == "available", read.code
        positive = detection.detect_all("browser", payload, read.rules, discover=False)
        assert positive and any(item.confirmed for item in positive)
        negative_payload = {"url": "https://benign.invalid/"}
        negative = reader.read_for_action(cfg, "browser", negative_payload)
        assert negative.state == "available", negative.code
        assert not detection.detect_all("browser", negative_payload, negative.rules, discover=False)
        assert not list(Path(home).rglob("ruleset.json"))
        print(json.dumps({"consumerProbe": "pass", "positiveConfirmed": True,
                          "benignNegative": True, "rulesExportCreated": False,
                          "chainEvidenceMode": read.evidence()["chain_evidence_mode"]}))


if __name__ == "__main__":
    main()
