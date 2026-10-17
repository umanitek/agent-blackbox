"""One trial run: the run folder, the facts of what is under test, the steps, the report."""

from __future__ import annotations

import argparse
import json
import logging
import platform
import subprocess
import sys
from pathlib import Path
from typing import Optional

from .cluster import Cluster, ClusterOptions
from .report import StepResult, TrialReport
from .steps import STATE_FILE, STEPS, Trial, TrialState, run_stamp
from .testnet import TestnetOptions

logger = logging.getLogger(__name__)


def run_trial(args: argparse.Namespace, repo_root: Path) -> int:
    if args.until and args.until not in {key for key, _title, _needs in STEPS}:
        logger.error("unknown step %r; the steps are: %s", args.until, ", ".join(key for key, _t, _n in STEPS))
        return 2
    resumed = _load(args.resume) if args.resume else None
    stamp = resumed["state"]["stamp"] if resumed else run_stamp()
    run_dir = (args.resume or args.run_dir or Path.home() / "blackbox-one-graph-trial" / stamp).expanduser().resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    report = TrialReport(run_dir, facts=_facts(repo_root, args.dkg_repo, stamp))
    network = getattr(args, "network", "devnet")
    testnet = _testnet_options(args, stamp) if network == "testnet" else None
    report.facts["network"] = network
    cluster = Cluster(ClusterOptions(dkg_repo=args.dkg_repo.expanduser().resolve(), run_dir=run_dir,
                                     repo_root=repo_root,
                                     start_devnet=(args.start_devnet or network == "testnet") and not resumed,
                                     devnet_nodes=args.devnet_nodes, curator_node=args.curator_node,
                                     cosigner_node=args.cosigner_node, curator_settings=not args.plain_curator,
                                     network=network, testnet=testnet,
                                     cosigner_reporter=getattr(args, "cosigner_reporter", "reporter-b")))
    scale = getattr(args, "timeout_scale", 0.0) or (2.0 if network == "testnet" else 1.0)
    report.facts["timeout_scale"] = scale
    if network == "testnet":
        report.facts["curator_1_node"] = f"{getattr(args, 'cosigner_reporter', 'reporter-b')}'s node"
    if getattr(args, "keep_going", False):
        report.facts["keep_going"] = True
    state = TrialState(stamp=stamp)
    if resumed:
        state = TrialState.from_json(resumed["state"])
        cluster.restore(resumed["cluster"])
        report.facts.update({key: value for key, value in resumed["facts"].items() if key not in report.facts})
        report.facts["resumed_runs"] = int(resumed["facts"].get("resumed_runs") or 0) + 1
        report.steps = [step for step in resumed["steps"] if step.passed]
        logger.info("resuming %s after: %s", run_dir, ", ".join(step.key for step in report.steps) or "nothing")
    logger.info("run folder: %s", run_dir)
    try:
        Trial(cluster, report, state, until=args.until or None, timeout_scale=scale,
              keep_going=getattr(args, "keep_going", False)).run()
    finally:
        if args.stop_devnet:
            cluster.stop_devnet()
        if cluster.links is not None:
            report.facts["links"] = cluster.links.summary()
        if network == "testnet":
            report.facts["node_logs"] = cluster.devnet.collect_logs(run_dir / "node-logs")
        report.write()
    for step in report.steps:
        logger.info("%-9s %-5s %s", step.key, step.status, step.summary)
    logger.info("report: %s", run_dir / "report.md")
    return 0 if report.ok else 1


def _testnet_options(args: argparse.Namespace, stamp: str) -> TestnetOptions:
    """The testnet nodes' homes, ports, wallets and lock from the command line (a resumed
    run keeps its stamp, so it finds the same homes)."""
    homes = (args.node_homes or Path.home() / ".dkg-bbtrial" / stamp).expanduser().resolve()
    indexes = tuple(int(part) for part in str(args.wallet_indexes or "").split(",") if part.strip())
    return TestnetOptions(homes=homes, api_port_base=args.api_port_base, store_port_base=args.store_port_base,
                          wallet_source=args.wallet_source.expanduser().resolve() if args.wallet_source else None,
                          wallet_indexes=indexes, node_bin=args.node_bin,
                          machine_lock=args.machine_lock.expanduser() if args.machine_lock else None,
                          oxigraph_seed=args.oxigraph_seed.expanduser() if args.oxigraph_seed else None)


def _load(run_dir: Path) -> Optional[dict]:
    """A run folder's saved state and report, to resume it."""
    folder = run_dir.expanduser().resolve()
    saved = json.loads((folder / STATE_FILE).read_text(encoding="utf-8-sig"))
    written = json.loads((folder / "report.json").read_text(encoding="utf-8-sig"))
    fields = set(StepResult.__dataclass_fields__)
    steps = [StepResult(**{key: value for key, value in step.items() if key in fields}) for step in written["steps"]]
    return {"state": saved["state"], "cluster": saved["cluster"], "facts": written.get("facts") or {}, "steps": steps}


def _facts(repo_root: Path, dkg_repo: Path, stamp: str) -> dict:
    return {
        "blackbox_commit": _git(repo_root, "rev-parse", "HEAD"),
        "blackbox_branch": _git(repo_root, "rev-parse", "--abbrev-ref", "HEAD"),
        "blackbox_dirty": bool(_git(repo_root, "status", "--porcelain", "--untracked-files=no")),
        "dkg_commit": _git(dkg_repo, "rev-parse", "HEAD"),
        "python": sys.version.split()[0],
        "platform": platform.platform(terse=True),
        "run_stamp": stamp,
    }


def _git(where: Path, *args: str) -> str:
    try:
        command = ["git", "-C", str(where.expanduser()), *args]
        completed = subprocess.run(command, capture_output=True, stdin=subprocess.DEVNULL, timeout=30, check=False,
                                   text=True, encoding="utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout.strip() if completed.returncode == 0 else ""
