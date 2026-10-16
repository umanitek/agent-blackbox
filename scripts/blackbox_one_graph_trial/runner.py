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
    cluster = Cluster(ClusterOptions(dkg_repo=args.dkg_repo.expanduser().resolve(), run_dir=run_dir,
                                     repo_root=repo_root, start_devnet=args.start_devnet and not resumed,
                                     devnet_nodes=args.devnet_nodes, curator_node=args.curator_node,
                                     cosigner_node=args.cosigner_node, curator_settings=not args.plain_curator))
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
        Trial(cluster, report, state, until=args.until or None, assist=not args.no_assist).run()
    finally:
        if args.stop_devnet:
            cluster.stop_devnet()
        report.write()
    for step in report.steps:
        logger.info("%-9s %-5s %s", step.key, step.status, step.summary)
    logger.info("report: %s", run_dir / "report.md")
    return 0 if report.ok else 1


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
