"""Command line of the one-graph trial: ``run`` (the trial) and ``actor`` (one Blackbox call).

``run`` is what an operator types; ``actor`` is how the trial runs Blackbox
code in a role's own process (:mod:`.actors`) and is not meant for people.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="blackbox-one-graph-trial",
                                     description="End-to-end trial of Agent Blackbox's one-graph flow on a DKG devnet "
                                                 "or on the public testnet.")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run the trial and write its report")
    run.add_argument("--dkg-repo", type=Path, required=True,
                     help="checkout of OriginTrail/dkg (built) whose scripts/devnet.sh runs the devnet")
    run.add_argument("--run-dir", type=Path, default=None,
                     help="where the report, the actors' homes and the logs go "
                          "(default: ~/blackbox-one-graph-trial/<stamp>)")
    run.add_argument("--start-devnet", action="store_true",
                     help="start the devnet first (scripts/devnet.sh start); otherwise attach to the running one")
    run.add_argument("--devnet-nodes", type=int, default=6, help="node count for --start-devnet (default 6)")
    run.add_argument("--stop-devnet", action="store_true", help="stop the devnet when the trial ends")
    run.add_argument("--curator-node", type=int, default=0,
                     help="the devnet node that creates and owns the graph (default: the first Edge node)")
    run.add_argument("--cosigner-node", type=int, default=0,
                     help="the node curator 1 works through (default: another node than the curator's)")
    run.add_argument("--resume", type=Path, default=None, metavar="RUN_DIR",
                     help="continue an earlier run in RUN_DIR on the same devnet, "
                          "from its first step that did not pass")
    run.add_argument("--until", default="", metavar="STEP",
                     help="stop after this step (e.g. `keys` to set up a devnet, graph and keys only)")
    run.add_argument("--plain-curator", action="store_true",
                     help="leave the curator node's settings as devnet.sh made them "
                          "(default: Blackbox's curator settings, scripts/blackbox-curator-config.py)")
    run.add_argument("--network", choices=("devnet", "testnet"), default="devnet",
                     help="devnet (default): a scripts/devnet.sh devnet; testnet: the trial's own nodes on the "
                          "public testnet, built from --dkg-repo, reaching each other only through its relays")
    run.add_argument("--node-homes", type=Path, default=None,
                     help="testnet: where the nodes' homes go (they hold keys; default ~/.dkg-bbtrial/<stamp>)")
    run.add_argument("--wallet-source", type=Path, default=None,
                     help="testnet: a funded node's home; the curator node pays with some of its operational "
                          "wallets (copied encrypted, never read)")
    run.add_argument("--wallet-indexes", default="2,1",
                     help="testnet: which operational wallets of --wallet-source, first = the curator's agent "
                          "(default 2,1; never 0, the source node's own agent)")
    run.add_argument("--api-port-base", type=int, default=19360, help="testnet: node n's API on base + n")
    run.add_argument("--store-port-base", type=int, default=47960, help="testnet: node n's Oxigraph on base + n")
    run.add_argument("--node-bin", default="node", help="testnet: the Node.js binary that runs cli.js")
    run.add_argument("--machine-lock", type=Path, default=None,
                     help="testnet: a lock directory the sessions sharing this machine agree on, held while the "
                          "trial's nodes run")
    run.add_argument("--oxigraph-seed", type=Path, default=None,
                     help="testnet: a managed Oxigraph binary of another node, copied into each new node "
                          "(checked against the node's pinned checksum) instead of a download")
    run.add_argument("--keep-going", action="store_true",
                     help="run every step even when a step it needs did not pass (default: SKIP it)")
    run.add_argument("--cosigner-reporter", default="reporter-b", choices=("reporter-a", "reporter-b"),
                     help="testnet: the reporter whose node curator 1 works through (default reporter-b)")
    run.add_argument("--timeout-scale", type=float, default=0.0,
                     help="multiply every wait (default 1 on a devnet, 2 on the testnet)")
    run.add_argument("--verbose", action="store_true")
    actor = sub.add_parser("actor", help=argparse.SUPPRESS)
    actor.add_argument("action")
    actor.add_argument("--params", default="{}")
    return parser


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    sys.path.insert(0, str(REPO_ROOT))   # Blackbox itself: plugins.blackbox of this checkout
    if args.command == "actor":
        from .actor_actions import main as actor_main

        return actor_main(args.action, json.loads(args.params), REPO_ROOT)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)
    from .runner import run_trial

    return run_trial(args, REPO_ROOT)
