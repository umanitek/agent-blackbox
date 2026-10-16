#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "cryptography>=46,<51",
#   "psutil>=7,<8",
#   "pyyaml>=6,<7",
#   "ruamel.yaml>=0.18,<0.19",
# ]
# ///
"""End-to-end trial of Agent Blackbox's one-graph flow on a DKG devnet.

Brings up (or attaches to) an OriginTrail DKG devnet, creates one public
context graph registered on chain with a curated publish policy and owned by
a curator node, starts Edge nodes with Blackbox's node settings, and drives
Blackbox's own Python code on each of them: a reporter files a report into the
graph's shared memory, another reporter's community reader returns it, the
curators promote it to Verified Memory with their two-signature statement,
every reporter's ruleset compiles it as a verified rule, a reporter that joins
later gets the reports and the rule, and a node restart keeps them.

Run it from a checkout of this repository, on a machine that may run a devnet::

    uv run scripts/blackbox-one-graph-trial.py --dkg-repo ~/dkg --start-devnet

The report lands in the run folder (``report.md`` and ``report.json``); the
exit code is 0 only when every step passed. ``--help`` lists the options;
the README section "One-graph trial" in ``plugins/blackbox/README.md`` says more.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))   # the trial's package sits beside this script

from blackbox_one_graph_trial.cli import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
