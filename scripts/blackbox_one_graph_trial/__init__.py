"""The one-graph trial of Agent Blackbox on a DKG devnet (``scripts/blackbox-one-graph-trial.py``).

* :mod:`.cli` — the command line (``run``; ``actor`` for the trial's own use).
* :mod:`.runner` — sets up the run folder and the cluster, runs the steps, writes the report.
* :mod:`.cluster` — the devnet nodes and the Blackbox actors bound to them.
* :mod:`.devnet` — OriginTrail/dkg's ``scripts/devnet.sh`` and the nodes' HTTP API.
* :mod:`.steps` — the trial's steps and what each must show.
* :mod:`.actors` / :mod:`.actor_actions` — one process per Blackbox role, and what it can do.
* :mod:`.report` — the step results, written as ``report.json`` and ``report.md``.
"""
