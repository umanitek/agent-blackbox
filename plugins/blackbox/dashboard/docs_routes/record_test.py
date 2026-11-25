"""Record one test run in the agent registry — the command a VM test run ends with.

Run from a checkout (it writes the registry and the generated coverage page beside the code)::

    python -m plugins.blackbox.dashboard.docs_routes.record_test \\
        --agent codex --os macos --os-version "macOS 26.6.2" --launch interactive --layer hooks \\
        --agent-version 0.171.0 --result pass \\
        --how "test VM: Codex's own hook command with its documented payloads; refusals in Block and Audit"

``--date`` defaults to today (UTC) and ``--blackbox`` to this checkout's version. The row for the
same OS, launch mode and layer is replaced; commit the two changed files with the run's report.
"""

from __future__ import annotations

import argparse
import sys
import time

from ...kernel import constants
from . import agent_registry


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="record_test", description="Record one test run in the agent registry.")
    parser.add_argument("--agent", required=True, help="the agent's id, e.g. claude-code")
    parser.add_argument("--os", required=True, choices=("macos", "linux", "windows"))
    parser.add_argument("--os-version", default="", help='e.g. "macOS 26.6.2"')
    parser.add_argument("--launch", required=True, help="the launch mode that was run, e.g. interactive")
    parser.add_argument("--layer", required=True, choices=agent_registry.LAYERS)
    parser.add_argument("--agent-version", default="", help="the agent's own --version answer")
    parser.add_argument("--result", required=True, choices=agent_registry.RESULTS)
    parser.add_argument("--how", required=True, help="what was run, in a sentence")
    parser.add_argument("--date", default=time.strftime("%Y-%m-%d", time.gmtime()))
    parser.add_argument("--blackbox", default=constants.__version__)
    args = parser.parse_args(argv)
    run = agent_registry.TestRun(agent=args.agent, os=args.os, launch=args.launch, layer=args.layer,
                                 agent_version=args.agent_version, os_version=args.os_version, blackbox=args.blackbox,
                                 date=args.date, how=args.how, result=args.result)
    try:
        agent_registry.save(agent_registry.record_test(agent_registry.load(), run))
    except ValueError as exc:
        print(f"not recorded: {exc}", file=sys.stderr)
        return 2
    print(f"recorded: {run.agent} {run.agent_version or '(version not given)'} · {run.os} · {run.launch} · {run.layer} · {run.result}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
