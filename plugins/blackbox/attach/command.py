"""``blackbox attach`` / ``blackbox detach`` — and the report rows they print.

``blackbox attach`` joins only the agents the operator chooses: the homes named on the
command line, or every discovered agent after ``--all`` or a "yes" at the terminal. Run
bare with no terminal (a script, a pipe), it lists what it found and attaches nothing —
every Hermes profile is its own trust and credential boundary.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Optional
from .. import attach

#: What a bare ``blackbox attach`` tells an operator it could not ask.
_HOW_TO_CHOOSE = ("Name the agents to protect:  blackbox attach <hermes-home-or-openclaw-workspace> ...\n"
                  "or protect every one listed:  blackbox attach --all")


def add_attach_parsers(sub: argparse._SubParsersAction) -> None:
    """Register ``blackbox attach`` and ``blackbox detach`` on the CLI's sub-parsers
    (called once by ``cli.setup_cli``); the parsed namespaces go to :func:`cmd_attach`
    and :func:`cmd_detach`. The stored names (``attach_homes``, ``attach_every_agent``)
    are never one Hermes reads before it dispatches (LES-035)."""
    attach_p = sub.add_parser(
        "attach", help="Protect the Hermes homes / OpenClaw workspaces you name (or --all)",
        description="Protect the agents you choose. Name each Hermes home or OpenClaw workspace, or use "
                    "--all for every one on this machine. Run bare on a terminal, it lists them and asks.",
    )
    attach_p.add_argument("attach_homes", nargs="*", metavar="HOME",
                          help="A Hermes home (e.g. ~/.hermes, ~/.hermes/profiles/work) or OpenClaw workspace")
    attach_p.add_argument("--all", dest="attach_every_agent", action="store_true",
                          help="Protect every Hermes home and OpenClaw workspace found on this machine")
    attach_p.add_argument("--dry-run", action="store_true", help="Show what would change; write nothing")
    attach_p.add_argument("--hermes-only", action="store_true", help="Only attach to Hermes homes")
    attach_p.add_argument("--openclaw-only", action="store_true", help="Only attach to OpenClaw workspaces")
    attach_p.set_defaults(func=cmd_attach)

    detach_p = sub.add_parser("detach", help="Disable Blackbox in every local agent")
    detach_p.add_argument("--dry-run", action="store_true", help="Show what would change; write nothing")
    detach_p.add_argument("--remove-files", action="store_true", help="Also delete copied plugin files")
    detach_p.add_argument("--hermes-only", action="store_true", help="Only detach from Hermes homes")
    detach_p.add_argument("--openclaw-only", action="store_true", help="Only detach from OpenClaw workspaces")
    detach_p.set_defaults(func=cmd_detach)


def cmd_attach(args: argparse.Namespace) -> int:
    """Attach the named homes, or every discovered agent on ``--all`` / a terminal "yes".
    Exit 0 when everything asked for is protected (or the operator said no), 1 when a
    named path is not an agent, an attach failed, or there was no terminal to ask on."""
    kinds = {"hermes": not args.openclaw_only, "openclaw": not args.hermes_only}
    named = list(getattr(args, "attach_homes", None) or [])
    if named and args.attach_every_agent:
        print("Name agents OR use --all, not both.")
        return 2
    if named:
        report = attach.attach_named(named, dry_run=args.dry_run, **kinds)
    elif args.attach_every_agent or args.dry_run:
        report = attach.attach_all(dry_run=args.dry_run, explicit=True, **kinds)
    else:
        choice = _confirm_every_agent(kinds)
        if choice != "yes":
            return 1 if choice == "no-terminal" else 0
        report = attach.attach_all(explicit=True, **kinds)
    return _print_attach_report(report, dry_run=args.dry_run)


def _confirm_every_agent(kinds: dict[str, bool]) -> str:
    """List every discovered agent and ask whether to protect the ones not protected yet.
    Returns ``"yes"``, ``"no"``, ``"nothing-to-do"`` or ``"no-terminal"``."""
    found = attach.attach_all(dry_run=True, explicit=True, **kinds)
    rows = found.get("hermes", []) + found.get("openclaw", [])
    waiting = [row for row in rows if not row.get("protected")]
    if not rows:
        print("No Hermes home or OpenClaw workspace found on this machine.")
    elif not waiting:
        print(f"All {len(rows)} agent(s) found are protected.")
    if not waiting:
        return "nothing-to-do"
    print(f"Found {len(rows)} agent(s):")
    for row in rows:
        print(f"  - {row.get('target')} ({row.get('kind')}, {_protection_state(row)})")
    answer = _ask_terminal(f"Protect the {len(waiting)} not protected yet? [y/N] ")
    if answer is None:
        print("\nNo terminal to ask on, so nothing was changed.\n" + _HOW_TO_CHOOSE)
        return "no-terminal"
    if answer.strip().lower() in {"y", "yes"}:
        return "yes"
    print("Nothing changed.\n" + _HOW_TO_CHOOSE)
    return "no"


def _protection_state(row: dict[str, Any]) -> str:
    if row.get("protected"):
        return "protected"
    if attach.is_declined(str(row.get("kind")), str(row.get("target"))):
        return "switched off by you"
    return "not protected"


def _ask_terminal(prompt: str) -> Optional[str]:
    """Ask on the operator's terminal; None when there is none. Under ``curl … | bash`` stdin is
    the pipe, so the controlling terminal is opened directly (POSIX ``/dev/tty``)."""
    if sys.stdin is not None and sys.stdin.isatty():
        try:
            return input(prompt)
        except EOFError:
            return None
    if os.name == "nt":
        return None
    try:
        with open("/dev/tty", "r+", encoding="utf-8") as tty:
            tty.write(prompt)
            tty.flush()
            return tty.readline()
    except OSError:
        return None


def _print_attach_report(report: dict[str, Any], *, dry_run: bool) -> int:
    prefix = "Would protect" if dry_run else "Protected"
    for row in report.get("hermes", []):
        print_hermes_attach_row(row, prefix)
    for row in report.get("openclaw", []):
        print_openclaw_attach_row(row, prefix)
    for path in report.get("unknown", []):
        print(f"  ! {path}: not a Hermes home or OpenClaw workspace — nothing changed")
    count = report.get("count", 0)
    if dry_run:
        print(f"\nDry run: Blackbox would watch {count} agent(s). Nothing was written.")
    else:
        print(f"\nBlackbox is watching {count} agent(s). Restart any running agent to activate.")
    failed = any(row.get("error") for group in ("hermes", "openclaw") for row in report.get(group, []))
    return 1 if failed or report.get("unknown") else 0


def cmd_detach(args: argparse.Namespace) -> int:
    do_hermes = not args.openclaw_only
    do_openclaw = not args.hermes_only
    report = attach.detach_all(
        hermes=do_hermes, openclaw=do_openclaw, remove_files=args.remove_files, dry_run=args.dry_run
    )
    prefix = "Would detach" if args.dry_run else "Detached"
    for row in report.get("hermes", []):
        if row.get("error"):
            print(f"  ! {row['target']} (hermes): {row['error']}")
        elif row.get("already") and not row.get("removed"):
            print(f"  - {row['target']} (hermes): already detached")
        else:
            extra = ", files removed" if row.get("removed") else ""
            print(f"  {prefix} {row['target']} (hermes){extra}")
    for row in report.get("openclaw", []):
        if row.get("error"):
            print(f"  ! {row['target']} (openclaw): {row['error']}")
        elif row.get("already"):
            print(f"  - {row['target']} (openclaw): already detached")
        else:
            note = f"  note: {row['note']}" if row.get("note") else ""
            print(f"  {prefix} {row['target']} (openclaw){note}")
    print("\nBlackbox detached. Restart any running agent to apply.")
    failed = any(row.get("error") for group in ("hermes", "openclaw") for row in report.get(group, []))
    return 1 if failed else 0   # like `attach`: a target that failed is a failed command


def print_hermes_attach_row(row: dict[str, Any], prefix: str) -> None:
    if row.get("error"):
        print(f"  ! {row['target']} (hermes): {row['error']}")
        return
    if row.get("already") and not row.get("copied"):
        print(f"  - {row['target']} (hermes): already protected")
        return
    bits = []
    if row.get("copied"):
        bits.append("plugin copied")
    if row.get("enabled"):
        bits.append("enabled")
    elif row.get("already"):
        bits.append("already enabled")
    detail = f" ({', '.join(bits)})" if bits else ""
    print(f"  {prefix} {row['target']} (hermes){detail}")


def print_openclaw_attach_row(row: dict[str, Any], prefix: str) -> None:
    if row.get("error"):
        print(f"  ! {row['target']} (openclaw): {row['error']}")
        return
    if row.get("already"):
        print(f"  - {row['target']} (openclaw): already protected")
        return
    note = f"  note: {row['note']}" if row.get("note") else ""
    print(f"  {prefix} {row['target']} (openclaw){note}")
