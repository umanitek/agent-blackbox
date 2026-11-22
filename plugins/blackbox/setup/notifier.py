"""``blackbox notifications`` — the plugin's own native notifier, from the command line.

* ``blackbox notifications setup [--from <archive> --sha256 <hex>]`` — put Blackbox's notifier in
  place (macOS: ``Blackbox.app`` from the verified archive; the system then asks once whether
  Blackbox may show notifications). Without an archive nothing is installed and the system's
  own notifier is used. The installer runs this step; it never fails an install.
* ``blackbox notifications status`` — what is in use and whether you allowed it.
* ``blackbox notifications test`` — show one harmless notification now.

Removal needs no command: the notifier lives in Blackbox's own data folder
(``$BLACKBOX_HOME/notifier``), which ``blackbox uninstall`` removes.
"""

from __future__ import annotations

import argparse
from pathlib import Path


def cmd_notifications(args: argparse.Namespace) -> int:
    from .. import notify   # late: the dashboard's packages load only when this command runs
    action = getattr(args, "notifications_command", None) or "status"
    if action == "setup":
        source = Path(args.source).expanduser() if args.source else None
        try:
            status = notify.install_notifier(source, (args.sha256 or "").strip().lower())
        except ValueError as problem:
            print(f"Blackbox's notifier was not installed: {problem}")
            return 1
        print(f"Notifications: {status.detail}")
        return 0
    if action == "test":
        shown = notify.send_test()
        print("A test notification was shown." if shown else f"It could not be shown: {notify.notifier_status().detail}")
        return 0 if shown else 1
    status = notify.notifier_status()
    print(f"Notifications: {status.detail}")
    print(f"  notifier: {status.kind} · permission: {status.permission}")
    return 0


def add_notifications_parser(sub: argparse._SubParsersAction) -> None:
    """Register ``blackbox notifications`` on the ``blackbox`` command's sub-parsers."""
    parser = sub.add_parser("notifications", help="Blackbox's native notifications: set up, status, test")
    actions = parser.add_subparsers(dest="notifications_command")
    setup = actions.add_parser("setup", help="Install Blackbox's own notifier from a verified archive")
    setup.add_argument("--from", dest="source", help="the notifier archive (macOS: blackbox-notify-darwin.zip)")
    setup.add_argument("--sha256", help="the archive's SHA-256 (64 hex characters)")
    actions.add_parser("status", help="What shows Blackbox's notifications, and whether you allowed it")
    actions.add_parser("test", help="Show one harmless notification now")
    parser.set_defaults(func=cmd_notifications)
