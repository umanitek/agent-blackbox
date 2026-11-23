"""``blackbox uninstall``'s steps on Blackbox's own data: the keys kept in a backup folder, then
Blackbox's data folders and its ``blackbox`` command deleted (see :mod:`.uninstall`).

Usage::

    _back_up(plan, report)
    _delete_data(plan, report)
"""

from __future__ import annotations

import os
import shutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .uninstall import UninstallPlan


def _back_up(plan: UninstallPlan, report: list[str]) -> None:
    if plan.backup_dir is None:
        return
    keys = plan.backup_dir / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    os.chmod(plan.backup_dir, 0o700)
    for src in plan.key_files:
        dest = keys / ("node-" + src.name if plan.dkg_home and src.parent == plan.dkg_home else src.name)
        shutil.copy2(src, dest)
        os.chmod(dest, 0o600)
    if plan.keep_logs and plan.blackbox_home.is_dir():
        logs = plan.backup_dir / "audit-record"
        logs.mkdir(exist_ok=True)
        for item in plan.blackbox_home.iterdir():
            if item.suffix == ".jsonl" or item.name == "sandbox":
                (shutil.copytree if item.is_dir() else shutil.copy2)(item, logs / item.name)
    (plan.backup_dir / "README.txt").write_text(_BACKUP_README, encoding="utf-8")
    report.append(f"kept your keys in {plan.backup_dir}")


_BACKUP_README = """\
Kept by `blackbox uninstall` (delete this folder when you no longer need it).

keys/node-*               your Blackbox DKG node's identity and operational wallet
                          (agent-keystore.json, wallets.json, wallets.key, auth.token, config.json)
keys/reporter_key.pem     the key that signed your community threat reports
keys/sharing_consent.json your community-sharing consent record
audit-record/             your local audit record, if you ran uninstall with --keep-logs

To use the same node identity again after reinstalling Blackbox: stop the Blackbox DKG node,
copy keys/node-<name> back into its DKG home (dropping the "node-" prefix), copy
reporter_key.pem and sharing_consent.json into ~/.hermes/blackbox, then start the node.
These files are secrets: keep this folder private.
"""


def _delete_data(plan: UninstallPlan, report: list[str]) -> None:
    targets = [plan.blackbox_home]
    if plan.dkg_home and plan.blackbox_home not in plan.dkg_home.parents:
        targets.append(plan.dkg_home)
    for target in targets:
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
            report.append(f"deleted {target}")
    if plan.shim:
        plan.shim.unlink(missing_ok=True)
        report.append(f"removed {plan.shim}")
