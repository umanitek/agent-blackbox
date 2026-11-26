"""``blackbox uninstall``'s steps on Blackbox's own data: the keys kept in a backup folder, the
node's Blackbox-managed Blazegraph store (its Docker container and data volume), then Blackbox's
data folders and its ``blackbox`` command deleted (see :mod:`.uninstall`).

Usage::

    store = managed_store(dkg_home)       # plan time: None unless the node's config names one
    _back_up(plan, report)
    _remove_store(plan, run, report)
    _delete_data(plan, report)
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional, Sequence

if TYPE_CHECKING:
    from .uninstall import UninstallPlan


def _back_up(plan: UninstallPlan, report: list[str]) -> None:
    """The keys (and, with --keep-logs, the audit record) moved to the backup folder — made only
    when there is something to keep (KI-611: a second uninstall made an empty one, "kept your keys")."""
    keeps_logs = plan.keep_logs and plan.blackbox_home.is_dir() and any(
        item.suffix == ".jsonl" or item.name == "sandbox" for item in plan.blackbox_home.iterdir())
    if plan.backup_dir is None or not (plan.key_files or keeps_logs):
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


#: How the DKG node's Docker provisioner names a managed Blazegraph store: the container
#: ``dkg-blazegraph-<node name>``, its volume ``<container>-data``, and a too-small one it replaced,
#: kept stopped as ``<container>-pre-4g-<time>`` (setup/blackbox-blazegraph.mjs).
STORE_PREFIX = "dkg-blazegraph-"
STORE_BACKUP_INFIX = "-pre-4g-"
DEFAULT_NODE_NAME = "agent-blackbox"


@dataclass(frozen=True)
class ManagedStore:
    """The Blazegraph store the node's provisioner made for Blackbox: a *container* and its data *volume*."""

    container: str
    volume: str


def managed_store(dkg_home: Optional[Path]) -> Optional[ManagedStore]:
    """The store *dkg_home*'s ``config.json`` says the DKG provisioner manages for it (backend
    blazegraph, ``managedByDkg``), or None — an operator's own Blazegraph is never touched."""
    if dkg_home is None:
        return None
    try:
        data = json.loads((dkg_home / "config.json").read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None
    store = data.get("store") if isinstance(data, dict) and isinstance(data.get("store"), dict) else {}
    options = store.get("options") if isinstance(store.get("options"), dict) else {}
    if store.get("backend") != "blazegraph" or options.get("managedByDkg") is not True:
        return None
    name = data.get("name") if isinstance(data.get("name"), str) and data.get("name") else DEFAULT_NODE_NAME
    container = STORE_PREFIX + name
    return ManagedStore(container=container, volume=container + "-data")


def _docker_names(run_output: Callable[[Sequence[str]], str], args: Sequence[str]) -> list[str]:
    return [line.strip() for line in run_output(["docker", *args]).splitlines() if line.strip()]


def _remove_store(plan: UninstallPlan, run: Callable[[Sequence[str]], int], report: list[str],
                  run_output: Optional[Callable[[Sequence[str]], str]] = None) -> None:
    """KI-676 (Linux round L2): the store's container (restart: unless-stopped, so back at every
    boot, a 2.5 GB JVM on 127.0.0.1:9999) and its volume outlived the uninstall. Removed here,
    with any too-small copy the provisioner kept; Docker not answering is said, never fatal."""
    store = plan.store
    if store is None:
        return
    output = run_output or _docker_output
    backups = [name for name in _docker_names(output, ["container", "ls", "--all", "--format", "{{.Names}}"])
               if name.startswith(store.container + STORE_BACKUP_INFIX)]
    failed = [name for name in (store.container, *backups) if run(["docker", "rm", "-f", name]) != 0]
    if run(["docker", "volume", "rm", "-f", store.volume]) != 0:
        failed.append(store.volume)
    if failed:
        report.append(f"could not remove the Blazegraph store's {', '.join(failed)} (is Docker running?) — "
                      f"remove with: docker rm -f {store.container}; docker volume rm {store.volume}")
    else:
        report.append(f"removed the Blazegraph store (Docker container {store.container} and its volume {store.volume})")


def _docker_output(command: Sequence[str]) -> str:
    import subprocess
    try:
        return subprocess.run(list(command), capture_output=True, text=True, encoding="utf-8", timeout=30, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _delete_data(plan: UninstallPlan, report: list[str]) -> None:
    from ..agent_hooks import spool_folder   # late: uninstall only
    targets = [plan.blackbox_home, spool_folder()]   # hook events still waiting for a dashboard that is gone
    if plan.dkg_home and plan.blackbox_home not in plan.dkg_home.parents:
        targets.append(plan.dkg_home)
    for target in targets:
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
            report.append(f"deleted {target}")
    if plan.shim:
        plan.shim.unlink(missing_ok=True)
        report.append(f"removed {plan.shim}")
