"""``blackbox setup`` — the full Blackbox install after a Hermes plugin-catalog install.

`hermes plugins install blackbox` copies the plugin only. This command finishes the
job with the same installer `curl blackbox.umanitek.ai | bash` runs: an identical
copy of ``scripts/blackbox-install.sh`` (and the Windows ``.ps1``) ships in this
folder, with the two helper scripts it calls, and runs in its setup-only mode —
everything after Hermes, in the Hermes this command runs in: the DKG node and its
login service, the verified and community graphs, attaching every local agent, the
first sync, the dashboard. ``tests/plugins/test_blackbox_setup.py`` keeps the
copies byte-identical to ``scripts/`` (copy them over after changing the originals).

What it downloads is pinned (Hermes plugin catalog rule 17): the DKG node is
:data:`DKG_PACKAGE`, checked against :data:`DKG_INTEGRITY` before npm installs it;
the store image is pinned by digest inside that DKG release.

Usage::

    hermes blackbox setup                  # or: blackbox setup
    hermes blackbox setup --store oxigraph  # no Docker
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from ..kernel import constants

#: The DKG node release a plugin-catalog setup installs, and the npm integrity hash it must have.
DKG_PACKAGE = "@origintrail-official/dkg@10.0.26"
DKG_INTEGRITY = "sha512-QlCW/5UvL2UHaR2QGAemQzvu+ZtBKfefwuitoX2hGr/XZAgkFXsln1NHitzftQM99qTrlKBq8CFfDSfDFAbMHg=="

HERE = Path(__file__).resolve().parent
PLUGIN_DIR = HERE.parent
STORES = ("auto", "blazegraph", "oxigraph", "native")

__all__ = ["DKG_INTEGRITY", "DKG_PACKAGE", "add_setup_parser", "cmd_setup", "setup_environment"]


def _hermes_bin() -> str:
    """The `hermes` of the environment this command runs in, else the one on PATH."""
    beside = Path(sys.executable).with_name("hermes.exe" if os.name == "nt" else "hermes")
    return str(beside) if beside.is_file() else (shutil.which("hermes") or "")


def _revision() -> str:
    """The commit this plugin was installed from (the catalog's pin), else its version."""
    try:
        sidecar = json.loads((PLUGIN_DIR / ".hermes-catalog.json").read_text(encoding="utf-8-sig"))
        if sidecar.get("sha"):
            return str(sidecar["sha"])
    except (OSError, ValueError):
        pass
    return f"plugin-{constants.__version__}"


def setup_environment(base: dict[str, str] | None = None) -> dict[str, str]:
    """The environment the installer runs with: setup-only mode in this Hermes, pinned DKG.

    *base* defaults to this process's environment; the keys set here always win.
    """
    env = dict(os.environ if base is None else base)
    env.update({
        "BLACKBOX_SETUP_ONLY": "true",
        "HERMES_BIN": _hermes_bin(),
        "VENV_DIR": sys.prefix,
        "HERMES_HOME": str(constants.hermes_home()),
        "BLACKBOX_INSTALL_DIR": str(constants.blackbox_home() / "node"),
        "BLACKBOX_HELPER_DIR": str(HERE),
        "BLACKBOX_PLUGIN_DIR": str(PLUGIN_DIR),
        "BLACKBOX_REVISION": _revision(),
        "BLACKBOX_DKG_PACKAGE": DKG_PACKAGE,
        "BLACKBOX_DKG_INTEGRITY": DKG_INTEGRITY,
    })
    return env


def _installer_command(store: str) -> list[str]:
    if os.name == "nt":
        return ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                str(HERE / "blackbox-install.ps1"), "-StoreBackend", store]
    return ["bash", str(HERE / "blackbox-install.sh"), "--store", store]


def cmd_setup(args: argparse.Namespace) -> int:
    """Run the installer in setup-only mode; its exit code is this command's."""
    if not _hermes_bin():
        print("error: cannot find the hermes command this plugin runs in.")
        return 1
    from . import sync_profile
    try:
        sync_profile.configure(args)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}")
        return 1
    store = getattr(args, "store", None) or "auto"
    print(f"Blackbox setup: the DKG node ({DKG_PACKAGE}), the verified graph and its community reports, every local agent, "
          "the dashboard. This takes a few minutes.")
    # The installer asks its questions on the terminal itself (/dev/tty), never on stdin.
    completed = subprocess.run(_installer_command(store), env=setup_environment(), stdin=subprocess.DEVNULL, check=False)
    return completed.returncode


def add_setup_parser(sub: argparse._SubParsersAction) -> None:
    """Register ``blackbox setup`` on the `blackbox` command's sub-parsers."""
    parser = sub.add_parser("setup", help="Finish a plugin-catalog install: DKG node, threat graphs, agents, dashboard")
    parser.add_argument("--store", choices=STORES, default=None,
                        help="the node's store: auto (default), blazegraph (Docker) oxigraph (no Docker), or native (experimental fresh bootstrap)")
    parser.add_argument("--snapshot-graph-id", help="Registered numeric graph ID for core-cache sync (requires trusted cores)")
    parser.add_argument("--trusted-core-peer", action="append", help="Explicit trusted core peer; repeat for up to four cores")
    parser.add_argument("--dkg-core-chain-cache", action="store_true",
                        help="Lower RPC usage by using the DKG Core chain cache (official chains in the selected mainnet or testnet)")
    parser.add_argument("--registered-cores", action="store_true",
                        help="Legacy Base-only registered-core policy; use --dkg-core-chain-cache for all official chains")
    parser.set_defaults(func=cmd_setup)
