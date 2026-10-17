"""OriginTrail/dkg's local devnet, as the trial uses it: ``scripts/devnet.sh`` and the nodes' HTTP API.

What the trial relies on (``scripts/devnet.sh`` on testnet-canary, Oct 2026):

* ``start [N]`` — a Hardhat chain and N nodes; the first ``NUM_CORE_NODES``
  (4) are Cores, the rest Edges. Node *n* answers on ``9200 + n``
  (``API_PORT_BASE``, as devnet.sh reads it); its home is
  ``.devnet/node<n>`` (``config.json``, ``daemon.log``, ``auth.token``).
* ``addnode <n> edge`` — one more Edge (n <= 10) against the running devnet,
  funded from the Hardhat keys; ``DEVNET_ADDNODE_CONFIG_OVERRIDES`` (a JSON
  object) is kept beside its config and applied on EVERY start, after the
  values devnet.sh generates.
* ``restart-node <n>`` / ``stop-node <n>`` — one node, data kept.
* A node inherits the environment devnet.sh runs with, so a node's launch
  environment is the environment of the devnet.sh call that starts it.
* Every node shares node 1's API token; requests are HMAC-signed (DKG >= 10.0.19),
  which :class:`NodeApi` does through Blackbox's own client.

Devnet runs on one machine are serialised by a lock file the sessions sharing a
machine agree on, ``<dkg repo>/.claude/devnet.lock``: the trial refuses to
start a devnet while it exists, and holds it while its own devnet runs.
"""

from __future__ import annotations

import calendar
import json
import logging
import os
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from plugins.blackbox.kernel.dkg_client import DkgClient, DkgError

logger = logging.getLogger(__name__)

MAX_NODE = 10   # devnet.sh's Hardhat key array bound
#: How the trial's devnet lock starts (what tells a later run the lock is the trial's own).
_LOCK_TEXT = "blackbox one-graph trial"


def api_port(number: int) -> int:
    """Node *number*'s API port as devnet.sh assigns it (``API_PORT_BASE``, default 9201, + n - 1)."""
    return int(os.environ.get("API_PORT_BASE") or 9201) + number - 1


def libp2p_port(number: int) -> int:
    return int(os.environ.get("LIBP2P_PORT_BASE") or 10001) + number - 1


def store_port(number: int) -> int:
    """The managed Oxigraph port the trial gives a node it adds (devnet.sh's scheme for nodes 1-2)."""
    return int(os.environ.get("DEVNET_OXIGRAPH_BASE") or 7900) + number


class DevnetError(RuntimeError):
    """devnet.sh failed, or the devnet is not in the state the trial needs."""


@dataclass(frozen=True)
class DevnetNode:
    """One devnet node: its number, role, home and API address."""

    number: int
    role: str
    home: Path
    api_url: str

    @property
    def label(self) -> str:
        return f"node{self.number}"


class Devnet:
    """``scripts/devnet.sh`` of one OriginTrail/dkg checkout. Every call's output
    is kept in the run folder (``devnet-<command>.log``)."""

    def __init__(self, repo: Path, run_dir: Path) -> None:
        self.repo = repo
        self.dir = Path(os.environ.get("DEVNET_DIR") or repo / ".devnet")
        self.script = repo / "scripts" / "devnet.sh"
        self.lock = repo / ".claude" / "devnet.lock"
        self.run_dir = run_dir
        self.holds_lock = False

    # -- devnet.sh ----------------------------------------------------------------

    def run(self, *args: str, env: Optional[Mapping[str, str]] = None, unset: Sequence[str] = (),
            timeout: float = 900.0) -> str:
        environment = {name: value for name, value in os.environ.items() if name not in set(unset)}
        environment.update(env or {})
        log = self.run_dir / f"devnet-{args[0]}.log"
        started = time.time()
        with log.open("a", encoding="utf-8") as handle:
            handle.write(f"=== {time.strftime('%H:%M:%S')} devnet.sh {' '.join(args)}\n")
            handle.flush()
            try:
                completed = subprocess.run(["bash", str(self.script), *args], cwd=self.repo, env=environment,
                                           stdin=subprocess.DEVNULL, stdout=handle, stderr=subprocess.STDOUT,
                                           timeout=timeout, check=False)
            except subprocess.TimeoutExpired as exc:
                raise DevnetError(f"devnet.sh {' '.join(args)} did not finish in {timeout:.0f} s (see {log})") from exc
        if completed.returncode != 0:
            raise DevnetError(f"devnet.sh {' '.join(args)} exited {completed.returncode} after "
                              f"{time.time() - started:.0f} s (see {log})")
        return str(log)

    def start(self, nodes: int) -> None:
        if not (self.repo / "packages" / "cli" / "dist" / "cli.js").is_file():
            raise DevnetError(f"{self.repo} is not built (no packages/cli/dist/cli.js); "
                              "build it before starting a devnet")
        if self.lock.exists():
            holder = self.lock.read_text(encoding="utf-8-sig")[:200]
            raise DevnetError(f"another devnet run holds {self.lock}: {holder!r}")
        self.lock.parent.mkdir(parents=True, exist_ok=True)
        self.lock.write_text(f"{_LOCK_TEXT}, pid {os.getpid()}, since {time.ctime()}\n", encoding="utf-8")
        self.holds_lock = True
        # `start` empties the node folders but keeps them, and a kept node7 blocks `addnode 7`:
        # start from a clean devnet (it is being reset either way).
        self.run("clean", timeout=600.0)
        self.run("start", str(nodes), timeout=2400.0)

    def stop(self) -> None:
        """Stop the devnet and give the machine back: the lock goes too when this
        trial wrote it (this run, or the run a ``--resume`` continues)."""
        try:
            self.run("stop", timeout=300.0)
        finally:
            ours = self.lock.is_file() and self.lock.read_text(encoding="utf-8-sig").startswith(_LOCK_TEXT)
            if self.holds_lock or ours:
                self.lock.unlink(missing_ok=True)
                self.holds_lock = False

    def add_edge(self, number: int, *, overrides: Mapping[str, Any], env: Mapping[str, str],
                 unset: Sequence[str] = ()) -> DevnetNode:
        self.run("addnode", str(number), "edge", env={**env, "DEVNET_ADDNODE_CONFIG_OVERRIDES": json.dumps(overrides)},
                 unset=unset, timeout=600.0)
        return self.node(number)

    def restart(self, number: int, *, env: Mapping[str, str], unset: Sequence[str] = ()) -> None:
        self.run("restart-node", str(number), env=env, unset=unset, timeout=600.0)

    # -- what the devnet's files say ----------------------------------------------

    def numbers(self) -> list[int]:
        found = []
        for home in self.dir.glob("node*"):
            suffix = home.name[len("node"):]
            if suffix.isdigit() and (home / "config.json").is_file():
                found.append(int(suffix))
        return sorted(found)

    def config(self, number: int) -> dict[str, Any]:
        return json.loads((self.dir / f"node{number}" / "config.json").read_text(encoding="utf-8-sig"))

    def node(self, number: int) -> DevnetNode:
        config = self.config(number)
        port = int(config.get("apiPort") or api_port(number))
        return DevnetNode(number, str(config.get("nodeRole") or "edge"), self.dir / f"node{number}",
                          f"http://127.0.0.1:{port}")

    def token(self) -> str:
        """The devnet's shared API token (node 1's)."""
        for line in (self.dir / "node1" / "auth.token").read_text(encoding="utf-8-sig").splitlines():
            if line.strip() and not line.startswith("#"):
                return line.strip()
        raise DevnetError("node 1 has no API token")

    def free_numbers(self) -> list[int]:
        """Node numbers addnode can still use: no folder and both ports free."""
        taken = set(self.numbers()) | {int(home.name[4:]) for home in self.dir.glob("node*") if home.name[4:].isdigit()}
        return [n for n in range(1, MAX_NODE + 1) if n not in taken
                and _port_free(api_port(n)) and _port_free(libp2p_port(n)) and _port_free(store_port(n))]

    def log_lines(self, number: int, since: float, *, limit: int = 80) -> list[str]:
        """The node's daemon.log lines written since *since* (epoch s) that say
        something went wrong — the evidence a failed step carries."""
        path = self.dir / f"node{number}" / "daemon.log"
        if not path.is_file():
            return []
        picked: list[str] = []
        current = 0.0   # the time of the last line that carried one; continuation lines inherit it
        with path.open(encoding="utf-8-sig", errors="replace") as handle:
            for line in handle:
                current = _line_time(line) or current
                if current >= since - 5 and any(word in line.lower() for word in _WORTH_QUOTING):
                    picked.append(line.rstrip()[:400])
        return picked[-limit:]


_WORTH_QUOTING = ("error", "warn", "fail", "refus", "denied", "not authorized", "reject", "timed out", "timeout")


def _line_time(line: str) -> float:
    """Epoch seconds of a daemon.log line: ``[2026-10-15T10:08:32.231Z] …`` (UTC)
    or ``2026-10-15 14:17:02 …`` (local time); 0.0 for a line without one."""
    try:
        if line.startswith("[") and len(line) > 20 and line[11] == "T":
            return calendar.timegm(time.strptime(line[1:20], "%Y-%m-%dT%H:%M:%S"))
        if len(line) > 19 and line[4] == "-" and line[10] == " ":
            return time.mktime(time.strptime(line[:19], "%Y-%m-%d %H:%M:%S"))
    except ValueError:
        return 0.0
    return 0.0


def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.5)
        return probe.connect_ex(("127.0.0.1", port)) != 0


class NodeApi:
    """One node's HTTP API for the trial's own setup calls (create the graph,
    read status), signed the way Blackbox's client signs."""

    def __init__(self, node: DevnetNode, token: str) -> None:
        self.node = node
        self._client = DkgClient(url=node.api_url, token=token, dkg_home=str(node.home))

    def call(self, method: str, path: str, body: Optional[dict[str, Any]] = None, *,
             timeout: float = 60.0) -> dict[str, Any]:
        return self._client.request(method, path, body, timeout=timeout)

    def status(self) -> dict[str, Any]:
        return self._client.status(timeout=10.0)

    def agent_address(self) -> str:
        return str(self._client.agent_identity().get("agentAddress") or "")

    def wait_ready(self, timeout: float = 180.0) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        last = ""
        while time.monotonic() < deadline:
            try:
                status = self.status()
                if status.get("peerId"):
                    return status
            except DkgError as exc:   # not answering yet: retried until the deadline
                last = str(exc)
            time.sleep(3)
        raise DevnetError(f"{self.node.label} did not answer within {timeout:.0f} s ({last})")

    def graph_entry(self, graph: str) -> Optional[dict[str, Any]]:
        rows = self.call("GET", "/api/context-graph/list", timeout=120.0).get("contextGraphs") or []
        return next((row for row in rows if isinstance(row, dict) and row.get("id") == graph), None)
