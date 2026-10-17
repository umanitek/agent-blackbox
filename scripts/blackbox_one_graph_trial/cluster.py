"""The network the trial runs on (a devnet, or its own nodes on the testnet), and the
Blackbox actors bound to its nodes.

Roles (node numbers are the devnet's, chosen at run time):

* the CURATOR node — creates and owns the graph and publishes to its Verified
  Memory; curator 2 (the second key, who publishes) works through it, with the
  curator node settings Blackbox ships (``scripts/blackbox-curator-config.py``);
* the CO-SIGNER node — curator 1 (the first key) works through it, as a
  second curator's own machine would;
* reporter A, B (and C, added later) — Edge nodes added for the trial with
  Blackbox's node settings: the installer's config and the native sync
  profile, and the launch environment Blackbox starts its node with
  (``actor_actions.node_settings`` derives them from the checked-out code).

On the testnet (``--network testnet``, :mod:`.testnet`) the trial starts its own
nodes and they reach each other only through the network's relays: the curator
node first, then reporter A's and B's Edges, and reporter C's for the late join.
Curator 1 works through reporter B's node (a proposal cannot be sent to the
node it comes from, and the trial runs three nodes, not four).
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .actors import Actor, NodeEndpoint
from .devnet import Devnet, DevnetError, DevnetNode, NodeApi, store_port
from .testnet import LinkWatcher, Testnet, TestnetOptions

logger = logging.getLogger(__name__)

#: The sub-graph community reports live in (``constants.COMMUNITY_SUB_GRAPH``).
REPORTS_SUB_GRAPH = "reports"
#: Settings every actor runs with: nothing leaves for outside services, nothing
#: touches the machine's own Hermes homes.
_BASE_SETTINGS = {"BLACKBOX_REPORT": "1", "BLACKBOX_OSV_LOOKUP": "0", "BLACKBOX_AUTO_ATTACH": "0",
                  "BLACKBOX_DISCOVER": "0"}


@dataclass(frozen=True)
class ClusterOptions:
    dkg_repo: Path
    run_dir: Path
    repo_root: Path
    start_devnet: bool = False
    devnet_nodes: int = 6
    curator_node: int = 0
    cosigner_node: int = 0
    curator_settings: bool = True
    network: str = "devnet"                       # "devnet" or "testnet"
    testnet: Optional[TestnetOptions] = None
    #: On the testnet, the reporter whose node curator 1 works through.
    cosigner_reporter: str = "reporter-b"


@dataclass
class _Reporter:
    node: DevnetNode
    env: dict[str, str]
    unset: list[str] = field(default_factory=list)


class Cluster:
    """The devnet plus one :class:`.actors.Actor` per role."""

    def __init__(self, options: ClusterOptions) -> None:
        self.options = options
        self.testnet = options.network == "testnet"
        self.devnet: Any = (Testnet(options.dkg_repo, options.run_dir, options.testnet)
                            if self.testnet and options.testnet else Devnet(options.dkg_repo, options.run_dir))
        self.links: Optional[LinkWatcher] = (LinkWatcher(options.run_dir, self.local_nodes)
                                             if self.testnet else None)
        #: The node's own waits (a registration, a sub-graph) take longer on the public chain.
        self._slow = 2.5 if self.testnet else 1.0
        self.settings: dict[str, str] = dict(_BASE_SETTINGS)
        self.actors: dict[str, Actor] = {}
        self.reporters: dict[str, _Reporter] = {}
        self.curator: Optional[DevnetNode] = None
        self.cosigner: Optional[DevnetNode] = None
        self.graph_id = ""
        self._token = ""
        self._peer_ids: dict[str, str] = {}   # node label -> peer id (the link watcher names links by them)

    # -- the devnet ---------------------------------------------------------------

    def ensure_devnet(self) -> dict[str, Any]:
        if self.testnet:
            return self._ensure_testnet()
        if self.options.start_devnet:
            self.devnet.start(self.options.devnet_nodes)
        numbers = self.devnet.numbers()
        if not numbers:
            raise DevnetError(f"no devnet nodes under {self.devnet.dir}; pass --start-devnet or start one first")
        self._token = self.devnet.token()
        nodes = [self.devnet.node(number) for number in numbers]
        edges = [node.number for node in nodes if node.role == "edge"]
        curator = self.options.curator_node or (edges[0] if edges else 0)
        cosigner = self.options.cosigner_node or next((n for n in edges if n != curator), 0)
        if not curator or not cosigner or curator == cosigner:
            raise DevnetError(f"need two distinct nodes for the curators (Edges: {edges}); "
                              "pass --curator-node / --cosigner-node")
        self.curator, self.cosigner = self.devnet.node(curator), self.devnet.node(cosigner)
        statuses = {node.label: self.api(node).wait_ready() for node in nodes}
        networks = {str(status.get("networkId") or "") for status in statuses.values()}
        if len(networks) != 1 or not next(iter(networks)):
            raise DevnetError(f"the nodes do not agree on one network id: {sorted(networks)}")
        self._bind("curator-2", self.curator)
        self._bind("curator-1", self.cosigner)
        curator_status = statuses[self.curator.label]
        return {"nodes": len(nodes), "network_id": next(iter(networks)),
                "cores": [n.number for n in nodes if n.role == "core"],
                "edges": edges, "curator_node": curator, "cosigner_node": cosigner,
                "dkg_version": str(curator_status.get("version") or curator_status.get("nodeVersion") or ""),
                "started_here": self.options.start_devnet}

    def _ensure_testnet(self) -> dict[str, Any]:
        """The curator node on the testnet: started here (a resumed run finds it
        running), relay-only, paying with the wallets it was given. Curator 1's
        node is reporter B's, bound once that Edge exists (``add_reporter_edge``)."""
        if self.options.start_devnet:
            self.devnet.start()
        from .testnet import CURATOR_NUMBER

        self.curator = self.devnet.node(CURATOR_NUMBER)
        status = self.api(self.curator).wait_ready(timeout=300.0)
        self._bind("curator-2", self.curator)
        self._peer_ids[self.curator.label] = str(status.get("peerId") or "")
        if self.links is not None:
            self.links.start()
        relays = self.devnet.relays()
        return {"nodes": len(self.devnet.numbers()), "network_id": str(status.get("networkId") or ""),
                "network_config": self.options.testnet.network_config if self.options.testnet else "",
                "curator_node": CURATOR_NUMBER, "cosigner_node": f"{self.options.cosigner_reporter}'s node (added in step edges)",
                "dkg_version": str(status.get("version") or status.get("nodeVersion") or ""),
                "dkg_status_commit": str(status.get("commit") or ""),
                "curator_wallets": self.devnet.wallet_addresses(CURATOR_NUMBER),
                "relays": [relay.rsplit("/p2p/", 1)[-1] for relay in relays],
                "announce": "dead loopback address + a circuit through each relay (no direct address)",
                "relay_status": _relay_block(status), "started_here": self.options.start_devnet}

    def stop_devnet(self) -> None:
        if self.links is not None:
            self.links.stop()
        try:
            self.devnet.stop()
        except DevnetError as exc:
            logger.warning("devnet stop: %s", exc)

    def api(self, node: DevnetNode) -> NodeApi:
        return NodeApi(node, self._token_of(node))

    def api_of(self, name: str) -> NodeApi:
        """The API of the node actor *name* works through."""
        return self.api(self._node_of(name))

    def _token_of(self, node: DevnetNode) -> str:
        """The API token of *node*: its own on the testnet, the devnet's shared one otherwise."""
        if self.testnet:
            return self.devnet.token_for(node.number)
        return self._token or self.devnet.token()

    def local_nodes(self) -> dict[str, tuple[NodeApi, str]]:
        """The trial's running nodes by label, with their peer ids (for the link watcher)."""
        found: dict[str, tuple[NodeApi, str]] = {}
        for name, actor in sorted(dict(self.actors).items()):   # a copy: the trial may bind meanwhile
            label = actor.node.label
            if label in found:
                continue
            node = self._node_of(name)
            found[label] = (self.api(node), self._peer_ids.get(label, ""))
        return found

    # -- the graph ----------------------------------------------------------------

    def create_curated_graph(self, name: str) -> dict[str, Any]:
        """The curator node creates a PUBLIC graph, registered on chain with a
        CURATED publish policy (publishPolicy 0: only the owner publishes to
        Verified Memory), and its ``reports`` sub-graph."""
        api = self.api(self.curator)
        owner = api.agent_address()
        graph = self.graph_id or f"{owner}/{name}"
        if self.graph_id and api.graph_entry(graph):   # a resumed run: the graph exists already
            curator_config = self._curator_settings(graph) if self.options.curator_settings else "not applied"
            status = api.status()
            return {"graph_id": graph, "curator_peer": str(status.get("peerId") or ""), "curator_address": owner,
                    "publish_policy": "curated (0)", "reused": True, "listing": api.graph_entry(graph),
                    "curator_settings": curator_config}
        created = api.call("POST", "/api/context-graph/create",
                           {"id": graph, "name": name, "accessPolicy": 0, "publishPolicy": 0, "register": True},
                           timeout=240.0 * self._slow)
        if created.get("created") != graph or created.get("registered") is not True:
            raise DevnetError(f"the graph was not created and registered: {json.dumps(created)[:600]}")
        sub = api.call("POST", "/api/sub-graph/create", {"contextGraphId": graph, "subGraphName": REPORTS_SUB_GRAPH},
                       timeout=180.0 * self._slow)
        self.graph_id = graph
        listed = api.graph_entry(graph) or {}
        curator_config = self._curator_settings(graph) if self.options.curator_settings else "not applied"
        status = api.status()
        return {"graph_id": graph, "curator_peer": str(status.get("peerId") or ""), "curator_address": owner,
                "on_chain_id": created.get("onChainId"), "publish_policy": "curated (0)", "access_policy": "public (0)",
                "sub_graph": sub, "listing": listed, "curator_settings": curator_config}

    def _curator_settings(self, graph: str) -> str:
        """Blackbox's curator node settings (the script the production curator
        runs before every start), then a restart so they hold."""
        script = self.options.repo_root / "scripts" / "blackbox-curator-config.py"
        done = subprocess.run([sys.executable, str(script), "--config", str(self.curator.home / "config.json"),
                               "--graph", graph], capture_output=True, stdin=subprocess.DEVNULL, timeout=60,
                              check=False, text=True, encoding="utf-8", errors="replace")
        if done.returncode != 0:
            raise DevnetError(f"blackbox-curator-config.py failed: {done.stderr.strip()[-400:]}")
        if done.stdout.strip() != "already configured":   # the script says "updated" when it changed the config
            self.devnet.restart(self.curator.number, env={})
            self.api(self.curator).wait_ready()
        return done.stdout.strip()

    def configure_actors(self, *, graph_id: str, graph_peer: str) -> None:
        """Every actor (and every later one) uses the trial's graph — as the one
        graph, for the verified tier and the community alike."""
        self.settings.update({"BLACKBOX_CONTEXT_GRAPH_ID": graph_id, "BLACKBOX_GRAPH_PEER_ID": graph_peer,
                              "BLACKBOX_COMMUNITY_GRAPH_ID": graph_id, "BLACKBOX_COMMUNITY_GRAPH_PEER_ID": graph_peer})

    def set_trusted_root(self, root_key: str) -> None:
        """The test root for THIS network only: Blackbox takes roots from the
        environment only for a network no pin names (``trust_anchors``)."""
        self.settings["BLACKBOX_CURATOR_ROOT_KEYS"] = root_key

    # -- reporters ----------------------------------------------------------------

    def add_reporter_edge(self, name: str) -> dict[str, Any]:
        """A new Edge node for reporter *name*, started with Blackbox's node
        settings (a resumed run reuses the node it already added)."""
        if name in self.reporters:
            node = self.reporters[name].node
            status = self.api(node).wait_ready()
            self._bind(name, node)
            return {"node": node.label, "peer_id": str(status.get("peerId") or ""), "reused": True}
        free = self.devnet.free_numbers()
        candidates = [n for n in free if n > max(self.devnet.numbers() or [0])] or free
        if not candidates:
            raise DevnetError("no free devnet node number left (devnet.sh allows 1-10)")
        number = candidates[0]
        settings = self._blackbox_node_settings(number)
        port = self.devnet.store_port(number) if self.testnet else store_port(number)
        overrides = {**settings["config"], "store": {"backend": "oxigraph-server", "options": {"port": port}},
                     "contextGraphs": [], "localBootstrapContextGraphs": []}
        node = self.devnet.add_edge(number, overrides=overrides, env=settings["env"], unset=settings["env_removed"])
        self.reporters[name] = _Reporter(node, settings["env"], settings["env_removed"])
        status = self.api(node).wait_ready(timeout=300.0 if self.testnet else 180.0)
        self._bind(name, node)
        self._peer_ids[node.label] = str(status.get("peerId") or "")
        if self.testnet and name == self.options.cosigner_reporter:
            self.cosigner = node
            self._bind("curator-1", node)
        applied = self.devnet.config(number)
        mismatched = sorted(key for key, value in overrides.items() if not _holds(applied.get(key), value))
        if mismatched:
            raise DevnetError(f"{node.label} does not run Blackbox's settings: {mismatched}")
        return {"node": node.label, "peer_id": str(status.get("peerId") or ""),
                "store_url_reported": bool(status.get("storeUrl")),
                "settings_keys": settings["changed_keys"], "env": settings["env"],
                **({"announce": applied.get("announceAddresses"), "relay_status": _relay_block(status),
                    "also_curator_1": name == self.options.cosigner_reporter} if self.testnet else {})}

    def _blackbox_node_settings(self, number: int) -> dict[str, Any]:
        """Blackbox's settings for a fresh node (``actor_actions.node_settings``),
        derived in a throwaway actor process from the checked-out code."""
        staging = self.options.run_dir / "node-settings" / f"node{number}"
        staging.mkdir(parents=True, exist_ok=True)
        (staging / "config.json").write_text("{}\n", encoding="utf-8")
        helper = Actor("node-settings", self.options.run_dir, NodeEndpoint("none", "http://127.0.0.1:1", ""),
                       settings=dict(self.settings))
        installer = self.options.repo_root / "plugins" / "blackbox" / "setup" / "blackbox-install.sh"
        answer = helper.call("node-settings", {"staging_home": str(staging), "graph": self.graph_id,
                                               "installer": str(installer)})
        if not answer.get("ok"):
            raise DevnetError(f"Blackbox's node settings could not be derived: {answer.get('error')}")
        return answer

    def graph_row(self, name: str) -> Optional[dict[str, Any]]:
        """The trial graph's row in the listing of *name*'s node (None: not listed)."""
        return self.api(self._node_of(name)).graph_entry(self.graph_id)

    def _node_of(self, name: str) -> DevnetNode:
        return self.devnet.node(int(self.actors[name].node.label[len("node"):]))

    def restart_node_of(self, name: str) -> dict[str, Any]:
        actor = self.actors[name]
        reporter = self.reporters.get(name)
        number = int(actor.node.label[len("node"):])
        started = time.monotonic()
        self.devnet.restart(number, env=reporter.env if reporter else {}, unset=reporter.unset if reporter else [])
        status = self.api(self.devnet.node(number)).wait_ready()
        return {"node": actor.node.label, "seconds": round(time.monotonic() - started),
                "peer_id": str(status.get("peerId") or "")}

    # -- resuming -------------------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        """The roles and settings a resumed run needs (no secrets: the API token
        is read from the devnet again)."""
        return {
            "graph_id": self.graph_id,
            "settings": dict(self.settings),
            "curator_node": self.curator.number if self.curator else 0,
            "cosigner_node": self.cosigner.number if self.cosigner else 0,
            "actors": {name: actor.node.label for name, actor in self.actors.items()},
            "reporters": {name: {"node": r.node.number, "env": r.env, "unset": r.unset}
                          for name, r in self.reporters.items()},
            "peer_ids": dict(self._peer_ids),
        }

    def restore(self, snapshot: dict[str, Any]) -> None:
        self._token = self.devnet.token()
        self.graph_id = str(snapshot.get("graph_id") or "")
        self.settings.update(snapshot.get("settings") or {})
        self._peer_ids.update(snapshot.get("peer_ids") or {})
        if snapshot.get("curator_node"):
            self.curator = self.devnet.node(int(snapshot["curator_node"]))
        if snapshot.get("cosigner_node"):
            self.cosigner = self.devnet.node(int(snapshot["cosigner_node"]))
        for name, label in (snapshot.get("actors") or {}).items():
            self._bind(name, self.devnet.node(int(str(label)[len("node"):])))
        for name, saved in (snapshot.get("reporters") or {}).items():
            self.reporters[name] = _Reporter(self.devnet.node(int(saved["node"])), dict(saved.get("env") or {}),
                                             list(saved.get("unset") or []))

    # -- actors -------------------------------------------------------------------

    def actor(self, name: str) -> Actor:
        actor = self.actors[name]
        actor.settings = dict(self.settings)
        return actor

    def _bind(self, name: str, node: DevnetNode) -> None:
        self.actors[name] = Actor(name, self.options.run_dir,
                                  NodeEndpoint(node.label, node.api_url, self._token_of(node)),
                                  settings=dict(self.settings))

    def log_excerpts(self, *, since: float) -> dict[str, list[str]]:
        """Problem lines each role's node logged since *since*."""
        excerpts = {}
        for name, actor in sorted(self.actors.items()):
            number = actor.node.label[len("node"):]
            if number.isdigit():
                lines = self.devnet.log_lines(int(number), since)
                if lines:
                    excerpts[f"{actor.node.label} ({name})"] = lines
        return excerpts


def _relay_block(status: dict[str, Any]) -> dict[str, Any]:
    """What a node's status says about its reachability: relay reservations held and
    what it advertises — circuits counted, any direct address only by its kind (no IP)."""
    relay = status.get("relay") if isinstance(status.get("relay"), dict) else {}
    advertised = [str(address) for address in relay.get("advertisedAddresses") or []]
    direct = [_address_kind(address) for address in advertised if "/p2p-circuit" not in address]
    return {"relayConnected": status.get("relayConnected"), "connectedPeers": status.get("connectedPeers"),
            "reservationsHeld": relay.get("reservationsHeld"), "natStatus": relay.get("natStatus"),
            "advertised_circuits": len(advertised) - len(direct), "advertised_direct": direct}


def _address_kind(address: str) -> str:
    """``loopback:<port>``, ``private:<port>``, ``tailnet:<port>`` or ``public:<port>`` for a direct multiaddr."""
    parts = address.split("/")
    host = parts[2] if len(parts) > 2 else ""
    port = parts[4] if len(parts) > 4 else "?"
    if host.startswith("127.") or host == "::1":
        kind = "loopback"
    elif host.startswith(("10.", "192.168.")) or any(host.startswith(f"172.{n}.") for n in range(16, 32)):
        kind = "private"
    elif host.startswith("100.") and 64 <= int((host.split(".") + ["0", "0"])[1] or 0) <= 127:
        kind = "tailnet"
    else:
        kind = "public"
    return f"{kind}:{port}"


def _holds(actual: Any, expected: Any) -> bool:
    """*actual* carries *expected*: equal values, or for an object every expected
    member (the node may add members of its own, e.g. under ``auth``)."""
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(_holds(actual.get(key), value) for key, value in expected.items())
    return actual == expected
