"""The devnet the trial runs on, and the Blackbox actors bound to its nodes.

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


@dataclass
class _Reporter:
    node: DevnetNode
    env: dict[str, str]
    unset: list[str] = field(default_factory=list)


class Cluster:
    """The devnet plus one :class:`.actors.Actor` per role."""

    def __init__(self, options: ClusterOptions) -> None:
        self.options = options
        self.devnet = Devnet(options.dkg_repo, options.run_dir)
        self.settings: dict[str, str] = dict(_BASE_SETTINGS)
        self.actors: dict[str, Actor] = {}
        self.reporters: dict[str, _Reporter] = {}
        self.curator: Optional[DevnetNode] = None
        self.cosigner: Optional[DevnetNode] = None
        self.graph_id = ""
        self._token = ""

    # -- the devnet ---------------------------------------------------------------

    def ensure_devnet(self) -> dict[str, Any]:
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

    def stop_devnet(self) -> None:
        try:
            self.devnet.stop()
        except DevnetError as exc:
            logger.warning("devnet stop: %s", exc)

    def api(self, node: DevnetNode) -> NodeApi:
        return NodeApi(node, self._token or self.devnet.token())

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
                           timeout=240.0)
        if created.get("created") != graph or created.get("registered") is not True:
            raise DevnetError(f"the graph was not created and registered: {json.dumps(created)[:600]}")
        sub = api.call("POST", "/api/sub-graph/create", {"contextGraphId": graph, "subGraphName": REPORTS_SUB_GRAPH},
                       timeout=180.0)
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
        overrides = {**settings["config"], "store": {"backend": "oxigraph-server",
                                                     "options": {"port": store_port(number)}},
                     "contextGraphs": [], "localBootstrapContextGraphs": []}
        node = self.devnet.add_edge(number, overrides=overrides, env=settings["env"], unset=settings["env_removed"])
        self.reporters[name] = _Reporter(node, settings["env"], settings["env_removed"])
        status = self.api(node).wait_ready()
        self._bind(name, node)
        applied = self.devnet.config(number)
        mismatched = sorted(key for key, value in overrides.items() if not _holds(applied.get(key), value))
        if mismatched:
            raise DevnetError(f"{node.label} does not run Blackbox's settings: {mismatched}")
        return {"node": node.label, "peer_id": str(status.get("peerId") or ""),
                "store_url_reported": bool(status.get("storeUrl")),
                "settings_keys": settings["changed_keys"], "env": settings["env"]}

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

    def force_catchup(self, name: str) -> dict[str, Any]:
        """The documented DKG work-around for a registered graph whose catch-up
        is not re-run: subscribe again with ``forceCatchup``."""
        return self.api(self._node_of(name)).call(
            "POST", "/api/context-graph/subscribe",
            {"contextGraphId": self.graph_id, "includeSharedMemory": True, "forceCatchup": True}, timeout=180.0)

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
        }

    def restore(self, snapshot: dict[str, Any]) -> None:
        self._token = self.devnet.token()
        self.graph_id = str(snapshot.get("graph_id") or "")
        self.settings.update(snapshot.get("settings") or {})
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
                                  NodeEndpoint(node.label, node.api_url, self._token or self.devnet.token()),
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


def _holds(actual: Any, expected: Any) -> bool:
    """*actual* carries *expected*: equal values, or for an object every expected
    member (the node may add members of its own, e.g. under ``auth``)."""
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(_holds(actual.get(key), value) for key, value in expected.items())
    return actual == expected
