"""Local DKG nodes on the public testnet, as the trial's ``--network testnet`` runs them.

Same calls as :class:`.devnet.Devnet` (the cluster uses either), but every node
is a node of the real testnet started on this machine, and nodes reach each
other only through the network's relays. What the trial relies on (OriginTrail/dkg
10.0.25 candidate, Oct 2026, read from source):

* A node is a home folder (``DKG_HOME``) holding ``config.json``. ``cli.js start``
  spawns its daemon detached (it inherits the environment of that call: the
  launch environment) and ``cli.js stop`` stops the daemon of that home, through
  the home's own pid file — never through a process name.
* ``networkConfig: "testnet"`` takes the chain and the relays from the bundled
  network file. An Edge with relays reserves on, dials through and accepts
  circuits from those Cores only, and it starts without mDNS.
* Relay-only: each node announces a dead loopback address and a circuit through
  each relay, nothing else (``announceAddresses``). No peer learns an address it
  could dial directly, and DCUtR finds no public address to upgrade a relayed
  connection to. ``GET /api/connections`` gives each connection's transport;
  :class:`LinkWatcher` records the links between the trial's own nodes, and the
  report names any that was direct.
* The curator node pays for the graph's registration and its Verified Memory
  publishes: it runs with operational wallets of a funded node (``wallets.json``
  entries copied encrypted as they are, plus the ``wallets.key`` that opens them).
  Its first wallet is its agent address. Nothing here reads or prints a key.
* Each node has its own API token (``auth.token``), written before its first start.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import shutil
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

import psutil

from plugins.blackbox.kernel.dkg_client import DkgError

from .devnet import DevnetError, DevnetNode, _line_time, _WORTH_QUOTING

logger = logging.getLogger(__name__)

#: The node that creates and owns the graph; reporters get the numbers after it.
CURATOR_NUMBER = 1
MAX_NODE = 9
#: Never dialable: what each node announces besides its circuits (port 9 is "discard").
DEAD_ADDRESS = "/ip4/127.0.0.1/tcp/9"
#: How the trial's machine lock starts (what tells a later run the lock is the trial's own).
_LOCK_TEXT = "blackbox one-graph trial on the testnet"


class TestnetError(DevnetError):
    """A local testnet node did not start, stop or answer as the trial needs."""


@dataclass(frozen=True)
class TestnetOptions:
    """Where the trial's testnet nodes live and what they run."""

    homes: Path                                   # node homes: outside the evidence folder (they hold keys)
    network_config: str = "testnet"
    api_port_base: int = 19360                    # node n answers on base + n
    store_port_base: int = 47960                  # node n's managed Oxigraph on base + n
    wallet_source: Optional[Path] = None          # a funded node's home: the curator's wallets come from it
    wallet_indexes: tuple[int, ...] = (2, 1)      # which of its operational wallets; the first is the agent
    node_bin: str = "node"
    machine_lock: Optional[Path] = None           # the lock the sessions sharing this machine agree on
    lock_planned_minutes: int = 120
    #: A managed Oxigraph binary another node already fetched (the node checks its pinned
    #: checksum and uses it instead of downloading the same release again).
    oxigraph_seed: Optional[Path] = None


@dataclass
class _Started:
    env: dict[str, str] = field(default_factory=dict)
    unset: list[str] = field(default_factory=list)
    pids: list[int] = field(default_factory=list)


class Testnet:
    """The trial's own nodes on the public testnet (``cli.js`` of one built OriginTrail/dkg tree).
    Every ``cli.js`` call's output is kept in the run folder (``node-<command>.log``)."""

    def __init__(self, repo: Path, run_dir: Path, options: TestnetOptions) -> None:
        self.repo = repo
        self.run_dir = run_dir
        self.options = options
        self.dir = options.homes
        self.cli = repo / "packages" / "cli" / "dist" / "cli.js"
        self.lock = options.machine_lock
        self.holds_lock = False
        self._started: dict[int, _Started] = {}

    # -- the nodes ------------------------------------------------------------------

    def start(self, nodes: int = 1) -> None:
        """Start the curator node (the cluster adds the reporters as Edges later);
        *nodes* is the devnet's node count and means nothing here."""
        if not self.cli.is_file():
            raise TestnetError(f"{self.repo} is not built (no packages/cli/dist/cli.js); build it first")
        self._take_lock()
        if CURATOR_NUMBER not in self.numbers():
            self._create(CURATOR_NUMBER, overrides={}, wallets=True)
        self._start(CURATOR_NUMBER, env={}, unset=())

    def stop(self) -> None:
        """Stop every node of this run and release the machine lock when this run holds it."""
        try:
            for number in reversed(self.numbers()):
                self._stop(number)
        finally:
            self._release_lock()

    def add_edge(self, number: int, *, overrides: Mapping[str, Any], env: Mapping[str, str],
                 unset: Sequence[str] = ()) -> DevnetNode:
        """A new Edge whose config is the trial's testnet base plus *overrides*
        (Blackbox's node settings), started with *env* from its first start."""
        self._create(number, overrides=overrides, wallets=False)
        self._start(number, env=env, unset=unset)
        return self.node(number)

    def restart(self, number: int, *, env: Mapping[str, str], unset: Sequence[str] = ()) -> None:
        started = self._started.get(number)
        self._stop(number)
        self._start(number, env=env or (started.env if started else {}),
                    unset=unset or (started.unset if started else ()))

    # -- what the nodes' files say --------------------------------------------------

    def home(self, number: int) -> Path:
        return self.dir / f"node{number}"

    def numbers(self) -> list[int]:
        found = []
        for home in self.dir.glob("node*"):
            suffix = home.name[len("node"):]
            if suffix.isdigit() and (home / "config.json").is_file():
                found.append(int(suffix))
        return sorted(found)

    def config(self, number: int) -> dict[str, Any]:
        return json.loads((self.home(number) / "config.json").read_text(encoding="utf-8-sig"))

    def node(self, number: int) -> DevnetNode:
        config = self.config(number)
        return DevnetNode(number, str(config.get("nodeRole") or "edge"), self.home(number),
                          f"http://127.0.0.1:{int(config['apiPort'])}")

    def token(self) -> str:
        return self.token_for(CURATOR_NUMBER)

    def token_for(self, number: int) -> str:
        """Node *number*'s own API token."""
        for line in (self.home(number) / "auth.token").read_text(encoding="utf-8-sig").splitlines():
            if line.strip() and not line.startswith("#"):
                return line.strip()
        raise TestnetError(f"node{number} has no API token")

    def free_numbers(self) -> list[int]:
        taken = set(self.numbers())
        return [n for n in range(CURATOR_NUMBER + 1, MAX_NODE + 1) if n not in taken
                and _port_free(self.api_port(n)) and _port_free(self.store_port(n))]

    def api_port(self, number: int) -> int:
        return self.options.api_port_base + number

    def store_port(self, number: int) -> int:
        return self.options.store_port_base + number

    def log_lines(self, number: int, since: float, *, limit: int = 80) -> list[str]:
        """The node's daemon.log lines since *since* (epoch s) that say something went wrong."""
        return [line for line in self.log_window(number, since)
                if any(word in line.lower() for word in _WORTH_QUOTING)][-limit:]

    def log_window(self, number: int, since: float, *, until: float = 0.0) -> list[str]:
        """Every daemon.log line of node *number* written from *since* (to *until*)."""
        path = self.home(number) / "daemon.log"
        if not path.is_file():
            return []
        picked: list[str] = []
        current = 0.0
        with path.open(encoding="utf-8-sig", errors="replace") as handle:
            for line in handle:
                current = _line_time(line) or current
                if current >= since - 5 and (not until or current <= until + 5):
                    picked.append(line.rstrip()[:400])
        return picked

    def pids(self, number: int) -> list[int]:
        """The processes of node *number*: its worker (``daemon.pid``, which serves the
        API port), the worker's supervisor, the managed Oxigraph on its store port and
        the Oxigraph's watchdog. Read from the node's own pid file and its own ports."""
        found: list[int] = []
        try:
            text = (self.home(number) / "daemon.pid").read_text(encoding="utf-8-sig").strip()
            worker = int(text) if text.isdigit() else 0
        except OSError:
            worker = 0
        for pid in (worker, _listener(self.api_port(number))):
            if pid and pid not in found:
                found += [pid, *[parent for parent in (_ppid(pid),) if parent > 1]]
        store = _listener(self.store_port(number))
        if store:
            found += [store, *[parent for parent in (_ppid(store),) if parent > 1 and parent not in found]]
        return list(dict.fromkeys(found))

    def collect_logs(self, dest: Path) -> dict[str, Any]:
        """Each node's daemon.log, gzipped into *dest* (the evidence folder); a line that
        carries any node's API token is replaced, so no token leaves the node homes."""
        import gzip

        dest.mkdir(parents=True, exist_ok=True)
        tokens = []
        for number in self.numbers():
            try:
                tokens.append(self.token_for(number))
            except (OSError, TestnetError):
                continue
        written: dict[str, Any] = {}
        for number in self.numbers():
            source = self.home(number) / "daemon.log"
            if not source.is_file():
                continue
            redacted = 0
            target = dest / f"node{number}-daemon.log.gz"
            with source.open(encoding="utf-8", errors="replace") as reader, gzip.open(target, "wt",
                                                                                      encoding="utf-8") as writer:
                for line in reader:
                    if any(token and token in line for token in tokens):
                        line, redacted = "[line removed: it carried an API token]\n", redacted + 1
                    writer.write(line)
            written[f"node{number}"] = {"file": str(target.relative_to(dest.parent)), "redacted_lines": redacted}
        return written

    # -- creating and starting --------------------------------------------------------

    def base_config(self, number: int) -> dict[str, Any]:
        """What makes node *number* a relay-only Edge of the testnet, on this machine's ports."""
        return {
            "name": f"bb-trial-node{number}",
            "apiPort": self.api_port(number),
            "apiHost": "127.0.0.1",
            "listenPort": 0,
            "nodeRole": "edge",
            "networkConfig": self.options.network_config,
            "announceAddresses": relay_only_announce(self.relays()),
            "autoUpdate": {"enabled": False},
            "telemetry": {"enabled": False},
            "contextGraphs": [],
            "store": {"backend": "oxigraph-server", "options": {"port": self.store_port(number)}},
            "auth": {"enabled": True},
        }

    def relays(self) -> list[str]:
        """The relays of the bundled network file (the Cores every Edge of it reserves on)."""
        path = self.repo / "network" / f"{self.options.network_config}.json"
        relays = json.loads(path.read_text(encoding="utf-8-sig")).get("relays") or []
        if not relays:
            raise TestnetError(f"{path} names no relays")
        return [str(relay) for relay in relays]

    def _create(self, number: int, *, overrides: Mapping[str, Any], wallets: bool) -> None:
        home = self.home(number)
        if (home / "config.json").exists():
            raise TestnetError(f"{home} exists already; a run never reuses a node home")
        for port in (self.api_port(number), self.store_port(number)):
            if not _port_free(port):
                raise TestnetError(f"port {port} for node{number} is taken")
        home.mkdir(parents=True, mode=0o700)
        os.chmod(home, 0o700)
        config = {**self.base_config(number), **dict(overrides)}
        _write_private(home / "config.json", json.dumps(config, indent=2) + "\n")
        _write_private(home / "auth.token", "# DKG node API token - treat this like a password\n"
                       + secrets.token_urlsafe(32) + "\n")
        if wallets:
            self._copy_wallets(home)
        seed = self.options.oxigraph_seed
        if seed is not None and seed.is_file():
            (home / "oxigraph").mkdir(mode=0o755)
            shutil.copy2(seed, home / "oxigraph" / seed.name)

    def _copy_wallets(self, home: Path) -> None:
        """The curator's operational wallets: entries of the source node's ``wallets.json``
        copied encrypted, with the ``wallets.key`` that opens them. Refuses the source's own
        first wallet (its agent address: two nodes must never be the same agent)."""
        source = self.options.wallet_source
        if source is None:
            return   # the node makes its own (unfunded) wallets on first start
        indexes = tuple(self.options.wallet_indexes)
        if not indexes or 0 in indexes:
            raise TestnetError("the curator's wallets must not include the source node's first wallet (its agent)")
        stored = json.loads((source / "wallets.json").read_text(encoding="utf-8-sig"))
        entries = stored.get("wallets") if isinstance(stored, dict) else stored
        if not isinstance(entries, list) or max(indexes) >= len(entries):
            raise TestnetError(f"{source}/wallets.json has no operational wallets {list(indexes)}")
        picked = [entries[index] for index in indexes]
        if not all(isinstance(entry, dict) and entry.get("keystore") for entry in picked):
            raise TestnetError("the source wallets are not encrypted keystores; refusing to copy plaintext keys")
        _write_private(home / "wallets.json", json.dumps({"wallets": picked}, indent=2) + "\n")
        shutil.copyfile(source / "wallets.key", home / "wallets.key")
        os.chmod(home / "wallets.key", 0o600)

    def wallet_addresses(self, number: int) -> list[str]:
        """The public addresses of node *number*'s operational wallets (first = its agent)."""
        try:
            stored = json.loads((self.home(number) / "wallets.json").read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            return []
        entries = stored.get("wallets") if isinstance(stored, dict) else stored
        return [str(entry.get("address") or "") for entry in entries or [] if isinstance(entry, dict)]

    def _start(self, number: int, *, env: Mapping[str, str], unset: Sequence[str]) -> None:
        home = self.home(number)
        removed = set(unset)
        environment = {name: value for name, value in os.environ.items() if name not in removed}
        environment.update(dict(env))
        environment["DKG_HOME"] = str(home)
        self._run(number, "start", environment, timeout=180.0, check=False)
        self._started[number] = _Started(dict(env), list(unset))
        self._wait_listening(number, timeout=240.0)
        self._started[number].pids = self.pids(number)

    def _stop(self, number: int) -> None:
        started = self._started.get(number)
        pids = list(dict.fromkeys([*(started.pids if started else []), *self.pids(number)]))
        if not pids:
            return
        environment = {**os.environ, "DKG_HOME": str(self.home(number))}
        self._run(number, "stop", environment, timeout=180.0, check=False)
        deadline = time.monotonic() + 60
        while any(_alive(pid) for pid in pids) and time.monotonic() < deadline:
            time.sleep(1)
        alive = [pid for pid in pids if _alive(pid)]
        if alive:   # still up after `stop`: these are this run's own node's pids (its pid file, its ports)
            logger.warning("node%d did not stop; signalling its own pid(s) %s", number, alive)
            for pid in alive:
                _signal(pid)

    def _run(self, number: int, command: str, environment: Mapping[str, str], *, timeout: float,
             check: bool) -> None:
        log = self.run_dir / f"node-{command}.log"
        with log.open("a", encoding="utf-8") as handle:
            handle.write(f"=== {time.strftime('%H:%M:%S')} node{number} cli.js {command}\n")
            handle.flush()
            try:
                completed = subprocess.run([self.options.node_bin, str(self.cli), command], cwd=self.repo,
                                           env=dict(environment), stdin=subprocess.DEVNULL, stdout=handle,
                                           stderr=subprocess.STDOUT, timeout=timeout, check=False)
            except subprocess.TimeoutExpired as exc:
                raise TestnetError(f"cli.js {command} for node{number} did not finish in {timeout:.0f} s") from exc
        if check and completed.returncode != 0:
            raise TestnetError(f"cli.js {command} for node{number} exited {completed.returncode} (see {log})")

    def _wait_listening(self, number: int, timeout: float) -> None:
        """Until node *number*'s API port takes connections (the cluster then waits for its status)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not _port_free(self.api_port(number)):
                return
            time.sleep(2)
        raise TestnetError(f"node{number} did not open its API port {self.api_port(number)} in {timeout:.0f} s "
                           f"(see {self.home(number) / 'daemon.log'})")

    # -- the machine lock ---------------------------------------------------------------

    def _take_lock(self) -> None:
        """The lock the sessions sharing this machine agree on (a directory, taken with mkdir)."""
        if self.lock is None or self.holds_lock:
            return
        try:
            self.lock.mkdir(parents=False)
        except FileExistsError as exc:
            holder = (self.lock / "holder").read_text(encoding="utf-8-sig")[:300] if (self.lock / "holder").is_file() \
                else ""
            raise TestnetError(f"another run holds {self.lock}: {holder!r}") from exc
        end = time.strftime("%H:%MZ", time.gmtime(time.time() + 60 * self.options.lock_planned_minutes))
        note = ""
        if self.options.wallet_source is not None:   # a node of the source signs with all its wallets in turn
            note = (f"note: its curator node signs with operational wallets {self._source_addresses()} of "
                    f"{self.options.wallet_source.name}; that node must not publish from them meanwhile\n")
        (self.lock / "holder").write_text(f"holder: {_LOCK_TEXT}, pid {os.getpid()} (local testnet nodes, no devnet)\n"
                                          f"since: {time.strftime('%H:%MZ', time.gmtime())}\n"
                                          f"planned end: {end}\n{note}", encoding="utf-8")
        self.holds_lock = True

    def _source_addresses(self) -> list[str]:
        """The public addresses of the source wallets the curator node is given."""
        try:
            stored = json.loads((self.options.wallet_source / "wallets.json").read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            return []
        entries = stored.get("wallets") if isinstance(stored, dict) else stored
        return [str((entries[index] or {}).get("address") or "") for index in self.options.wallet_indexes
                if isinstance(entries, list) and index < len(entries)]

    def _release_lock(self) -> None:
        if self.lock is None:
            return
        holder = self.lock / "holder"
        ours = holder.is_file() and _LOCK_TEXT in holder.read_text(encoding="utf-8-sig")
        if self.holds_lock or ours:
            shutil.rmtree(self.lock, ignore_errors=True)
            self.holds_lock = False


def relay_only_announce(relays: Sequence[str]) -> list[str]:
    """A node's announce list when it may be reached only through *relays*:
    a dead loopback address (without one the node churns its relayed links)
    and a circuit through every relay."""
    return [DEAD_ADDRESS, *(f"{relay.rstrip('/')}/p2p-circuit" for relay in relays)]


class LinkWatcher:
    """Samples ``GET /api/connections`` on the trial's nodes every *interval* seconds
    and keeps every link between two of them: who, when, relayed or direct.
    Writes each sample to ``links.jsonl`` in the run folder."""

    def __init__(self, run_dir: Path, nodes: Any, interval: float = 15.0) -> None:
        self.path = run_dir / "links.jsonl"
        self._nodes = nodes            # () -> {label: (NodeApi, peer id)}
        self._interval = interval
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self.samples: list[dict[str, Any]] = []

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._loop, name="link-watcher", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=30)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.sample()
            except Exception:   # a sample that fails is skipped; the next one runs
                logger.debug("link sample failed", exc_info=True)
            self._stop.wait(self._interval)

    def sample(self) -> dict[str, Any]:
        nodes = self._nodes()
        labels = {peer: label for label, (_api, peer) in nodes.items() if peer}
        record: dict[str, Any] = {"t": round(time.time(), 1), "links": [], "unreadable": []}
        for label, (api, _peer) in sorted(nodes.items()):
            try:
                answer = api.call("GET", "/api/connections", timeout=20.0)
            except (DkgError, OSError, ValueError) as exc:
                record["unreadable"].append(f"{label}: {type(exc).__name__}")
                continue
            cores = 0
            for connection in answer.get("connections") or []:
                other = labels.get(str(connection.get("peerId") or ""))
                if other is None:
                    cores += 1
                    continue
                record["links"].append({"from": label, "to": other,
                                        "transport": str(connection.get("transport") or ""),
                                        "direction": str(connection.get("direction") or ""),
                                        "via": _relay_of(str(connection.get("remoteAddr") or ""))})
            record.setdefault("other_peers", {})[label] = cores
        with self._lock:
            self.samples.append(record)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        return record

    def summary(self, since: float = 0.0) -> dict[str, Any]:
        """The links seen since *since*: per pair, how often relayed and how often direct."""
        with self._lock:
            picked = [sample for sample in self.samples if sample["t"] >= since]
        pairs: dict[str, dict[str, int]] = {}
        direct: list[dict[str, Any]] = []
        for sample in picked:
            for link in sample["links"]:
                pair = " - ".join(sorted((link["from"], link["to"])))
                counts = pairs.setdefault(pair, {"relayed": 0, "direct": 0})
                kind = "direct" if link["transport"] == "direct" else "relayed"
                counts[kind] += 1
                if kind == "direct":
                    direct.append({"t": sample["t"], **link})
        return {"samples": len(picked), "pairs": pairs, "direct_links": direct[:20],
                "relay_only": not direct, "unreadable_samples": sum(1 for s in picked if s["unreadable"])}


def _relay_of(address: str) -> str:
    """The relay's peer id of a circuit address (``…/p2p/<relay>/p2p-circuit…``), "" for a direct one."""
    if "/p2p-circuit" not in address:
        return ""
    before = address.split("/p2p-circuit", 1)[0]
    return before.rsplit("/p2p/", 1)[-1][-8:] if "/p2p/" in before else ""


def _write_private(path: Path, text: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(path, 0o600)


def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.5)
        return probe.connect_ex(("127.0.0.1", port)) != 0


def _listener(port: int) -> int:
    """The pid listening on 127.0.0.1:*port* (0: none)."""
    try:
        done = subprocess.run(["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-t"], capture_output=True,
                              text=True, encoding="utf-8", errors="replace", timeout=20, check=False,
                              stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return 0
    first = done.stdout.split()
    return int(first[0]) if first and first[0].isdigit() else 0


def _ppid(pid: int) -> int:
    try:
        done = subprocess.run(["ps", "-o", "ppid=", "-p", str(pid)], capture_output=True,
                              text=True, encoding="utf-8", errors="replace", timeout=20, check=False,
                              stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return 0
    text = done.stdout.strip()
    return int(text) if text.isdigit() else 0


def _alive(pid: int) -> bool:
    return psutil.pid_exists(pid)


def _signal(pid: int) -> None:
    try:
        os.kill(pid, 15)
    except ProcessLookupError:
        pass
