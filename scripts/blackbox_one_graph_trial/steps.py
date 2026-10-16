"""The trial's steps: what each one does with Blackbox's code, and when it passes.

Every step is one method of :class:`Trial`. It returns its evidence, or raises
:class:`.report.StepFailed` when Blackbox did not do what the step checks;
any other exception is an ERROR of the trial itself. :meth:`Trial.run` runs
them in order, skips a step whose prerequisites did not pass, and attaches the
node log lines of a step's time window when it did not pass.

The flow (the one-graph decision): one public context graph, registered on
chain with a curated publish policy and owned by the curator node. Reporters
share into its shared memory (sub-graph ``reports``); the curators promote a
selected report to its Verified Memory with their two-signature statement;
every reporter's ruleset then holds it as a verified rule.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Optional

from plugins.blackbox.kernel import threat_ids

from .actors import Actor, ActorError
from .cluster import Cluster
from .report import ASSISTED, ERROR, FAIL, PASS, SKIP, StepFailed, StepResult, TrialReport

logger = logging.getLogger(__name__)

#: Seconds a reporter's community read may take to show another node's report.
READ_TIMEOUT_S = 300.0
#: Seconds a ruleset may take to hold a promotion (refresh + asset tiering).
COMPILE_TIMEOUT_S = 420.0
#: Seconds a node that joins later may take to catch up.
LATE_JOIN_TIMEOUT_S = 600.0
#: Seconds a subscribed node may take to list the graph with its definition.
READY_TIMEOUT_S = 240.0
#: How often a wait runs the beat a running Blackbox performs (a ruleset refresh:
#: membership check, retry queue, keep-alive); its pulse runs every 20 s, a refresh hourly.
BEAT_S = 45.0
POLL_S = 10.0
#: The file in the run folder a resumed run starts from.
STATE_FILE = "trial-state.json"
#: Why a node that holds a registered graph's definition can still list it synced=false
#: (Blackbox reads the flag only to trust an empty community read).
_SYNCED_FLAG_GAPS = {
    "OriginTrail/dkg#3281": "OriginTrail/dkg#3281: the first catch-up can run before the graph's authority and "
                            "is not repeated (fixed by #3287 on builds that carry it)",
    "OriginTrail/dkg#3296": "OriginTrail/dkg#3296: a node that already holds the graph's data is never marked synced",
}


@dataclass(frozen=True)
class Threat:
    """A malware dependency the trial reports: unique per run, so a devnet that
    served an earlier run cannot answer for this one."""

    ecosystem: str
    name: str
    version: str

    @property
    def identifier(self) -> str:
        return f"dep:{self.ecosystem}:{self.name}@{self.version}"

    @property
    def candidate(self) -> list[str]:
        return [self.ecosystem, self.name, self.version]

    def report_argv(self, severity: str = "critical") -> list[str]:
        return ["report", "--type", "dependency", "--ecosystem", self.ecosystem, "--name", self.name,
                "--package-version", self.version, "--kind", "malware", "--reason", "typosquat",
                "--severity", severity]


@dataclass
class TrialState:
    """What earlier steps established and later steps use."""

    stamp: str
    graph_id: str = ""
    network_id: str = ""
    curator_peer: str = ""
    curator_address: str = ""
    root_key: str = ""
    curator_keys: dict[str, str] = field(default_factory=dict)
    reporter_keys: dict[str, str] = field(default_factory=dict)
    reporter_addresses: dict[str, str] = field(default_factory=dict)
    proposal_id: str = ""
    promoted: Optional[Threat] = None
    control: Optional[Threat] = None

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> TrialState:
        threats = {key: Threat(**data[key]) if data.get(key) else None for key in ("promoted", "control")}
        return cls(**{**data, **threats})


#: (step key, title, prerequisite step keys). The order is the run order.
STEPS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("devnet", "DKG devnet up", ()),
    ("graph", "Curator creates the registered, curated graph", ("devnet",)),
    ("edges", "Two Edge nodes with Blackbox's node settings", ("devnet",)),
    ("keys", "Curator keys: test root for the devnet's network id, manifest published", ("graph", "edges")),
    ("subscribe", "Reporters subscribe to the one graph (blackbox sync)", ("keys",)),
    ("share", "Reporter A files a report through community sharing", ("subscribe",)),
    ("read", "Reporter B's community reader returns A's report", ("share",)),
    ("promote", "Curators promote A's report to Verified Memory with two signatures", ("read",)),
    ("compile", "Both reporters' rulesets hold the promoted report as a verified rule", ("promote",)),
    ("late-join", "A reporter that joins later gets the reports and the rule", ("compile",)),
    ("restart", "A node restart keeps the reports and the rule", ("late-join",)),
)


class Trial:
    """The trial run over one :class:`.cluster.Cluster` (the devnet and its actors)."""

    def __init__(self, cluster: Cluster, report: TrialReport, state: TrialState, until: Optional[str] = None,
                 assist: bool = True) -> None:
        self.cluster = cluster
        self.report = report
        self.state = state
        self.until = until
        self.assist = assist
        self._assists: list[str] = []

    # -- running ------------------------------------------------------------------

    def run(self) -> TrialReport:
        """Run every step in order (a resumed run skips the steps that passed
        before), saving the state after each one (:meth:`save`)."""
        for key, title, needs in STEPS:
            if self._passed(key):
                logger.info("step %s: passed in the run being resumed", key)
            else:
                missing = [need for need in needs if not self._passed(need)]
                if missing:
                    self.report.add(StepResult(key, title, SKIP, summary=f"not run: {', '.join(missing)} did not pass"))
                else:
                    self.report.add(self._run_one(key, title))
                self.save()
            if key == self.until:
                break
        return self.report

    def save(self) -> None:
        """What a resumed run needs: the state the steps built and the cluster's roles."""
        document = {"state": self.state.to_json(), "cluster": self.cluster.snapshot()}
        (self.report.run_dir / STATE_FILE).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n",
                                                      encoding="utf-8")

    def _passed(self, key: str) -> bool:
        result = self.report.result(key)
        return result is not None and result.passed

    def _run_one(self, key: str, title: str) -> StepResult:
        method: Callable[[], dict[str, Any]] = getattr(self, "step_" + key.replace("-", "_"))
        result = StepResult(key, title, started_at=time.time())
        self._assists = []
        logger.info("step %s: %s", key, title)
        try:
            evidence = method() or {}
            result.status, result.summary = PASS, str(evidence.pop("summary", "") or "")
            result.evidence = evidence
            if self._assists:
                result.status = ASSISTED
                result.summary += " — only after the trial's DKG work-around: " + "; ".join(self._assists)
                result.evidence["assists"] = list(self._assists)
        except StepFailed as failed:
            result.status, result.summary, result.evidence = FAIL, failed.summary, failed.evidence
            if self._assists:   # the work-around was tried and did not help: part of the evidence
                result.evidence["assists"] = list(self._assists)
        except ActorError as exc:
            result.status, result.summary, result.error = ERROR, "an actor gave no answer", str(exc)
        except Exception as exc:   # the trial's own failure: recorded, the run goes on
            logger.exception("step %s errored", key)
            result.status, result.summary, result.error = ERROR, f"{type(exc).__name__}: {exc}", repr(exc)
        result.seconds = time.time() - result.started_at
        if result.status != PASS:
            result.logs = self.cluster.log_excerpts(since=result.started_at)
        logger.info("step %s: %s (%.0f s) %s", key, result.status, result.seconds, result.summary)
        return result

    # -- the steps ----------------------------------------------------------------

    def step_devnet(self) -> dict[str, Any]:
        facts = self.cluster.ensure_devnet()
        self.state.network_id = facts["network_id"]
        self.report.facts.update({"dkg": facts.get("dkg_version", ""), "network_id": self.state.network_id})
        return {"summary": f"{facts['nodes']} node(s) answering, network {self.state.network_id}", **facts}

    def step_graph(self) -> dict[str, Any]:
        created = self.cluster.create_curated_graph(f"bb-trial-{self.state.stamp}")
        self.state.graph_id = created["graph_id"]
        self.state.curator_peer = created["curator_peer"]
        self.state.curator_address = created["curator_address"]
        self.cluster.configure_actors(graph_id=self.state.graph_id, graph_peer=self.state.curator_peer)
        return {"summary": f"graph {self.state.graph_id} registered, publish policy {created.get('publish_policy')}",
                **created}

    def step_edges(self) -> dict[str, Any]:
        added = {name: self.cluster.add_reporter_edge(name) for name in ("reporter-a", "reporter-b")}
        return {"summary": "reporter-a and reporter-b run with Blackbox's node settings", "nodes": added}

    def step_keys(self) -> dict[str, Any]:
        """Test keys for the devnet's network id only: Blackbox takes curator
        roots from the environment for a network no pin names, and ignores the
        variable for a pinned one (``kernel/signing/trust_anchors``). No pin is
        changed, and the trial refuses a network that has pins."""
        owner, cosigner = self.cluster.actor("curator-2"), self.cluster.actor("curator-1")
        seen = owner.call("identity")
        if seen.get("root_pinned_for_network"):
            raise StepFailed(f"network {seen.get('network_id')} has pinned curator roots; the trial refuses to add "
                             "test roots there", identity=seen)
        root = _cli(owner, ["curate", "--authority", "verified", "keys", "--root"])
        self.state.root_key = _hex_after(root["stdout"], "root key (SANDBOX ONLY):")
        self.state.curator_keys["curator-2"] = _hex_after(root["stdout"], "curator key:")
        self.state.curator_keys["curator-1"] = _hex_after(
            _cli(cosigner, ["curate", "--authority", "verified", "keys"])["stdout"], "curator key:")
        self.cluster.set_trusted_root(self.state.root_key)
        published = "a trusted manifest was already in force (resumed run)"
        if not self._trusts_manifest("curator-2"):
            manifest = _cli(owner, ["curate", "--authority", "verified", "manifest",
                                    "--curator-key", self.state.curator_keys["curator-1"],
                                    "--curator-operator", "trial-operator-1",
                                    "--curator-key", self.state.curator_keys["curator-2"],
                                    "--curator-operator", "trial-operator-2",
                                    "--threshold", "2", "--promotion-author", self.state.curator_address,
                                    "--root-epoch", "1", "--manifest-version", "1"])
            staged = _word_after(manifest["stdout"], "staged as")
            answer = _cli(owner, ["curate", "--authority", "verified", "publish", staged, "--yes"], timeout=600.0)
            published = answer["stdout"].strip()
            if answer["rc"] != 0 and not _not_readable_yet(answer):
                raise StepFailed("the key manifest was not published", manifest=manifest, publish=answer)
        trusted, _waited = _wait(lambda: self._trusts_manifest("curator-2"), READ_TIMEOUT_S)
        trust = owner.call("trust")
        if not trusted:
            raise StepFailed("the curator node does not act on the published manifest", trust=trust, publish=published)
        return {"summary": f"root {self.state.root_key[:12]}… trusted on network {self.state.network_id} only "
                           "(environment variable, no pin changed); manifest with 2 curator keys of 2 operators "
                           "published and trusted on the curator node",
                "root_key": self.state.root_key, "curator_keys": self.state.curator_keys,
                "trusted_roots_seen": seen.get("trusted_roots"), "manifest_publish": published, "trust": trust}

    def step_subscribe(self) -> dict[str, Any]:
        """The reporters and curator 1's node subscribe the way Blackbox does
        (``blackbox sync``); each then holds the graph's definition and acts on
        the curators' manifest it read from Verified Memory."""
        names = ("reporter-a", "reporter-b", "curator-1")
        answers = {name: self._sync(name) for name in names}
        ready = {name: self._graph_ready(name) for name in names}
        joined = {name: self.cluster.actor(name).call("read").get("join_state") for name in names}
        if any(state != "joined" for state in joined.values()):
            raise StepFailed("Blackbox does not see a node as joined to the graph", join=joined, ready=ready,
                             sync=answers)
        trusted, waited = _wait(lambda: all(self._trusts_manifest(name) for name in names), READ_TIMEOUT_S)
        if not trusted:
            raise StepFailed("a subscribed node does not act on the curators' manifest", join=joined,
                             trust={name: self.cluster.actor(name).call("trust") for name in names})
        unsynced = [name for name in names if not ready[name]["synced"]]
        evidence: dict[str, Any] = {"ready": ready, "join": joined, "sync": answers}
        note = ""
        if unsynced:
            evidence["known_dkg_gap"] = {"listing_synced_false": unsynced, "issues": list(_SYNCED_FLAG_GAPS)}
            note = (f"; known DKG gap, not a pass condition: the listing says synced=false for "
                    f"{', '.join(unsynced)} ({'; '.join(_SYNCED_FLAG_GAPS.values())})")
        return {"summary": f"reporter-a, reporter-b and curator-1's node joined the graph (definition in) "
                           f"and trust the manifest (after {waited:.0f} s more){note}", **evidence}

    def _trusts_manifest(self, name: str) -> bool:
        return self._manifest_is_ours(self.cluster.actor(name).call("trust"))

    def _manifest_is_ours(self, trust: dict[str, Any]) -> bool:
        manifest = trust.get("manifest") or {}
        return set(manifest.get("curator_keys") or []) == set(self.state.curator_keys.values()) and bool(
            self.state.curator_keys)

    def step_share(self) -> dict[str, Any]:
        reporter = self.cluster.actor("reporter-a")
        self.state.promoted = Threat("npm", f"bb-trial-{self.state.stamp}-wallet-drainer", "1.0.0")
        identity = reporter.call("identity", {"reporter_key": True})
        self.state.reporter_keys["reporter-a"] = identity["reporter_key"]
        self.state.reporter_addresses["reporter-a"] = identity["reporter_address"]
        sharing = self._enable_sharing("reporter-a")
        filed = _cli(reporter, self.state.promoted.report_argv())
        own, waited = self._landed("reporter-a", self.state.promoted, filed)
        if own is None:
            raise StepFailed("reporter-a's report did not land: its own node does not read it back", report=filed,
                             last_read=reporter.call("read"))
        how = "at once" if filed["rc"] == 0 else "through Blackbox's retry queue"
        return {"summary": f"{self.state.promoted.identifier} shared by reporter-a {how}; its own reader has it "
                           f"after {waited:.0f} s", "sharing": sharing, "report": filed, "reporter": identity}

    def _enable_sharing(self, name: str) -> dict[str, Any]:
        """``blackbox report --enable-sharing``, the operator's opt-in: community
        sharing stays off until a node records it (since umanitek/agent-blackbox#41).
        Where sharing was on by default it records a fresh acceptance."""
        answer = _cli(self.cluster.actor(name), ["report", "--enable-sharing"])
        if answer["rc"] != 0:
            raise StepFailed(f"`blackbox report --enable-sharing` did not turn sharing on for {name}", answer=answer)
        return {"rc": answer["rc"], "stdout": answer["stdout"][-400:]}

    def _landed(self, name: str, threat: Threat, filed: dict[str, Any]) -> tuple[Optional[dict[str, Any]], float]:
        """Wait for *name*'s own reader to return its report of *threat*. A share
        the node refused is in Blackbox's retry queue (``blackbox report`` says
        so and exits 1): the beat a running Blackbox performs (a ruleset
        refresh, which retries due shares) is then run here between reads."""
        actor = self.cluster.actor(name)
        author = self.state.reporter_keys[name]

        def probe() -> Optional[dict[str, Any]]:
            if filed["rc"] != 0:
                actor.call("ruleset", timeout=600.0)   # Blackbox's own beat: retries the queued share
            return _report_of(actor.call("read"), threat, author)

        if filed["rc"] != 0 and "retry" not in filed["stdout"].lower():
            raise StepFailed("`blackbox report` refused the report", report=filed)
        return _wait(probe, READ_TIMEOUT_S)

    def step_read(self) -> dict[str, Any]:
        threat = self.state.promoted
        author = self.state.reporter_keys["reporter-a"]
        beat = self._beater("reporter-b")

        def probe() -> Optional[dict[str, Any]]:
            found = _report_of(self.cluster.actor("reporter-b").call("read"), threat, author)
            if found is None:
                beat()
            return found

        seen, waited = self._assisted_wait("reporter-b", probe, READ_TIMEOUT_S, lambda: "A's report not read yet")
        if seen is None:
            raise StepFailed(f"reporter-b's community reader did not return A's report within {READ_TIMEOUT_S:.0f} s",
                             last_read=self.cluster.actor("reporter-b").call("read"))
        control = self._file_control_report()
        return {"summary": f"reporter-b reads A's signed report after {waited:.0f} s", "report": seen,
                "control_report": control}

    def step_promote(self) -> dict[str, Any]:
        """The promotion reads back from Verified Memory: a statement both curator
        keys signed that names reporter-a's report (its subject and digest), and
        either the report itself (reporter-a's own asset) or the curators' own
        verified asset built from it."""
        promoted = self._promote()
        curators = set(self.state.curator_keys.values())
        last: dict[str, Any] = {}

        def read_back() -> Optional[dict[str, Any]]:
            nonlocal last
            last = self.cluster.actor("curator-2").call("verified-memory", {
                "identifier": self.state.promoted.identifier,
                "reporter_address": self.state.reporter_addresses["reporter-a"],
                "reporter_key": self.state.reporter_keys["reporter-a"]})
            statement = next((p for p in last.get("promotions", []) if curators <= set(p.get("signers", []))
                              and p.get("names_report") and p.get("digest_matches")), None)
            report = last.get("report") or {}
            as_itself = report.get("vm_signed_by") == self.state.reporter_keys["reporter-a"] and _own_asset(
                report.get("asset_graphs"), self.state.reporter_addresses["reporter-a"])
            as_curator_asset = statement is not None and statement.get("in_curator_asset") is not False
            return statement if statement is not None and (as_itself or as_curator_asset) else None

        statement, waited = _wait(read_back, READ_TIMEOUT_S)
        if statement is None:
            raise StepFailed("Verified Memory does not hold the promotion: a statement signed by both curator keys "
                             "that names reporter-a's report (subject and digest), with the report itself or the "
                             "curators' own asset built from it", promotion=promoted, verified_memory=last)
        form = "the report itself" if last.get("form") == "report-itself" else "the curators' own asset built from it"
        return {"summary": f"Verified Memory holds {form}, with the two-key statement naming reporter-a's report "
                           f"(read back after {waited:.0f} s)", "promotion": promoted, "verified_memory": last}

    def _promote(self) -> dict[str, Any]:
        """The two-key promotion as two curator machines run it: curator-1 (on its
        own node) proposes and sends the proposal to the graph owner's node;
        curator-2 (the owner) receives it, co-signs, and publishes."""
        threat, evidence = self.state.promoted, f"advisory:BB-TRIAL-{self.state.stamp}"
        first, owner = self.cluster.actor("curator-1"), self.cluster.actor("curator-2")
        proposed = _cli(first, ["curate", "--authority", "verified", "propose", "--promote", threat.identifier,
                                "--severity", "critical", "--evidence", evidence, "--reason", "typosquat",
                                "--to", self.state.curator_peer])
        proposal_id = _word_after(proposed["stdout"], "proposed")
        self.state.proposal_id = proposal_id

        def received() -> bool:
            inbox = _cli(owner, ["curate", "--authority", "verified", "inbox"])
            return proposal_id in inbox["stdout"] or proposal_id in _cli(
                owner, ["curate", "--authority", "verified", "list"])["stdout"]

        got, waited = _wait(received, 180.0)
        if not got:
            raise StepFailed("curator-2 never received curator-1's proposal", proposal=proposed)
        approved = _cli(owner, ["curate", "--authority", "verified", "approve", proposal_id, "--evidence", evidence,
                                "--yes"], timeout=600.0)
        if ": published" not in approved["stdout"] and not _not_readable_yet(approved):
            raise StepFailed("curator-2's approval did not publish the promotion", proposal=proposed, approval=approved)
        return {"proposal": proposal_id, "proposed": proposed["stdout"][-600:], "received_after_s": round(waited),
                "approved": approved["stdout"][-800:]}

    def step_compile(self) -> dict[str, Any]:
        found = {name: self._verified_rule(name, COMPILE_TIMEOUT_S) for name in ("reporter-a", "reporter-b")}
        return {"summary": "both rulesets serve the promoted dependency as a verified rule and their guards in "
                           "block mode refuse installing it; the unpromoted control report is not verified",
                "rulesets": found}

    def step_late_join(self) -> dict[str, Any]:
        node = self.cluster.add_reporter_edge("reporter-c")
        sync = self._sync("reporter-c")
        ready = self._graph_ready("reporter-c")
        reports = self._reports_present("reporter-c", LATE_JOIN_TIMEOUT_S)
        rule = self._verified_rule("reporter-c", LATE_JOIN_TIMEOUT_S)
        return {"summary": "reporter-c (added after the promotion) reads both reports and holds the verified rule",
                "node": node, "sync": sync, "ready": ready, "reports": reports, "ruleset": rule}

    def step_restart(self) -> dict[str, Any]:
        restarted = {}
        for name in ("reporter-b", "reporter-c"):
            restarted[name] = self.cluster.restart_node_of(name)
        # fresh: the reporter's ruleset cache is dropped first, so the rule can only come from
        # what the restarted node holds now, never from Blackbox's last-good generation.
        after = {name: {"reports": self._reports_present(name, READ_TIMEOUT_S),
                        "ruleset": self._verified_rule(name, COMPILE_TIMEOUT_S, fresh=True)} for name in restarted}
        return {"summary": "after restarting reporter-b's and reporter-c's nodes both still read the reports and "
                           "hold the verified rule", "restart": restarted, "after": after}

    # -- helpers ------------------------------------------------------------------

    def _graph_ready(self, name: str, timeout: float = READY_TIMEOUT_S) -> dict[str, Any]:
        """Wait until *name*'s node lists the graph as subscribed with its
        definition (an access policy): what Blackbox's membership confirms, and
        what the node's write check needs with the graph content it holds. The
        listing's ``synced`` flag is recorded, not awaited: on a registered graph
        the DKG can leave it false while the node takes writes (``_SYNCED_FLAG_GAPS``).
        Blackbox's own beat runs meanwhile, as a running Blackbox's would."""
        last: dict[str, Any] = {}
        beat = self._beater(name)

        def probe() -> Optional[dict[str, Any]]:
            nonlocal last
            last = self.cluster.graph_row(name) or {}
            if _ready(last):
                return last
            beat()   # Blackbox's own membership check repairs what it can before any assist
            return None

        row, waited = self._assisted_wait(name, probe, timeout, lambda: f"its listing was {_row_state(last)}")
        if row is None:
            raise StepFailed(f"{name}'s node does not list the graph as subscribed with its definition within "
                             f"{timeout:.0f} s", listing=last)
        return {"seconds": round(waited), "listing": _row_state(row), "synced": bool(row.get("synced"))}

    def _assisted_wait(self, name: str, probe: Callable[[], Any], timeout: float,
                       state: Callable[[], str]) -> tuple[Any, float]:
        """:func:`_wait` for *probe*. When it is not there halfway, the trial applies
        the documented DKG work-around for a registered graph whose catch-up is
        not re-run, a subscribe with forceCatchup on *name*'s node, and records it
        as an assist (*state* says what was missing); ``--no-assist`` waits the
        whole time without it."""
        if not self.assist:
            return _wait(probe, timeout)
        found, waited = _wait(probe, timeout / 2)
        if found is None:
            self.cluster.force_catchup(name)
            self._assists.append(f"forced a catch-up on {self.cluster.actors[name].node.label} ({name}) after "
                                 f"{waited:.0f} s: {state()}")
            found, more = _wait(probe, timeout / 2)
            waited += more
        return found, waited

    def _report_subject(self, name: str) -> str:
        """The subject of *name*'s report of the promoted threat."""
        return threat_ids.report_uri(self.state.promoted.identifier, self.state.reporter_addresses[name])

    def _sync(self, name: str) -> dict[str, Any]:
        """``blackbox sync``: subscribe to the graph and refresh once. Not ``--wait``:
        that waits for the graph to hold verified rules, which a new graph does not."""
        answer = _cli(self.cluster.actor(name), ["sync"], timeout=420.0)
        return {"rc": answer["rc"], "tail": answer["stdout"][-1500:]}

    def _file_control_report(self) -> dict[str, Any]:
        """Reporter B files its own report of another threat: never promoted, so
        it must stay a community entry (the negative control of ``compile``)."""
        reporter = self.cluster.actor("reporter-b")
        self.state.control = Threat("npm", f"bb-trial-{self.state.stamp}-unpromoted", "2.0.0")
        identity = reporter.call("identity", {"reporter_key": True})
        self.state.reporter_keys["reporter-b"] = identity["reporter_key"]
        self.state.reporter_addresses["reporter-b"] = identity["reporter_address"]
        sharing = self._enable_sharing("reporter-b")
        filed = _cli(reporter, self.state.control.report_argv(severity="high"))
        own, waited = self._landed("reporter-b", self.state.control, filed)
        if own is None:
            raise StepFailed("reporter-b's control report did not land on its own node", report=filed)
        return {"identifier": self.state.control.identifier, "landed_after_s": round(waited), "sharing": sharing,
                "stdout": filed["stdout"][-400:]}

    def _beater(self, name: str) -> Callable[[], None]:
        """A function that runs *name*'s Blackbox beat (a ruleset refresh: the
        membership check, the retry queue, keep-alive) when the last one is
        ``BEAT_S`` old — what a running Blackbox does between the trial's reads."""
        beat_at = 0.0

        def beat() -> None:
            nonlocal beat_at
            if time.monotonic() - beat_at >= BEAT_S:
                beat_at = time.monotonic()
                self.cluster.actor(name).call("ruleset", timeout=600.0)

        return beat

    def _reports_present(self, name: str, timeout: float) -> dict[str, Any]:
        wanted = {(self.state.promoted.identifier, self.state.reporter_keys["reporter-a"]),
                  (self.state.control.identifier, self.state.reporter_keys["reporter-b"])}
        last: dict[str, Any] = {}
        beat = self._beater(name)

        def probe() -> Optional[dict[str, Any]]:
            nonlocal last
            last = self.cluster.actor(name).call("read")
            have = {(r["identifier"], r["author"]) for r in last.get("reports", [])}
            if wanted <= have:
                return last
            beat()
            return None

        seen, waited = self._assisted_wait(name, probe, timeout,
                                           lambda: f"it read {len(last.get('reports', []))} of the 2 reports")
        if seen is None:
            raise StepFailed(f"{name} does not read both reports within {timeout:.0f} s", last_read=last)
        return {"seconds": round(waited), "state": seen.get("state"), "reports": len(seen.get("reports", []))}

    def _verified_rule(self, name: str, timeout: float, *, fresh: bool = False) -> dict[str, Any]:
        """Poll *name*'s ruleset until the promoted dependency is a verified rule
        (live lookup HIT, public source, not capped at flag) and the control
        report is not verified."""
        promoted, control = self.state.promoted, self.state.control
        params = {"dependencies": [promoted.candidate, control.candidate],
                  "identifiers": [promoted.identifier, control.identifier], "fresh": fresh}
        last: dict[str, Any] = {}

        def probe() -> Optional[dict[str, Any]]:
            nonlocal last
            last = self.cluster.actor(name).call("ruleset", params, timeout=600.0)
            return last if _is_verified(last, promoted) else None

        seen, waited = self._assisted_wait(name, probe, timeout, lambda: "no verified rule for it yet")
        if seen is None:
            raise StepFailed(f"{name}'s ruleset does not hold {promoted.identifier} as a verified rule within "
                             f"{timeout:.0f} s", last_ruleset=last)
        if control.identifier in seen.get("verified_subset", []):
            raise StepFailed(f"{name}'s ruleset treats the UNPROMOTED control report as verified", ruleset=seen)
        named = (_rule_for(seen, promoted) or {}).get("promotedReport")
        if named is not None and named != self._report_subject("reporter-a"):
            raise StepFailed(f"{name}'s verified rule names another report than reporter-a's", ruleset=seen)
        guard = self._guard(name)
        return {"seconds": round(waited), "rule": _rule_for(seen, promoted), "scope": seen.get("scope"),
                "control_community_entry": bool(seen.get("community", {}).get(control.identifier)), "guard": guard}

    def _guard(self, name: str) -> dict[str, Any]:
        """The enforcement the rule gives: *name*'s guard, in block mode (sharing
        off for the check), refuses ``npm install`` of the promoted package and
        does not refuse the unpromoted control (community rules never block)."""
        actor, mode = self.cluster.actor(name), {"BLACKBOX_MODE": "block", "BLACKBOX_REPORT": "0"}
        checks = {threat.identifier: actor.call("guard", {"command": f"npm install {threat.name}@{threat.version}"},
                                                env=mode)
                  for threat in (self.state.promoted, self.state.control)}
        promoted, control = checks[self.state.promoted.identifier], checks[self.state.control.identifier]
        if not promoted.get("blocked") or control.get("blocked"):
            raise StepFailed(f"{name}'s guard in block mode does not refuse the promoted package (or refuses the "
                             "unpromoted one)", guard=checks)
        return {identifier: {"blocked": check.get("blocked"), "findings": check.get("findings")}
                for identifier, check in checks.items()}


# -- pure helpers ---------------------------------------------------------------------


def _cli(actor: Actor, argv: list[str], *, timeout: float = 300.0) -> dict[str, Any]:
    answer = actor.call("cli", {"argv": argv}, timeout=timeout)
    if not answer.get("ok"):
        raise StepFailed(f"`blackbox {' '.join(argv[:3])}` crashed on {actor.name}", answer=answer)
    return answer


def _not_readable_yet(answer: dict[str, Any]) -> bool:
    return "cannot be read back yet" in answer.get("stdout", "")


def _hex_after(text: str, marker: str) -> str:
    for line in text.splitlines():
        if marker in line:
            value = line.split(marker, 1)[1].strip().split()[0].strip("…")
            if len(value) == 64:
                return value
    raise StepFailed(f"no key after {marker!r} in the command's output", output=text[-1500:])


def _word_after(text: str, marker: str) -> str:
    for line in text.splitlines():
        if marker in line:
            return line.split(marker, 1)[1].strip().split()[0]
    raise StepFailed(f"no {marker!r} in the command's output", output=text[-1500:])


def _report_of(read: dict[str, Any], threat: Threat, author: str) -> Optional[dict[str, Any]]:
    for report in read.get("reports", []):
        if report.get("identifier") == threat.identifier and report.get("author") == author:
            return report
    return None


def _own_asset(graphs: Optional[list[str]], address: str) -> bool:
    """*graphs* (None: the node has no store to ask) include a Verified Memory asset *address* authored."""
    return graphs is None or any(f"/_verifiable_memory/{address.lower()}/" in graph.lower() for graph in graphs)


def _ready(row: dict[str, Any]) -> bool:
    return bool(row.get("subscribed") and str(row.get("accessPolicy") or "").strip())


def _row_state(row: dict[str, Any]) -> str:
    return (f"subscribed={bool(row.get('subscribed'))} synced={bool(row.get('synced'))} "
            f"definition={'yes' if str(row.get('accessPolicy') or '').strip() else 'no'}") if row else "absent"


def _rule_for(answer: dict[str, Any], threat: Threat) -> Optional[dict[str, Any]]:
    rules = ((answer.get("dependency") or {}).get("rules") or {})
    return next((rule for rule in rules.values() if rule.get("identifier") == threat.identifier), None)


def _is_verified(answer: dict[str, Any], threat: Threat) -> bool:
    """The promoted threat is a verified rule: the live lookup serves it from the
    public tier (not capped at flag) and ``verified_subset`` lists it."""
    rule = _rule_for(answer, threat)
    return bool(answer.get("refreshed") and rule and rule.get("source") == "public"
                and rule.get("asset_tier") != "flag" and threat.identifier in answer.get("verified_subset", []))


def _wait(probe: Callable[[], Any], timeout: float, interval: float = POLL_S) -> tuple[Any, float]:
    """Call *probe* until it returns something truthy or *timeout* passes:
    (the value or None, seconds waited)."""
    started = time.monotonic()
    while True:
        value = probe()
        waited = time.monotonic() - started
        if value or waited >= timeout:
            return (value or None), waited
        time.sleep(interval)


def run_stamp() -> str:
    """A short, unique run stamp (UTC time + random), safe in package names and graph names."""
    now = time.strftime("%Y%m%d%H%M%S", time.gmtime())
    return f"{now}-{hashlib.sha256(str(time.time_ns()).encode()).hexdigest()[:6]}"
