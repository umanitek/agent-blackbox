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
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Optional

from plugins.blackbox.kernel import constants, sparql_text, threat_ids
from plugins.blackbox.kernel.dkg_client import DkgError

from .actors import Actor, ActorError
from .cluster import Cluster
from .devnet import NodeApi
from .report import ERROR, FAIL, PASS, SKIP, StepFailed, StepResult, TrialReport

logger = logging.getLogger(__name__)

#: Seconds a reporter's community read may take to show another node's report.
READ_TIMEOUT_S = 300.0
#: Seconds a ruleset may take to hold a promotion (refresh + asset tiering).
COMPILE_TIMEOUT_S = 420.0
#: Seconds a node that joins later may take to catch up.
LATE_JOIN_TIMEOUT_S = 600.0
#: Seconds a subscribed node may take to list the graph as synced and defined.
READY_TIMEOUT_S = 240.0
#: How often a wait runs the beat a running Blackbox performs (a ruleset refresh:
#: membership check, retry queue, keep-alive); its pulse runs every 20 s, a refresh hourly.
BEAT_S = 45.0
POLL_S = 10.0
#: The file in the run folder a resumed run starts from.
STATE_FILE = "trial-state.json"
#: Seconds the proposal from curator 1 may take to reach the graph owner's node.
PROPOSAL_TIMEOUT_S = 180.0
#: The node's refusal of a write into a graph it lists but has not proven synced. The trial's
#: one remaining DKG work-around retries it (:meth:`Trial._owner_write`).
NOT_WRITABLE = "CONTEXT_GRAPH_NOT_WRITABLE"
#: A node's log line when its shared-memory pull fetched triples and its verifier threw them away
#: (a graph-scoped share whose metadata names no root entity), and the fetch line before it.
PULL_DROP_MARK = "SWM sync dropped"
PULL_FETCH_MARK = "triples fetched"
#: How long a check of community reports waits once the run has shown that pulled reports
#: are dropped (the step 7 gap): it records the same failure without waiting it out again.
KNOWN_GAP_REPORT_WAIT_S = 180.0
#: Titles that differ on the testnet (the step keys stay the same).
TESTNET_TITLES = {
    "devnet": "Curator node up on the testnet (relay-only)",
    "edges": "Two reporter Edges on the testnet with Blackbox's node settings (relay-only)",
    "keys": "Curator keys: test root for the testnet's network id, manifest published",
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
    #: The promotion published reporter A's own asset (it then lives in Verified Memory, not shared memory).
    promoted_as_itself: bool = False

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
                 timeout_scale: float = 1.0, keep_going: bool = False) -> None:
        self.cluster = cluster
        self.report = report
        self.state = state
        self.until = until
        #: Run a step even when a step it needs did not pass (what it finds is still evidence;
        #: a step whose inputs are missing then ERRORs instead of being SKIPped).
        self.keep_going = keep_going
        #: Every wait of the trial, scaled (the testnet's chain and relays are slower than a devnet)
        self.read_timeout = READ_TIMEOUT_S * timeout_scale
        self.compile_timeout = COMPILE_TIMEOUT_S * timeout_scale
        self.late_join_timeout = LATE_JOIN_TIMEOUT_S * timeout_scale
        self.ready_timeout = READY_TIMEOUT_S * timeout_scale
        self.proposal_timeout = PROPOSAL_TIMEOUT_S * timeout_scale
        self.command_timeout_scale = timeout_scale
        self.arrivals: Optional[ArrivalWatcher] = None
        #: Set when step 7 failed and the reader's node had dropped the pulled share.
        self.known_pull_drop: dict[str, Any] = {}
        self._step_started = 0.0

    # -- running ------------------------------------------------------------------

    def run(self) -> TrialReport:
        """Run every step in order (a resumed run skips the steps that passed
        before), saving the state after each one (:meth:`save`)."""
        for key, title, needs in STEPS:
            if self.cluster.testnet:
                title = TESTNET_TITLES.get(key, title)
            if self._passed(key):
                logger.info("step %s: passed in the run being resumed", key)
            else:
                missing = [need for need in needs if not self._passed(need)]
                if missing and not self.keep_going:
                    self.report.add(StepResult(key, title, SKIP, summary=f"not run: {', '.join(missing)} did not pass"))
                else:
                    result = self._run_one(key, title)
                    if missing:
                        result.summary = f"(ran although {', '.join(missing)} did not pass) {result.summary}"
                    self.report.add(result)
                self.save()
            if key == self.until:
                break
        if self.arrivals is not None:   # the last word on when A's report reached each node
            self.report.facts["report_arrivals"] = self.arrivals.result()
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
        self._step_started = result.started_at
        logger.info("step %s: %s", key, title)
        try:
            evidence = method() or {}
            result.status, result.summary = PASS, str(evidence.pop("summary", "") or "")
            result.evidence = evidence
        except StepFailed as failed:
            result.status, result.summary, result.evidence = FAIL, failed.summary, failed.evidence
        except ActorError as exc:
            result.status, result.summary, result.error = ERROR, "an actor gave no answer", str(exc)
        except Exception as exc:   # the trial's own failure: recorded, the run goes on
            logger.exception("step %s errored", key)
            result.status, result.summary, result.error = ERROR, f"{type(exc).__name__}: {exc}", repr(exc)
        result.seconds = time.time() - result.started_at
        if self.cluster.links is not None:
            result.evidence["links"] = self.cluster.links.summary(since=result.started_at)
        if result.status != PASS:
            result.logs = self.cluster.log_excerpts(since=result.started_at)
        logger.info("step %s: %s (%.0f s) %s", key, result.status, result.seconds, result.summary)
        return result

    # -- the steps ----------------------------------------------------------------

    def step_devnet(self) -> dict[str, Any]:
        facts = self.cluster.ensure_devnet()
        self.state.network_id = facts["network_id"]
        self.report.facts.update({"dkg": facts.get("dkg_version", ""), "network_id": self.state.network_id})
        if facts.get("dkg_status_commit"):
            self.report.facts["dkg_commit_running"] = facts["dkg_status_commit"]
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
            answer, owner_write = self._owner_write(["curate", "--authority", "verified", "publish", staged, "--yes"])
            published = answer["stdout"].strip()
            if answer["rc"] != 0 and not _not_readable_yet(answer):
                raise StepFailed("the key manifest was not published", manifest=manifest, publish=answer,
                                 owner_write=owner_write)
        else:
            owner_write = {}
        trusted, _waited = _wait(lambda: self._trusts_manifest("curator-2"), self.read_timeout)
        trust = owner.call("trust")
        if not trusted:
            raise StepFailed("the curator node does not act on the published manifest", trust=trust, publish=published)
        note = ""
        if owner_write:
            note = (f"; the owner's node first refused its own write ({NOT_WRITABLE}), listing "
                    f"{owner_write.get('listing')} " + (f"until synced {owner_write['owner_synced_after_s']} s later"
                                                         if owner_write.get("owner_synced_after_s") is not None
                                                         else "and never synced"))
        return {"summary": f"root {self.state.root_key[:12]}… trusted on network {self.state.network_id} only "
                           "(environment variable, no pin changed); manifest with 2 curator keys of 2 operators "
                           f"published and trusted on the curator node{note}",
                "root_key": self.state.root_key, "curator_keys": self.state.curator_keys,
                "trusted_roots_seen": seen.get("trusted_roots"), "manifest_publish": published, "trust": trust,
                **({"owner_write": owner_write} if owner_write else {})}

    def _owner_write(self, argv: list[str]) -> tuple[dict[str, Any], dict[str, Any]]:
        """``blackbox <argv>`` on curator 2, a command that writes into the graph. When the
        owner's own node refuses it as not synced for writes (a registered graph whose
        catch-up after a restart ran before the node had the graph's authority), wait for
        the node's listing to say synced and run the command once more. Returns the last
        answer and what happened ({} when the first attempt was not refused that way).

        THE ONE REMAINING DKG WORK-AROUND, kept until OriginTrail/dkg#3320 ships: right
        after the curator node restarts (the trial restarts it to apply Blackbox's curator
        settings), the owner's first write can be refused for 13 to 23 s. Remove this
        retry once the pinned DKG release lets that write wait instead of refusing it."""
        owner = self.cluster.actor("curator-2")
        answer = _cli(owner, argv, timeout=600.0)
        if NOT_WRITABLE not in answer["stdout"]:
            return answer, {}
        last: dict[str, Any] = {}

        def synced() -> Optional[dict[str, Any]]:
            nonlocal last
            last = self.cluster.graph_row("curator-2") or {}
            return last if last.get("synced") else None

        row, waited = _wait(synced, self.ready_timeout)
        retry = _cli(owner, argv, timeout=600.0)
        return retry, {"first_refusal": answer["stdout"][-500:], "listing": _row_state(last),
                       "owner_synced_after_s": round(waited) if row else None, "retry_rc": retry["rc"]}

    def step_subscribe(self) -> dict[str, Any]:
        """The reporters and curator 1's node subscribe the way Blackbox does
        (``blackbox sync``); each then lists the graph synced with its definition
        and acts on the curators' manifest it read from Verified Memory."""
        names = ("reporter-a", "reporter-b", "curator-1")
        answers = {name: self._sync(name) for name in names}
        ready = {name: self._graph_ready(name) for name in names}
        joined = {name: self.cluster.actor(name).call("read").get("join_state") for name in names}
        if any(state != "joined" for state in joined.values()):
            raise StepFailed("Blackbox does not see a node as joined to the graph", join=joined, ready=ready,
                             sync=answers)
        trusted, waited = _wait(lambda: all(self._trusts_manifest(name) for name in names), self.read_timeout)
        if not trusted:
            raise StepFailed("a subscribed node does not act on the curators' manifest", join=joined,
                             trust={name: self.cluster.actor(name).call("trust") for name in names})
        return {"summary": f"reporter-a, reporter-b and curator-1's node joined the graph (synced, definition in) "
                           f"and trust the manifest (after {waited:.0f} s more)", "ready": ready, "join": joined,
                "sync": answers}

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
        self.arrivals = ArrivalWatcher(
            {name: self.cluster.api_of(name) for name in ("reporter-a", "reporter-b", "curator-2")},
            graph=self.state.graph_id, subject=self._report_subject("reporter-a"),
            timeout=self.read_timeout * 3)
        self.arrivals.start()
        filed = _cli(reporter, self.state.promoted.report_argv())
        self.arrivals.filed_at = time.time()
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
        return _wait(probe, self.read_timeout)

    def step_read(self) -> dict[str, Any]:
        threat = self.state.promoted
        author = self.state.reporter_keys["reporter-a"]
        beat = self._beater("reporter-b")

        def probe() -> Optional[dict[str, Any]]:
            found = _report_of(self.cluster.actor("reporter-b").call("read"), threat, author)
            if found is None:
                beat()
            return found

        seen, waited = _wait(probe, self.read_timeout)
        read_at = time.time()
        arrivals = self.arrivals.result() if self.arrivals else {}
        if seen is None:
            drops = self._pull_drops("reporter-b", since=self.arrivals.started_at if self.arrivals else read_at - 900)
            if drops.get("dropped"):
                self.known_pull_drop = drops
            # later steps (run with --keep-going) need B's control report, so B files it anyway
            control = self._file_control_report() if self.keep_going else None
            cause = (f"; B's node fetched the report {drops['fetched_with_data']} time(s) by pull and dropped it every "
                     f"time ({drops['first_drop']})" if drops.get("dropped") else "")
            raise StepFailed(f"reporter-b's community reader did not return A's report within "
                             f"{self.read_timeout:.0f} s{cause}",
                             last_read=self.cluster.actor("reporter-b").call("read"),
                             arrivals=arrivals, control_report=control, pull_drops=drops)
        control = self._file_control_report()
        filed = (self.arrivals.filed_at if self.arrivals else 0.0) or read_at
        return {"summary": f"reporter-b reads A's signed report after {waited:.0f} s "
                           f"({read_at - filed:.0f} s after A's share returned); {_arrival_text(arrivals)}",
                "report": seen, "control_report": control, "arrivals": arrivals,
                "reader_seconds_after_share": round(read_at - filed, 1)}

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

        statement, waited = _wait(read_back, self.read_timeout)
        if statement is None:
            raise StepFailed("Verified Memory does not hold the promotion: a statement signed by both curator keys "
                             "that names reporter-a's report (subject and digest), with the report itself or the "
                             "curators' own asset built from it", promotion=promoted, verified_memory=last)
        self.state.promoted_as_itself = last.get("form") == "report-itself"
        form = "the report itself" if self.state.promoted_as_itself else "the curators' own asset built from it"
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

        got, waited = _wait(received, self.proposal_timeout)
        if not got:
            raise StepFailed("curator-2 never received curator-1's proposal", proposal=proposed)
        approved = _cli(owner, ["curate", "--authority", "verified", "approve", proposal_id, "--evidence", evidence,
                                "--yes"], timeout=600.0)
        if ": published" not in approved["stdout"] and not _not_readable_yet(approved):
            raise StepFailed("curator-2's approval did not publish the promotion", proposal=proposed, approval=approved)
        return {"proposal": proposal_id, "proposed": proposed["stdout"][-600:], "received_after_s": round(waited),
                "approved": approved["stdout"][-800:]}

    def step_compile(self) -> dict[str, Any]:
        checks = _Checks(self.keep_going)
        found = {name: checks.run(f"{name}'s verified rule", lambda name=name: self._verified_rule(
            name, self.compile_timeout)) for name in ("reporter-a", "reporter-b")}
        checks.done()
        return {"summary": "both rulesets serve the promoted dependency as a verified rule and their guards in "
                           "block mode refuse installing it; the unpromoted control report is not verified",
                "rulesets": found}

    def step_late_join(self) -> dict[str, Any]:
        node = self.cluster.add_reporter_edge("reporter-c")
        sync = self._sync("reporter-c")
        ready = self._graph_ready("reporter-c")
        checks = _Checks(self.keep_going)
        # the verified rule first: what the community reports check finds is already known when step 7 failed
        rule = checks.run("reporter-c's verified rule",
                          lambda: self._verified_rule("reporter-c", self.late_join_timeout))
        reports = checks.run("reporter-c reads the community reports",
                             lambda: self._reports_present("reporter-c", self._report_wait(self.late_join_timeout)))
        checks.done(pull_drops=self._pull_drops("reporter-c", since=self._step_started) if checks.failed else None)
        return {"summary": "reporter-c (added after the promotion) reads the community reports and holds the verified "
                           "rule",
                "node": node, "sync": sync, "ready": ready, "reports": reports, "ruleset": rule}

    def step_restart(self) -> dict[str, Any]:
        restarted = {}
        for name in ("reporter-b", "reporter-c"):
            restarted[name] = self.cluster.restart_node_of(name)
        # fresh: the reporter's ruleset cache is dropped first, so the rule can only come from
        # what the restarted node holds now, never from Blackbox's last-good generation.
        checks = _Checks(self.keep_going)
        after = {name: {"ruleset": checks.run(f"{name}'s verified rule after the restart", lambda name=name:
                                              self._verified_rule(name, self.compile_timeout, fresh=True)),
                        "reports": checks.run(f"{name} reads the community reports after the restart",
                                              lambda name=name: self._reports_present(
                                                  name, self._report_wait(self.read_timeout)))}
                 for name in restarted}
        checks.done(restart=restarted)
        return {"summary": "after restarting reporter-b's and reporter-c's nodes both still read the community "
                           "reports and hold the verified rule", "restart": restarted, "after": after}

    def _report_wait(self, timeout: float) -> float:
        """How long a community-reports check waits: the step's wait, or a short one once
        step 7 showed that pulled reports are dropped (the outcome is then already known)."""
        return min(timeout, KNOWN_GAP_REPORT_WAIT_S) if self.known_pull_drop else timeout

    def _pull_drops(self, name: str, *, since: float) -> dict[str, Any]:
        """What *name*'s node logged about pulled shared memory since *since*: how often a pull
        fetched data, how often its verifier dropped what it fetched, and the first and last
        drop lines. {} when the node's log cannot be read here."""
        window = getattr(self.cluster.devnet, "log_window", None)
        if window is None or name not in self.cluster.actors:
            return {}
        lines = window(self.cluster._node_of(name).number, since)
        drops = [line for line in lines if PULL_DROP_MARK in line]
        fetched = [line for line in lines if "shared memory: " in line and PULL_FETCH_MARK in line
                   and "shared memory: 0 data" not in line]
        return {"node": self.cluster.actors[name].node.label, "dropped": len(drops), "fetched_with_data": len(fetched),
                "first_drop": drops[0][-160:] if drops else "", "last_drop": drops[-1][-160:] if drops else ""}

    # -- helpers ------------------------------------------------------------------

    def _graph_ready(self, name: str, timeout: float = 0.0) -> dict[str, Any]:
        """Wait until *name*'s node lists the graph as subscribed, synced and with
        its definition (an access policy): what the node needs before it accepts
        writes. Since DKG 10.0.25 a catch-up that finds nothing missing proves the
        graph synced too (OriginTrail/dkg#3304, fixing #3296). Blackbox's own beat
        runs meanwhile, as a running Blackbox's would."""
        timeout = timeout or self.ready_timeout
        last: dict[str, Any] = {}
        beat = self._beater(name)

        def probe() -> Optional[dict[str, Any]]:
            nonlocal last
            last = self.cluster.graph_row(name) or {}
            if _ready(last):
                return last
            beat()   # Blackbox's own membership check, as a running Blackbox's would
            return None

        row, waited = _wait(probe, timeout)
        if row is None:
            raise StepFailed(f"{name}'s node does not list the graph as subscribed, synced and defined within "
                             f"{timeout:.0f} s", listing=last)
        return {"seconds": round(waited), "listing": _row_state(row)}

    def _report_subject(self, name: str) -> str:
        """The subject of *name*'s report of the promoted threat."""
        return threat_ids.report_uri(self.state.promoted.identifier, self.state.reporter_addresses[name])

    def _sync(self, name: str) -> dict[str, Any]:
        """``blackbox sync``: subscribe to the graph and refresh once. Not ``--wait``:
        that waits for the graph to hold verified rules, which a new graph does not."""
        answer = _cli(self.cluster.actor(name), ["sync"], timeout=420.0 * self.command_timeout_scale)
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
        """Poll *name*'s community read until it returns the community reports: both of them, or
        only the unpromoted control once the promotion published reporter A's own asset (that report
        then lives in Verified Memory, which the verified-rule check reads)."""
        wanted = _community_reports(self.state)
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

        seen, waited = _wait(probe, timeout)
        if seen is None:
            raise StepFailed(f"{name} does not read the {len(wanted)} community report(s) within {timeout:.0f} s",
                             last_read=last)
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

        seen, waited = _wait(probe, timeout)
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
    return bool(row.get("subscribed") and row.get("synced") and str(row.get("accessPolicy") or "").strip())


def _row_state(row: dict[str, Any]) -> str:
    return (f"subscribed={bool(row.get('subscribed'))} synced={bool(row.get('synced'))} "
            f"definition={'yes' if str(row.get('accessPolicy') or '').strip() else 'no'}") if row else "absent"


def _community_reports(state: TrialState) -> set[tuple[str, str]]:
    """``(identifier, reporter key)`` of the reports the community tier must still hold after the
    promotion: B's unpromoted control, and A's report unless it was published as itself."""
    wanted = {(state.control.identifier, state.reporter_keys["reporter-b"])}
    if not state.promoted_as_itself:
        wanted.add((state.promoted.identifier, state.reporter_keys["reporter-a"]))
    return wanted


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


class _Checks:
    """The checks of one step. Without *keep_going* the first failing check ends the step at
    once (as always); with it every check runs, and the step then fails with the first
    failing check as its summary and every failing one in its evidence."""

    def __init__(self, keep_going: bool) -> None:
        self.keep_going = keep_going
        self.failed: list[tuple[str, StepFailed]] = []

    def run(self, label: str, check: Callable[[], Any]) -> Any:
        try:
            return check()
        except StepFailed as failed:
            if not self.keep_going:
                raise
            self.failed.append((label, failed))
            return {"failed": failed.summary}

    def done(self, **evidence: Any) -> None:
        if not self.failed:
            return
        label, first = self.failed[0]
        more = f" (and {len(self.failed) - 1} more failing check(s))" if len(self.failed) > 1 else ""
        raise StepFailed(f"first failing check, {label}: {first.summary}{more}",
                         failing_checks={name: {"summary": failed.summary, **failed.evidence}
                                         for name, failed in self.failed},
                         **{key: value for key, value in evidence.items() if value is not None})


class ArrivalWatcher:
    """When a report's signed statement first shows in each node's shared memory
    (sub-graph ``reports``), polled every *interval* seconds straight from the node
    — the network's delivery, before any Blackbox reader looks. ``filed_at`` is
    set when ``blackbox report`` returned; times are seconds after it."""

    def __init__(self, apis: dict[str, NodeApi], *, graph: str, subject: str, timeout: float,
                 interval: float = 2.0) -> None:
        self._apis = apis
        self._body = {"sparql": f"SELECT ?o WHERE {{ <{subject}> <{constants.SIGNED_STATEMENT_PRED}> ?o }} LIMIT 1",
                      "contextGraphId": graph, "view": constants.VIEW_SHARED_WORKING_MEMORY,
                      "subGraphName": constants.COMMUNITY_SUB_GRAPH}
        self._timeout, self._interval = timeout, interval
        self.started_at = time.time()
        self.filed_at = 0.0
        self.seen: dict[str, float] = {}
        self.errors: dict[str, str] = {}
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="arrivals", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        deadline = time.monotonic() + self._timeout
        while not self._stop.is_set() and time.monotonic() < deadline and len(self.seen) < len(self._apis):
            for name, api in self._apis.items():
                if name in self.seen:
                    continue
                try:
                    rows = sparql_text.recognized_bindings(api.call("POST", "/api/query", dict(self._body),
                                                                    timeout=20.0))
                except (DkgError, OSError, ValueError) as exc:   # one failed poll; the next one asks again
                    self.errors[name] = f"{type(exc).__name__}: {str(exc)[:160]}"
                    continue
                if rows is None:
                    self.errors[name] = "the node's answer had no bindings"
                elif rows:
                    self.seen[name] = time.time()
            self._stop.wait(self._interval)

    def result(self) -> dict[str, Any]:
        """Per node: seconds after ``blackbox report`` returned (negative: before) or None."""
        base = self.filed_at or self.started_at
        return {"seconds_after_share": {name: (round(self.seen[name] - base, 1) if name in self.seen else None)
                                        for name in self._apis},
                "poll_interval_s": self._interval, "still_polling": self._thread.is_alive(),
                "errors": dict(self.errors)}


def _arrival_text(arrivals: dict[str, Any]) -> str:
    seconds = arrivals.get("seconds_after_share") or {}
    parts = [f"{name}'s node " + (f"+{value:.0f} s" if value is not None else "not yet")
             for name, value in sorted(seconds.items()) if name != "reporter-a"]
    return ("in shared memory: " + ", ".join(parts)) if parts else "arrival not measured"


def run_stamp() -> str:
    """A short, unique run stamp (UTC time + random), safe in package names and graph names."""
    now = time.strftime("%Y%m%d%H%M%S", time.gmtime())
    return f"{now}-{hashlib.sha256(str(time.time_ns()).encode()).hexdigest()[:6]}"
