"""What an actor process can do — the Blackbox side of the trial.

Runs inside one actor's own process (:mod:`.actors`), with that actor's
``BLACKBOX_HOME`` and node in the environment, and calls Blackbox's own code:

* ``cli`` — the ``blackbox`` command exactly as an operator types it
  (``report``, ``sync``, ``curate …``), through the plugin's own argument parser;
* ``read`` — the community read every product surface uses
  (``community.read_verified_reports``);
* ``ruleset`` — a ruleset refresh, then the live verified lookups detection
  asks (``dependency_rules``, ``verified_subset``) and the verified scope;
* ``identity`` — this node as Blackbox sees it (network id, reporter address,
  the configured graph) and the public keys this installation holds.

Each action returns a JSON-able dict; :func:`main` prints it as the last line.
Nothing secret is returned: keys only as public keys.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import logging
import sys
import traceback
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

from .actors import ANSWER_PREFIX

Action = Callable[[Mapping[str, Any]], dict[str, Any]]


class _Captured(logging.Handler):
    """Keeps Blackbox's own WARNING+ log lines, so a refusal's reason reaches the report."""

    def __init__(self) -> None:
        super().__init__(logging.INFO)
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        if record.name.startswith(("plugins.blackbox", "hermes_plugins.blackbox")) or record.levelno >= logging.WARNING:
            self.lines.append(f"{record.levelname} {record.name}: {record.getMessage()}"[:600])


def _config_and_client() -> tuple[Any, Any]:
    from plugins.blackbox.kernel.config import load_blackbox_config
    from plugins.blackbox.kernel.dkg_client import DkgClient

    cfg = load_blackbox_config()
    return cfg, DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)


def run_cli(params: Mapping[str, Any]) -> dict[str, Any]:
    """``blackbox <argv>``: the exit code and what the command printed."""
    from plugins.blackbox import cli as blackbox_cli

    parser = argparse.ArgumentParser(prog="blackbox")
    blackbox_cli.setup_cli(parser)
    argv = [str(item) for item in params.get("argv", [])]
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            args = parser.parse_args(argv)
            code = args.func(args)
        except SystemExit as exc:   # argparse refused the arguments
            code = exc.code if isinstance(exc.code, int) else 2
    return {"argv": argv, "rc": int(code or 0), "stdout": out.getvalue()[-8000:], "stderr": err.getvalue()[-4000:]}


def read_reports(params: Mapping[str, Any]) -> dict[str, Any]:
    """The community read: its state and every verified report."""
    from plugins.blackbox import community

    cfg, client = _config_and_client()
    read = community.read_verified_reports(client, cfg)
    curator = read.curator
    return {
        "state": read.state.value,
        "reason": read.reason,
        "graph": cfg.context_graph_id,
        "reports": [{"identifier": r.identifier, "author": r.author, "reporter": r.reporter, "subject": r.subject,
                     "severity": r.severity, "day": r.day} for r in read.reports],
        "env_mismatch": read.env_mismatch,
        "future_dated": read.future_dated,
        "held_back": read.held_back,
        "curator_manifest": bool(getattr(curator, "manifest", None)),
        "join_state": community.read_join_state(client, cfg.context_graph_id).value,
    }


def refresh_ruleset(params: Mapping[str, Any]) -> dict[str, Any]:
    """Refresh the ruleset from the node, then ask it what detection asks."""
    from plugins.blackbox import ruleset

    cfg, client = _config_and_client()
    if params.get("fresh"):   # no last-good generation to fall back on: what is served comes from the node now
        from plugins.blackbox.kernel import constants

        (constants.blackbox_home() / "ruleset.json").unlink(missing_ok=True)
    try:
        rs = ruleset.refresh(cfg, client, force_query=bool(params.get("force")))
    except (ruleset.RulesetRefreshUnavailable, ruleset.RulesetRefreshIncomplete,
            ruleset.RulesetRefreshLockUnavailable) as exc:
        return {"refreshed": False, "refusal": f"{type(exc).__name__}: {exc}"}
    candidates = [tuple(str(part) for part in item) for item in params.get("dependencies", [])]
    answer = rs.dependency_rules(candidates) if candidates else None
    identifiers = [str(item) for item in params.get("identifiers", [])]
    return {
        "refreshed": True,
        "counts": rs.counts(),
        # what `blackbox sync --wait` waits on: a public count above zero
        "public_graph_count": int(rs.graph_count("public")) if callable(getattr(rs, "graph_count", None)) else None,
        "dependency": {"outcome": answer.outcome, "reason": answer.reason, "rules": _plain(answer.rules)}
        if answer is not None else None,
        "verified_subset": sorted(rs.verified_subset(identifiers)) if identifiers else [],
        "community": {identifier: _plain(rs.community.get(identifier)) for identifier in identifiers
                      if rs.community.get(identifier)},
        "scope": _scope_summary(rs.verified_scope),
        "curator_manifest_state": rs.curator_manifest_state,
        "curator_legacy_assets_hash": rs.curator_legacy_assets_hash,
        "curator_revoked": sorted(rs.curator_revoked),
    }


def curator_trust(params: Mapping[str, Any]) -> dict[str, Any]:
    """The curator view this node acts on: which key manifest it trusts (if any)."""
    from plugins.blackbox import community

    cfg, client = _config_and_client()
    view = community.read_curator_view(client, cfg)
    manifest = view.manifest
    return {
        "manifest": None if manifest is None else {
            "environment": manifest.environment, "graph": manifest.graph, "root_epoch": manifest.root_epoch,
            "version": manifest.version, "threshold": manifest.threshold, "curator_keys": list(manifest.curator_keys),
            "promotion_author": manifest.promotion_author},
        "unavailable": view.unavailable,
        "manifest_conflict": view.manifest_conflict,
        "manifest_state": view.manifest_state,
    }


def guard_check(params: Mapping[str, Any]) -> dict[str, Any]:
    """What the guard does with one shell command (``pre_tool_call``, the hook
    Hermes calls before a tool runs), and the findings it recorded for it."""
    from plugins.blackbox import guard
    from plugins.blackbox.kernel import constants

    command = str(params["command"])
    findings_file = constants.blackbox_home() / "findings.jsonl"
    before = findings_file.stat().st_size if findings_file.is_file() else 0
    decision = guard.on_pre_tool_call(tool_name="terminal", args={"command": command}, session_id="bb-trial",
                                      task_id="bb-trial", tool_call_id="bb-trial-guard")
    findings = []
    if findings_file.is_file():
        with findings_file.open(encoding="utf-8-sig") as handle:
            handle.seek(before)
            for line in handle:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                recorded = (row.get("detail") or {}).get("decision")
                for found in row.get("findings") or []:
                    sighting = found.get("sighting") or {}
                    findings.append({"identifier": found.get("identifier"), "source": found.get("source"),
                                     "severity": found.get("severity"), "confirmed": found.get("confirmed"),
                                     "matched_by": sighting.get("matched_by"), "outcome": sighting.get("outcome"),
                                     "decision": recorded})
    return {"command": command, "blocked": isinstance(decision, dict) and decision.get("action") == "block",
            "decision": decision, "findings": findings}


def _scope_summary(scope: Any) -> dict[str, Any]:
    if scope is None:
        return {"built": False}
    return {
        "built": True,
        "ready": scope.ready,
        "store_url_known": bool(scope.store_url),
        "assets": len(scope.assertion_graphs),
        "tiers": {graph: (fact.tier.value if fact.tier is not None else None)
                  for graph, fact in sorted(scope.asset_facts.items())},
        "signed_subjects": {graph: sorted(fact.signed) for graph, fact in sorted(scope.asset_facts.items())
                            if fact.signed},
        "verified_counts": dict(scope.verified_counts),
        "legacy_refused": scope.legacy_refused,
    }


def identity(params: Mapping[str, Any]) -> dict[str, Any]:
    """This node as Blackbox sees it, and this installation's public keys."""
    from plugins.blackbox import community
    from plugins.blackbox.kernel import constants, identity as node_identity
    from plugins.blackbox.kernel.reporter_key import ReporterKeyStore
    from plugins.blackbox.kernel.signing import trust_anchors

    cfg, client = _config_and_client()
    status = client.status()
    environment = community.network_environment(status)
    answer = {
        "network_id": environment,
        "peer_id": str(status.get("peerId") or ""),
        "store_url_reported": bool(status.get("storeUrl")),
        "reporter_address": node_identity.reporter_address(client) or "",
        "context_graph_id": cfg.context_graph_id,
        "graph_peer_id": cfg.graph_peer_id,
        "blackbox_version": constants.__version__,
        "root_pinned_for_network": bool(constants.CURATOR_ROOT_KEYS.get(environment)),
        "trusted_roots": sorted(trust_anchors.trusted_roots(environment)),
    }
    if params.get("reporter_key"):
        answer["reporter_key"] = ReporterKeyStore().public_key_hex()
    return answer


def verified_memory(params: Mapping[str, Any]) -> dict[str, Any]:
    """What the graph's Verified Memory holds about one promoted threat, read
    through this node: every ``blackbox.promotion`` statement naming the threat
    (the signers that verify, whether it names the reporter's report — its
    subject, digest and reporter key — and the asset that carries it), and the
    reporter's signed report, in Verified Memory and in shared memory.

    Two forms of a promotion are recognised: the report published ITSELF (the
    reporter's own asset) with the curators' statement beside it, or the
    curators' OWN verified asset built from the report, whose envelope names it.
    ``form`` says which this node sees ("" = neither)."""
    from plugins.blackbox import community
    from plugins.blackbox.kernel import constants, signing, threat_ids
    from plugins.blackbox.kernel.dkg_client import extract_binding
    from plugins.blackbox.kernel.signing.statement_order import CuratorStatement

    cfg, client = _config_and_client()
    graph, view = cfg.context_graph_id, constants.VIEW_VERIFIABLE_MEMORY
    environment = community.network_environment(client.status())
    identifier, reporter = str(params["identifier"]), str(params.get("reporter_address") or "")
    reporter_key = str(params.get("reporter_key") or "")
    subject = threat_ids.report_uri(identifier, reporter) if reporter else ""
    curator_segment = f"/_verifiable_memory/{graph.split('/', 1)[0].lower()}/"
    rows = client.query(f"SELECT ?s ?o WHERE {{ ?s <{constants.SIGNED_STATEMENT_PRED}> ?o }} LIMIT 5000",
                        graph, view=view, on_error=None)
    report = _report_copies(client, graph, environment, subject) if subject else None
    digests = set(report["vm_digests"] + report["swm_digests"]) if report else set()
    promotions = []
    for row in rows or []:
        envelope = signing.from_text(extract_binding(row.get("o")))
        if envelope is None or envelope.statement_type != CuratorStatement.PROMOTION.value:
            continue
        if envelope.payload.get("identifier") != identifier:
            continue
        signers = signing.verified_signers(envelope, statement_type=envelope.statement_type, environment=environment,
                                           graph=graph, chain=envelope.chain, root_epoch=envelope.root_epoch)
        named = " ".join(str(value) for value in envelope.payload.values())
        statement_subject = extract_binding(row.get("s"))
        graphs = _asset_graphs(client, statement_subject)
        promotions.append({"subject": statement_subject, "signers": sorted(signers),
                           "claimed_signers": list(envelope.signers), "sequence": envelope.sequence,
                           "payload": dict(envelope.payload), "asset_graphs": graphs,
                           "in_curator_asset": (None if graphs is None
                                                else any(curator_segment in g.lower() for g in graphs)),
                           "names_report": bool(subject) and subject in named,
                           "digest_matches": any(digest in named for digest in digests),
                           "names_reporter_key": bool(reporter_key) and reporter_key in named})
    form = ""
    if report and report["vm_signed_by"]:
        form = "report-itself"
    elif any(p["names_report"] and p["digest_matches"] and p["in_curator_asset"] is not False for p in promotions):
        form = "curator-asset"
    return {"graph": graph, "query_ok": rows is not None, "promotions": promotions, "report": report, "form": form}


def _report_copies(client: Any, graph: str, environment: str, subject: str) -> dict[str, Any]:
    """The report *subject* as this node holds it: its copies in Verified Memory
    (root and the reports sub-graph) and in shared memory, each verified as a
    report — the signer and the digest (``signing.content_id``) of each."""
    from plugins.blackbox.community.report_signer import REPORT_STATEMENT
    from plugins.blackbox.kernel import constants, signing
    from plugins.blackbox.kernel.dkg_client import extract_binding

    sparql = f"SELECT ?o WHERE {{ <{subject}> <{constants.SIGNED_STATEMENT_PRED}> ?o }} LIMIT 50"

    def signed(view: str, sub_graphs: tuple[str, ...]) -> list[tuple[str, str]]:
        texts = [extract_binding(row.get("o")) for sub in sub_graphs
                 for row in _view_rows(client, sparql, graph, view, sub)]
        return [(signer, signing.content_id(envelope)) for text in texts
                if (envelope := signing.from_text(text)) is not None
                and (signer := signing.verify(envelope, statement_type=REPORT_STATEMENT, environment=environment,
                                              graph=graph))]

    in_vm = signed(constants.VIEW_VERIFIABLE_MEMORY, ("", constants.COMMUNITY_SUB_GRAPH))
    in_swm = signed(constants.VIEW_SHARED_WORKING_MEMORY, (constants.COMMUNITY_SUB_GRAPH,))
    return {"subject": subject, "vm_signed_by": in_vm[0][0] if in_vm else None,
            "vm_digests": sorted({digest for _signer, digest in in_vm}),
            "swm_signed_by": in_swm[0][0] if in_swm else None,
            "swm_digests": sorted({digest for _signer, digest in in_swm}),
            "asset_graphs": _asset_graphs(client, subject)}


def _view_rows(client: Any, sparql: str, graph: str, view: str, sub_graph: str) -> list[dict[str, Any]]:
    """One query of one memory view of *graph* (sub-graph *sub_graph*, "" = the root); [] when it failed."""
    from plugins.blackbox.kernel import sparql_text
    from plugins.blackbox.kernel.dkg_client import DkgError

    body = {"sparql": sparql, "contextGraphId": graph, "view": view,
            **({"subGraphName": sub_graph} if sub_graph else {})}
    try:
        return sparql_text.recognized_bindings(client.request("POST", "/api/query", body, timeout=30.0)) or []
    except DkgError:
        return []


def _asset_graphs(client: Any, subject: str) -> Optional[list[str]]:
    """The named graphs of this node's own store holding *subject*'s signed
    statement — which asset (layer, sub-graph, author) carries the report;
    None when the node reports no loopback store."""
    from plugins.blackbox.kernel import constants
    from plugins.blackbox.kernel.dkg_client import extract_binding
    from plugins.blackbox.kernel.store import StoreClient, loopback_store_url

    url = loopback_store_url(client.status(timeout=5.0))
    if not url:
        return None
    answer = StoreClient(url).select(f"SELECT DISTINCT ?g WHERE {{ GRAPH ?g {{ <{subject}> "
                                     f"<{constants.SIGNED_STATEMENT_PRED}> ?o }} }} LIMIT 50")
    return sorted(extract_binding(row.get("g")) for row in answer.rows or []) if answer.known else None


#: config.json keys the trial keeps from the devnet when it applies Blackbox's
#: settings: what makes a node a node of THIS network (chain, relays, network
#: config) and what devnet.sh owns (ports, name, store). Everything else the
#: installer and `blackbox sync` write is Blackbox's node setting.
NETWORK_OWNED_KEYS = ("networkConfig", "chain", "relayPeers", "relay", "apiPort", "listenPort", "name", "store",
                      "bootstrapPeers", "announceAddresses", "nodeRole")


def node_settings(params: Mapping[str, Any]) -> dict[str, Any]:
    """Blackbox's settings for a DKG node whose config.json is *staging*/config.json:
    the installer's own config writer (cut from ``blackbox-install.sh``, run
    for *graph* as Blackbox's graph, so the native profile applies), then the
    native sync profile ``blackbox sync`` persists (``sync/node_profile.py``),
    then the launch environment Blackbox restarts its node with
    (``managed_node._dkg_sync_environment``). Returns the resulting config
    (the network-owned keys put back) and the environment variables to add."""
    import os
    import subprocess

    from plugins.blackbox.kernel import constants
    from plugins.blackbox.kernel.config import BlackboxConfig
    from plugins.blackbox.sync import managed_node, node_profile

    staging = Path(str(params["staging_home"]))
    config_path = staging / "config.json"
    original = json.loads(config_path.read_text(encoding="utf-8-sig"))
    graph = str(params["graph"])
    writer = installer_config_writer(Path(str(params["installer"])))
    store = original.get("store") if isinstance(original.get("store"), dict) else {}
    backend = str(store.get("backend") or "oxigraph-server")
    options = store.get("options") if isinstance(store.get("options"), dict) else {}
    argv = [str(staging), str(original.get("apiPort") or 9320),
            backend if backend in ("blazegraph", "oxigraph-server") else "oxigraph-server",
            str(options.get("url") or ""), "true" if options.get("managedByDkg") else "false", graph, graph]
    written = subprocess.run([sys.executable, "-", *argv], input=writer, capture_output=True, timeout=60, check=False,
                             text=True, encoding="utf-8", errors="replace")
    if written.returncode != 0:
        raise RuntimeError(f"the installer's config writer failed: {written.stderr.strip()[-600:]}")
    # The profile Blackbox gives the node of its own graph: in production that is the
    # shipped default graph, so ask for exactly that configuration (the devnet graph
    # plays its part here; the profile names no graph).
    cfg = BlackboxConfig(dkg_home=str(staging), context_graph_id=constants.DEFAULT_CONTEXT_GRAPH_ID,
                         graph_peer_id=constants.DEFAULT_GRAPH_PEER_ID)
    node_profile._set_persisted_dkg_sync_state(cfg)
    environment = managed_node._dkg_sync_environment(cfg)
    config = json.loads(config_path.read_text(encoding="utf-8-sig"))
    for key in NETWORK_OWNED_KEYS:
        if key in original:
            config[key] = original[key]
        else:
            config.pop(key, None)
    added_env = {name: value for name, value in environment.items()
                 if name.startswith(("DKG_", "NODE_OPTIONS")) and name != "DKG_HOME" and os.environ.get(name) != value}
    removed_env = sorted(name for name in os.environ if name.startswith("DKG_") and name not in environment)
    changed = sorted(key for key in set(config) | set(original) if config.get(key) != original.get(key))
    return {"config": config, "env": added_env, "env_removed": removed_env, "changed_keys": changed,
            "installer_writer": written.stdout.strip()}


def installer_config_writer(installer: Path) -> str:
    """The Python program ``blackbox-install.sh`` runs to write the node's
    config.json (the heredoc inside ``ensure_blackbox_dkg_config``)."""
    lines = installer.read_text(encoding="utf-8-sig").splitlines()
    start = next(index for index, line in enumerate(lines) if line.startswith("ensure_blackbox_dkg_config()"))
    begin = next(index for index in range(start, len(lines)) if "<<'PYEOF'" in lines[index])
    end = next(index for index in range(begin + 1, len(lines)) if lines[index].strip() == "PYEOF")
    return "\n".join(lines[begin + 1:end]) + "\n"


def _plain(value: Any) -> Any:
    """*value* as JSON-able data (dataclasses and sets included)."""
    if is_dataclass(value) and not isinstance(value, type):
        return _plain(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_plain(item) for item in value]
    return value if isinstance(value, (str, int, float, bool)) or value is None else str(value)


ACTIONS: dict[str, Action] = {
    "cli": run_cli,
    "read": read_reports,
    "ruleset": refresh_ruleset,
    "identity": identity,
    "verified-memory": verified_memory,
    "node-settings": node_settings,
    "trust": curator_trust,
    "guard": guard_check,
}


def main(action: str, params: Mapping[str, Any], repo_root: Path) -> int:
    """Run *action* and print its answer as the last line (``ANSWER_PREFIX`` + JSON)."""
    sys.path.insert(0, str(repo_root))
    captured = _Captured()
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    logging.getLogger().addHandler(captured)
    try:
        answer = ACTIONS[action](params)
        answer = {"ok": True, **answer}
    except Exception as exc:   # the actor's outermost boundary: the driver gets the reason, the log the traceback
        logging.getLogger(__name__).exception("actor action %s failed", action)
        answer = {"ok": False, "error": f"{type(exc).__name__}: {exc}", "traceback": traceback.format_exc()[-3000:]}
    answer["log"] = captured.lines[-40:]
    print(ANSWER_PREFIX + json.dumps(_plain(answer), sort_keys=True), flush=True)
    return 0 if answer["ok"] else 1
