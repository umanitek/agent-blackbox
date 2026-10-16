"""``blackbox curate pool | export | verify-bundle`` and the dossier's confirmation line (Community Curation C8).

``pool`` prints the confirmed pool as this node verifies it (the CLI stand-in
for the saved node-UI view). ``export`` writes it as one bundle file.
``verify-bundle`` checks a bundle OFFLINE — no node is contacted: the file, the
community root key, and the network and graph the receiver expects.
Everything printed from a bundle or the graph is untrusted text and goes
through ``term_safe``.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Optional

from ... import community
from ...kernel import display_safety
from ...kernel.config import load_blackbox_config
from ...kernel.dkg_client import DkgClient
from ...kernel.signing import trust_anchors
from ...kernel.signing.statement_order import CuratorStatement
from ..context import CurateContext
from ..dossier import CommunityConfirmation
from ..publishing import VerbError
from .live_pool import bundle_text, read_live_pool

_term = display_safety.term_safe


def _line(entry: community.pool.PoolEntry) -> str:
    return (f"  {_term(entry.identifier, 80)}  confirmed {entry.confirmed_day} by {len(entry.curators)} curator key(s)"
            f" · evidence {_term(entry.evidence, 120)} · {entry.reporters} reporter(s), {entry.trusted_voices} trusted"
            f" ({entry.partner_organisations} organisation(s)) · first reported {entry.first_reported or 'n/a'}")


def print_pool(ctx: CurateContext) -> int:
    pool = read_live_pool(ctx)
    if pool.unavailable:
        print(f"The confirmed pool is unavailable: {_term(pool.unavailable, 200)}")
        return 1
    print(f"CONFIRMED POOL: {len(pool.entries)} threat(s)"
          + (f" · {pool.withheld} more confirmed but withheld (the verified authority decided otherwise, or already lists them)"
             if pool.withheld else ""))
    for entry in pool.entries:
        print(_line(entry))
    return 0


def export(ctx: CurateContext, out: str) -> int:
    """Write the confirmed pool to *out* as one bundle (atomic: a reader never sees half a file)."""
    pool = read_live_pool(ctx)
    if pool.unavailable:
        raise VerbError(f"nothing exported: {pool.unavailable}")
    text = bundle_text(ctx, pool)
    path = Path(out).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}.{secrets.token_hex(6)}")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)
    print(f"exported {len(pool.entries)} confirmed threat(s) to {path} "
          f"(network {_term(ctx.environment, 60)}, graph {_term(ctx.verified_graph, 100)})")
    print("check it anywhere with: blackbox curate verify-bundle <file> --root <community root key> --network <network id>")
    return 0


def _network(given: str) -> str:
    """The network id to expect: the one given, else this node's (when it answers)."""
    if given:
        return given
    try:
        cfg = load_blackbox_config()
        return community.network_environment(DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home).status())
    except Exception:   # offline is the normal case for a verifier; the caller then asks for --network
        return ""


def check(path: str, *, root: str, network: str, graph: str, today: Optional[str] = None) -> community.pool.BundleReport:
    """Verify the bundle file at *path*. *root* — the community root key (hex;
    default: the one pinned for *graph*); *network* — the network id (default:
    this node's); *graph* — the community graph (default: this node's)."""
    graph = graph or load_blackbox_config().context_graph_id
    roots = {root.lower()} if root else trust_anchors.community_roots(graph)
    network = _network(network)
    if not network:
        raise VerbError("pass --network <network id>: this node did not answer, and a bundle is only valid for one network")
    try:
        text = Path(path).expanduser().read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise VerbError(f"cannot read the bundle: {exc}") from exc
    return community.pool.verify_bundle(text, roots, environment=network, graph=graph, today=today)


def verify_file(path: str, *, root: str, network: str, graph: str) -> int:
    report = check(path, root=root, network=network, graph=graph)
    if report.error:
        print(f"BUNDLE REFUSED: {report.error}")
        return 2
    failed = [result for result in report.entries if not result.ok]
    print(f"{len(report.entries) - len(failed)} of {len(report.entries)} entries verified "
          f"(key manifest epoch {report.manifest.root_epoch} version {report.manifest.version}, "
          f"{report.manifest.threshold} of {len(report.manifest.curator_keys)} curator keys)")
    for entry in report.passed:
        print(_line(entry))
    for result in failed:
        print(f"  FAILED  {_term(result.identifier, 80)}: {_term(result.reason, 200)}")
    return 0 if not failed else 2


def confirmation_for(ctx: CurateContext, identifier: str, bundle: str = "") -> Optional[CommunityConfirmation]:
    """What the dossier shows about the COMMUNITY curators' confirmation of
    *identifier*: from a verified bundle file when one is given, else from the
    statements this node verified. None when there is none."""
    if bundle:
        report = check(bundle, root="", network=ctx.environment, graph=ctx.verified_graph)
        if report.error:
            raise VerbError(f"the bundle was refused: {report.error}")
        for entry in report.passed:
            if entry.identifier == identifier:
                return CommunityConfirmation(entry.confirmed_day, entry.evidence, len(entry.curators), entry.reporters,
                                             "a verified export bundle")
        return None
    own = ctx.view.community
    record = own.verdicts.get(identifier) if own is not None else None
    if record is None or record.kind is not CuratorStatement.CONFIRMATION:
        return None   # no verdict, or a rejection / deferral / notice: not a confirmation
    return CommunityConfirmation(record.day, record.field("evidence"), len(record.signers), None, "the community graph")
