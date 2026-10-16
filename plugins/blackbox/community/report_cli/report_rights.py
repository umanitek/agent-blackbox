"""The operator's rights over this node's reporter identity (Refine R1).

Local verbs of ``blackbox report``. None needs the DKG node, and none sends
anything:

* ``--consent`` / ``--withdraw-consent`` — record or withdraw the opt-in to the
  reporter terms (R13). Consent alone does not start sharing.
* ``--enable-sharing`` / ``--disable-sharing`` — the sharing switch itself
  (``report`` in the config), through the same validate-then-persist path as
  the dashboard toggle, so turning it on without consent is refused (KI-299).

* ``--export PATH`` — a machine-readable JSON copy of this node's statements
  (the share ledger: reports, disputes, retractions and their outcomes) plus
  a BACKUP of the reporter key, so a reinstall does not silently drop a
  counted author. The file holds the private key: it is written owner-only
  (0600), never over an existing file, and the command says so.
* ``--restore-key PATH`` — install the key from such an export (or a bare
  PEM). It refuses to replace a different existing key, which would silently
  change this node's identity.
* ``--erase-identity --confirm`` — destroy the reporter key and the local
  share records. The next report starts a new, unlinked identity. What was
  already shared stays on the network (a shared graph cannot delete it), and
  the command says so; retract first to stop old reports counting.

Usage (from :func:`.report_command.cmd_report`)::

    if report_rights.wants_local_verb(args):
        return report_rights.run_local_verb(args)
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone, UTC
from pathlib import Path
from typing import Any, Dict

from ... import audit
from .. import consent, digest, share_retry
from .. import keep_alive as keep_alive_mod
from ...kernel import display_safety, reporter_key, signing

#: Identifies an export file and its layout version.
EXPORT_FORMAT = "blackbox-reporter-export"
EXPORT_VERSION = 1
#: Ledger rows an export carries (the ledger itself is size-capped).
_EXPORT_LEDGER_ROWS = 100_000


def wants_local_verb(args: argparse.Namespace) -> bool:
    """True when *args* ask for one of this module's verbs."""
    return bool(getattr(args, "export", None) or getattr(args, "restore_key", None)
                or getattr(args, "erase_identity", False) or getattr(args, "consent", False)
                or getattr(args, "withdraw_consent", False)
                or getattr(args, "enable_sharing", False) or getattr(args, "disable_sharing", False))


def run_local_verb(args: argparse.Namespace) -> int:
    """Run the requested verb; returns the process exit code."""
    store = reporter_key.ReporterKeyStore()
    if getattr(args, "consent", False):
        return record_consent()
    if getattr(args, "withdraw_consent", False):
        return withdraw_consent()
    if getattr(args, "enable_sharing", False) or getattr(args, "disable_sharing", False):
        return set_sharing(bool(getattr(args, "enable_sharing", False)))
    if args.export:
        return export_identity(store, Path(args.export).expanduser())
    if args.restore_key:
        return restore_key(store, Path(args.restore_key).expanduser())
    return erase_identity(store, confirmed=bool(args.confirm))


def record_consent() -> int:
    """``--consent``: print the reporter terms and record acceptance of them — the
    operator's opt-in (sharing is opt-in, 2026-10-16). It does not flip the
    ``report`` switch; ``--enable-sharing`` does both."""
    text = consent.terms_text()
    earlier = consent.current()
    if text and earlier is not None and earlier.terms_hash and earlier.terms_hash != consent.terms_hash(text):
        # C11: someone who accepted an earlier text sees what changed first.
        print(f"The terms changed since you accepted version {earlier.terms_version}.")
        changed = consent.changes_section(text)
        if changed:
            print(changed)
        print("The full terms follow.\n")
    print(text or "The reporter terms are missing from this installation; recording the choice anyway.")
    entry = consent.record()
    if entry is None:
        return 1
    print(f"Consent recorded for terms version {entry.terms_version} at {entry.accepted_at}.")
    if _sharing_on():
        print("Sharing is on. Turn it off with `blackbox report --disable-sharing`.")
    else:
        print("Sharing is still OFF in the settings. Turn it on with")
        print("`blackbox report --enable-sharing` (or the dashboard's Community sharing toggle).")
    print("Opt out at any time with `blackbox report --withdraw-consent`.")
    return 0


def set_sharing(on: bool) -> int:
    """``--enable-sharing`` / ``--disable-sharing``: the ``report`` switch (KI-299).

    Sharing is opt-in (2026-10-16). Turning it ON is the operator's opt-in, so it
    records an acceptance of the reporter terms first (``consent.for_settings``);
    the write goes through ``kernel.settings.write_settings``, the path the
    dashboard toggle uses, with the resulting state. No other path records it.
    """
    from ...kernel import settings
    payload = {"report": on}
    result = settings.write_settings(payload, sharing_consent=consent.for_settings(payload))
    if not result.get("ok"):
        for error in result.get("errors") or ["the setting could not be saved"]:
            print(f"Not changed: {error}")
        return 1
    if on:
        print("Sharing is on: when your agent meets a threat the verified graph already lists, a privacy-safe")
        print("statement (the threat's identifier and type, blocked or flagged; never prompts, commands, paths")
        print("or files) is shared with the community. Turn it off with `blackbox report --disable-sharing`.")
    else:
        print("Sharing is off: nothing new leaves this node.")
    return 0


def _sharing_on() -> bool:
    from ...kernel.config import load_blackbox_config
    try:
        return bool(load_blackbox_config().report)
    except Exception:   # cannot read the config: say nothing is on
        return False


def withdraw_consent() -> int:
    """``--withdraw-consent``: sharing stops on the next action.

    The withdrawal record stops every share by itself; the ``report`` switch is turned off
    too, through the same settings write the dashboard toggle uses, so the switch never
    reads "on" over a withdrawn consent (a dashboard Save would otherwise send that "on"
    back as an opt-in)."""
    if not consent.in_force():
        print("Community sharing was already off.")
        return 0
    if consent.withdraw():
        from ...kernel import settings
        if not settings.write_settings({"report": False}).get("ok"):
            print("Note: the sharing switch in config.yaml could not be turned off; your opt-out still stops sharing.")
        print("Community sharing turned off: nothing further leaves this machine for the community.")
        return 0
    print("Could not save the opt-out, so sharing is still ON. Check that the Blackbox home is writable and try again.")
    return 1


def export_document(store: reporter_key.ReporterKeyStore) -> dict[str, Any]:
    """The export as a dict: format, time, signer name, key backup, ledger."""
    pem = store.export_pem().decode("ascii")
    record = consent.current()
    tally = digest.SightingTally()
    return {
        "format": EXPORT_FORMAT,
        "version": EXPORT_VERSION,
        "exported": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "reporter_public_key": signing.public_key_hex(store.load_or_create()),
        "reporter_key_pem": pem,
        "statements": audit.read_share_ledger(limit=_EXPORT_LEDGER_ROWS),
        # KI-224: the access right covers EVERY store erasure covers — not only the ledger.
        "consent": None if record is None else {"terms_hash": record.terms_hash, "terms_version": record.terms_version,
                                                 "accepted_at": record.accepted_at, "withdrawn_at": record.withdrawn_at},
        "keep_alive": [entry.as_json() for entry in keep_alive_mod.LiveReportStore().all()],
        "retry_queue": [share.as_json() for share in share_retry.default_queue().pending()],
        "sighting_tally": {week: tally.counts(week) for week in tally.weeks()},
    }


def export_identity(store: reporter_key.ReporterKeyStore, path: Path) -> int:
    """``--export PATH``: write the export, owner-only, never overwriting."""
    try:
        document = export_document(store)
    except reporter_key.ReporterKeyError as exc:
        print(f"Nothing to export: {exc}")
        return 2
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        print(f"Refusing to overwrite {display_safety.term_safe(str(path))} — choose a new file.")
        return 2
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2)
    print(f"Exported {len(document['statements'])} statement record(s) and a key backup to "
          f"{display_safety.term_safe(str(path))}")
    print("This file contains your reporter PRIVATE KEY: anyone holding it can sign as this node.")
    print("Keep it offline; restore it with `blackbox report --restore-key FILE` after a reinstall.")
    return 0


def restore_key(store: reporter_key.ReporterKeyStore, path: Path) -> int:
    """``--restore-key PATH``: install the key from an export or a PEM file."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        print(f"Cannot read {display_safety.term_safe(str(path))}: {exc.strerror}")
        return 2
    pem = _pem_from(raw)
    try:
        signer = store.install_pem(pem)
    except reporter_key.ReporterKeyError as exc:
        print(f"Key not restored: {exc}")
        return 2
    print(f"Reporter key restored (signer {signer[:16]}…). Reports you sent before keep counting as yours.")
    return 0


def _pem_from(raw: bytes) -> bytes:
    """The PEM inside an export document, or *raw* itself (a bare PEM file)."""
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return raw
    if isinstance(document, dict) and document.get("format") == EXPORT_FORMAT:
        return str(document.get("reporter_key_pem") or "").encode("ascii")
    return raw


def erase_identity(store: reporter_key.ReporterKeyStore, *, confirmed: bool) -> int:
    """``--erase-identity``: destroy the key and local share records (needs --confirm)."""
    if not confirmed:
        print("This destroys this node's reporter key and its local record of what it shared.")
        print("Reports already shared stay on the network — a shared graph cannot delete them. To stop")
        print("them counting, `blackbox report --retract IDENTIFIER` each one BEFORE erasing (afterwards")
        print("this node can no longer sign as their author). Keep a copy first with `--export FILE`.")
        print("Run again with --confirm to erase. Nothing was changed.")
        return 2
    had_key = store.erase()
    records = audit.erase_share_records()
    # R13: erasure must stop every way this node could re-publish its old statements or consent again
    records += int(keep_alive_mod.LiveReportStore().forget_all())
    records += int(share_retry.default_queue().clear())
    records += int(consent.erase())
    records += int(digest.SightingTally().forget())   # KI-221: the tally would re-link the next key to this one
    print(f"Erased: reporter key {'removed' if had_key else '(none present)'}; {records} local share record file(s).")
    # KI-220: say what erasure does — it rotates the SIGNING key. The reporter address in every
    # statement is the node's wallet address, which this command does not change.
    print("Your next report is signed by a new reporter key. The node's wallet address stays the same;")
    print("statements already on the network keep carrying it.")
    print("Community sharing is now OFF; `blackbox report --enable-sharing` turns it back on.")
    return 0
