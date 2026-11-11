"""Trader Shield's detector table: which pack kinds it serves and how each kind's block is checked.

The pack loader (:mod:`...packs`) hands every ``supported`` manifest to the detector whose
``KINDS`` names its kind; that detector answers the first problem with its kind block as
one sentence, or None. The loader has already checked ``places`` templates, ``pointer``
and ``verified`` itself, so the validators here check only what is theirs:

* ``browser-extension`` (MetaMask, Phantom): ``stores.chromium`` — Chromium extension
  ids, each ``^[a-p]{32}$``; ``stores.firefox`` — addons.mozilla.org add-on ids, each a
  ``{uuid}`` or an ``name@domain`` id; at least one id in total.
* ``desktop-app`` (Exodus, Electrum) and ``cli-key-file`` (the Solana CLI): checked by
  :func:`.app_folder.validate_pack`, beside the matcher it serves.

Detection: :func:`detect` answers, for one tool call, a finding per
chosen pack whose key store the call reads — or copies or archives inside a folder
handed whole to ``tar``/``zip``/``cp``/``rsync`` (:func:`wallets_inside_folder`, which
needs to know where key stores exist on this machine: :data:`EXISTING_STORES`, a
bounded glob under every ``browsers.json`` root plus every app place and pointer key
file, reused for five minutes). The browser-extension matcher lives in
:mod:`.browser_extension`, the app-folder kinds' in :mod:`.app_folder`. Every finding carries ``fields["pack"]`` (the pack id); a Firefox folder
no pack can be tied to carries none and belongs to the shield as a whole.

Usage::

    from plugins.blackbox.shields.trader import detectors
    Shield(..., detectors=detectors.DETECTORS, detect=detectors.detect)
    detectors.detect("terminal", {"command": "tar czf x.tgz ~/.config/google-chrome"}, mode.current())
    # -> [Finding(category="fileaccess", source="secret", fields={"pack": "metamask", ...}), ...]
"""

from __future__ import annotations

import functools
import glob
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

from ....detection import SHELL_TOOLS, Finding, command_from_args, file_access_arg, shell_file_args
from ....kernel import threat_ids
from ...contract import BrowserRoot, Pack, PackDetector, ShieldMode
from ...packs import COMMON_FIELDS, load_browser_roots
from .. import mode as trader_mode
from . import app_folder
from .app_folder import AppFolderMatcher
from .browser_extension import BrowserExtensionMatcher, Owner, normalize_path

CHROMIUM_ID = re.compile(r"[a-p]{32}")
FIREFOX_ID = re.compile(r"\{[0-9a-f-]{36}\}|[A-Za-z0-9._+-]{1,64}@[A-Za-z0-9.-]{1,64}")


@dataclass(frozen=True)
class KindTable:
    """One row of the detector table: the kinds it serves and its kind-block validator
    (satisfies :class:`~...contract.PackDetector`)."""

    KINDS: tuple[str, ...]
    check: Callable[[Mapping[str, Any]], Optional[str]]

    def validate_pack(self, manifest: Mapping[str, Any]) -> Optional[str]:
        """The first problem with *manifest*'s kind block, or None when it is valid."""
        return self.check(manifest)


def _unknown_fields(manifest: Mapping[str, Any], allowed: frozenset[str]) -> Optional[str]:
    unknown = sorted(set(manifest) - COMMON_FIELDS - allowed)
    return f"a {manifest.get('kind')} pack has no field {unknown[0]!r}" if unknown else None


def _ids(value: Any, pattern: re.Pattern[str], what: str) -> Optional[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and pattern.fullmatch(item) for item in value):
        return f"stores.{what} must be a list of {what} extension ids"
    return None


#: ``availability`` states: the publisher ships it there and Blackbox guards it (``protected``),
#: ships it under an id the pack does not list yet (``not-covered``), says it does not ship it
#: (``not-offered``), or no official listing was found (``not-found``).
AVAILABILITY_STATES = frozenset({"protected", "not-covered", "not-offered", "not-found"})
_AVAILABILITY_FIELDS = frozenset({"store", "browsers", "state", "url", "source", "note"})
#: The store whose "protected" entry needs the pack's ids for that engine.
_STORE_ENGINE = {"Chrome Web Store": "chromium", "Edge Add-ons": "chromium", "Firefox Add-ons": "firefox"}


def _check_availability(manifest: Mapping[str, Any]) -> Optional[str]:
    """``availability``: where the publisher ships the extension and whether Blackbox guards it
    there, with the source of each claim. Documentation data (detection never reads it), but a
    "protected" entry must be backed by the pack's own ids for that engine."""
    entries = manifest.get("availability")
    if entries is None:
        return None
    if not isinstance(entries, list) or not entries:
        return "availability must be a non-empty list of stores"
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) - _AVAILABILITY_FIELDS:
            return "an availability entry takes store, browsers, state, url, source and note only"
        if not isinstance(entry.get("store"), str) or not entry["store"].strip():
            return "an availability entry names its store"
        browsers = entry.get("browsers")
        if not isinstance(browsers, list) or not browsers or not all(isinstance(name, str) and name for name in browsers):
            return "an availability entry lists its browsers"
        if entry.get("state") not in AVAILABILITY_STATES:
            return f"availability state must be one of {', '.join(sorted(AVAILABILITY_STATES))}"
        if "url" in entry and not (isinstance(entry["url"], str) and entry["url"].startswith("https://")):
            return "an availability url is an https link"
        for text in ("source", "note"):
            if text in entry and not (isinstance(entry[text], str) and 0 < len(entry[text]) <= 300):
                return f"an availability {text} is text of at most 300 characters"
        engine = _STORE_ENGINE.get(entry["store"])
        if entry["state"] == "protected" and engine and not manifest["stores"].get(engine):
            return f"availability says {entry['store']} is protected, but the pack lists no {engine} id"
    return None


def _check_browser_extension(manifest: Mapping[str, Any]) -> Optional[str]:
    stores = manifest.get("stores")
    if not isinstance(stores, dict) or set(stores) - {"chromium", "firefox"}:
        return "stores must be an object with chromium and/or firefox id lists"
    problem = (_unknown_fields(manifest, frozenset({"stores", "availability"}))
               or _ids(stores.get("chromium", []), CHROMIUM_ID, "chromium")
               or _ids(stores.get("firefox", []), FIREFOX_ID, "firefox")
               or _check_availability(manifest))
    if problem:
        return problem
    if not stores.get("chromium") and not stores.get("firefox"):
        return "a browser-extension pack names at least one extension id"
    return None


#: Every detector Trader Shield has, as the loader sees it.
DETECTORS: tuple[PackDetector, ...] = (
    KindTable(KINDS=("browser-extension",), check=_check_browser_extension),
    KindTable(KINDS=app_folder.KINDS, check=app_folder.validate_pack),
)


# -- detection ----------------------------------------------------------------

#: The file category these findings carry (a closed name, never a path).
WALLET_CATEGORY = "crypto-wallet"
#: How long the list of key stores found on this machine is reused.
_EXISTING_TTL_SECONDS = 300.0

_matchers_for: tuple[tuple[Pack, ...], BrowserExtensionMatcher, AppFolderMatcher] = (
    (), BrowserExtensionMatcher(()), AppFolderMatcher(()))


def _matchers() -> tuple[tuple[Pack, ...], BrowserExtensionMatcher, AppFolderMatcher]:
    """Both kinds' matchers for the packs the mode holds now (built once, rebuilt only
    when the shield hands the mode its packs again)."""
    global _matchers_for
    packs = trader_mode.wallet_packs()
    if _matchers_for[0] is not packs:
        _matchers_for = (packs, BrowserExtensionMatcher(packs), AppFolderMatcher(packs))
    return _matchers_for


def matcher() -> BrowserExtensionMatcher:
    """The browser-extension matcher for the packs the mode holds now."""
    return _matchers()[1]


def app_matcher() -> AppFolderMatcher:
    """The app-folder matcher (``desktop-app``, ``cli-key-file``) for the packs the mode holds now."""
    return _matchers()[2]


def owner(path: str) -> Optional[Owner]:
    """Whose key store *path* lies inside — a browser extension's first, then an app's — or None."""
    return matcher().owner(path) or app_matcher().owner(normalize_path(path))


@functools.cache
def browser_roots() -> tuple[BrowserRoot, ...]:
    """Every root in Trader's ``browsers.json``, loaded and validated once."""
    from ...trader import TRADER   # here, not at the top: the shield record imports this module before it exists
    return load_browser_roots(TRADER)[0]


def expand_template(template: str) -> str:
    """A path template (``$XDG_CONFIG_HOME/google-chrome*``) as a glob on this machine: its
    root from the environment now (``$XDG_CONFIG_HOME`` → ``~/.config``, ``%APPDATA%`` →
    ``~/AppData/Roaming``, ``%LOCALAPPDATA%`` → ``~/AppData/Local`` when unset)."""
    home = os.path.expanduser("~")
    # An EMPTY variable means its default too (`or`): it would make the glob relative to the current folder.
    roots = {"~": home, "$XDG_CONFIG_HOME": os.environ.get("XDG_CONFIG_HOME") or os.path.join(home, ".config"),
             "%APPDATA%": os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming"),
             "%LOCALAPPDATA%": os.environ.get("LOCALAPPDATA") or os.path.join(home, "AppData", "Local")}
    root, *below = template.split("/")
    return os.path.join(roots[root], *below)


class _ExistingStores:
    """The key-store folders present on this machine, found by a bounded glob
    (browser folder → profile → store, then the app places and pointer key files) and
    reused for a few minutes. Each is kept twice: lower-cased for matching (:meth:`get`)
    and as it is on disk (:meth:`located`, for anything that shows or names the path).
    One lock."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._found: list[tuple[str, Owner]] = []
        self._on_disk: list[tuple[str, Owner]] = []
        self._at = float("-inf")

    def _refresh(self) -> None:
        if time.monotonic() - self._at > _EXISTING_TTL_SECONDS:
            self._on_disk = self._scan()
            self._found = [(normalize_path(path), store_owner) for path, store_owner in self._on_disk]
            self._at = time.monotonic()

    def get(self) -> list[tuple[str, Owner]]:
        """``[(lower-cased store path, owner)]`` — what the matchers compare against."""
        with self._lock:
            self._refresh()
            return list(self._found)

    def located(self) -> list[tuple[str, Owner]]:
        """``[(store path as it is on disk, owner)]``, in the same order as :meth:`get`."""
        with self._lock:
            self._refresh()
            return list(self._on_disk)

    def reset(self) -> None:
        with self._lock:
            self._at = float("-inf")

    @staticmethod
    def _scan() -> list[tuple[str, Owner]]:
        stores = matcher()
        found: list[tuple[str, Owner]] = []
        for root in browser_roots():
            for candidate in stores.store_globs(expand_template(root.path), root.engine):
                for match in glob.glob(candidate):
                    store_owner = stores.owner(match)
                    if store_owner:
                        found.append((match.replace("\\", "/"), store_owner))
        return found + app_matcher().existing()


EXISTING_STORES = _ExistingStores()


def wallets_inside_folder(path: str) -> list[Owner]:
    """Every wallet whose key store sits somewhere inside folder *path* on this machine,
    in the order found, each once (empty when none exists here).

    ALL of them, not the first: the gate keeps only findings for the packs the operator
    chose, so naming one wallet would let a chosen wallet's vault leave inside an
    archive named after an unchosen one (KI-367)."""
    folder = normalize_path(path)
    if not folder:
        return []
    prefix = folder.rstrip("/") + "/"
    wallets: list[Owner] = []
    for store, wallet in EXISTING_STORES.get():
        if (store == folder or store.startswith(prefix) or folder == "/") and wallet not in wallets:
            wallets.append(wallet)
    return wallets


def _finding(tool: str, mode: str, wallet: Owner) -> Finding:
    fields = {"tool_name": tool, "file_category": WALLET_CATEGORY,
              "wallet": wallet.pack or trader_mode.ANY_EXTENSION_WALLET}
    if wallet.pack:
        fields["pack"] = wallet.pack   # absent: a store no pack can be named for, the shield's as a whole
    return Finding(
        identifier=threat_ids.fileaccess_identifier(tool, WALLET_CATEGORY),
        category="fileaccess",
        severity="critical",
        title=f"Read of a crypto wallet's key store ({wallet.wallet})",
        tool_name=tool,
        matched=WALLET_CATEGORY,
        evidence=f"{mode} {WALLET_CATEGORY} ({wallet.wallet})",
        confirmed=False,
        source="secret",   # built-in, local-only, blockable — never shared (it names this machine's wallet)
        fields=fields,
    )


def _all_packs_findings(tool_name: str, args: Any) -> list[Finding]:
    """A finding when this call reads a key store of ANY supported pack, or copies/archives
    a folder that holds some — one per wallet involved. Fail-open (an error returns ``[]``
    so a Blackbox fault never breaks the agent)."""
    try:
        access = file_access_arg(tool_name, args)
        if access:
            wallet = owner(access["path"])
            return [_finding(access["tool"], access["mode"], wallet)] if wallet else []
        tool = (tool_name or "").strip().lower()
        if tool not in SHELL_TOOLS:
            return []
        mode_by_wallet: dict[Owner, str] = {}   # each wallet once, with how it was first reached
        for arg in shell_file_args(command_from_args(tool_name, args)):
            direct = owner(arg.path)
            found = [direct] if direct else (wallets_inside_folder(arg.path) if arg.recursive else [])
            for wallet in found:
                mode_by_wallet.setdefault(wallet, "copy" if arg.recursive else "read")
        return [_finding(tool, mode, wallet) for wallet, mode in mode_by_wallet.items()]
    except Exception:  # pragma: no cover - fail open
        return []


def detect(tool_name: str, args: Any, active: ShieldMode) -> list[Finding]:
    """Trader's own findings for this call under *active*: one per CHOSEN pack whose key
    store the call reaches, plus every pack-less one (the gate decides those for the
    shield as a whole)."""
    chosen = set(trader_mode.wallets(active))
    return [finding for finding in _all_packs_findings(tool_name, args)
            if "pack" not in finding.fields or finding.fields["pack"] in chosen]
