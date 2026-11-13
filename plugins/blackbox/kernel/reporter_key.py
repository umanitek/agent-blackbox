"""This node's reporter key — the private key that signs its community reports.

One Ed25519 key per Blackbox home, created on first use and kept at
``$BLACKBOX_HOME/reporter_key.pem`` with owner-only permissions (0600). It is
NOT the DKG node's wallet: the wallet pays and is managed by the node; this key
only signs statements (see :mod:`.signing`). Losing it means a new reporter
identity; leaking it lets someone sign as this node, so it never leaves the
machine and is never logged.

Pattern: the key file has exactly one owner — :class:`ReporterKeyStore` — with
one lock; creation is atomic (exclusive temp file, 0600 from the first byte,
fsync, then a hard link that refuses to overwrite), so two processes starting
together end up sharing ONE key and a reader never sees a half-written file.

Usage::

    from ..kernel import reporter_key
    store = reporter_key.ReporterKeyStore()        # default path
    key = store.load_or_create()                   # Ed25519PrivateKey
    print(store.public_key_hex())                  # the signer name
    backup = store.export_pem()                    # operator rights (Refine R1):
    store.install_pem(backup)                      # restore after a reinstall
    store.erase()                                  # destroy this identity

The export/install/erase methods exist for the operator's own rights
(``blackbox report --export / --restore-key / --erase-identity``); nothing
else reads the key bytes out.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)

from . import constants, signing
from .bounded_files import create_once

KEY_FILE_NAME = "reporter_key.pem"
_KEY_FILE_MODE = 0o600


class ReporterKeyError(RuntimeError):
    """The key file exists but cannot be used (unreadable, not Ed25519)."""


class ReporterKeyStore:
    """Owns this node's reporter key file.

    ``path`` defaults to ``$BLACKBOX_HOME/reporter_key.pem``. The loaded key is
    cached per instance; :meth:`load_or_create` is thread-safe.
    """

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path or (constants.blackbox_home() / KEY_FILE_NAME)
        self._lock = threading.Lock()
        self._key: Optional[Ed25519PrivateKey] = None

    @property
    def path(self) -> Path:
        return self._path

    def load_or_create(self) -> Ed25519PrivateKey:
        """Return the key, creating it on first use. Raises
        :class:`ReporterKeyError` when an existing file is unusable — never
        silently replaces a key (that would change this node's identity)."""
        with self._lock:
            if self._key is None:
                self._key = self._read() if self._path.exists() else self._create()
            return self._key

    def public_key_hex(self) -> str:
        """The signer name of this node's key (creates the key if needed)."""
        return signing.public_key_hex(self.load_or_create())

    # -- operator rights (Refine R1: export with key backup, restore, erase) --

    def export_pem(self) -> bytes:
        """The key file's PEM, for a backup the OPERATOR keeps. Raises
        :class:`ReporterKeyError` when there is no usable key."""
        with self._lock:
            if not self._path.exists():
                raise ReporterKeyError("this node has no reporter key yet")
            self._read()   # refuse to back up an unusable file
            return self._path.read_bytes()

    def install_pem(self, pem: bytes) -> str:
        """Restore a backed-up key; returns its signer name.

        Idempotent for the same key. Refuses (:class:`ReporterKeyError`) to
        replace a DIFFERENT existing key — that would silently change this
        node's identity; erase first. The file is created like a new key
        (atomic, 0600).
        """
        try:
            key = load_pem_private_key(pem, password=None)
        except (ValueError, TypeError) as exc:
            raise ReporterKeyError(f"not a reporter key backup: {exc}") from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise ReporterKeyError("not an Ed25519 reporter key")
        restored = signing.public_key_hex(key)
        with self._lock:
            if not create_once(self._path, pem, mode=_KEY_FILE_MODE):
                current = signing.public_key_hex(self._read())
                if current != restored:
                    raise ReporterKeyError("a different reporter key already exists; erase it first")
            self._key = key
        return restored

    def erase(self) -> bool:
        """Destroy the key file (a new identity is created on next use).
        True when a key was removed."""
        with self._lock:
            self._key = None
            try:
                self._path.unlink()
            except FileNotFoundError:
                return False
            return True

    def _read(self) -> Ed25519PrivateKey:
        try:
            key = load_pem_private_key(self._path.read_bytes(), password=None)
        except (OSError, ValueError, TypeError) as exc:
            raise ReporterKeyError(f"reporter key at {self._path} is unreadable: {exc}") from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise ReporterKeyError(f"reporter key at {self._path} is not an Ed25519 key")
        return key

    def _create(self) -> Ed25519PrivateKey:
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        if not create_once(self._path, pem, mode=_KEY_FILE_MODE):
            return self._read()   # another process created the key meanwhile: keep theirs
        return key
