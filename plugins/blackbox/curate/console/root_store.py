"""Root A at rest: the core root's private half, encrypted (trust-and-threat-lab C1, §03.1/§03.2).

The key console's node holds root A only as ``<curate home>/root_a.enc.pem``:
PKCS8 encrypted with the ``cryptography`` library's ``BestAvailableEncryption``
under a passphrase Amos types for each signature and the node never stores.
It does not reuse ``kernel.reporter_key.ReporterKeyStore`` — that store writes
``NoEncryption()`` and is kernel code two modules share — so the root gets this
curate-only store.

The store caches NOTHING: :meth:`EncryptedRootStore.open` decrypts and hands the
key to its caller, who drops it (``root_signer.RootSigner`` signs one manifest
and discards it). The file is created once (exclusive temp file, 0600 from the
first byte, fsync, then a hard link that refuses to overwrite) and never
replaced: a second :meth:`create` is refused, so a mistake cannot swap the pinned root.

Usage::

    store = EncryptedRootStore()                 # <curate home>/root_a.enc.pem
    public_hex = store.create(passphrase)        # once, at the root ceremony
    key = store.open(passphrase)                 # RootStoreError on a wrong passphrase
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    PrivateFormat,
    load_pem_private_key,
)

from ...kernel import signing
from ...kernel.bounded_files import create_once
from .. import keys

ROOT_FILE = "root_a.enc.pem"
_FILE_MODE = 0o600
#: A passphrase shorter than this is refused at creation (it guards an online root).
MIN_PASSPHRASE_LENGTH = 12


class RootStoreError(RuntimeError):
    """The root cannot be created or opened (exists already, wrong passphrase,
    unreadable, not an encrypted Ed25519 key). The message never carries the passphrase."""


class EncryptedRootStore:
    """Owns root A's encrypted key file; holds no key itself.

    *path* defaults to ``<curate home>/root_a.enc.pem``.
    """

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path or (keys.curate_home() / ROOT_FILE)

    @property
    def path(self) -> Path:
        return self._path

    def exists(self) -> bool:
        return self._path.exists()

    def create(self, passphrase: str) -> str:
        """Generate root A, write it encrypted under *passphrase*, and return
        its public key hex (what goes into the code pin). Refuses when a root
        file already exists or the passphrase is shorter than
        :data:`MIN_PASSPHRASE_LENGTH`."""
        if len(passphrase) < MIN_PASSPHRASE_LENGTH:
            raise RootStoreError(f"the root passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters")
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8,
                                BestAvailableEncryption(passphrase.encode("utf-8")))
        if not create_once(self._path, pem, mode=_FILE_MODE):
            raise RootStoreError(f"a root already exists at {self._path}; it is never replaced")
        return signing.public_key_hex(key)

    def open(self, passphrase: str) -> Ed25519PrivateKey:
        """Decrypt and return root A. The caller owns the key and must drop it
        after ONE use. Raises :class:`RootStoreError` on a wrong passphrase, a
        missing or damaged file, or a file that is not encrypted."""
        try:
            pem = self._path.read_bytes()
        except OSError as exc:
            raise RootStoreError(f"no readable root at {self._path}") from exc
        try:
            key = load_pem_private_key(pem, password=passphrase.encode("utf-8"))
        except TypeError:
            # cryptography raises TypeError for an UNENCRYPTED file given a password.
            raise RootStoreError(f"the root at {self._path} is not encrypted; refusing to use it") from None
        except ValueError:
            raise RootStoreError("wrong root passphrase or a damaged root file") from None
        if not isinstance(key, Ed25519PrivateKey):
            raise RootStoreError(f"the root at {self._path} is not an Ed25519 key")
        return key
