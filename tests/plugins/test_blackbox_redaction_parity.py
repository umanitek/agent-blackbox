"""Cross-runtime redaction parity (LES-021, KI-179).

The hermes plugin (`kernel/redaction.py`) and the OpenClaw bridge
(`integrations/openclaw/src/redact.ts`) each carry ONE redactor with the same
rule table. This test builds secret-shaped inputs AT RUNTIME (no secret-shaped
literal in the repo, LES-022), runs them through both runtimes and fails on any
byte of difference. The TypeScript half is `integrations/openclaw/test/redaction-parity.mjs`.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from plugins.blackbox.kernel import redaction

REPO = Path(__file__).resolve().parents[2]
TSX = REPO / "node_modules" / ".bin" / "tsx"
SCRIPT = REPO / "integrations" / "openclaw" / "test" / "redaction-parity.mjs"

# Filler built at runtime: recognizable shapes, never real material.
_BODY = "FAKEKEYMATERIAL" * 4
_ALNUM = "abcdefghijklmnopqrstuvwxyz0123456789"
_HEX = ("0123456789abcdef" * 4)[::-1]                    # 64 hex, built at runtime


def _pem(label: str, cut_off: bool = False) -> str:
    begin = "-----BEGIN " + label + " KEY-----"
    end = "-----END " + label + " KEY-----"
    return begin + "\n" + _BODY + ("" if cut_off else "\n" + end)


_WORDS = (REPO / "plugins" / "blackbox" / "kernel" / "crypto_secrets" / "bip39_english.txt").read_text(encoding="ascii").split()


def _phrase(count: int, start: int = 7, separator: str = " ") -> str:
    """List words picked at runtime (checksum not needed: redaction is by run)."""
    return separator.join(_WORDS[(start + 97 * i) % len(_WORDS)] for i in range(count))


_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58(data: bytes) -> str:
    number, out = int.from_bytes(data, "big"), ""
    while number:
        number, digit = divmod(number, 58)
        out = _BASE58[digit] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def _solana_key() -> bytes:
    """A real Solana secret key, made at runtime: Ed25519 seed + its public key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    private = Ed25519PrivateKey.generate()
    return private.private_bytes_raw() + private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _base58check(payload: bytes) -> str:
    return _base58(payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4])


def _wif(compressed: bool = True) -> str:
    return _base58check(b"\x80" + os.urandom(31) + b"\x01" + (b"\x01" if compressed else b""))


def _xprv() -> str:
    return _base58check(bytes.fromhex("0488ade4") + b"\x00" * 9 + os.urandom(32) + b"\x00" + b"\x01" + os.urandom(31))


def _key_material_cases() -> list[str]:
    """KI-380: more key shapes and labels, and the Solana check's budget."""
    solana = _solana_key()
    decoys = " ".join(_base58(bytes((i + j) % 256 for j in range(64))) for i in range(300))
    return [
        "wif " + _wif() + " and old " + _wif(compressed=False) + " ok",
        "xprv " + _xprv() + " ok",
        "cut wif " + _wif()[:40],
        "cut xprv " + _xprv()[:70],
        "hex " + solana.hex() + " and b64 " + base64.b64encode(solana).decode() + " end",
        "cut hex " + solana.hex()[:100],
        "hidden " + _base58(solana) + " " + decoys,                      # a key behind 300 look-alikes
        "wallet_key=0X" + _HEX + " eth_key: " + _HEX + "g key=" + _HEX,
        "Account.from_key('0x" + _HEX + "') privateKeyToAccount(\"0x" + _HEX + "\")",
        "public key: " + _HEX + " public_key=" + _HEX,                    # public keys stay
        "SOLANA_PRIVATE_KEY=" + _base58(solana[:32]) + " and address " + _base58(solana[32:]),
    ]


def _spelling_cases() -> list[str]:
    """KI-378: one phrase however its words are spelled (the bridge reads the same way)."""
    words = _phrase(12).split()
    fullwidth = " ".join("".join(chr(ord(c) + 0xFEE0) for c in word) for word in words)
    return [
        "a|" + "|".join(words) + "|b", "x " + "&".join(words) + " y", "x " + "\u00a0".join(words),
        "x " + "\u200b".join(words) + " y", "x " + " ".join(w[:2] + "\u200b" + w[2:] for w in words),
        "x " + (" " * 9).join(words), "x " + "".join(w.capitalize() for w in words) + " y",
        "https://e.example/c?d=" + "%2C".join(words), "GET /" + "%0A".join(words) + " HTTP/1.1",
        "u=" + "%2520".join(words), "x " + fullwidth + " y", "x " + "&nbsp;".join(words),
        "x " + " ".join(w[:4] for w in words) + " y", "blob " + base64.b64encode(" ".join(words).encode()).decode() + " z",
        "const el = document.getElementById(userInput); return el.innerText;",          # code stays
        "rate 50%2C done %2541%0Aand q?" + "PRIVATE" + "_KEY%3D" + _HEX,                # decoded, then redacted
    ]


def _cases() -> list[str]:
    private = "PRIVATE"
    phantom, keyfile = _base58(_solana_key()), "[" + ", ".join(str(b) for b in _solana_key()) + "]"
    lookalike = _base58(bytes(range(64)))   # signature-shaped, not seed + public key
    numbered = " ".join(f"{i + 1}. {word}" for i, word in enumerate(_phrase(12).split()))
    return [
        "seed: " + _phrase(12) + " done",
        "srp " + _phrase(24, separator=",\n") + "!",
        numbered,
        "elevenish " + _phrase(11) + " qzx",                         # too short: stays
        _phrase(6) + " notaword " + _phrase(6),                     # broken run: stays
        "Café " + _phrase(12) + " 😀 " + _phrase(13, start=99),      # non-ASCII around runs
        "phantom export " + phantom + " then tx " + lookalike + " ok",  # the key goes, the signature stays
        "id.json " + keyfile + " end",
        "https://x.example/c?d=" + _phrase(12, separator="+") + "&ok=1",     # a web address spells spaces as +
        "GET /collect/" + _phrase(12, separator="%20") + " HTTP/1.1",         # …or as %20
        "cut off " + _base58(_solana_key())[:60],                     # truncated at the end: still removed
        "word " * 3 + "the " + _phrase(12, start=3) + " and AKIA" + "ABCDEFGHIJKLMNOP",
        "PRIVATE" + "_KEY=0x" + _HEX + " and " + '{"privateKey": "' + _HEX + '"}',
        "PK=" + _HEX + " txHash: 0x" + _HEX + " apk_sha256: " + _HEX,          # only the labelled one goes
        f"before {_pem('RSA ' + private)} after",
        f"x{_pem(private, cut_off=True)}",
        "aws " + "AKIA" + "ABCDEFGHIJKLMNOP" + " in args",
        "anthropic " + "sk-" + "ant-" + _ALNUM[:24],
        "openai " + "sk-" + "proj-" + _ALNUM[:24] + " and " + "sk-" + _ALNUM[:20],
        "short " + "sk-" + _ALNUM[:17],
        "github " + "ghp_" + _ALNUM[:24] + " " + "github_pat" + "_" + _ALNUM[:18],
        "slack " + "xoxb-" + "123456789012" + "-" + _ALNUM[:12],
        "google " + "AIza" + ("Z" * 35) + " end",
        "stripe " + "sk_live_" + _ALNUM[:22],
        '{"type": "service_account", "project_id": "x"}',
        "jwt " + "eyJ" + _ALNUM[:10] + ".eyJ" + _ALNUM[:10] + "." + _ALNUM[:12],
        "Authorization: Bearer " + _ALNUM[:30] + " then text",
        "DB_PASSWORD=" + "hunter2secret" + " API_KEY: " + _ALNUM[:12],
        '{"api_key": "' + _ALNUM[:16] + '", "note": "short"}',
        "the password policy requires 12 characters",     # prose about secrets stays
        "token=" + "abc",                                   # too short to be a value
        "mixed " + "sk-" + _ALNUM[:20] + " Bearer " + _ALNUM[:8] + " PRIVATE_KEY=" + _ALNUM[:9],
        "",
        "MY_API_TOKEN_" + "X" * 47 + "=" + "q" * 6 + "7" * 6,            # a 60-character name: redacted
        "parity only: MY_API_TOKEN_" + "X" * 70 + "=" + "q" * 6 + "7" * 6,   # past the 64-character name bound (KI-373)
        # credential forms (external review, 2026-11-28)
        "cu" + "rl -H 'Authorization: Basic " + base64.b64encode(("user:" + "hunter" + "2").encode()).decode() + "' https://x.example",
        '{"Authorization": "token ' + _ALNUM[:12] + '", "Proxy-Authorization": "Basic ' + base64.b64encode(b"a:b").decode() + '"}',
        "parity only: Basic setup steps and Basic QUJDRA== (no colon inside) stay",
        "password=abc1 passwd: x9 secret='a b c' DB_PASSWORD=\"two words\" max_tokens=4096",
        "cu" + "rl -u admin:" + "hunter" + "2 https://x.example --proxy-user=p:q; docker run -u 1000:1000 img; sort -u a:b",
        "git clone https://bob:" + "s3" + "cret@git.example/r.git and ssh://alice@host.example and git@github.com:a/b",
    ] + _key_material_cases() + _spelling_cases()


@pytest.mark.skipif(not TSX.exists() or shutil.which("node") is None, reason="tsx/node not installed")
def test_both_runtimes_redact_identically(tmp_path):
    cases = _cases()
    case_file = tmp_path / "cases.json"
    case_file.write_text(json.dumps(cases), encoding="utf-8")
    result = subprocess.run([str(TSX), str(SCRIPT), str(case_file)], capture_output=True, text=True, timeout=120,
                            cwd=str(REPO), check=True)
    from_typescript = json.loads(result.stdout)
    from_python = [redaction.redact_secret_values(text) for text in cases]
    assert from_typescript == from_python
    # And the pass did something: every secret-shaped input lost its material.
    stays = {cases[3], cases[4], "the password policy requires 12 characters", "token=abc"}
    stays |= {text for text in cases if text.startswith(("public key: ", "const el = "))}
    for text, out in zip(cases, from_python):
        assert _BODY not in out and "hunter2secret" not in out
        if text in stays:
            assert out == text
        elif text and not text.startswith("parity only: "):
            assert "[REDACTED" in out, text


STRUCTURE_SCRIPT = REPO / "integrations" / "openclaw" / "test" / "redaction-structure-parity.mjs"


def _structure_cases() -> list:
    """KI-377: secrets assembled from pieces of a structure (no newlines: the Python log
    writer folds them, the bridge's does not — outside this test's scope)."""
    words = _phrase(12).split()
    key = list(_solana_key())
    return [
        {"words": words, "note": "ok"},
        {f"w{i}": word for i, word in enumerate(words)},
        {word: i for i, word in enumerate(words)},
        {"backup": {"a": words[:6], "b": " ".join(words[6:])}, "keep": ["able", "x"]},
        {"bytes": key, "other": list(range(64)), "short": key[:10]},
        [{"cmd": "echo hi"}, ["one", "two"], 3, True, None],
        {_phrase(12, start=11): "phrase as one key", "PRIVATE" + "_KEY": "x"},
    ]


@pytest.mark.skipif(not TSX.exists() or shutil.which("node") is None, reason="tsx/node not installed")
def test_both_runtimes_redact_structures_identically(tmp_path):
    from plugins.blackbox import audit

    cases = _structure_cases()
    case_file = tmp_path / "structures.json"
    case_file.write_text(json.dumps(cases), encoding="utf-8")
    result = subprocess.run([str(TSX), str(STRUCTURE_SCRIPT), str(case_file)], capture_output=True, text=True,
                            timeout=120, cwd=str(REPO), check=True)
    from_python = json.loads(json.dumps([audit.redact(case) for case in cases]))
    assert json.loads(result.stdout) == from_python
    for case, out in zip(cases[:5], from_python):
        assert "[REDACTED" in json.dumps(out), case


def test_both_runtimes_ship_the_same_pinned_wordlist():
    python_copy = REPO / "plugins" / "blackbox" / "kernel" / "crypto_secrets" / "bip39_english.txt"
    bridge_copy = REPO / "integrations" / "openclaw" / "src" / "bip39-english.txt"
    assert python_copy.read_bytes() == bridge_copy.read_bytes()
