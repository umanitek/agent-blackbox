"""What a threat goes after: goal, resource at risk, ATT&CK technique (threat-profiles §03.2).

A fixed table, keyed on what the detector already knows (category, file category,
command shape, skill danger shape, indicator kind or type). Nothing is guessed:
when the table has no answer the goal is ``unknown`` and nothing is put at risk,
so a reviewer never reads a classification the code did not earn.

Pattern: table-driven Strategy — one lookup per category, all pure.

Usage::

    classify({"category": "fileaccess", "fields": {"file_category": "ssh-private-key"}})
    # Classification(threat_goal="credential-theft", resource_at_risk="ssh-key", attack_technique="T1552.004")
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping


@dataclass(frozen=True)
class Classification:
    """The threat-level description a sighting carries. ``attack_technique`` is
    ``""`` when no technique fits; the other two always hold a vocabulary word."""

    threat_goal: str = "unknown"
    resource_at_risk: str = "none-identified"
    attack_technique: str = ""

    def as_fields(self) -> dict[str, str]:
        out = {"threat_goal": self.threat_goal, "resource_at_risk": self.resource_at_risk}
        if self.attack_technique:
            out["attack_technique"] = self.attack_technique
        return out


UNKNOWN = Classification()
#: An injection tries to make the agent follow the attacker (MITRE ATLAS: LLM Prompt Injection).
_INJECTION = Classification("agent-hijack", "agent-instructions", "AML.T0051")
#: A malicious package is a software supply-chain compromise of the host.
_PACKAGE = Classification("malware-delivery", "host-system", "T1195.002")

#: Sensitive-file category (detection's closed list) -> what reading it steals.
_FILE: dict[str, Classification] = {
    "credentials": Classification("credential-theft", "cloud-credentials", "T1552.001"),
    "env-file": Classification("credential-theft", "api-keys", "T1552.001"),
    "ssh-private-key": Classification("credential-theft", "ssh-key", "T1552.004"),
    "password-store": Classification("credential-theft", "password-store", "T1555"),
    "browser-cookies": Classification("credential-theft", "browser-session", "T1539"),
    "system-shadow": Classification("credential-theft", "system-accounts", "T1003.008"),
    # A browser wallet's key store: the encrypted vault, cracked offline once copied (ATT&CK: Credentials from Web Browsers).
    "crypto-wallet": Classification("wallet-drain", "wallet-keys", "T1555.003"),
    # The macOS keychain: saved passwords and the browsers' Safe Storage keys (ATT&CK: Keychain).
    "macos-keychain": Classification("credential-theft", "password-store", "T1555.001"),
}
#: A secret the agent handled or sent (local-only findings): which secret type -> what it opens.
_SECRET: dict[str, Classification] = {
    "seed-phrase": Classification("wallet-drain", "wallet-keys", "T1552.001"),
    "wallet-private-key": Classification("wallet-drain", "wallet-keys", "T1552.001"),
    "solana-private-key": Classification("wallet-drain", "wallet-keys", "T1552.001"),
    "bitcoin-private-key": Classification("wallet-drain", "wallet-keys", "T1552.001"),   # WIF or xprv/yprv/zprv…
    # An exchange's API key sent to a host that is not the exchange: it trades and withdraws as the account.
    "exchange-api-key": Classification("wallet-drain", "api-keys", "T1552.001"),
    # A token approval: the signature a drainer needs to move the tokens (ATT&CK: Financial Theft).
    "token-approval-drainer": Classification("wallet-drain", "funds", "T1657"),
    "token-approval-unlimited": Classification("wallet-drain", "funds", "T1657"),
}
#: Dangerous command shape -> what running it does.
_COMMAND: dict[str, Classification] = {
    "remote-script-pipe": Classification("command-execution", "host-system", "T1059.004"),
    "remote-eval-pipe": Classification("command-execution", "host-system", "T1059.004"),
    "rm-rf-system-paths": Classification("command-execution", "host-system", "T1485"),
    "chmod-world-writable": Classification("privilege-escalation", "host-system", "T1222.002"),
    "insecure-tls-fetch": Classification("malware-delivery", "host-system", "T1105"),
}
#: Skill danger shape -> what installing the skill hands over (a skill's code can
#: hold the same dangerous command shapes a shell call can).
_SKILL: dict[str, Classification] = {
    **_COMMAND,
    "shell-exec": Classification("command-execution", "host-system", "T1059"),
    "over-broad-shell": Classification("command-execution", "host-system", "T1059"),
    "credential-exfil": Classification("credential-theft", "api-keys", "T1552"),
    "over-broad-filesystem": Classification("data-exfil", "host-system", "T1005"),
    "over-broad-network": Classification("data-exfil", "host-system", "T1041"),
    "obfuscation": Classification("agent-hijack", "agent-tools", "T1027"),
}
#: A known-bad named skill (verified or registry): the agent's tools are compromised.
_NAMED_SKILL = Classification("agent-hijack", "agent-tools", "AML.T0010")
#: Indicator kind (the verified rule's ``kind``) or report reason -> what it is for.
_INDICATOR: dict[str, Classification] = {
    "phishing": Classification("phishing-lure", "user-credentials", "T1566.002"),
    "credential-harvest": Classification("phishing-lure", "user-credentials", "T1566.002"),
    "scam": Classification("phishing-lure", "funds", "T1566.002"),
    "malware": Classification("malware-delivery", "host-system", "T1105"),
    "malware-delivery": Classification("malware-delivery", "host-system", "T1105"),
    "c2": Classification("command-and-control", "host-system", "T1071"),
    "command-and-control": Classification("command-and-control", "host-system", "T1071"),
    "exfil-endpoint": Classification("data-exfil", "host-system", "T1041"),
    "injection-host": Classification("agent-hijack", "agent-instructions", "AML.T0051"),
    # The verified graph's Maltrail feed (sourceId maltrail_static) lists malware
    # infrastructure — command-and-control and distribution trails — as malicious_ioc.
    "malicious_ioc": Classification("malware-delivery", "host-system", "T1105"),
}
#: A known-bad file digest is a malware file (ATT&CK: User Execution, Malicious File).
_FILE_HASH = Classification("malware-delivery", "host-system", "T1204.002")
_WALLET = Classification("wallet-drain", "funds", "T1657")


def _fields(finding: Mapping[str, Any]) -> Mapping[str, Any]:
    fields = finding.get("fields")
    return fields if isinstance(fields, Mapping) else {}


def _indicator(finding: Mapping[str, Any]) -> Classification:
    fields = _fields(finding)
    for key in (str(fields.get("reason") or ""), str(finding.get("kind") or "")):
        if key.lower() in _INDICATOR:
            return _INDICATOR[key.lower()]
    if str(fields.get("ioc_type") or "") in ("wallet", "contract"):
        return _WALLET
    if str(fields.get("ioc_type") or "") == "hash":
        return _FILE_HASH
    return UNKNOWN


def _skill(finding: Mapping[str, Any]) -> Classification:
    shape = str(_fields(finding).get("danger_shape") or "")
    return _SKILL.get(shape, UNKNOWN) if shape else _NAMED_SKILL


_BY_CATEGORY: dict[str, Callable[[Mapping[str, Any]], Classification]] = {
    "injection": lambda finding: _INJECTION,
    "dependency": lambda finding: _PACKAGE,
    "fileaccess": lambda finding: _FILE.get(str(_fields(finding).get("file_category") or ""), UNKNOWN),
    "escalation": lambda finding: _COMMAND.get(str(_fields(finding).get("arg_shape") or ""), UNKNOWN),
    "skill": _skill,
    "ioc": _indicator,
    "secret": lambda finding: _SECRET.get(str(finding.get("identifier") or "").split(":", 1)[-1],
                                          Classification("credential-theft", "api-keys", "T1552")),
}


def classify(finding: Mapping[str, Any]) -> Classification:
    """The classification of one finding dict (``Finding.to_dict()`` shape)."""
    strategy = _BY_CATEGORY.get(str(finding.get("category") or ""))
    return strategy(finding) if strategy else UNKNOWN
