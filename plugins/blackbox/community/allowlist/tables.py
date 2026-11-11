"""The allowlist and warninglist tables (R9) — immutable after load.

Two tables, both keyed the way the plan says (§06 ALLOWLIST): domains by
PSL registrable domain (``kernel.public_suffix``), shared-hosting hosts at
URL granularity (the full host), and packages by ``ecosystem:name``.

* ALLOWLIST — brands and services whose exact name is almost never the
  threat (a report naming them byte-for-byte is HELD for a curator; a
  look-alike SUPPORTS the report, see :mod:`.verdicts`).
* WARNINGLIST — popular packages where a NAME-LEVEL or vulnerability report
  is noise (held), while a version-pinned malware report still counts
  (hijacked popular packages are the highest-impact real threat).

The vendored seed below is deliberately small and well known; the refresh
path is ``$BLACKBOX_HOME/allowlist.json`` (``{"domains": [...], "packages":
["npm:lodash", ...]}``), merged on top at load. The seed is data, kept
immutable here; transformations happen in code, never by hand-editing a
running node.

Usage::

    tables = load()
    tables.is_allowlisted_domain("login.paypal.com")   # True (registrable domain paypal.com)
    tables.is_warninglisted_package("npm", "lodash")   # True
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable

from ...kernel import constants, public_suffix

logger = logging.getLogger(__name__)

#: Seed allowlist: registrable domains of brands commonly impersonated, and
#: hosts under shared-hosting suffixes that are themselves first-party.
SEED_DOMAINS: frozenset[str] = frozenset({
    "google.com", "youtube.com", "gmail.com", "apple.com", "icloud.com", "microsoft.com", "live.com",
    "office.com", "outlook.com", "amazon.com", "aws.amazon.com", "paypal.com", "facebook.com", "instagram.com",
    "whatsapp.com", "x.com", "twitter.com", "linkedin.com", "github.com", "gitlab.com", "npmjs.com", "pypi.org",
    "python.org", "nodejs.org", "rust-lang.org", "crates.io", "rubygems.org", "docker.com", "cloudflare.com",
    "netflix.com", "dropbox.com", "slack.com", "zoom.us", "openai.com", "anthropic.com", "huggingface.co",
    "stripe.com", "coinbase.com", "binance.com", "metamask.io", "origintrail.io", "umanitek.ai",
})
#: Seed warninglist: ``ecosystem:name`` of packages so widely used that a
#: name-level or vulnerability report against them is noise.
SEED_PACKAGES: frozenset[str] = frozenset({
    "npm:lodash", "npm:react", "npm:react-dom", "npm:express", "npm:axios", "npm:chalk", "npm:debug",
    "npm:typescript", "npm:next", "npm:vue", "npm:webpack", "npm:eslint", "npm:prettier", "npm:jest",
    "npm:moment", "npm:commander", "npm:minimist", "npm:uuid", "npm:semver", "npm:dotenv",
    "pypi:requests", "pypi:numpy", "pypi:pandas", "pypi:django", "pypi:flask", "pypi:pytest", "pypi:boto3",
    "pypi:setuptools", "pypi:pip", "pypi:urllib3", "pypi:certifi", "pypi:cryptography", "pypi:pydantic",
    "pypi:fastapi", "pypi:sqlalchemy", "pypi:pyyaml", "pypi:six", "pypi:torch", "pypi:transformers",
    "cargo:serde", "cargo:tokio", "cargo:rand", "cargo:syn", "cargo:clap", "gem:rails", "gem:rake", "gem:bundler",
})
_OVERRIDE_FILE = "allowlist.json"


@dataclass(frozen=True)
class AllowTables:
    """``domains`` — registrable domains (or full shared-hosting hosts);
    ``packages`` — ``ecosystem:name`` keys. Both lower-case."""

    domains: frozenset[str]
    packages: frozenset[str]

    def is_allowlisted_domain(self, host: str) -> bool:
        """Byte-exact on the comparison key: the full host under shared
        hosting, else the registrable domain."""
        return allowlist_key(host) in self.domains

    def is_warninglisted_package(self, ecosystem: str, name: str) -> bool:
        return f"{ecosystem.lower()}:{name.lower()}" in self.packages


def allowlist_key(host: str) -> str:
    """What a host is compared by: itself under shared hosting (URL
    granularity), else its registrable domain (``login.paypal.com`` →
    ``paypal.com``); a bare public suffix compares as itself."""
    host = host.lower().strip(".")
    if public_suffix.is_shared_hosting(host):
        return host
    return public_suffix.registrable_domain(host) or host


def _lower(items: Iterable[object]) -> frozenset[str]:
    return frozenset(str(item).lower().strip() for item in items if str(item).strip())


@lru_cache(maxsize=1)
def load() -> AllowTables:
    """The seed tables merged with ``$BLACKBOX_HOME/allowlist.json`` (missing
    or unreadable: the seed alone — fail-open, logged)."""
    domains, packages = set(SEED_DOMAINS), set(SEED_PACKAGES)
    path = constants.blackbox_home() / _OVERRIDE_FILE
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        domains |= _lower(data.get("domains", []))
        packages |= _lower(data.get("packages", []))
    except FileNotFoundError:
        pass
    except (OSError, ValueError, AttributeError) as exc:
        logger.warning("blackbox: allowlist override ignored (%s)", exc)
    return AllowTables(domains=frozenset(domains), packages=frozenset(packages))
