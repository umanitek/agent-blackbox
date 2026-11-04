"""How a secret leaves the machine: commands that send, web addresses, network-calling scripts.

A secret VALUE an agent merely handles (a key in its own config) is flagged; the same
value on its way OFF the machine is exfiltration and blocks. These predicates say
whether a tool call's text sends what it holds. Pure, linear-time regex checks.

Two strengths of "sends", because two kinds of secret differ (KI-378):

* an API key has a right destination (its own API), so only a command that sends DATA
  counts (:func:`looks_like_egress`: ``curl -d``/``--json``/``-X POST``, ``wget
  --post-data``, ``nc``, ``ssh``/``scp``, mail…);
* a wallet secret (seed phrase, private key) has no right destination, so ANY route off
  the machine counts (:func:`reaches_network`): a network program anywhere in the
  command (``curl`` even as a GET, ``git push``, ``| mail``, ``rsync``…), script code that
  calls the network (``requests``, ``http.client``, ``require('https')``…), or a tool
  whose arguments themselves leave the machine (MCP tools, the browser, messaging).

Usage::

    looks_like_egress("curl -d @- https://x")      # -> True: a command that sends data
    looks_like_script_send("requests.post(url)")   # -> True: script code that calls the network
    reaches_network("terminal", "git push origin") # -> True: a route off the machine
    url_payloads("GET https://x/?d=a+b")           # -> "https://x/?d=a b": what rides in each URL
"""

from __future__ import annotations

import re
from urllib.parse import unquote_plus

# Commands that SEND data off-box — a secret value alongside one of these is
# exfiltration (critical/block), not routine handling. curl's data flags may be
# combined with others (-sd, -sSd); -X/--request with a writing method sends a body.
_EGRESS_RE = re.compile(
    r"\b(?:nc|ncat|netcat|telnet|sendmail|socat|scp|sftp)\b"
    r"|\b(?:curl|wget)\b[\s\S]{0,300}(?:\s-[A-Za-z]*[dFT]\b|--data|--json|--form|--upload-file"
    r"|--post-(?:data|file)|--body-(?:data|file)|(?:\s-X\s*|--request[\s=]+|--method[\s=]+)['\"]?(?:POST|PUT|PATCH)\b)"
    r"|\|\s*(?:nc|ncat|curl|wget|mail|mailx|mutt|ssh)\b"
    r"|(?:^|[|;&(`\n]|\$\()\s*ssh\s+(?:-\S+\s+)*[\w.@-]+\s+\S",
    re.IGNORECASE | re.MULTILINE,
)
# A program that moves data off the machine, standing where a command starts (line start,
# after | ; & ( ` $( or a wrapper like sudo / env / xargs), with or without its path.
_NETWORK_COMMAND_RE = re.compile(
    r"(?:^|[|;&(`\n]|\$\(|\b(?:sudo|env|xargs|nohup|time|exec|command)\s)\s*(?:[\w./-]*/)?"
    r"(?:curl|wget|https?|xh|nc|ncat|netcat|socat|telnet|ssh|scp|sftp|rsync|ftp|tftp|lftp|sendmail|mail|mailx"
    r"|mutt|swaks|aws|gsutil|gcloud|az|rclone|s3cmd|gh|openssl)(?=\s|$)"
    r"|\bgit\s+(?:-\S+\s+)*push\b",
    re.IGNORECASE | re.MULTILINE,
)
#: Tools whose arguments leave the machine by themselves: every MCP tool (a remote server
#: may sit behind it), the browser (it types into and submits web pages), messaging.
_SENDING_TOOL_RE = re.compile(
    r"^(?:mcp_|browser_)|(?:^|_)(?:send|post|upload|email|mail|message|webhook|publish|tweet|reply|share|http)(?:_|$)",
    re.IGNORECASE,
)


def looks_like_egress(text: str) -> bool:
    """True when *text* contains a command that sends data off the machine."""
    return bool(text and _EGRESS_RE.search(text))


#: A web address in text (the part a secret would ride in: path, query, fragment).
_URL = re.compile(r"https?://[^\s'\"<>`]+", re.IGNORECASE)
#: Script code that talks to the network — an HTTP client, a raw socket, mail. A wallet
#: secret in the same code is being sent (python requests/httpx/urllib, JS fetch/axios/
#: http(s).request, PowerShell Invoke-WebRequest/-RestMethod, Ruby Net::HTTP, PHP curl).
_SCRIPT_SEND_RE = re.compile(
    r"\brequests\.(?:get|post|put|patch|request)\s*\(|\bhttpx\.(?:get|post|put|patch|request|Client|AsyncClient)\b"
    r"|\burlopen\s*\(|\burllib\.request\b|\bfetch\s*\(|\baxios(?:\.(?:get|post|put|patch|request))?\s*\("
    r"|\bhttps?\.(?:request|get)\s*\(|\bXMLHttpRequest\b|\bInvoke-(?:WebRequest|RestMethod)\b|\b(?:iwr|irm)\s"
    r"|\bsmtplib\b|\bsocket\.(?:connect|create_connection|socket)\b|\bnet\.connect\s*\(|\bNet::HTTP\b|\bcurl_exec\s*\("
    # KI-378: python http.client / aiohttp / urllib3 / ftplib / paramiko, node's network
    # modules however they are loaded, WebSockets.
    r"|\bhttp\.client\b|\bHTTPS?Connection\s*\(|\baiohttp\b|\burllib3\b|\bpycurl\b|\bftplib\b|\bparamiko\b"
    r"|\brequire\s*\(\s*['\"`](?:node:)?(?:https?|http2|net|tls|dgram)['\"`]\s*\)"
    r"|\bfrom\s+['\"](?:node:)?(?:https?|http2|net|tls|dgram)['\"]|\bWebSocket\s*\(|\bwebsockets?\b",
    re.IGNORECASE,
)


def url_payloads(text: str) -> str:
    """Every web address in *text*, decoded (``+`` and ``%20`` back to spaces), one per
    line — what a secret looks like after it has been written into a URL."""
    return "\n".join(unquote_plus(url) for url in _URL.findall(text or ""))


def looks_like_script_send(text: str) -> bool:
    """True when *text* holds script code that makes a network call."""
    return bool(text and _SCRIPT_SEND_RE.search(text))


def reaches_network(tool_name: str, text: str) -> bool:
    """True when this call has a route off the machine for what it holds: a command that
    sends data, a network program anywhere in it, network-calling script code, or a tool
    whose arguments leave the machine by themselves (see module doc). The test applied to
    WALLET secrets, which have no right destination."""
    return bool(_SENDING_TOOL_RE.search(tool_name or "")) or bool(text) and (
        looks_like_egress(text) or bool(_NETWORK_COMMAND_RE.search(text)) or looks_like_script_send(text))
