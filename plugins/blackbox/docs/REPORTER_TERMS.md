# Agent Blackbox — Reporter Terms (community reports)

Version: 1.5 (draft for counsel review, 2026-10-16)

## What changed in version 1.5

- ONE GRAPH. Your statements now go to the SHARED MEMORY of the verified
  threat graph (`0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox-vm`,
  registered on chain), in its sub-graph `reports`, not to a separate
  community graph. Every node that follows the verified graph reads your
  statements (sections 1 and 4).
- PROMOTION PUBLISHES YOUR REPORT. Umanitek's curators review reports and
  promote the threats they choose. A promotion publishes one report, exactly
  as its reporter signed it, to the graph's VERIFIED MEMORY, and next to it
  the curators' promotion statement, signed by two curators, that points to
  it. The report can be yours (section 4).
- A PROMOTED REPORT IS PERMANENT. Nobody can remove or change it: not you,
  not Umanitek, not anyone. Only the curators can stop it counting, with a
  revocation or a correction, and neither removes it; your retraction stops
  your report counting, not the rule (sections 2 and 5).
- THE LINK IS PUBLIC. Anyone can see which report a verified rule came from,
  and so the reporter address and reporter public key in that report. Until
  now a promotion carried random ids in place of the reports behind it, and
  only Umanitek's curator could link them to you (section 4).
- Erasing your identity cannot reach a promoted report: it keeps the key and
  the address it was signed with (section 5).
- NO COMMUNITY CURATORS FOR NOW. The community curators of version 1.1 are
  not in use: there are none, and no reader acts on community-curator
  statements. Some may be added later. Umanitek's curators are the only ones
  who rule on reports (section 4).

## What changed in version 1.4

- Community sharing is OPT-IN again: it is off when Blackbox is installed and
  stays off until you turn it on with `blackbox report --enable-sharing` or the
  dashboard's sharing toggle. Turning it on records your agreement to these
  terms; no installer, upgrade or automatic step ever turns it on for you.
- An installation that was sharing only because of the version 1.2 default
  (you never turned it on yourself) stops sharing when Blackbox is updated. If
  you turned sharing on yourself, it stays on.

## What changed in version 1.3

- Each statement now describes the sighting in closed words (section 1):
  - the tool that met the threat (a tool you wrote yourself is only "other" or "mcp-tool");
  - what the agent was doing;
  - whether Blackbox blocked or only flagged it;
  - how it was matched, and the Blackbox version;
  - the verified rule it matched;
  - what the threat goes after (a goal, a CLASS of resource such as "cloud credentials", and a MITRE technique id).
- When a VERIFIED prompt-injection pattern is found in a page your agent fetched, the page's SITE is shared as a separate statement. Only the registrable domain is shared (`evil.example`), never the address, path or text. Popular and user-content platforms are never named.

## What changed in version 1.2

- Community sharing is now ON by default when Blackbox is installed, with an
  easy opt-out (it was off until you opted in). The installer and the
  dashboard say so; turning it off is one command or one toggle, and it stops
  sharing on the next action (section 5).
- Changing these terms no longer pauses sharing; this page always shows the
  version in force.

## What changed in version 1.1

- The community graph now has its OWN curators (section 4): they keep a
  trusted-reporter list in the community graph itself, confirm, reject or
  defer community threats, and keep a private reputation ledger. Before, only
  Umanitek's curator did this, and only in the verified graph.
- A trusted-reporter listing lasts at most 90 days unless renewed; what it
  publishes about you is listed in section 4.
- Confirmed threats can be handed to the verified graph's owner as a bundle of
  the signed statements already public in the community graph (section 4).
- Erasure rotates your SIGNING key; your node's wallet address is not changed
  by it (section 5).

These terms apply to the OPERATOR of a machine running Agent Blackbox.
Community sharing is OFF until you turn it on (`report: false` by default).
Turn it on with `blackbox report --enable-sharing` or the dashboard's sharing
toggle; that records your agreement to these terms. You can turn it off at
any time with `blackbox report --disable-sharing`, `blackbox report
--withdraw-consent` or the toggle; sharing stops on the next action.

## 1. What you share

When a protected agent on your machine meets a threat that the VERIFIED
threat graph already lists, or when you file a report yourself with
`blackbox report`, this node publishes a privacy-safe STATEMENT to the shared
memory of the verified threat graph on the OriginTrail Decentralized Knowledge
Graph (DKG), in its sub-graph `reports`:

- the threat's deterministic identifier (for example `dep:npm:evil-pkg@1.0.0`
  or `ioc:domain:evil.example`) and its closed, typed metadata (category,
  severity, ecosystem, a closed reason word);
- the UTC day of the statement, rounded to the day;
- your node's REPORTER ADDRESS (the DKG agent address of your node's wallet)
  and a signature by your node's reporter key;
- a weekly SIGHTING DIGEST: the verified threats your agents met that week,
  with coarse buckets (1 / 2–9 / 10–99 / 100+), never exact counts or times;
- the SIGHTING, in closed words only (version 1.3):
  - the host tool (`web_fetch`, `terminal`, `read_file`…; any other tool is `mcp-tool` or `other`);
  - what the agent was doing (fetch, install a package or skill, read or write a file, run a command, model input);
  - blocked or flagged;
  - how it was matched and the Blackbox version;
  - the verified rule it matched;
  - the threat's goal, the CLASS of resource at risk, and a MITRE ATT&CK / ATLAS technique id;
- for a verified prompt injection in a fetched page, the site's registrable domain, as its own statement.

Never shared, by construction: prompts, commands, file paths, file or skill
source, secrets, LLM outputs, local-only or custom-rule findings,
vulnerability findings, the names of locally authored skills, the names of
your own tools, the address, path or text of the page an injection came from
(only a verified injection's registrable domain, as above), the actual file or
resource at risk (only its class), exact times, your location, or any
person's identity.

## 2. What you grant

You dedicate each statement you publish to the public domain under
**CC0 1.0** (no rights reserved) so every node on the network may read,
store, verify and act on it, and Umanitek's curators may publish it,
unchanged, to Verified Memory (section 4). The graph is
shared and replicated: a published statement cannot be deleted by you, by
Umanitek or by anyone; you can RETRACT a report (`blackbox report --retract`)
and every current reader stops counting it, but the record of the statement
stays on the network. A promoted report stays in Verified Memory permanently, and
your retraction does not withdraw it: only the curators can stop a rule
promoted from your report, with a revocation or a correction (section 4).

## 3. What you promise

- **No personal data.** You will not put any person's name, contact
  details, account identifiers or other personal data into a report
  (`--name`, `--pattern`, `--reason` and every free field are for the
  threat, never for a person). The client refuses free text where it can;
  the warranty is yours where it cannot.
- **Good faith.** You report what your agents actually met or what you
  verified. Confirmed bad faith (for example, reporting planted canaries or
  flooding) removes your node from the counted-author list; the counted list
  is public.
- **Your identity.** Your reporter key and address are yours. Statements by
  other nodes under your address are rejected by every reader because they
  fail your signature.

## 4. Who sees what, and for how long

- Every node that follows the verified threat graph receives your
  statements in the graph's shared memory and keeps them for ITS OWN
  retention setting (30 days by default on current nodes; a replica may
  lengthen or disable expiry). Readers keep a counted threat locally for up
  to 90 days after its network copies expire.
- Umanitek's curator (the VERIFIED graph's owner) reads the reports. It may
  list you as a trusted reporter, confirm, reject or defer a community
  threat, pause intake for up to 7 days, promote a threat into Verified
  Memory (below), revoke a verified rule, and publish the kill list.
- The COMMUNITY curators (named in the controller map) are NOT IN USE: there
  are none for now, and no reader acts on community-curator statements; some
  may be added later. Once in use, they may list trusted reporters, confirm,
  reject or defer a community threat, and pause intake for up to 7 days;
  their statements can only make a threat FLAG,
  never block.
- PROMOTION. Umanitek's curators promote a threat by publishing one report
  they select, by default the earliest shared for it, exactly as its
  reporter signed it, to the graph's VERIFIED MEMORY. Their promotion
  statement, signed by two curators, is published next to it and points to
  it. A promoted report carries everything your statement carries
  (section 1), your REPORTER ADDRESS, reporter public key, sighting fields
  and signature included. Reports of malicious packages, indicators, skills
  and file access can be promoted; an injection report cannot. A promoted
  report is PERMANENT: nobody can remove or change it. Anyone can read it and
  see which verified rule it led to. Only the curators can stop it counting
  on every reader, with a revocation or a correction; it stays readable.
  Your retraction stops your report counting, not the rule: to have a rule
  revoked, ask Umanitek (the contact is in the controller map).
- A curator node on a DKG release older than 10.0.25 cannot publish your
  report itself. It publishes instead a verified rule built from it, with
  the threat's identifier and fields, that names your report: its subject,
  which carries your REPORTER ADDRESS, the digest of what you signed, and
  your reporter public key. That rule is permanent too.
- Each group of curators may keep a PRIVATE reputation ledger about reporters
  on its own curator nodes: which of your reports were confirmed or rejected,
  keyed by a per-reporter random salt. Nothing from it is published. The index
  that links your key to its entry is encrypted. Erasure deletes the salt.
- A trusted-reporter listing publishes, about you: your reporter key and
  node address (already on your own reports), that you are listed, your class
  (established or partner), an organisation name for partners, and an expiry
  day. A community listing lasts at most 90 days unless renewed.
- A community curator node may run a service that signs routine statements on
  its own (a heartbeat, an acknowledgement that a report is in review, a
  confirmation of a package that a public malicious-package advisory already
  names, listings its own ledger calls for). Rejections and anything that
  accuses a reporter of bad faith are always a person's decision.
- Threats the community curators confirmed can be handed to the verified
  graph's owner as one file holding the signed statements behind them, your
  signed reports included, so the receiver can credit the original reporters.
  The file holds nothing that is not already public in the graph's shared
  memory. This hand-off is not in use while there are no community curators.

## 5. Your rights and the tools for them

- **Access and export:** `blackbox report --export FILE` writes your key
  backup and your local ledger of every statement this node made.
- **Correction / withdrawal of a statement:** `blackbox report --retract`,
  `blackbox report --false-positive`. A retraction withdraws your report;
  a verified rule already promoted from it stays until the curators revoke
  or correct it, which you can ask Umanitek to do (section 4).
- **Erasure of your identity:** `blackbox report --erase-identity --confirm`
  destroys the reporter key and every local share record, including the
  keep-alive memory, so this node can never re-publish its old statements.
  Your next report is signed by a new key; your node's WALLET address, which
  every statement also carries, is not changed by this command. Each group of
  curators deletes its ledger salt on request (crypto-shredding) and stops
  keeping your listing alive. Erasure cannot reach a promoted report: it
  stays in Verified Memory with the reporter key and address it was signed
  with.
- **Turn sharing on (opt in):** `blackbox report --enable-sharing` (or the
  dashboard toggle).
- **Turn sharing off (opt out):** `blackbox report --withdraw-consent` (or
  `--disable-sharing`, or the dashboard toggle).
- Requests that need a human: the contact points in the controller map
  (one for the community curators, one for Umanitek); either forwards a
  request it cannot serve to the other.

## 6. Changes

The version in force is the one shipped with your installation, and its
"What changed" section lists every change. Your choice stays in force across
versions: a change of these terms never turns sharing on, and never pauses
sharing you turned on.
