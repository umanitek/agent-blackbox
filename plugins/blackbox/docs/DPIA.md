# Data Protection Impact Assessment — Agent Blackbox community reports

Version: 1.7 (draft for counsel review, 2026-10-16; v1.7 records the move to one context graph: reports in the verified graph's shared memory, and a promoted report published permanently to Verified Memory with the curators' statement pointing to it — project lead decision; the community authority is not in use (no community curators for now); v1.6 returns community sharing to OPT-IN — off by default, on only after the operator's recorded acceptance — for the Hermes plugin catalog listing, so §3's departure from the privacy-by-default baseline is closed; earlier: 2026-10-12; amended 2026-10-14 with Trader Shield's local data — what it finds and records on this machine, and the operator's own wallet addresses; v1.5 adds the threat-profile sighting fields and the site of a verified injection; v1.4 records the switch to sharing ON by default with an opt-out — founder decision; v1.3 adds the community authority — Community Curation C11; v1.2 corrected §2/§5 after review round 5 — KI-221/223/224, erasure semantics KI-220). Engineering assessment,
not legal advice; the launching party still needs counsel for its market.

## 1. The processing

Agent Blackbox nodes (run by node OPERATORS) publish privacy-safe threat
statements to the shared memory of one replicated graph on the OriginTrail
DKG: Umanitek's verified threat graph, registered on chain, sub-graph
`reports` (v1.7; earlier versions planned a separate "community graph").
Umanitek's curators read them, keep a trusted-reporter list and verdicts, and
may promote threats into the verified tier that every node enforces. The
COMMUNITY curators (v1.3) are not in use: there are none for now, and no
reader trusts a community root (v1.7); some may be added later. Promotion
publishes the selected report itself, as its reporter signed it, to the
graph's Verified Memory, with the curators' two-signature promotion statement
beside it, pointing to it; a curator node older than DKG 10.0.25 publishes
instead a verified rule built from the report that names it (subject, digest,
reporter key). Every node verifies signatures and computes stages itself. No
new kind of personal data is collected in v1.7; what changes is where the
statements live, and that a promoted report, with its reporter's pseudonymous
identity, is published permanently and linked in public to its verified rule.
Purpose: early warning about malicious packages, skills, MCP servers,
prompt-injection patterns and indicators of compromise met by AI agents, so
other agents are protected sooner.

## 2. Personal data inventory (what, why, where, how long)

| Data | Purpose | Where it lives | Retention |
| --- | --- | --- | --- |
| Reporter address (the node wallet's DKG agent address) and reporter public key | identity binding: every statement is signed; readers count distinct reporters | every replica of the graph's shared memory; trusted-reporter listings; every promoted report in Verified Memory (v1.7) | per replica's own expiry (30 d default; a replica may disable expiry → unbounded); verified listings ≤ 12 months, community listings ≤ 90 days, both renewable; each curator node re-publishes only its CURRENT statements; in a promoted report: PERMANENT |
| Trusted-reporter listing (listed yes/no, class, partner organisation, expiry day) | which reporters' reports count | as above | as above; a delisting is in force at most 12 months |
| Reader trust store (`community_trust.json`: the curator statements and key manifests this node verified, listings included) | keep working when the graph cannot be read | every reader's own machine | current statements only, nothing older than 500 days; pruned on every read |
| Export bundle of the confirmed pool (signed confirmations, the signed reports behind them, listings of those reporters) | hand-off to the verified graph's owner | wherever the receiver keeps the file | the receiver's own retention; holds nothing not already public; not in use while there are no community curators (v1.7) |
| Threat statements (identifier, closed metadata, day) signed by the reporter | the product's purpose | every replica of the graph's shared memory | as above; readers keep a counted threat ≤ 90 d past expiry locally; PERMANENT once promoted (next rows) |
| Promoted report (v1.7): one reporter's signed statement, unchanged — identifier, closed metadata, day, sighting fields, reporter address and public key, signature — with the curators' two-key promotion statement beside it, pointing to it; one report per promotion, by default the earliest; package (malware), indicator, skill and file-access reports only, never an injection report | the evidence behind a verified rule: every reader can check the report it came from | the graph's Verified Memory, on every node's replica; each publish recorded in the curator node's `publish_ledger.jsonl` | PERMANENT: Verified Memory cannot remove or change it; only the curators' revocation or correction stops it counting, the reporter's retraction only the report's community count |
| Promotion by a curator node older than DKG 10.0.25 (v1.7): a verified rule built from the report — the threat's identifier and fields, the curators' severity, the two-key envelope — naming the report: its subject (which carries the reporter's agent address), the digest of its signed content and the reporter's public key | as above | Verified Memory | PERMANENT, as above; the report itself stays in shared memory under the retention above |
| Weekly sighting digest (verified threats met, coarse buckets) | frequency signal | every replica | as above |
| Sighting fields on each statement, closed words only (v1.5): host tool (own tools → `mcp-tool`/`other`), agent action, blocked/flagged, match method, Blackbox version, verified rule link, goal, resource CLASS at risk, MITRE technique; plus a record digest and the signer key beside the signature | reviewers can understand each threat without the operator's content | every replica | as above |
| Site of a verified prompt injection (registrable domain only, never allowlisted or user-content platforms), as its own statement (v1.5) | other agents flag the site | every replica | as above |
| Share ledger (what this node shared, outcomes) | the operator's own record, rights (export) | the operator's machine only | until erased by the operator |
| Keep-alive memory (signed quads of accepted reports) | re-publishing copies before expiry | the operator's machine only | retired at the threat type's lifetime (47–460 d); erased with the identity |
| Curator reputation ledger (outcomes per reporter, credited automatically from published verdicts) | graduation / demotion decisions | each curator group's own curator nodes, pseudonymised by a per-reporter random salt; the index from key to salt is encrypted, its key in a third owner-only file (KI-257) | inactive entries deleted after 24 months together with their salts; erasure deletes the salt (crypto-shredding) |
| Curator node records (proposals, the consent ledger of what was published and why, the node's own share ledger entry for each published statement, the statements kept alive, the automation-policy acceptance, the service's daily count) | accountability for every statement signed under a curator key | the curator node only | proposals and the consent ledger are kept as the record of published acts; statements kept alive are retired when no longer current or on erasure |
| Curator signing log (`signing_log.jsonl`: for each signature this node's keys made — the statement kind, the digest of the signed bytes, the signing key's public key, the time; never the statement's text, a prompt or a command) | detecting a curator key used somewhere else: statements published under the key are compared with this log | the curator node only (owner-only file) | kept as the record of signatures made under the curator key; names no reporter |
| Curator service state (`self_test.json`: the last self-test result over synthetic fixtures — day, matched, failures; `undelivered.json`: ids of this node's proposals no other curator has received yet, with the beat count and last attempt time) | suspending a curator whose verdict rules fail; alarming a halted quorum | the curator node only | current state only: overwritten each run; an entry is removed once its proposal is delivered or published; names no reporter |
| Canaries (planted identifiers) | detecting bad-faith reporters | the curator node only | curator's discretion |
| Provenance map (`provenance.jsonl` in the curate home: the random ids an earlier promotion carried → the report subjects behind them) | crediting reporters without a public link, before v1.7 | the curator node only (owner-only file) | no longer written (v1.7: a promotion links its report in public); a file an earlier build wrote stays until the curator deletes it (§7) |
| Local audit logs on an operator's machine | the operator's own visibility | the operator's machine, redacted at capture | the operator's log rotation |
| Private audit record (identifier, severity, REDACTED evidence text ≤ 1200 chars, exact time) | the operator's own forensic trail | the operator's OWN DKG node's private working memory, never shared; written only when the node is on the same machine (a remote `dkg_url` disables it, KI-223) | the node's working-memory retention |
| Weekly sighting tally (verified-threat identifiers met, per ISO week) | source of the weekly digest | the operator's machine only | 8 weeks; erased with the identity (KI-221) |
| Trader Shield status and events (2026-10-14): the wallets found on this machine (wallet, browser, profile folder name, which key-store areas exist — folder names only, nothing inside a store is opened) and each wallet event (outcome, the tool call with its command REDACTED and size-capped, the request just before it, redacted, and that session's steps) | the operator's own view of what the agent reached for and what was blocked | the operator's machine only: built on request from the local audit logs and served only by the loopback dashboard (`GET /api/shields`, `/api/shields/{id}/events`); shield findings carry `source: "secret"`, which the share gate never sends, so none of it leaves the machine | the local audit logs' size caps (each log trimmed to its most recent ~4 MB once it passes 8 MB); the status is rebuilt on each request, the wallet scan reused for five minutes in memory |
| The operator's own wallet addresses (`shields.trader.addresses`, 2026-10-14): up to 50 public addresses, validated `0x` + 40 hex, stored lower-case | recognise a raw private key that opens one of them, so sending it is blocked | this machine's `config.yaml` only; OPT-IN — empty unless the operator types them in Settings; returned only by the Settings view that edits them. NEVER in a finding, an event, a log line, a report or the status payload (the card shows a count only); tested | until the operator removes them: clearing the field in Settings (or the key in `config.yaml`) deletes them |
| Settings files Trader Shield reads to place a key store (2026-10-14): the Solana CLI's `cli/config.yml` (only its `keypair_path:` line) and each Firefox profile's `prefs.js` (only its add-on → storage-folder map) | know which file or folder holds a wallet's keys, so a read of it can be refused | read in place on this machine through the kernel's bounded reader (size-capped, regular files only, symlinked `prefs.js` refused); the key file itself and wallet storage are NEVER opened | not stored: the pointer is used for the check at hand; the Firefox map is kept in memory and re-read when `prefs.js` changes |

Never processed: prompts, commands, paths, file/skill source, secrets, LLM
outputs, vulnerability findings, anything Trader Shield finds or records (wallets on the machine, wallet events, the operator's own addresses), the names of locally authored skills, the
names of the operator's own tools, the page address, path or text an
injection came from (only a verified injection's registrable domain is
shared), the actual resource at risk (only its class), exact times (days
only), locations, end-user identities. Enforced by the client's closed report schema and the
never-shared source list; tested.

## 3. Lawful basis and consent

- Node operators: sharing is OPT-IN, default OFF (2026-10-16; it was on by
  default with an opt-out from 2026-10-12 to 2026-10-16, a recorded departure
  now closed). Nothing is shared until the operator turns sharing on with
  `blackbox report --enable-sharing` or the dashboard toggle, which records an
  acceptance of the reporter terms (unbundled from installation: no installer,
  upgrade or automatic step records it). An install that was sharing only
  because of the 2026-10-12 default, with no acceptance on record, stops at its
  next update. One command or one toggle stops the processing on the next
  action, and an opt-out survives upgrades, terms changes and identity erasure.
  Basis: consent, with legitimate interest in network and information security
  (GDPR recital 49) as the fallback. COUNSEL REVIEW REQUIRED before a wide
  launch, in particular for EU/UK operators and for the weekly sighting digest.
- Legitimate interest (network and information security, GDPR recital 49) is
  the fallback basis for the curator's processing of statements that nodes
  chose to publish into a public graph.
- Promotion (v1.7, project lead decision 2026-10-16) relies on the same
  legitimate interest: a verified rule whose source report every reader can
  check. The operator is told before opting in (reporter terms v1.5, §4) and
  can turn sharing off at any time; a report already promoted stays.
  COUNSEL REVIEW REQUIRED: erasure cannot reach a promoted report (§5), and the
  link from the verified rule to the report and its reporter is public.

## 4. Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| Immutable statements cannot be deleted from a replicated graph | The terms say so before consent; retraction stops counting on every current reader; nothing identifying beyond the reporter address is ever in a statement |
| A promoted report is permanent: Verified Memory cannot remove or change it, the reporter address and key in it included, and identity erasure cannot reach it (v1.7; the project lead accepted this) | Only a report the curators select is published, and it holds nothing its reporter had not already shared in public: closed fields, the day, the sighting fields, a pseudonymous address and key; the terms (v1.5) say so before sharing, and an opt-out stops every later share; only the curators' revocation or correction stops it counting on every reader, and a reporter can ask Umanitek for one. Counsel to confirm (§7) |
| Anyone can see which report a verified rule came from: the promotion statement points to the report, so a reporter address is linked, in public and for good, to a threat its agents met (before, random ids kept that link curator-private; the project lead accepted this) | The identity is pseudonymous: a wallet address of Blackbox's own node and a public key, with no mapping to persons anywhere in the product; one report per promotion, so the threat's other reporters are not named and their reports expire as before; the report carries closed vocabularies only, day-rounded, never a count, a path or content; the terms say so before sharing; the operator can turn sharing off. Counsel to confirm (§7) |
| Author linkability: a reporter's dependency reports reveal which packages its agents install | Day-rounded timestamps; automatic sightings only for VERIFIED-tier matches; vulnerability findings never leave; the operator may run a dedicated reporter identity and erase it |
| The weekly digest is a week-level list of verified threats per address | Coarse buckets; verified threats only; the digest is one statement per week; only from nodes that opted in, and it stops with every other share after an opt-out |
| A replica disables expiry → unbounded retention | Disclosed in the terms; readers' own persistence is bounded (≤ 90 d past expiry); the inventory records the replica setting as the retention boundary |
| The counted-author list is public | It carries addresses and classes only; graduation needs the reporter's own reports; delisting is one statement |
| Reputation ledger profiling | Curator-private, salted pseudonyms, encrypted index, 24-month retention, erasure by salt deletion; decisions reach readers only as list entries |
| Automated decisions about reporters (the curator service lists or delists a reporter when its ledger calls for it) | The rules are arithmetic over public outcomes, written in the automation policy the operator accepted; two curator nodes must each reach the same answer from their own ledgers; strikes and anything alleging bad faith are always a person's; the reporter sees its own progress (`blackbox report --standing`) and can dispute and retract |
| A second group of controllers (the community curators) | Separate root keys: neither group can speak for the other; the controller map names both; the terms say what changed; a terms change neither pauses sharing the operator turned on nor turns it on (opt-in since 2026-10-16); not in use: there are none for now, and no reader trusts a community root (v1.7) |
| The export bundle spreads reporters' signed reports to a new receiver | It holds only statements already public in the graph's shared memory; reporters are told in the terms; crediting reporters is its purpose; not in use while there are no community curators (v1.7) |
| A breach of the curator ledger | Copying the entries file or the index alone links no key to any outcome (the index is encrypted); all three files together do, so the key file is the one to protect |
| The sighting fields add to each reporter's accumulated public pattern (what its agents do, whether it runs block mode) | Closed vocabularies only; private tool names collapse to `mcp-tool`/`other`; resource is a class, never a path; no count leaves the node (network counts are computed by readers and curators); day-rounded |
| The site of an injection reveals a site the operator's agent visited, and an attacker could give each target its own domain to learn which reporter met which page | Only VERIFIED injection patterns trigger it; only the registrable domain (a per-target sub-domain collapses); allowlisted brands and user-content platforms are never named; the operator can turn sharing off. Counsel to confirm (§7) |
| Re-identification of a node from its address | The address is a wallet, pseudonymous by design; the terms warn; no mapping to persons is kept anywhere in the product |
| Trader Shield's local data ties the operator to their funds: the wallets found reveal what they hold, their own addresses link them to their history on-chain (2026-10-14) | Opt-in shield; addresses are opt-in and live in `config.yaml` only, out of every finding, event, log, report and status payload (a count is shown); status and events are read from the local audit logs and served only on loopback; shield findings are `source: "secret"`, refused by the share gate; settings files are read for the one line or map needed, never key material. The next shield inherits the same rule: its status and events stay on this machine |
| Children's or special-category data | None is collected; the schema has no field for it |
| Breach | Statements are public by design; the private surfaces (ledger, canaries, audit logs) are files on single machines with owner-only modes. The ledger is two files: the entries (pseudonym → outcomes) and the salt map (reporter key → salt, owner-only, pruned with its entry); a breach of the entries file alone links no key to any outcome, a breach of both does — the salt map is the file to protect |

## 5. Rights operations

| Right | Operation |
| --- | --- |
| Access / export | `blackbox report --export FILE` (key backup, ledger, consent record, keep-alive memory, retry queue, sighting tally — machine-readable JSON, KI-224) |
| Rectification | `--retract`, `--false-positive`; a retraction stops the report's community count, not its promotion: that takes the curators' revocation or correction, which the reporter can ask Umanitek for (v1.7) |
| Erasure | `--erase-identity --confirm` (signing key, ledger, keep-alive memory, retry queue, consent record, sighting tally); on request, each curator group runs `blackbox curate graduate --erase KEY` (salt deletion, and its statements about the reporter are no longer kept alive). NOTE (KI-220): erasure rotates the SIGNING key; the reporter address in every statement is the node's wallet address, which this command does not change — a new reporter identity in full needs a new node wallet (decision pending). NOTE (v1.7): no operation can erase a promoted report; it keeps the key and address it was signed with |
| Restriction / objection | sharing is off until the operator opts in; `--withdraw-consent` (opt-out, kept across upgrades and erasure); `--disable-sharing` / the dashboard toggle (`report: false`) |
| Portability | the export file restores the identity on another machine (`--restore-key`) |

## 6. Transfers and sub-processors

The DKG is a peer-to-peer network; replicas may be anywhere. No processor
acts on Umanitek's behalf for the graph itself; the curator node's
hosting provider is a sub-processor for the curator-private files (named in
the controller map).

## 7. Open items for counsel

- Name the community curators' operator and its contact point (decision 15);
  until then, no reporter outside the pilot.
- Confirm that automated listing and delisting by the curator service, with
  the safeguards above, is acceptable (GDPR art. 22).

- Confirm the joint-controller analysis (controller map §2).
- Confirm CC0 as the licence for statements.
- Confirm the v1.5 sighting fields and the shared site of a verified injection under the operator's opt-in consent (legitimate interest as the fallback).
- Confirm the v1.7 promotion under the legitimate-interest basis: a promoted report, with its reporter's pseudonymous identity, is permanent in Verified Memory, out of reach of erasure, and linked in public to its verified rule.
- Confirm that a reporter's retraction not reaching a promoted report (only the curators' revocation or correction withdraws it; project lead decision 2026-10-16) is acceptable for rectification requests.
- Check the privacy policy's retention for the curated public graph (at most 36 months, unless needed for the graph's integrity) against permanent promoted reports.
- Decide whether curator nodes delete the provenance map an earlier build wrote (§2).
- Confirm the 24-month ledger retention and the 90-day reader persistence.
- Decide whether the counted-author list needs a published privacy notice of its own.

## 8. Compliant-by-default checklist (run 2026-10-03, Community Curation C11)

| Item | State | Where |
| --- | --- | --- |
| Only necessary fields, each mapped to a purpose | done | §2: no new kind of personal data; listings carry key, address, class, organisation, expiry |
| Consent opt-in, unbundled, default off; record stored; withdrawal works | done | §3 (since 2026-10-16): off by default; on only after the operator's recorded acceptance (`--enable-sharing` or the toggle); the record is stored and honoured by both runtimes; withdrawal is one step; a node with `report: true` and no acceptance in force shows an ACTION item in `blackbox status` and the dashboard |
| Access, export, correction, deletion, opt-out are real, tested operations | done | §5; the curator-side erasure removes the ledger entry and ends keep-alive of statements about the reporter; deletion cannot reach a promoted report (next row) |
| Retention set; automatic deletion | departed | §2: replica expiry, 90-day community listings, 24-month ledger, 500-day trust store, current-only keep-alive; a promoted report is permanent in Verified Memory (v1.7, project lead decision); counsel review pending (§7) |
| Encryption at rest for the sensitive store; secrets kept out of statements | done | the ledger index is encrypted (AES-256-GCM); keys and tokens never leave their owner-only files |
| No personal data in logs | done | statements carry no free text; display strings are sanitized; the consent ledger records codes and summaries, never report content; Trader Shield's own addresses are never logged and its events carry redacted commands (2026-10-14) |
| Sensitive and children's data | not applicable | the schema has no field for it |
| Sub-processors and data locations; transfer basis | done, one name open | controller map §1, §3, §4; the community curators' operator is to be named (decision 15) |
| Breach detection and runbook for the 72-hour clock | partly | statements are public by design; curator nodes alarm on manifest conflicts, silence and floods; a written runbook for a curator-node compromise belongs to the launch gate (C13) |
| Privacy notice matches the code | done | reporter terms v1.5, this DPIA v1.7, controller map v1.2, revised for the one-graph change and reviewed with its code |

Open, outside engineering: counsel review of these three documents before the
first reporter outside the pilot.
