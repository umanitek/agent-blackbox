# Continuous Blackbox threat publisher

This directory is the standalone outer pipeline for continuously discovering,
staging, reviewing, and publishing new threat observations. It does **not**
modify the DKG package, daemon, graph configuration, or any DKG patch helper.
It calls the existing guarded `publish.mjs` boundary only after a signed human
approval, or an explicit audited `publisher.auto_approve` decision, and only
when `publisher.enabled: true`.

The default configuration is safe for development:

- deterministic acquisition and staging are enabled only for reviewed sources;
- Slack, AI discovery, and paid publishing are disabled;
- one knowledge asset contains 1,000 observations;
- one immutable production approval bundle contains exactly 10,000
  observations (ten complete assets);
- no more than 100,000 successfully verified observations count toward a UTC
  publishing day;
- an asset counts as published only after the existing registry records VM
  finalization and the explicit VM-only `swmRestoreSkippedAt` marker;
- ambiguous paid operations stop the worker and are never blindly retried.
- `publisher.auto_approve` defaults to `false`; enabling it is an explicit
  operator override, not the normal approval policy.

## Architecture

```text
blackbox-acquire.timer (every 3 hours)
  -> allowlisted shallow Git snapshot
  -> bounded inert text parsing
  -> canonicalization + SQLite WAL state
  -> bounded read-only checks of pending values in the confirmed DKG partition
  -> exact event dedupe + canonical-entity linking
  -> immutable approval manifest (10,000)
  -> checksummed assets (1,000 each)
  -> local publisher dry-run
  -> compact Slack report with exact JSON attachment / Approve / Decline

blackbox-slack-approvals.service
  -> authenticated outbound Socket Mode
  -> workspace/channel/user allowlists
  -> fresh timestamp + one-use nonce + exact manifest hash
  -> exact-bundle publish trigger after approval

blackbox-publish-triggered.path
  -> reconcile prior registry first
  -> enforce transactional UTC daily cap
  -> repeat the exact bundle's graph-absence check
  -> preflight existing publisher
  -> publish only approved immutable bundle
  -> reconcile VM finalization and the explicit VM-only completion marker
  -> post a short Slack success message, or stop and report failure

blackbox-publisher.timer with publisher.auto_approve: true
  -> select only the oldest bundled manifest when no publish is in progress
  -> refresh an expired read-only graph-deduplication snapshot under the shared DKG workload lock
  -> run the same live graph, wallet, manifest, and publisher preflight
  -> upload the exact JSON to Slack as an informational card without buttons
  -> record an audited publisher-cron approval and publish sequentially
  -> stop at the same transactional 100,000-observation UTC daily cap

Slack-hosted approval attachment
  -> upload the exact checksummed JSON into the approval message thread
  -> expose Approve / Decline only after the upload succeeds
```

The SQLite database is the queue and audit ledger. Source content remains
untrusted throughout. Raw values are stored for provenance and included as RDF
literals, but logs and Slack reports use inert hashes/prefix summaries rather
than rendering hostile payloads.

Each 1,000-observation asset keeps canonical identity, source, category,
lifecycle, and citations as direct RDF predicates. Confidence, attribution,
evidence, licensing, severity, source revision, and the record digest are
encoded losslessly in a deterministic `urn:blackbox:p:provenanceJson` literal.
This keeps normal assets below DKG's exact 4 MiB N-Quads inline storage-ACK
staging ceiling even after the full VM assertion graph URI is applied, so
public-graph publishing can still replicate to compatible core peers when the
initial SWM topic has too few hosts. The checksummed approval JSON continues to
contain every original field.

Superseded manifests remain immutable audit artifacts. Schema version 2 allows
their clean observations to appear in one later replacement manifest while
retaining a unique observation only once inside each individual bundle.

## Files

| File | Purpose |
|---|---|
| `cli.py` | scheduler/operator entrypoint |
| `core.py` | configuration, canonicalization, SQLite schema, redacted audit log |
| `sources.py` | allowlisted shallow-Git adapter with durable per-line cursor and removal detection |
| `graph.py` | bounded read-only candidate checks against the confirmed DKG partition |
| `pipeline.py` | immutable bundles, approval state machine, daily cap, guarded publisher handoff |
| `slack.py` | reports and authenticated Socket Mode buttons |
| `discovery.py` | optional budgeted OpenAI source proposals; no publication authority |
| `mapping.mjs` | append-only source-observation RDF mapping |
| `validate-inline-size.mjs` | fail-closed exact DKG inline storage-ACK size gate |
| `config.example.yaml` | non-secret behavioral configuration |
| `requirements.txt` | pinned Python runtime dependencies for the isolated node environment |
| `systemd/` | new publisher-side services and timers; no DKG units |

`chunk.mjs` and `publish.mjs` gained one backward-compatible mapping-path
option. Their default remains the existing `mapping.mjs`, so the one-time
460,000-record corpus and its manifest hash contract are unchanged.

## Local verification

Use the repository virtual environment:

```bash
cd /path/to/agent-blackbox
.venv/bin/python -m pytest -q \
  tests/scripts/test_blackbox_continuous_publisher.py

cd scripts/dkg-kc-publisher
node test.mjs
```

The tests use temporary state, local fixtures, and a mock DKG HTTP server. They
perform no external network operation and no paid transaction.

For a local status-only smoke test, copy the example outside Git and keep all
external capabilities disabled:

```bash
cd scripts/dkg-kc-publisher
cp continuous/config.example.yaml continuous/config.yaml
python3 -m continuous.cli --config continuous/config.yaml status
```

Do not run the production example unchanged on a laptop: its state path and
publisher path intentionally target `blackbox-publisher-node`.

## Commands

```bash
python3 -m continuous.cli --config /etc/blackbox-continuous/config.yaml acquire
python3 -m continuous.cli --config /etc/blackbox-continuous/config.yaml status
python3 -m continuous.cli --config /etc/blackbox-continuous/config.yaml inspect <bundle-id>
python3 -m continuous.cli --config /etc/blackbox-continuous/config.yaml post-slack <bundle-id>
python3 -m continuous.cli --config /etc/blackbox-continuous/config.yaml reconcile
python3 -m continuous.cli --config /etc/blackbox-continuous/config.yaml graph-sync
python3 -m continuous.cli --config /etc/blackbox-continuous/config.yaml publish-once
python3 -m continuous.cli --config /etc/blackbox-continuous/config.yaml publish-triggered
python3 -m continuous.cli --config /etc/blackbox-continuous/config.yaml discover
python3 -m continuous.cli --config /etc/blackbox-continuous/config.yaml slack-listen
python3 -m continuous.cli --config /etc/blackbox-continuous/config.yaml downloads-serve
```

`acquire` never publishes. It posts a summary even when no new observations are
found. When AI discovery is enabled, the same three-hour acquisition run makes
one budgeted advisory discovery request; a model/API failure is logged but does
not block the reviewed deterministic feeds. `publish-once` exits before
preflight unless paid publishing is explicitly enabled, and then still
requires an approved unexpired bundle.

When `publisher.auto_approve: true`, `publish-once` may create that approval
for one oldest bundle only after its live preflight and Slack JSON upload both
succeed. The checked-in/default value is `false`; switching paid publishing on
does not implicitly switch auto-approval on. A crash after the audited decision
is restart-safe because the next timer run reconciles and resumes the same
approved bundle. Auto mode refreshes its own graph snapshot when the configured
freshness window expires; it does not require acquisition to be enabled.

Manual CLI approvals exist only for an offline rehearsal and require
`slack.allow_manual_cli_approval: true`. Production keeps that setting false.

## Initial sources

The example enables only the two reviewed P0 sources:

1. Phishing.Database active URL/domain files (MIT).
2. Maltrail nested `trails/static/**/*.txt` feeds (MIT), with its reviewed
   whitespace-delimited inline-comment parser and path-based risk categories.

The Block List Project remains disabled and would be quarantined by default
because bare domain membership is insufficient for a high-confidence malicious
verdict. New adapters are deny-by-default: an enabled source must have an
explicit redistribution approval in `config.yaml`, and model proposals never
change that configuration.

The source cursor pins a commit until its reviewed files are completely
processed. A later timer resumes the exact file/line without silently jumping
to a newer snapshot. At snapshot completion, missing active members generate
append-only inactive observations rather than deleting history.

Before paid mode can be enabled, the read-only graph check must be enabled and
fresh. After every acquisition, pending canonical values are sent in bounded
`VALUES` sets to the confirmed
`did:dkg:context-graph:<id>/context/<on-chain-id>` partition. The lookup checks
both the legacy `urn:defender:p:value` predicate and the incremental
`urn:blackbox:p:normalizedValue` predicate. It never performs a paid or write
operation. Known positives remain in the local monotonic set, while the exact
immutable bundle is checked again during the live Slack preflight and once
more immediately before paid publication. A query failure stops bundling or
publishing; an empty or unavailable confirmed partition is not accepted. If a
previously clean approval bundle gains a graph match before publication, that
manifest is superseded, its graph matches are excluded, and its remaining
observations return to the candidate queue for a fresh manifest and approval.

Within the local queue, only the oldest unpublished observation for a
canonical indicator enters a bundle; corroborating observations remain
available as append-only follow-ups after that indicator is published.

## Slack setup (Phase 2, not yet installed)

Create a dedicated private-channel Slack app:

1. enable Socket Mode and create an app-level token with `connections:write`;
2. add the bot scopes `chat:write` and `files:write`, then install the app;
3. enable Interactivity (Socket Mode needs no public interaction URL);
4. invite the bot to the private review channel;
5. record the workspace ID, channel ID, and exact approver user IDs in
   `config.yaml`;
6. install the bot and app tokens through protected systemd credentials.

Outbound reports normally use the bot Web API. A channel-bound incoming
webhook can instead be configured as `webhook_url_credential`; Socket Mode
still authenticates every button event and all workspace/channel/manifest
checks remain unchanged.

The approval card intentionally shows only a short threat/source summary and
Approve / Decline. The exact immutable, checksummed JSON set is uploaded into
the card's Slack thread before those actions appear. If the upload fails, the
card remains non-actionable and must be refreshed after the Slack issue is
fixed. The legacy loopback download service remains available for private
operator tooling, but approval messages do not depend on it.

Approving a live card atomically creates an exact manifest-bound trigger.
`blackbox-publish-triggered.path` starts the one-shot publisher immediately;
it is not delayed until the next three-hour acquisition. On verified success,
Slack receives `Published <count> <category> threats as <count> knowledge
assets.` While the worker runs, the channel receives a start message and a new
short update whenever another knowledge asset becomes verified. An ambiguous
publication is quarantined, never retried automatically, and posts a short
operator-review message. The quarantine applies only to that immutable bundle:
auto mode may continue with later independently checksummed and graph-checked
bundles under the same singleton paid-worker lock. If no other bundle is ready,
the cron reports `waiting_reconciliation` successfully instead of repeatedly
failing its systemd service. Auto mode may resume a definitive pre-publication rejection only when
the reviewed publisher returned the durable record to `shared` with no
`publishStartedAt`, transaction, UAL, or finalized VM marker. The publisher
repeats its chain-state check before a new paid call; every other failure stays
stopped for operator review.

Expired, never-published approval manifests are not reused. When auto mode has
no current bundle, their observations return to candidate state while the old
manifest and membership rows remain intact for audit. The publisher builds a
fresh checksummed bundle, uploads its current JSON report, repeats graph
deduplication immediately before payment, and only then auto-approves it.

An approval is accepted only if the authenticated Socket Mode event has the
configured workspace and channel, an authenticated user allowed by policy, a timestamp no older than five
minutes, a one-use random nonce, the exact on-disk manifest SHA-256, and the
hash of a fresh approval-preflight report. In paid mode, the report is not
posted unless the existing publisher's read-only node preflight passes and its
current wallet balances can be shown. Preflight reports expire after 30 minutes;
`post-slack` refreshes one without changing the immutable bundle. Any manifest
change invalidates approval.

Set `slack.allow_any_channel_member: true` to let any authenticated user who
clicks the message inside that exact channel approve or decline. When false,
`approver_user_ids` is the explicit allowlist. Both modes retain the channel,
workspace, manifest, preflight, freshness, and one-use nonce checks.

Never put Slack tokens, webhook URLs, signing secrets, or credentials in Git,
Markdown, shell command arguments, or service unit text.

## Secrets

Treat any credential pasted into a conversation as a disposable test
credential. Install it only through a non-echoing protected input path and
rotate it immediately after the test; production should use restricted
project/service credentials supplied out of band.

The code resolves secrets in this order:

1. a named file inside systemd's `$CREDENTIALS_DIRECTORY`;
2. an explicitly configured protected file;
3. an explicitly named environment variable (development fallback only).

For production, use a root-owned systemd drop-in whose values are local paths,
not secret text:

```ini
[Service]
LoadCredential=slack_bot_token:/root/.secrets/blackbox/slack-bot-token
LoadCredential=slack_app_token:/root/.secrets/blackbox/slack-app-token
LoadCredential=slack_webhook_url:/root/.secrets/blackbox/slack-webhook-url
LoadCredential=openai_api_key:/root/.secrets/blackbox/openai-api-key
LoadCredential=dkg_auth_token:/home/ubuntu/.dkg/auth.token
```

The combined acquisition worker needs read-only DKG access for graph dedupe,
the Slack bot token for reports, and the OpenAI credential when discovery is
enabled. The listener needs only the Slack bot/app tokens. The paid worker
needs DKG access and, when auto-approval is explicitly enabled, the Slack bot
token for its mandatory informational JSON report. Before production rollout
these should be split into separate Unix users/credential sets; the checked-in
units are a minimal single-user staging baseline.

## Optional AI discovery

AI discovery is disabled by default and is not used for bulk parsing,
canonicalization, deduplication, source enablement, approval, or publishing. It
makes at most the configured number of OpenAI Responses API requests, uses the
hosted `web_search` tool, requires strict JSON-schema output, stores proposals
for human/legal review, and records calls/tokens/estimated cost.

The model name and price estimates are configuration, not constants. Before
enabling, update the estimates from current project pricing; zero estimates are
an explicit rollout blocker. The request uses `store: false`, low reasoning,
an output-token cap, domain filters, and no access to local shell or secrets
other than its own API credential. Current API shapes are based on the official
[Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs)
and [web search](https://developers.openai.com/api/docs/guides/tools-web-search)
guides.

## Publisher-node rollout phases

No production scheduling should be enabled in the first transfer.

1. **Read-only inventory:** confirm the exact deployed publisher scripts, DKG
   version, context graph ID/on-chain ID, registry paths, active publisher
   process, disk, and Python dependencies. Do not restart or alter DKG. Review
   the deployed `publish.mjs`, confirm its incremental VM-only completion
   support, and pin its exact SHA-256, node/ledger versions, network, on-chain
   graph ID, and public/private access policy in config; paid mode fails closed
   without those confirmations.
2. **Offline install:** copy publisher-only files and run the Python tests plus
   `node test.mjs` on the node. Keep every external capability disabled.
3. **Shadow acquisition:** enable only `blackbox-acquire.timer`; run seven days
   with Slack and publishing disabled. Confirm cursors, locks, volume, disk,
   schema stability, removals, and repeated-run dedupe.
4. **Slack rehearsal:** install Slack credentials with `chat:write` and
   `files:write`, enable the listener, and test the attached-JSON approval card
   against dry-run bundles. Keep publishing and the publish-trigger path
   disabled.
5. **One smoke asset:** explicitly enable the publisher and approve exactly one
   1,000-observation asset after current wallet/cost review. Set
   `publisher.swm_restore_mode: skip`, verify the confirmed VM assertion, and
   verify that the registry records `swmRestoreSkippedAt` without a post-VM
   SWM restore.
6. **One 10k bundle:** publish ten assets sequentially, test restart/resume and
   cap accounting, then review quality and costs.
7. **Gradual recurring rollout:** enable the publisher timer below the 100k/day
   ceiling and increase only after measured review.

The three-hour acquisition timer and ten-minute approved-queue timer use
non-blocking per-worker singleton locks, so a second copy of either worker is
never started. Candidate graph synchronization and paid VM publication also
share a blocking `dkg-workload` lock. Source ingestion may continue in
parallel, but graph queries wait for publication (and publication waits for an
active graph query) instead of saturating the same local Blazegraph process.

## Inputs needed before Phase 2

Install these through secure channels, not chat:

- Slack bot token and Socket Mode app token;
- workspace ID, private review channel ID, and approver user IDs;
- a newly rotated restricted OpenAI service credential (only if discovery is
  enabled);
- exact publisher-node DKG version, context graph ID/on-chain ID, and protected
  auth-token path/credential;
- confirmation that the existing curated/private graph and 12-epoch retention
  remain the intended policy.

No TRAC or ETH budget number is required to stage work. The live preflight must
show balances before any approved publish, and insufficient funds leave the
bundle queued without a blind retry.
