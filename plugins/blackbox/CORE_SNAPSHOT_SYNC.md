# Core snapshot sync

This path uses the new DKG public snapshot capability to avoid repeating asset
chain reads on every install. It requires the companion DKG changes on the
selected core nodes and the local node, with exact-batch streaming enabled.
The new persistent-core defaults and automatic source selection require the
companion DKG update.

**Compatibility and rollout:** the installer still pins DKG 10.0.25. Ordinary
fresh installs retain community protection and `legacy-cache` sync. Upgrades
preserve the saved graph, reader and trust settings. Installing this Blackbox
change before the companion DKG release is therefore supported for those
ordinary profiles; it does not enable the new snapshot path on an older daemon.

The direct reader does not yet preserve community retention, first-seen reader
budgets and curator semantics. Setup refuses to select it while community reads
are enabled, including when report sharing is off. It never empties
`community_graph_id` to make a faster path pass. A DKG/core rollout alone is not
enough to change the default for community-enabled installations.

For a new profile whose owner has already explicitly chosen public-only reads,
automatic selection is limited to the shipped Base mainnet graph. It requires
all of the following read-only evidence from the configured loopback daemon:

- `DKG_Core_chain_cache` snapshot-source support;
- a matching completed job, finished within the last 60 seconds, with positive,
  fully committed current coverage and authenticated selected cache sources;
- bounded-query version 1 with explicit `core-cache` support.

Setup never starts a job to obtain that evidence. An idle, old, unreachable or
unproven daemon keeps ordinary sync, as does stale or mismatched evidence.
Existing profiles are not automatically migrated when those capabilities
later appear. Snapshot sync revalidates the configured source policy and full
coverage at runtime; installation-time evidence is not a permanent availability
promise. There is no silent downgrade of an explicitly selected trust mode.

To use automatic registered sources explicitly, the local daemon and eligible
cores need the companion DKG update. Publish that update and verify its package
integrity before changing `setup.DKG_PACKAGE` / `DKG_INTEGRITY`. An older daemon
returns `DKG_UPGRADE_REQUIRED` before an automatic transfer. These compatibility
checks do not establish a particular sync time or a fleet-wide warm cache.

The user-facing option is **Lower RPC usage by using the DKG Core chain cache**.
Enable `DKG_Core_chain_cache: true` in the local DKG node's `config.json`.
Upgraded official cores serve the cache by default; a core operator can disable
it with `false`. Edges opt in. Mainnet accepts registrations from the locally
shipped official mainnet deployments; testnet uses the identical implementation
with its own official registries. Private deployments and the other environment
never establish trust. A peer cannot provide an RPC URL or registry contract.

For an explicitly public-only Blackbox profile with compatible DKG and cores, use:

```sh
blackbox setup --dkg-core-chain-cache --snapshot-graph-id REGISTERED_GRAPH_NUMERIC_ID
```

Or configure `plugins.entries.blackbox.snapshot_sync` in `config.yaml`:

```yaml
on_chain_id: "REGISTERED_GRAPH_NUMERIC_ID"
DKG_Core_chain_cache: true
mode: core-cache
```

Set `detection_backend: dkg` on the Blackbox entry. Setting the cache option to
`false` disables this automatic snapshot profile and keeps ordinary sync;
conflicting explicit trust settings are refused. Existing explicit peer scopes
and the legacy `--registered-cores` Base-only policy remain supported without
an automatic trust-scope migration.

Eligible new public-only Base profiles use graph registration `14`. A custom graph or
another data network needs its own registration ID; the option never maps
Base graph 14 onto another chain. Existing profiles are retained.

The selected core signs a fresh, peer- and graph-bound challenge. The Edge
checks its operational key and active ShardingTable registration on that core's
registration deployment. The proof separately binds the requested data chain
and deployment. At most 16 candidates are probed, four at a time, and up to four
proven cache suppliers are pinned. Eligibility is not a promise that every core
is reachable or upgraded; configured official relays and discovered peers are
bounded discovery hints, not trust evidence.

The cache supplies **DKG graph registration, asset inventory, versions and
content roots recorded on-chain**. It does not supply arbitrary blockchain
history or replace transaction RPC. A cache core can read these public records
for another official chain without storing the graph's RDF. DKG content comes
from peers admitted to the Edge's data network, and its identity and content
roots are checked against the pinned inventory. Cross-chain cache admission
allows only the two public cache protocols, never private graphs, publishing,
or ordinary network traffic. Content transfer deadlines and verification stay
unchanged. Initial and final inventories must agree before current coverage
is reported.

`chainCacheRpcUsage` in the completed job records physical registry requests
by chain and RPC method. It excludes the node's unrelated/background RPC,
which must be measured separately. Registration checks remain per candidate;
per-asset chain reads are delegated to the cache core. Provider billing depends
on method weights and plan, so request counts are not a monetary estimate.

Existing profiles retain their current sync behavior. Setup can now write the
explicit peer scope and install the pinned daemon in one command:

```sh
blackbox setup --snapshot-graph-id REGISTERED_GRAPH_NUMERIC_ID --trusted-core-peer OPERATOR_CONFIGURED_CORE_PEER_ID
```

Repeat `--trusted-core-peer` for up to four explicitly selected cores. Setup
preserves other settings and refuses replacing a different existing snapshot
trust scope. The serving cores must host this graph and support public snapshot
recovery; discovery advertisements never become trust configuration. The
registered default mainnet graph has numeric ID `14`, but custom graphs and
networks require their own registration IDs. A production core rollout remains
necessary to use this path. Preserving the community read model is a separate
prerequisite for any rollout to ordinary new installations.

Alternatively, after upgrading an isolated local node, configure that profile's
`config.yaml`:

```yaml
plugins:
  entries:
    blackbox:
      detection_backend: dkg
      snapshot_sync:
        on_chain_id: "REGISTERED_GRAPH_NUMERIC_ID"
        trusted_core_peers:
          - "OPERATOR_CONFIGURED_CORE_PEER_ID"
        mode: core-cache
```

Use the numeric registration ID of the configured `context_graph_id`, and one
to four explicit trusted peer identities. Do not populate trust from discovery
advertisements. `core-cache` is the default within this configuration; setting
`mode: rpc-only` gets the inventory and roots independently from the local
node's configured RPC. Content still comes from configured peers in both modes.
There is no silent mode fallback or global configuration change.

Core-cache trusts those cores' chain statements, while DKG still checks content
roots and graph/asset identity. It is not an independent blockchain proof.
Imported data and query results retain that distinction. A graph imported with
core trust cannot subsequently be described as RPC-only by changing one flag:
use a separate fresh DKG profile/store for independent-only operation.

`blackbox sync --wait --require-rules` starts or observes one matching DKG job,
lets the DKG job establish its own public subscription without a second legacy
catch-up, checks usable local rules through direct queries, and waits for a fresh final
inventory comparison. A failed job remains failed even if some rules arrived.
A changing graph is reported as partial. Without `--wait`, the command starts or
reattaches to the job and reports that it is still running. Interrupting the
observer does not cancel the node's job. Starting a different graph/mode while
one job runs is refused.

Newer daemons may add their selected `transport` (`exact` or `bulk`) to the job
request. The client accepts that known addition when starting or reattaching to
a matching job, then pins the complete returned request and job ID. Any later
change, an unknown field, or a different graph, registration ID, trust mode or
trusted peer list is refused. Daemons that omit transport remain compatible.

The managed snapshot profile disables competing connection-time and periodic
VM recovery. This is intended for a dedicated managed node. With an externally
managed shared node, the operator must arrange that isolation explicitly.
No network sync is started by the detection read client; every decision uses
bounded local DKG queries that explicitly acknowledge the selected trust mode.
No threat-rule JSON export is generated. `authoritative-sync.json` remains a
small operational status file, not a rule database.

The daemon selects the transport under its own configuration: the exact path
uses ten-asset batches, while the experimental bulk path requires the companion
DKG implementation and its explicit opt-in. This client compatibility change
does not enable bulk mode, parallel core downloads or persistent job resumption,
and does not claim a five-minute full-graph result.

## Local validation

The focused tests cover profile A → B → A isolation, explicit mode propagation,
one HTTP job, incomplete/failed outcomes, and existing native/direct/semantic
behavior. `scripts/blackbox_core_cache_probe.py` is an opt-in consumer smoke
against an already prepared isolated local DKG node and public fixture graph.
It uses a temporary profile, starts the real snapshot job, reads real local
rules, checks a confirmed IOC plus a benign negative, and checks that no
`ruleset.json` was created. It never visits the IOC or executes a command.

The local integration fixture used 12 on-chain assets, separate DKG core and
receiver stores, actual libp2p streaming and the daemon's snapshot/bounded-query
route handlers. Receiver per-asset chain methods were set to fail if called.
This is a functional integration fixture, not the 564-asset mainnet benchmark.
