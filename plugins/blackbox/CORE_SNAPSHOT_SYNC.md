# Core snapshot sync

This path uses the new DKG public snapshot capability to avoid repeating asset
chain reads on every install. It requires the companion DKG changes on the
selected core nodes and the local node, with exact-batch streaming enabled.
Published DKG 10.0.23 alone does not provide this endpoint.

Existing profiles retain their current sync behavior. After upgrading an
isolated local node, configure that profile's `config.yaml`:

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
