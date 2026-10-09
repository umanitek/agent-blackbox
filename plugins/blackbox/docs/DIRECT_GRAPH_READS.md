# Direct local graph reads

Implementation status: opt-in consumer backend. It needs the companion DKG
bounded-query capability; published DKG 10.0.23 does not provide that API.
Do not enable this against an older daemon. This change is the direct-read
part of [the five-minute sync plan](https://github.com/OriginTrail/dkgv10-spec/pull/196),
not a claim that network synchronization now takes five minutes.

## Behavior

With `detection_backend: dkg`, each agent decision reads the local DKG store:

- Exact indicators and dependency candidates select relevant verified entities.
- Curated injection, escalation, file-access and skill patterns are read as a
  bounded set and checked locally by the existing detector. Overflow is an
  unavailable check, not a truncated clean result.
- Confirmed, owner-pinned VM partitions supply public rules. Tentative assets,
  unrelated graphs and community data cannot acquire public blocking authority.
- Signed curator revocations and the independently persisted last-good kill list
  retain their existing semantics. Revocation-read failures mark the check degraded.
- The existing block/flag policy remains: IOCs, vulnerabilities and historical
  skill findings do not acquire automatic blocking merely by using this backend.

No full `ruleset.json` export is loaded, written, periodically refreshed or
required for detection. Per-asset export caches are not used. The small selected
rule objects and compiled patterns live only for that decision. Operational
state, audit records, local overrides and signed trust/kill-list records remain;
removing the rules export does not mean deleting those independent records.

Queries go only to a literal loopback address (or `localhost`, resolved to
loopback without DNS). Proxies, redirects and remote node addresses are refused.
Full commands, prompt text, file content and credentials stay in the process;
only extracted indicator/package candidates go to the local node. That client
cannot start subscriptions, publish data or request another network sync.

The shared decision budget is 2.5 seconds, with at most 2 seconds per DKG query,
64 extracted candidates, 8,192 returned rows across reads, and 2,048 expanded
compiler rows. Responses are bounded to 1 MiB. These are safety ceilings, not
measured latency targets. Pattern-tier growth beyond this bound requires an
indexed rule-selection capability rather than raising the bounds indefinitely.

Failures have explicit codes (`DKG_UPGRADE_REQUIRED`, `QUERY_ACCESS_DENIED`,
`QUERY_DEADLINE_EXCEEDED`, `QUERY_RESULT_TOO_LARGE`, etc.). The hook records
`protection_degraded`; a failed check is not logged as a successful graph read.
The existing host fail-open policy remains, while independent local secret and
protected-path checks still run. Successful results cover only the locally
confirmed subset; they do not establish full network coverage or global safety.

## Migration and compatibility

Existing installations keep `legacy-cache` until explicitly switched. No files
are deleted, no profiles are auto-attached, and no daemon is upgraded or restarted
by this change. After installing a DKG build with `/api/query/bounded` version 1,
set this in the **isolated profile's** existing configuration:

```yaml
plugins:
  entries:
    blackbox:
      detection_backend: dkg
      community_graph_id: ""
      auto_attach: false
```

Keep the profile's existing local DKG address, graph and DKG home. Run normal
Blackbox sync/status only against that owned profile. Default-graph sync uses
native recovery and validates a bounded sample of usable rules; it no longer
compiles the full graph. Its sample count is explicitly a lower bound, not the
old exported-rules total. Graph status and paged browsing report confirmed
entity counts, which can differ from compiled usable-rule counts.

The first rollout is the public consumer path. Community-enabled configurations
are explicitly refused with `DIRECT_COMMUNITY_MIGRATION_REQUIRED`: the current
community implementation has persisted first-seen budgets, retained threats and
curator workflows tied to its compiled generation. Porting that read model must
preserve those rules; silently dropping it or promoting SWM reports is unsafe.
It continues to work through `legacy-cache`. Whole-graph curator enumeration
also remains a legacy workflow. Custom graph sync drivers remain on the existing
backend; direct detection reads can use confirmed wallet-pinned VM partitions.
Legacy root-graph/proof-only layouts must be migrated before cutover.

Source observations must use the canonical `normalizedValue` produced by the
current publisher for exact indexed matching. This is not a compatibility
promise for arbitrary noncanonical historical RDF literals. A legacy corpus
should pass a normalization/parity audit before migration.

Rollback is explicit: select `legacy-cache` and refresh it from verified local
data. A preserved export may be stale and should not be treated as a current
snapshot. Direct mode never silently falls back to it.

## Validation and remaining release gates

Tests exercise all six detection categories, confirmed/tentative separation,
corrections, immediate graph changes, local HTTP transport, unavailable reads,
A → B → A profile switching, bounded browsing/readiness and an absent or invalid
legacy export. Existing detection, native sync, cache and curator tests remain
applicable. DKG tests exercise real query scoping, typed authorization failures,
overflow witnesses and cancellation.

Before changing the default, run the paired source builds and an isolated
representative graph benchmark. Measure per-decision p50/p95/p99 latency,
concurrent decisions, startup to usable protection and graph coverage separately.
Verify canonical IOC values and category parity on the actual corpus. The plan's
100 ms p95 and five-minute full-sync goals remain unmeasured by unit tests.
