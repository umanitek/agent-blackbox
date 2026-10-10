# Agent Blackbox — architecture map

This is the map of `plugins/blackbox/`. It must match the disk: the guard
tests in `tests/plugins/test_blackbox_architecture.py` read this file and fail
when a package is missing from it, when a listed path does not exist, or when
code depends on a package its row does not allow. The commit that adds, moves
or re-wires a module updates this file.

Blackbox follows Foreman's structure standard (FMN-V12-STRUCTURE): one module
per feature, one kernel for shared infrastructure, dependencies pointing one
way, and every package used only through its public entry (`__init__.py`).

## The four flows

1. **SYNC (down)** — `sync` keeps the local DKG node's copy of Umanitek's
   verified threat graph current; `ruleset` compiles what the node holds into
   O(1) lookups.
2. **CHECK (hot path)** — `guard` intercepts every tool call and model request;
   `detection` matches it against the ruleset (pure, microseconds, fail-open).
3. **RECORD (local)** — `audit` keeps redacted, size-capped logs on this
   machine; `dashboard` renders them.
4. **REPORT (up)** — `community` decides what may leave the machine, builds
   privacy-safe reports, and reads what other nodes reported.

## Modules

| Module | Owns | Entry | May depend on |
|---|---|---|---|
| `kernel` | constants + ontology IRIs, config and settings, the DKG HTTP client, threat identifiers, RDF terms, SPARQL escaping, YAML files, terminal-safe display, this node's identity, secret redaction, signed statements and the pinned root keys (the `kernel/signing/` sub-package: the envelope, a statement's identity (what was signed, never its text) and its canonical text, the key manifest, statement order, the two authorities and which statement kinds each may sign in which graph, trust anchors pinned per network and per community graph), the cursor pager every statement read uses, the reporter key, the curator-side node routes (`node_routes`), operator alarms (the `kernel/health/` sub-package, with the community authority's own alarms), and the vendored Public Suffix List (the `kernel/public_suffix/` sub-package: registrable domains and shared-hosting suffixes) | `kernel/__init__.py` (each kernel module is public; `kernel/signing` through its `__init__`) | — |
| `attach` | finding Hermes homes and OpenClaw workspaces, copying the plugin in, enabling/disabling it; `blackbox attach` / `detach` | `attach/__init__.py` | `kernel` |
| `detection` | the pure detectors, action parsing, content scanners, escalation shapes, OSV lookups, the LLM reviewer; `blackbox setup-llm` | `detection/__init__.py` | `kernel`, `attach` |
| `audit` | local findings / activity logs, redaction, the private audit record, the outbound share ledger + cooldown + daily cap | `audit/__init__.py` | `kernel` |
| `community` | the outbound share gate and send, the validated report schema, report / dispute / retraction quads, the weekly sighting digest (tally + publish), reading + verifying + aggregating community reports, statements about reports and how readers honour them (the `community/statements/` sub-package: retractions, disputes, the per-author budget, pending tombstones, curator statements including the Phase 2 stage attestation readers prefer (R3-attest), and the verified curator view), what a reader does to know whom to trust (the `community/trust/` sub-package: reading each authority's manifest and statements from its graph, which manifest a reader acts on, combining the verified and the community authority under the most-restrictive-wins rule, looking trust statements up by identifier in the open community graph, the reader's own verified trust store `community_trust.json`, the trust layer as one read model for the dashboard and `blackbox status`, and the reader's daily cap on raising statements), graph-wide statistics for the dashboard, retrying refused shares (`share_retry`), the community pulse (`pulse` — "did the graph change?" between refreshes) keep-alive (the `community/keep_alive/` sub-package: epoch naming, the live-reports memory, the publish step — each author re-publishes its own reports so they outlive shared-memory expiry) the shadow phase (the `community/shadow/` sub-package — R15: the MONITOR clamp and the §12 metrics log), the sharing consent record (`consent` — R13: opt-in, bound to the shipped reporter terms, checked by the gate), the allowlist (the `community/allowlist/` sub-package: PSL-keyed allowlist and warninglist tables with a home override, the inverted look-alike verdict, curator-private canaries) and reputation (the `community/reputation/` sub-package: bands, Beta reputation with forgetting, hardened novelty credit, partner grants and sponsorship, peer-id / overlap collapse and the ring detector, graduation → counted-author payloads, the curator-private salted ledger); `blackbox report` (the `community/report_cli/` sub-package: filing, disputes/retractions, export / key restore / identity erasure), the confirmed pool (threats with a standing, evidenced community confirmation, as a view) and the export bundle a receiver checks offline from the community root (the `community/pool/` sub-package) | `community/__init__.py` | `kernel`, `audit`, `detection` (the closed report vocabularies) |
| `ruleset` | action-scoped direct DKG reads (`ruleset/direct`), SPARQL reads of the verified graph (each confirmed asset read once as plain triples and cached — the `ruleset/partitions/` sub-package, KI-288), compiling rows into the `Ruleset`, disk + memory cache, cross-process refresh lock, the curator overlay (revocations withdraw verified rules), merging the community tier, the pulse that re-applies it between refreshes | `ruleset/__init__.py` | `kernel`, `community`, `killlist`, `detection` |
| `sync` | the local node's catch-up of the verified graph, the managed DKG node process and its sync profile (native for Umanitek's default graph on DKG 10.0.21+, steady otherwise), the native route that observes the node's own recovery (`native`), the node's process limits (`process_limits`, stdlib-only: the installer's fingerprint script loads it by path), which running process is the node (`node_process`; never a stale daemon.pid), sync state + progress bookmarks; `blackbox sync` | `sync/__init__.py` | `kernel`, `ruleset`, `community` |
| `guard` | the five Hermes hooks, filtering + recording + sharing findings, per-session context, background OSV / LLM / auto-attach work, the kill-list check on every tool call | `guard/__init__.py` | `kernel`, `attach`, `audit`, `community`, `detection`, `ruleset`, `killlist`, `overrides` |
| `overrides` | the operator's local release valve (Refine R7b): `blackbox rules unblock` demotes a verified rule BLOCK → FLAG on this machine only — audited, never shared, reduction-only | `overrides/__init__.py` | `kernel` |
| `killlist` | the curators' kill list (Refine R14): the signed versioned statement, blast-radius gates (wide kills need the root; popular targets the root + a 24 h hold; ≤20 new disables per version), the last-good list on disk, and the hook-side match that refuses or warns — never uninstalls | `killlist/__init__.py` | `kernel`, `detection` |
| `chat` | `blackbox chat` — the managed Blackbox assistant profile | `chat/__init__.py` | `kernel`, `attach` |
| `dashboard` | the local web UI (FastAPI, loopback-only) and its static assets, including the trust panel (`GET /api/trust`: who curates, who is trusted, what is confirmed); `blackbox dashboard` | `dashboard/__init__.py` | `kernel`, `attach`, `audit`, `community`, `ruleset`, `sync` |
| `curate` | the curator node's tooling (Refine R6): the delta-view queue and lanes, the evidence dossier + checklist, two-key proposals by private message, content-bound consent, the acting authority (verified or community) every verb routes by, publishing with a read-back (the `curate/publishing/` sub-package: sequence numbers, quorum check, consent, the write, and published means readable), keeping the authority's published statements alive and the curator heartbeat (the `curate/upkeep/` sub-package), crediting reporters from published verdicts and gathering the novelty facts (the `curate/ladder/` sub-package), the confirmed pool as this node verifies it, its export bundle and the offline `verify-bundle` check (the `curate/handoff/` sub-package), the curator service (the `curate/service/` sub-package: the automation policy as one decision table, the standing consent bound to its text, this node's own advisory and ledger checks, the service's own daily limit, and the beat — heartbeat, read, co-sign, first signatures, credit, ladder, keep-alive — run by `blackbox curate run`), promotion into the verified tier, intake webhook, saved node-UI views; `blackbox curate` | `curate/__init__.py` | `kernel`, `audit`, `community`, `detection` (OSV for the dossier), `killlist` |

## Root (the composition layer — Hermes' plugin layout, kept thin)

| File | Role |
|---|---|
| `plugin.yaml` | Hermes plugin manifest (hooks list, eager `backend` load). |
| `__init__.py` | `register(ctx)`: wires the `guard` hooks and the `blackbox` CLI. May depend on `cli`, `guard`, `kernel`. |
| `cli.py` | The `blackbox` argument parser and dispatch, plus `status`. May depend on every module. |
| `README.md` | Operator-facing plugin readme. |

## Rules

- **One way.** A module depends only on the modules in its row. The kernel
  depends on nothing in the plugin. No cycles.
- **Through the entry.** Code outside a package imports the package, or a
  name / submodule listed in its `__all__` — never its internals
  (`from ..community.reader import …` is a violation). Kernel modules are all
  public. Tests may reach internals; plugin code may not.
- **Size.** A file over ~400 lines or a folder over 15 files is split. Files
  and functions (over ~50 lines) that were already over when the guard landed
  are listed in `tests/plugins/architecture_baseline.json` and may only shrink
  — lower the number in the same commit that shrinks them.
- **Lazy imports count.** Every relative import, including ones inside
  functions, must resolve (a broken lazy import fails silently behind the
  fail-open hooks — FIX-0017).
- **Moves are refactors.** Moving code between modules is its own commit with
  the suite green, never mixed with behaviour changes.

## Installed layout

`attach` copies this whole folder into each agent home
(`~/.hermes/plugins/blackbox/`) minus caches and tests, plus the OpenClaw JS
bridge bundled under `_openclaw/` (built at install time, not in the repo).
