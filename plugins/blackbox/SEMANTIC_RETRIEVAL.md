# Semantic retrieval from the local Context Graph

The semantic path retrieves behaviorally relevant graph entities, reads their
current confirmed VM evidence, and asks a local model for an advisory. It runs
even when the deterministic detectors find no regex match. It does not replace
exact IOC, package, secret, or local file protection.

This is opt-in. Similarity never blocks an action. The model must cite an exact
quote from the input and an exact quote from a retrieved entity; positive
advisories additionally require a valid entity ID and confidence of at least
0.9. Those checks establish traceability, not proof that the model is correct.
Advisories use the existing `source="llm"`, `confirmed=false`, never-share path.
They remain local and are recorded as `semantic_review` events.

## Set up

1. Use a local DKG build with the generic entity discovery API and bounded query
   API. Configure its local embedding provider and model digest as described in
   the DKG entity-discovery documentation. No external inference fallback exists.
2. Select the Blackbox profile that should use it. Configure the direct graph
   backend (`detection_backend: dkg`) and its local node connection. The initial
   direct backend supports the verified graph; a separately configured community
   graph requires the existing community migration and is rejected explicitly.
3. Run `hermes blackbox semantic index`. This reads the local graph and creates a
   derived DKG entity index, not a second sync. It needs the node operator token.
   Save the returned `indexId` in this profile's configuration.
4. Enable semantic review explicitly, naming an already installed local model:

```yaml
plugins:
  entries:
    blackbox:
      detection_backend: dkg
      semantic:
        enabled: true
        index_id: "<returned indexId>"
        model: qwen3:8b
        model_url: http://127.0.0.1:11434
        max_candidates: 5
        budget_s: 12
```

The embedding model and reviewer are separate choices. The bundled smoke uses
`nomic-embed-text` for retrieval and `qwen3:8b` for review. Neither a model nor a
profile is installed or attached automatically. Model quality must be evaluated
on your own cases before enabling this across users.

Rerun `hermes blackbox semantic index --restart` after new graph content arrives.
Unchanged documents reuse their embeddings. DKG checks current graph permissions
and current indexed text at search time, discarding stale/deleted candidates.
New entities become discoverable after a rescan. Index completion means a local
scan completed, never full network coverage.

## Retrieval and decision flow

- The index selects the names and descriptions of `InjectionSignal` and
  `SkillSignal` entities in VM. It excludes the bulk IOC population. Entity IDs,
  graph facts, and provenance remain in the DKG; no rules JSON is exported.
- Current user input, tool output, and proposed tool arguments retain their
  origin labels. System/developer instructions and earlier assistant turns are
  excluded from the request hook's scan.
- Secret values are redacted before sending text to local embeddings or local
  review. Oversized input produces an explicit unavailable result instead of a
  silently shortened security judgment.
- DKG search returns candidate entity/source-graph pairs. Blackbox uses bounded
  SPARQL `VALUES` to hydrate those exact pairs, verifies confirmed owner-pinned
  VM provenance, applies correction/suppression records and curator withdrawals,
  then builds evidence. Description-only entities do not require a regex.
- The reviewer sees the input origin, input text, and candidate evidence. Vector
  scores stay outside its prompt: retrieval similarity is not threat confidence.
  Exact quoted evidence and entity IDs are checked in code before an advisory.
- Review runs in a profile-bound background thread, with at most one batch per
  profile and two total. Busy, oversized, timed-out, malformed, absent-index, and
  authority-unavailable paths are recorded distinctly; they are not clean
  negative detections. A batch accepts at most four input sources.

The current client gives retrieval at most five seconds within the shared review
budget; the DKG search request itself has a two-second deadline. The reviewer
uses an explicit 8,192-token context and a conservative 7,000-byte request ceiling.
This prevents an inference-server default from reserving a huge context for a
small classification request, or silently truncating the evidence. Large inputs
are reported unavailable. Cold model loading can also exceed the budget; keep
models warm when evaluating latency and record cold and warm behavior separately.

`no-candidates` means this local index found no usable current evidence.
`no-finding` means the reviewer found no supported behavior in the retrieved
subset. Neither means the whole graph, every attack, or every agent action was
checked. Source trust, relation facts, and final enforcement remain separate
from semantic proximity.

## Local tests and smoke

Run focused tests through the repository runner:

```sh
scripts/run_tests.sh -j 2 tests/plugins/test_blackbox_semantic.py \
  tests/plugins/test_blackbox_direct_graph.py \
  tests/plugins/test_blackbox_direct_graph_regressions.py \
  tests/plugins/test_blackbox_architecture.py --file-retries 0
```

With the two models already installed locally:

```sh
.venv/bin/python scripts/blackbox_semantic_smoke.py \
  --dkg-root /path/to/dkg-checkout --report /path/to/smoke-report.json
```

The smoke starts an ephemeral local DKG route fixture with real RDF queries,
SQLite vectors and real local embeddings/review. It checks paraphrases, malicious
skills, benign requests, and quoted security examples; writes timings and model
identities; confirms there is no exported rules file; and stops its own fixture.
It makes no chain calls, executes no proposed command, reads no credential values,
and is not a full interactive-agent or production-graph benchmark.
