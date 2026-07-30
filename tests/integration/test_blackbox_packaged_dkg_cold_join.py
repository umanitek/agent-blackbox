"""Exercise direct cold-join verification against an installed DKG package.

Run explicitly with a DKG CLI installation that contains OriginTrail/dkg#1885:

    BLACKBOX_TEST_DKG_ROOT=/path/to/dkg pytest -m integration \
      tests/integration/test_blackbox_packaged_dkg_cold_join.py

The test imports packaged JavaScript rather than DKG source files. This guards
the exact distribution assumed by Blackbox's direct-recovery version gate.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest


pytestmark = pytest.mark.integration

_AGENT_DIST = Path("node_modules/@origintrail-official/dkg-agent/dist")
_REQUIRED_CAPABILITY_MARKERS = (
    (Path("dkg-agent-crypto.js"), "requireCommittedNameHash"),
    (Path("dkg-agent-lifecycle.js"), "requireCommittedNameHash: true"),
    (
        Path("sync/requester/graph-scoped-materialization.js"),
        "verifyContextGraphBinding",
    ),
)


def _packaged_dkg_root() -> Path:
    configured = os.environ.get("BLACKBOX_TEST_DKG_ROOT")
    if not configured:
        pytest.skip("set BLACKBOX_TEST_DKG_ROOT to an installed DKG CLI root")
    root = Path(configured).expanduser().resolve()
    if not (root / "node_modules").is_dir():
        pytest.fail(f"BLACKBOX_TEST_DKG_ROOT has no node_modules directory: {root}")
    return root


def _require_cold_join_capability(root: Path) -> Path:
    dist = root / _AGENT_DIST
    for relative_path, marker in _REQUIRED_CAPABILITY_MARKERS:
        path = dist / relative_path
        if not path.is_file() or marker not in path.read_text(encoding="utf-8"):
            pytest.skip(
                "installed DKG package does not contain the chain-name-hash "
                f"cold-join capability: missing {marker!r} in {path}"
            )
    return dist


def test_packaged_dkg_cold_join_materializes_and_rejects_wrong_name_hash():
    root = _packaged_dkg_root()
    dist = _require_cold_join_capability(root)
    storage_entrypoint = (
        root
        / "node_modules"
        / "@origintrail-official"
        / "dkg-storage"
        / "dist"
        / "index.js"
    )
    package_json = dist.parent / "package.json"
    for path in (dist / "dkg-agent.js", storage_entrypoint, package_json):
        if not path.is_file():
            pytest.fail(f"installed DKG package is incomplete: {path}")

    script = f"""
import {{ createRequire }} from 'node:module';
import {{ pathToFileURL }} from 'node:url';

const agentDist = {json.dumps(str(dist))};
const storageEntrypoint = {json.dumps(str(storage_entrypoint))};
const packageJson = {json.dumps(str(package_json))};
const {{ DKGAgent }} = await import(pathToFileURL(`${{agentDist}}/dkg-agent.js`).href);
const {{
  authenticateVerifiedGraphScopedAsset,
  materializeVerifiedGraphScopedAsset,
}} = await import(
  pathToFileURL(`${{agentDist}}/sync/requester/graph-scoped-materialization.js`).href
);
const {{ OxigraphStore }} = await import(pathToFileURL(storageEntrypoint).href);
const require = createRequire(pathToFileURL(packageJson).href);
const {{ ethers }} = require('ethers');

const DKG = 'http://dkg.io/ontology/';
const contextGraphId = 'graph-scoped-sync-materialization';
const metaGraph = `did:dkg:context-graph:${{contextGraphId}}/_meta`;
const assertionGraph = `did:dkg:context-graph:${{contextGraphId}}/_verifiable_memory/0x1111111111111111111111111111111111111111/1`;
const ual = 'did:dkg:otp:2043/0x1111111111111111111111111111111111111111/1';
const ctx = {{ kind: 'system', id: 'blackbox-packaged-test', startedAt: 0 }};
const root = new Uint8Array(32);
root[31] = 2;

const dataQuad = {{
  subject: 'http://example.com/entity/v2',
  predicate: 'http://example.com/value',
  object: '"v2"',
  graph: assertionGraph,
}};
const metadataQuads = [
  ['contentScopeVersion', '"2"'],
  ['kaUal', ual],
  ['assertionVersion', '"2"'],
  ['assertionGraph', assertionGraph],
  ['contextGraph', `did:dkg:context-graph:${{contextGraphId}}`],
  ['merkleRoot', `"${{'2'.padStart(64, '0')}}"`],
  ['transactionHash', `"0x${{'2'.padStart(64, '0')}}"`],
].map(([predicate, object]) => ({{
  subject: ual,
  predicate: `${{DKG}}${{predicate}}`,
  object,
  graph: metaGraph,
}}));
const asset = {{
  contextGraphId,
  ual,
  assertionVersion: 2n,
  assertionGraph,
  metaGraph,
  dataQuads: [dataQuad],
  metadataQuads,
}};

const initialBindingMapSizes = [];
function strictBindingVerifier(chain) {{
  const agentLike = {{
    chain,
    subscribedContextGraphs: new Map(),
    wireIdToLocalCgId: new Map(),
    log: {{ info() {{}}, warn() {{}}, debug() {{}} }},
  }};
  initialBindingMapSizes.push([
    agentLike.subscribedContextGraphs.size,
    agentLike.wireIdToLocalCgId.size,
  ]);
  agentLike.isWireIdKeyedSubscription = DKGAgent.prototype.isWireIdKeyedSubscription;
  agentLike.raceChainPolicyRead = DKGAgent.prototype.raceChainPolicyRead;
  return (localId, onChainId) => DKGAgent.prototype.localCgMatchesOnChainSlot.call(
    agentLike,
    localId,
    onChainId.toString(),
    ctx,
    {{ requireCommittedNameHash: true }},
  );
}}

function chainWithNameHash(nameHash) {{
  return {{
    chainId: 'otp:2043',
    getLatestMerkleRoot: async () => root,
    getMerkleRootCount: async () => 2n,
    getKAContextGraphId: async () => 14n,
    getContextGraphNameHash: async () => nameHash,
    getLatestMerkleRootPublisher: async () => '0x2222222222222222222222222222222222222222',
    verifyKAUpdate: async () => ({{
      verified: true,
      onChainMerkleRoot: root,
      blockNumber: 123,
      txIndex: 4,
      merkleRootCount: 2n,
    }}),
  }};
}}

const matchingChain = chainWithNameHash(
  ethers.keccak256(ethers.toUtf8Bytes(contextGraphId)),
);
const authenticated = await authenticateVerifiedGraphScopedAsset(
  matchingChain,
  asset,
  strictBindingVerifier(matchingChain),
  new Date('2026-07-16T08:30:00.000Z'),
);
const store = new OxigraphStore();
const outcome = await materializeVerifiedGraphScopedAsset({{
  store,
  asset: authenticated.asset,
}});
const durable = await store.query(`ASK {{ GRAPH <${{assertionGraph}}> {{
  <${{dataQuad.subject}}> <${{dataQuad.predicate}}> "v2" .
}} }}`);

let mismatchCode = null;
const mismatchedChain = chainWithNameHash(
  ethers.keccak256(ethers.toUtf8Bytes('different-context-graph')),
);
try {{
  await authenticateVerifiedGraphScopedAsset(
    mismatchedChain,
    asset,
    strictBindingVerifier(mismatchedChain),
  );
}} catch (error) {{
  mismatchCode = error?.code ?? null;
}}

console.log(JSON.stringify({{
  mapsInitiallyEmpty: initialBindingMapSizes.every(
    ([subscriptions, wireBindings]) => subscriptions === 0 && wireBindings === 0,
  ),
  onChainContextGraphId: authenticated.onChainContextGraphId,
  outcome,
  durable: durable.type === 'boolean' && durable.value === true,
  mismatchCode,
}}));
"""
    completed = subprocess.run(
        ["node", "--input-type=module", "--eval", script],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout.strip().splitlines()[-1])
    assert result == {
        "mapsInitiallyEmpty": True,
        "onChainContextGraphId": "14",
        "outcome": "applied",
        "durable": True,
        "mismatchCode": "VM_CHAIN_CONTEXT_GRAPH_MISMATCH",
    }
