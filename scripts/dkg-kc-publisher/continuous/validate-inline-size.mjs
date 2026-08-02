#!/usr/bin/env node
/** Fail closed when a prepared asset cannot use DKG's inline storage-ACK path. */
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const MAX_STAGING_BYTES = 4 * 1024 * 1024;
const MAX_KA_NUMBER = (1n << 96n) - 1n;
const argv = process.argv.slice(2);

function option(name) {
  const index = argv.indexOf(`--${name}`);
  if (index === -1 || !argv[index + 1]) throw new Error(`missing --${name}`);
  return argv[index + 1];
}

function canonicalRdfSetQuads(quads) {
  const unique = new Map();
  for (const quad of quads) {
    const normalized = {
      subject: String(quad.subject),
      predicate: String(quad.predicate),
      object: String(quad.object),
      graph: '',
    };
    const key = JSON.stringify([
      normalized.subject, normalized.predicate, normalized.object, normalized.graph,
    ]);
    if (!unique.has(key)) unique.set(key, normalized);
  }
  return [...unique.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([, quad]) => quad);
}

const batchDir = resolve(option('batch-dir'));
const mappingPath = resolve(option('mapping'));
const contextGraphId = option('context-graph-id');
if (/[<>"\\\s]/.test(contextGraphId)) throw new Error('context graph id is not safe for an IRI');
const addressMatch = /^(0x[0-9a-fA-F]{40})(?:\/|$)/.exec(contextGraphId);
if (!addressMatch) {
  throw new Error('context graph id must begin with the canonical 0x agent address');
}
const worstCaseGraph = `did:dkg:context-graph:${contextGraphId}/_verifiable_memory/${addressMatch[1].toLowerCase()}/${MAX_KA_NUMBER}`;
const { extractRecords, recordQuads } = await import(pathToFileURL(mappingPath).href);
const manifest = JSON.parse(readFileSync(join(batchDir, 'manifest.json'), 'utf8'));
const batches = [];

for (const entry of manifest.batches ?? []) {
  const payload = JSON.parse(readFileSync(join(batchDir, entry.file), 'utf8'));
  const records = extractRecords(payload);
  const quads = canonicalRdfSetQuads(records.flatMap(recordQuads));
  const nquads = quads
    .map((quad) => `<${quad.subject}> <${quad.predicate}> ${quad.object.startsWith('"') ? quad.object : `<${quad.object}>`} <${worstCaseGraph}> .`)
    .join('\n');
  const bytes = Buffer.byteLength(nquads);
  if (bytes > MAX_STAGING_BYTES) {
    throw new Error(
      `${entry.name}: ${bytes} serialized N-Quads bytes exceed DKG's ${MAX_STAGING_BYTES}-byte inline storage-ACK limit`,
    );
  }
  batches.push({
    name: entry.name,
    records: records.length,
    triples: quads.length,
    bytes,
    headroom: MAX_STAGING_BYTES - bytes,
  });
}

if (batches.length === 0) throw new Error('batch manifest contains no assets');
console.log(JSON.stringify({
  version: 1,
  graphUriPolicy: 'vm-max-uint96-ka-number',
  maxStagingBytes: MAX_STAGING_BYTES,
  maxAssetBytes: Math.max(...batches.map((batch) => batch.bytes)),
  minHeadroomBytes: Math.min(...batches.map((batch) => batch.headroom)),
  assets: batches.length,
  batches,
}));
