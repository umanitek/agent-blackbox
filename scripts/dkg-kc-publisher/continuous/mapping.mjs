/** Append-only source-observation mapping for incremental Blackbox bundles. */
import { createHash } from 'node:crypto';

const NS = 'urn:blackbox:';
const P = `${NS}p:`;
const RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';
const SCHEMA = 'http://schema.org/';

const escapeLiteral = (value) => String(value)
  .replace(/\\/g, '\\\\')
  .replace(/"/g, '\\"')
  .replace(/\n/g, '\\n')
  .replace(/\r/g, '\\r')
  .replace(/\t/g, '\\t');
const literal = (value) => `"${escapeLiteral(value)}"`;
const hash = (value) => createHash('sha256').update(String(value), 'utf8').digest('hex');
const iri = (value, field) => {
  const text = String(value ?? '');
  if (!/^[a-z][a-z0-9+.-]*:/i.test(text) || text.startsWith('_:')) {
    throw new Error(`${field} must be an absolute IRI`);
  }
  return text;
};

export function extractRecords(json) {
  if (Array.isArray(json)) return json;
  if (Array.isArray(json?.records)) return json.records;
  throw new Error('continuous source must be an array or {records:[...]}');
}

export function recordKey(record) {
  if (record?.type !== 'source_observation') throw new Error('continuous mapping accepts only source_observation records');
  const id = iri(record.observationId, 'observationId');
  if (!id.startsWith(`${NS}observation:`)) throw new Error('observationId must use the Blackbox observation namespace');
  return id;
}

export function recordQuads(record) {
  const subject = recordKey(record);
  const canonicalId = iri(record.canonicalId, 'canonicalId');
  // Keep the fields used by graph filtering and attribution directly queryable.
  // Less frequently queried provenance remains losslessly available in one
  // deterministic literal so a 1,000-record asset stays below DKG's 4 MiB
  // inline storage-ACK staging limit even when public SWM hosts are sparse.
  const provenance = {
    originalValue: record.originalValue,
    upstreamId: record.upstreamId,
    sourceRevision: record.sourceRevision,
    confidence: record.confidence,
    severity: record.severity,
    licenseId: record.licenseId,
    licenseUrl: record.licenseUrl,
    attribution: record.attribution,
    evidence: record.evidence,
    parserVersion: record.parserVersion,
    fetchedAt: record.fetchedAt,
    contentSha256: record.contentSha256,
    recordDigest: hash(JSON.stringify(record)),
  };
  const quads = [];
  const add = (predicate, object) => {
    if (object !== undefined && object !== null && object !== '') {
      quads.push({ subject, predicate, object, graph: '' });
    }
  };
  const addLiteral = (predicate, value) => add(predicate, literal(value));

  add(RDF_TYPE, `${NS}SourceObservation`);
  add(P + 'observes', canonicalId);
  addLiteral(P + 'canonicalType', record.canonicalType);
  addLiteral(P + 'normalizedValue', record.normalizedValue);
  addLiteral(P + 'sourceId', record.sourceId);
  addLiteral(P + 'category', record.category);
  addLiteral(P + 'lifecycleStatus', record.lifecycleStatus);
  for (const reference of record.references ?? []) addLiteral(SCHEMA + 'citation', reference);
  addLiteral(P + 'provenanceJson', JSON.stringify(provenance));
  return quads;
}
