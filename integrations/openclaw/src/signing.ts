/**
 * Signed statements — the TypeScript mirror of `plugins/blackbox/kernel/signing/envelope.py`
 * (Refine R0b). ONE envelope format across runtimes (KI-171): the same domain
 * tag, the same canonical JSON (sorted keys, compact separators, non-ASCII
 * escaped as `\uXXXX` exactly like Python's `ensure_ascii`), the same Ed25519
 * signature over the same bytes. A reader in either runtime verifies a report
 * signed by the other; `tests/plugins/test_blackbox_signing_parity.py` proves it.
 *
 * What is signed: domain fields (`type`, `env`, `graph`, `chain`, `epoch`, `seq`,
 * `schema`, `v`) plus the flat str→str payload. Reporter statements leave chain /
 * epoch / sequence at their defaults. A signer is named by its raw public key (hex).
 *
 * Usage:
 *   const signer = new ReportSigner(privateKey, networkId, contextGraphId);   // the graph the community lives in
 *   quads.push(q(subject, BLACKBOX_SIGNED_STATEMENT_PRED, literal(signer.sign(REPORT_STATEMENT, payload))));
 */
import { createPublicKey, sign as cryptoSign, type KeyObject } from "node:crypto";

export const ENVELOPE_VERSION = 2;
export const MAX_ENVELOPE_CHARS = 4096;
export const REPORT_STATEMENT = "blackbox.report";
export const STATEMENT_SCHEMA_VERSION = 1;
const DOMAIN_TAG = "blackbox-signed-statement\n";

export interface StatementDomain {
  statementType: string;
  environment: string;
  graph: string;
  chain?: string;
  rootEpoch?: number;
  sequence?: number;
  schemaVersion?: number;
}

/** Python `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)`. */
export function canonicalJson(value: unknown): string {
  const sorted = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(sorted);
    if (v && typeof v === "object") {
      const out: Record<string, unknown> = {};
      for (const key of Object.keys(v as Record<string, unknown>).sort()) out[key] = sorted((v as Record<string, unknown>)[key]);
      return out;
    }
    return v;
  };
  return JSON.stringify(sorted(value)).replace(/[^\x00-\x7f]/g, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

/** The signer name for a key: its raw 32-byte Ed25519 public key as hex. */
export function publicKeyHex(key: KeyObject): string {
  const spki = createPublicKey(key).export({ type: "spki", format: "der" }) as Buffer;
  return spki.subarray(spki.length - 32).toString("hex");
}

function domainDocument(domain: StatementDomain, payload: Record<string, string>): Record<string, unknown> {
  return {
    v: ENVELOPE_VERSION,
    type: domain.statementType,
    env: domain.environment,
    graph: domain.graph,
    chain: domain.chain ?? "",
    epoch: domain.rootEpoch ?? 0,
    seq: domain.sequence ?? 0,
    schema: domain.schemaVersion ?? STATEMENT_SCHEMA_VERSION,
    payload: { ...payload },
  };
}

/** The exact bytes every signature covers: domain tag + canonical JSON. */
export function signedMessage(domain: StatementDomain, payload: Record<string, string>): Buffer {
  return Buffer.concat([Buffer.from(DOMAIN_TAG, "ascii"), Buffer.from(canonicalJson(domainDocument(domain, payload)), "ascii")]);
}

/** One signature over `payload` for one statement domain, serialized as Python `SignedEnvelope.to_text()`. */
export function signEnvelope(privateKey: KeyObject, domain: StatementDomain, payload: Record<string, string>): string {
  for (const [k, v] of Object.entries(payload)) {
    if (typeof k !== "string" || typeof v !== "string") throw new Error("payload must map str to str");
  }
  const signature = cryptoSign(null, signedMessage(domain, payload), privateKey).toString("hex");
  const document = domainDocument(domain, payload);
  document.sigs = [{ signer: publicKeyHex(privateKey), sig: signature }];
  const text = canonicalJson(document);
  if (text.length > MAX_ENVELOPE_CHARS) throw new Error(`signed envelope exceeds ${MAX_ENVELOPE_CHARS} characters`);
  return text;
}

/** Everything needed to sign this node's community statements (mirror of Python `ReportSigner`). */
export class ReportSigner {
  constructor(
    readonly privateKey: KeyObject,
    readonly environment: string,
    readonly graph: string,
  ) {}

  sign(statementType: string, payload: Record<string, string>): string {
    return signEnvelope(this.privateKey, { statementType, environment: this.environment, graph: this.graph }, payload);
  }

  get signerHex(): string {
    return publicKeyHex(this.privateKey);
  }
}
