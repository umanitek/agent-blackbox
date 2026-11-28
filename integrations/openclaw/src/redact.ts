/**
 * Secret redaction — the OpenClaw runtime's copy of ONE rule set.
 *
 * The canonical rule table lives in the hermes plugin, `kernel/redaction.py`
 * (`SECRET_VALUE_RULES`, the redaction-only shapes, the bearer rule and the
 * secret-assignment rule). This file carries the same rules in the same order
 * with the same markers, and `tests/plugins/test_blackbox_redaction_parity.py`
 * runs generated inputs through BOTH runtimes and fails on any byte of
 * difference (LES-021: one redactor per runtime, a cross-runtime parity test).
 * Change a rule here only together with the Python table.
 *
 * Reports NEVER carry raw content; evidence snippets are always run through
 * this first. Pure, zero deps. Redact BEFORE truncating — a secret cut in half
 * no longer matches (KI-178).
 */

import { SEED_PHRASE_MARKER, allSeedPhraseSpans, redactSeedPhrases } from "./seedPhrase.js";
import { SOLANA_KEY_MARKER, isSolanaSecretKey, redactSolanaKeys } from "./solanaKey.js";
import { redactBitcoinKeys } from "./bitcoinKey.js";
import { percentDecoded } from "./textView.js";

/** Known secret shapes → typed markers. Mirrors `redaction.SECRET_VALUE_RULES`. */
const SECRET_VALUE_RULES: ReadonlyArray<readonly [string, RegExp]> = [
  // The WHOLE private-key block — through its END line, or to the end of the
  // text when the block was cut off — so the key material goes, not just the
  // header line (KI-178).
  ["private-key", /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g],
  ["aws-access-key", /\bAKIA[0-9A-Z]{16}\b/g],
  ["anthropic-api-key", /\bsk-ant-[A-Za-z0-9_-]{20,}/g],
  ["openai-api-key", /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}/g],
  ["github-token", /\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{20,}/g],
  ["slack-token", /\bxox[baprs]-[A-Za-z0-9-]{10,}/g],
  ["google-api-key", /\bAIza[0-9A-Za-z_-]{35}\b/g],
  ["stripe-key", /\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}/g],
  ["gcp-service-account-key", /"type"\s*:\s*"service_account"/g],
  ["jwt", /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g],
  // A raw wallet key only right after a key label or inside a key-taking call (it is shaped like a tx hash).
  // Names around the keyword are bounded (64 each side) so the rule runs in linear time (KI-382).
  ["wallet-private-key", /(?:\b(?:[A-Za-z0-9_]{0,64}?(?:private[ _-]?key|priv[_-]?key|secret[ _-]?key|signer[ _-]?key|signing[ _-]?key|wallet[ _-]?key|eth[_-]?key|evm[_-]?key|account[_-]?key)[A-Za-z0-9_]{0,64}|pk|(?<!public )(?<!public_)(?<!public-)key)["']?[ \t]*(?:[:=]|\bis\b)[ \t]*["']?|\b(?:from_key|from_private_key|fromPrivateKey|privateKeyToAccount|Wallet|Account)[ \t]*\([ \t]*["'`]?)(?:0x)?[0-9a-f]{64}[0-9a-f]*/gi],
  // A labelled Solana seed half (43-44 base58 characters, no self-check of its own).
  ["wallet-private-key", /\b[A-Za-z0-9_]{0,32}?(?:sol(?:ana)?|phantom|keypair)[_ -]?(?:private|secret)?[_ -]?(?:key|seed)[A-Za-z0-9_]{0,32}["']?[ \t]*[:=][ \t]*["']?[1-9A-HJ-NP-Za-km-z]{43,44}(?![1-9A-HJ-NP-Za-km-z])/gi],
];

/** Redaction-only shapes (too broad to be detection signals). Mirrors `_REDACTION_ONLY_RULES`. */
const REDACTION_ONLY_RULES: ReadonlyArray<readonly [string, RegExp]> = [
  ["api-key", /\bsk-[A-Za-z0-9_-]{16,}/g],
  ["github-token", /\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{16,}/g],
];

const BEARER_RE = /Bearer\s+[A-Za-z0-9._~+/=-]+/gi;

// A secret-named key followed by `:` or `=` and a value: `DB_PASSWORD=...`,
// `"api_key": "..."`. The key name stays (it explains the log line); the
// value goes. A value already replaced by a typed marker is kept. Linear time,
// as in Python (KI-373): a bounded look-ahead finds the keyword, then at most
// 64 name characters are taken with no backtracking — JavaScript has no
// possessive `{1,64}+`, so the capture-inside-a-look-ahead + back-reference
// idiom stands in for it.
// The names are Python's `SECRET_NAME_WORDS`, in its order.
const SECRET_NAMES = "api[_-]?key|token|secret|password|passwd|credential|authorization|private[_-]?key|access[_-]?key";
const SECRET_ASSIGNMENT_RE = new RegExp(
  String.raw`(?<key>\b(?=[A-Za-z0-9_-]{0,64}?(?:${SECRET_NAMES}))(?=(?<name>[A-Za-z0-9_-]{1,64}))\k<name>["']?)(?<sep>\s*[:=]\s*["']?)(?<value>[^\s"'[\],;]{8,})`, "gi");

// The credential forms the assignment rule can not see (external review, 2026-11-28), each as
// Python's `redact_credentials` reads them: kernel/redaction.py is the one rule table.
const STRONG_NAMES = "password|passwd|passphrase|secret|credential";
const SHORT_SECRET_RE = new RegExp(
  String.raw`(?<key>\b(?=[A-Za-z0-9_-]{0,64}?(?:${STRONG_NAMES}))(?=(?<name>[A-Za-z0-9_-]{1,64}))\k<name>["']?)(?<sep>\s*[:=]\s*["']?)(?<value>[^\s"'[\],;]{1,7})(?![^\s"'[\],;])`, "gi");
const QUOTED_SECRET_RE = new RegExp(
  String.raw`(?<key>\b(?=[A-Za-z0-9_-]{0,64}?(?:${SECRET_NAMES}))(?=(?<name>[A-Za-z0-9_-]{1,64}))\k<name>["']?)(?<sep>[ \t]*[:=][ \t]*)(?<quote>["'])(?<value>[^"'\r\n]{1,512})\k<quote>`, "gi");
const AUTH_HEADER_RE = /(?<head>\b(?:proxy-)?authorization["']?[ \t]*[:=][ \t]*["']?)(?<rest>[^\r\n"',;]{1,1024})/gi;
const SCHEME = /^[A-Za-z][A-Za-z0-9_-]{0,31}$/;
const BASIC_RE = /\bBasic[ \t]+(?<value>[A-Za-z0-9+/]{4,}={0,2})(?![A-Za-z0-9+/=])/gi;
const USER_OPTION_RE = /(?<opt>(?<![^\s"'])(?:-u|-U|--user|--proxy-user)(?:[ \t]+|=)["']?)(?<user>[^\s"':]{1,128}):(?<pw>[^\s"']{1,256})/g;
const URL_PASSWORD_RE = /(?<pre>\b[a-z][a-z0-9+.-]{0,30}:\/\/[^\s/?#@:'"<>]{1,128}):(?<pw>[^\s/?#@'"<>]{1,256})@/gi;
const REDACTED = "[REDACTED]";
const DIGITS = /^[0-9]+$/;

function headerValue(whole: string, head: string, rest: string): string {
  const words = rest.split(" ");
  const at = words.length > 1 && SCHEME.test(words[0]!) ? 1 : 0;
  if (words[at]!.startsWith("[REDACTED")) return whole;
  words[at] = REDACTED;
  return head + words.join(" ");
}

function basicValue(whole: string, value: string): string {
  if (value.length % 4) return whole;
  return Buffer.from(value, "base64").includes(0x3a) ? "Basic " + REDACTED : whole;
}

/** Python's `redact_credentials`: headers, Basic, `-u user:pw`, URL passwords, quoted and short secrets. */
function redactCredentials(text: string): string {
  let out = text.replace(AUTH_HEADER_RE, (whole, head: string, rest: string) => headerValue(whole, head, rest));
  out = out.replace(BASIC_RE, (whole, value: string) => basicValue(whole, value));
  out = out.replace(USER_OPTION_RE, (whole, opt: string, user: string, pw: string) =>
    DIGITS.test(user) && DIGITS.test(pw) ? whole : `${opt}${user}:${REDACTED}`);
  out = out.replace(URL_PASSWORD_RE, (_whole, pre: string) => `${pre}:${REDACTED}@`);
  out = out.replace(QUOTED_SECRET_RE, "$<key>$<sep>$<quote>" + REDACTED + "$<quote>");
  return out.replace(SHORT_SECRET_RE, "$<key>$<sep>" + REDACTED);
}

/** Object KEYS whose whole value is dropped. Mirrors `audit/redaction._SECRET_KEY_RE`. */
const SECRET_KEY_RE =
  /(api[_-]?key|token|secret|password|passwd|credential|authorization|private[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token)/i;

function marker(secretType: string): string {
  return `[REDACTED_${secretType.toUpperCase().replace(/-/g, "_")}]`;
}

/**
 * Replace every recognizable secret value in `text` with a marker — the pure
 * rule pass, byte-for-byte the Python `redact_secret_values`. No truncation.
 */
export function redactSecretValues(text: string): string {
  let out = percentDecoded(String(text)); // a URL read as its receiver reads it, as in Python (KI-377)
  out = redactSeedPhrases(out); // wallet seed phrases first, as in Python
  out = redactSolanaKeys(out); // then verified Solana keys, as in Python
  out = redactBitcoinKeys(out); // then Bitcoin WIF / xprv keys, as in Python
  for (const [secretType, pattern] of SECRET_VALUE_RULES) out = out.replace(pattern, marker(secretType));
  for (const [secretType, pattern] of REDACTION_ONLY_RULES) out = out.replace(pattern, marker(secretType));
  out = redactCredentials(out); // as Python, just before the bearer rule
  out = out.replace(BEARER_RE, "Bearer [REDACTED]");
  return out.replace(SECRET_ASSIGNMENT_RE, "$<key>$<sep>[REDACTED]");
}

// A long value is cut BEFORE redaction past this margin (cost), and the cut edge is
// dropped after it (a secret split by the cut sits there) — as Python's sanitize_text.
const REDACTION_MARGIN = 8192;
const CUT_GUARD = 1024;

/** Redact, THEN clamp to `maxLength` (never the other way round). */
export function sanitizeText(value: string, maxLength = 2000): string {
  let text = String(value);
  const precut = text.length > maxLength + REDACTION_MARGIN;
  if (precut) text = text.slice(0, maxLength + REDACTION_MARGIN);
  let redacted = redactSecretValues(text);
  if (precut) redacted = redacted.slice(0, Math.max(0, redacted.length - CUT_GUARD));
  return precut || redacted.length > maxLength ? `${redacted.slice(0, maxLength)}...[truncated]` : redacted;
}

const MAX_DEPTH = 5;
const MAX_ITEMS = 50;
const SOLANA_KEY_BYTES = 64;
type Visitor = (kind: "value" | "key" | "bytes", piece: unknown) => unknown;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** `value` rebuilt with each piece the visitor replaces (`undefined` keeps it) — Python `_walk`. */
function walk(value: unknown, depth: number, visit: Visitor): unknown {
  if (depth > MAX_DEPTH) return value;
  if (typeof value === "string") return visit("value", value) ?? value;
  if (Array.isArray(value)) {
    if (value.length === SOLANA_KEY_BYTES && value.every((item) => Number.isInteger(item) && item >= 0 && item < 256)) {
      return visit("bytes", value) ?? value;
    }
    return value.slice(0, MAX_ITEMS).map((item) => walk(item, depth + 1, visit));
  }
  if (isPlainObject(value)) {
    const out: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) out[(visit("key", key) as string | undefined) ?? key] = walk(child, depth + 1, visit);
    return out;
  }
  return value;
}

/** Indexes of the pieces that belong to a seed phrase read across them — Python `_hit_pieces`. */
function hitPieces(pieces: string[]): Set<number> {
  const starts: number[] = [];
  let text = "";
  for (const piece of pieces) {
    starts.push(text.length);
    text += piece + " ";
  }
  const hits = new Set<number>();
  for (const [start, end] of allSeedPhraseSpans(text)) {
    starts.forEach((pieceStart, index) => {
      if (pieceStart < end && pieceStart + pieces[index].length > start) hits.add(index);
    });
  }
  return hits;
}

/** Every piece of a secret assembled across pieces replaced by its marker — Python `_blank_assembled_secrets`. */
function blankAssembledSecrets(value: unknown): unknown {
  const pieces = { value: [] as string[], key: [] as string[], bytes: [] as unknown[] };
  walk(value, 0, (kind, piece) => {
    (pieces[kind] as unknown[]).push(piece);
    return undefined;
  });
  const hits = { value: hitPieces(pieces.value), key: hitPieces(pieces.key) };
  if (!hits.value.size && !hits.key.size && !pieces.bytes.length) return value;
  const seen = { value: 0, key: 0 };
  return walk(value, 0, (kind, piece) => {
    if (kind === "bytes") return isSolanaSecretKey(Buffer.from(piece as number[])) ? SOLANA_KEY_MARKER : undefined;
    const index = seen[kind]++;
    if (!hits[kind].has(index)) return undefined;
    return kind === "value" ? SEED_PHRASE_MARKER : `${SEED_PHRASE_MARKER}#${index}`;
  });
}

export function redact(value: unknown, depth = 0): unknown {
  if (depth === 0 && (Array.isArray(value) || isPlainObject(value))) value = blankAssembledSecrets(value);
  if (depth > 5) return "[truncated-depth]";
  if (value == null) return value;
  if (typeof value === "string") return sanitizeText(value);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) return value.slice(0, 50).map((item) => redact(item, depth + 1));
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [rawKey, child] of Object.entries(value as Record<string, unknown>)) {
      const key = sanitizeText(rawKey, 200); // a key is text an agent chose: scrubbed too (KI-377)
      if (SECRET_KEY_RE.test(key)) {
        out[key] = "[REDACTED]";
      } else if (/^(content|body|fileContent|input|prompt)$/i.test(key) && typeof child === "string") {
        out[key] = sanitizeText(child, 1200);
      } else {
        out[key] = redact(child, depth + 1);
      }
    }
    return out;
  }
  return String(value);
}
