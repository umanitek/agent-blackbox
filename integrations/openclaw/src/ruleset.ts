/**
 * Graph-synced rule cache.
 *
 * The ruleset is the ONLY source of detection truth (mirrors Python
 * `ruleset.py`):
 *
 *   - `verifiable-memory` (the curated public threat graph) → rules tagged
 *     `source: "public"`. The source of truth: matches are CONFIRMED and, in
 *     block mode, blockable.
 * Each tier pulls both legacy Guardian threats and Defender signal entities, normalized into a
 * `Ruleset` and cached to a JSON file (source tags included) under the
 * OpenClaw state dir with a TTL. On an empty graph the ruleset is empty and
 * the matcher detects nothing — by design.
 *
 * Fail-open: if the node is unreachable we keep serving the last cached (or
 * empty) ruleset and try again after the TTL.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { DkgClient, DkgError, DkgView } from "./dkgClient.js";
import {
  DependencyRule,
  EscalationRule,
  FileAccessRule,
  IocRule,
  InjectionRule,
  RuleSource,
  Ruleset,
  SkillRule,
  emptyRuleset,
} from "./detection.js";
import {
  BLACKBOX_ARG_SHAPE_PRED,
  BLACKBOX_CATEGORY_PRED,
  BLACKBOX_DANGER_SHAPE_PRED,
  BLACKBOX_IDENTIFIER_PRED,
  BLACKBOX_KIND_PRED,
  BLACKBOX_OWASP_CATEGORY_PRED,
  BLACKBOX_PACKAGE_ECOSYSTEM_PRED,
  BLACKBOX_PACKAGE_NAME_PRED,
  BLACKBOX_PACKAGE_VERSION_PRED,
  BLACKBOX_PATTERN_PRED,
  BLACKBOX_SEVERITY_PRED,
  BLACKBOX_SKILL_NAME_PRED,
  BLACKBOX_SKILL_VERSION_PRED,
  BLACKBOX_TOOL_NAME_PRED,
  DEFENDER_CORRECTION_ACTION_PRED,
  DEFENDER_CORRECTION_SUPPRESS,
  DEFENDER_CORRECTION_TARGET_PRED,
  DEFENDER_CORRECTION_TYPE_IRI,
  SCHEMA_DESCRIPTION,
  SCHEMA_NAME,
  RDF_TYPE,
  iocIdentifier,
  normalizeSeverity,
} from "./quads.js";

const SCHEMA_ADVISORY = "http://schema.org/identifier";
const DEFENDER = "urn:defender:";
const DEFENDER_P = "urn:defender:p:";
const SOURCE_OBSERVATION = "urn:blackbox:SourceObservation";
const SOURCE_OBSERVATION_P = "urn:blackbox:p:";
const IOC_TYPES = new Set(["domain", "url", "ip", "hash", "wallet", "contract"]);

/**
 * SPARQL that pulls legacy threats and the current Defender signal ontology.
 */
function rulesetQuery(): string {
  return `
SELECT ?s ?p ?o WHERE {
  {
    {
      ?s <${BLACKBOX_IDENTIFIER_PRED}> ?identifier .
    }
    UNION
    {
      ?s a ?signalType .
      VALUES ?signalType {
        <${DEFENDER}DependencySignal> <${DEFENDER}InjectionSignal>
        <${DEFENDER}SkillSignal> <${DEFENDER}IocSignal>
        <${DEFENDER_CORRECTION_TYPE_IRI}>
      }
    }
    ?s ?p ?o .
  }
  UNION
  {
    ?s a <${SOURCE_OBSERVATION}> .
    ?s ?p ?o .
    VALUES ?p {
      <${RDF_TYPE}>
      <${SOURCE_OBSERVATION_P}canonicalType>
      <${SOURCE_OBSERVATION_P}category>
      <${SOURCE_OBSERVATION_P}lifecycleStatus>
      <${SOURCE_OBSERVATION_P}normalizedValue>
      <${SOURCE_OBSERVATION_P}provenanceJson>
      <${SOURCE_OBSERVATION_P}sourceId>
    }
  }
}`.trim();
}

/** Agent Blackbox is VM-only until community support ships. */
const TIERS: ReadonlyArray<readonly [DkgView, RuleSource]> = [
  ["verifiable-memory", "public"],
];

export function resolveStateDir(explicit?: string): string {
  if (explicit) return explicit;
  const base =
    process.env.OPENCLAW_STATE_DIR ||
    process.env.OPENCLAW_HOME ||
    join(homedir(), ".openclaw");
  return join(base, "blackbox");
}

/** Extract SPARQL SELECT bindings from the node's response envelope, tolerantly.
 * The v10 node nests them under ``result.bindings`` (singular); older/other
 * shapes use ``results.bindings`` or a top-level ``bindings``. */
function extractBindings(resp: unknown): Array<Record<string, unknown>> {
  const r = resp as Record<string, unknown> | null;
  const container = (r?.result ?? r?.results ?? r) as Record<string, unknown> | undefined;
  const bindings =
    (container as { bindings?: unknown })?.bindings ?? (r as { bindings?: unknown })?.bindings;
  return Array.isArray(bindings) ? (bindings as Array<Record<string, unknown>>) : [];
}

/** Unwrap a binding value: ``{value}`` object, a quoted N-Triples literal
 * (``"x"``, ``"x"^^<type>``, ``"x"@lang``), or a bare IRI/string. */
function bindingValue(v: unknown): string | undefined {
  if (v == null) return undefined;
  if (typeof v === "object" && "value" in (v as Record<string, unknown>)) {
    return String((v as { value: unknown }).value);
  }
  const s = String(v);
  const m = s.match(/^"([\s\S]*)"(?:\^\^.*|@.*)?$/);
  return m ? m[1] : s;
}

interface ThreatAccum {
  subject?: string;
  rdfType?: string;
  identifier?: string;
  severity?: string;
  name?: string;
  description?: string;
  pattern?: string;
  owaspCategory?: string;
  toolName?: string;
  argShape?: string;
  packageName?: string;
  packageVersion?: string;
  packageEcosystem?: string;
  advisoryId?: string;
  // dependency threat kind (malware | vulnerability)
  kind?: string;
  // fileaccess
  category?: string;
  // skill
  skillName?: string;
  skillVersion?: string;
  dangerShape?: string;
  // IOC
  iocValue?: string;
  // append-only correction
  targetSubject?: string;
  correctionAction?: string;
  // compact VM source observation
  canonicalType?: string;
  observationCategory?: string;
  lifecycleStatus?: string;
  normalizedValue?: string;
  provenanceJson?: string;
  sourceId?: string;
}

/** Accumulate the s/p/o rows of one tier's response into per-subject threats. */
function collectThreats(resp: unknown): ThreatAccum[] {
  const bySubject = new Map<string, ThreatAccum>();
  for (const b of extractBindings(resp)) {
    const s = bindingValue(b.s);
    const p = bindingValue(b.p);
    const o = bindingValue(b.o);
    if (!s || !p || o === undefined) continue;
    const acc = bySubject.get(s) ?? {};
    acc.subject = s;
    switch (p) {
      case RDF_TYPE: acc.rdfType = o; break;
      case BLACKBOX_IDENTIFIER_PRED: acc.identifier = o; break;
      case BLACKBOX_SEVERITY_PRED:
      case `${DEFENDER_P}severity`: acc.severity = o; break;
      case SCHEMA_NAME: acc.name = o; break;
      case SCHEMA_DESCRIPTION: acc.description = o; break;
      case BLACKBOX_PATTERN_PRED:
      case `${DEFENDER_P}pattern`: acc.pattern = o; break;
      case BLACKBOX_OWASP_CATEGORY_PRED: acc.owaspCategory = o; break;
      case BLACKBOX_TOOL_NAME_PRED: acc.toolName = o; break;
      case BLACKBOX_ARG_SHAPE_PRED: acc.argShape = o; break;
      case BLACKBOX_PACKAGE_NAME_PRED:
      case `${DEFENDER_P}package`: acc.packageName = o; break;
      case BLACKBOX_PACKAGE_VERSION_PRED:
      case `${DEFENDER_P}version`: acc.packageVersion = o; break;
      case BLACKBOX_PACKAGE_ECOSYSTEM_PRED:
      case `${DEFENDER_P}ecosystem`: acc.packageEcosystem = o; break;
      case BLACKBOX_KIND_PRED:
      case `${DEFENDER_P}kind`: acc.kind = o; break;
      case SCHEMA_ADVISORY:
      case `${DEFENDER_P}advisoryId`: acc.advisoryId = o; break;
      case BLACKBOX_CATEGORY_PRED:
      case `${DEFENDER_P}iocType`: acc.category = o; break;
      case `${DEFENDER_P}value`: acc.iocValue = o; break;
      case BLACKBOX_SKILL_NAME_PRED: acc.skillName = o; break;
      case BLACKBOX_SKILL_VERSION_PRED: acc.skillVersion = o; break;
      case BLACKBOX_DANGER_SHAPE_PRED: acc.dangerShape = o; break;
      case DEFENDER_CORRECTION_TARGET_PRED: acc.targetSubject = o; break;
      case DEFENDER_CORRECTION_ACTION_PRED: acc.correctionAction = o; break;
      case `${SOURCE_OBSERVATION_P}canonicalType`: acc.canonicalType = o; break;
      case `${SOURCE_OBSERVATION_P}category`: acc.observationCategory = o; break;
      case `${SOURCE_OBSERVATION_P}lifecycleStatus`: acc.lifecycleStatus = o; break;
      case `${SOURCE_OBSERVATION_P}normalizedValue`: acc.normalizedValue = o; break;
      case `${SOURCE_OBSERVATION_P}provenanceJson`: acc.provenanceJson = o; break;
      case `${SOURCE_OBSERVATION_P}sourceId`: acc.sourceId = o; break;
      default: break;
    }
    bySubject.set(s, acc);
  }
  return [...bySubject.values()];
}

type MappedRule =
  | { category: "injection"; key: string; rule: InjectionRule }
  | { category: "escalation"; key: string; rule: EscalationRule }
  | { category: "dependency"; key: string; rule: DependencyRule }
  | { category: "fileaccess"; key: string; rule: FileAccessRule }
  | { category: "skill"; key: string; rule: SkillRule }
  | { category: "ioc"; key: string; rule: IocRule };

const QUOTED_SKILL_NAME_RE = /^["'`]([^"'`]+)["'`]/;
const SKILL_PACKAGE_NAME_RE = /^@?[a-z0-9][a-z0-9._-]*(?:\/[a-z0-9][a-z0-9._-]*)?$/i;
const TITLED_SKILL_NAME_RE = /^(@?[a-z0-9][a-z0-9._-]*(?:\/[a-z0-9][a-z0-9._-]*)?)\s+(?:\(|bcc\b)/i;

/** Recover only explicit package-shaped names from legacy display titles. */
export function skillNameFromTitle(title: string): string {
  const value = (title || "").trim();
  return QUOTED_SKILL_NAME_RE.exec(value)?.[1]?.trim()
    ?? TITLED_SKILL_NAME_RE.exec(value)?.[1]?.trim()
    ?? "";
}

function sourceObservationProvenance(acc: ThreatAccum): Record<string, unknown> {
  if (!acc.provenanceJson) return {};
  try {
    const value = JSON.parse(acc.provenanceJson) as unknown;
    return value && typeof value === "object" && !Array.isArray(value)
      ? value as Record<string, unknown>
      : {};
  } catch {
    return {};
  }
}

/** Map one accumulated threat to `(category, key, rule)` or null. Port of Python `_row_to_rule`. */
function accumToRule(acc: ThreatAccum, source: RuleSource): MappedRule | null {
  let identifier = acc.identifier;
  const suffix = acc.subject?.split(":").pop() ?? "";
  if (!identifier && acc.rdfType === `${DEFENDER}DependencySignal`) {
    const eco = (acc.packageEcosystem || "").toLowerCase();
    const pkg = (acc.packageName || "").toLowerCase();
    const ver = acc.packageVersion || "";
    if (eco && pkg && ver) identifier = `dep:${eco}:${pkg}@${ver}`;
  } else if (!identifier && acc.rdfType === `${DEFENDER}InjectionSignal` && suffix) {
    identifier = `injection:${suffix}`;
  } else if (!identifier && acc.rdfType === `${DEFENDER}SkillSignal` && suffix) {
    identifier = `skill:${suffix}`;
  } else if (!identifier && acc.rdfType === `${DEFENDER}IocSignal` && acc.category && acc.iocValue) {
    identifier = `ioc:${acc.category.trim().toLowerCase()}:${acc.iocValue}`;
  } else if (!identifier && acc.rdfType === SOURCE_OBSERVATION) {
    const iocType = (acc.canonicalType || "").trim().toLowerCase();
    if (
      acc.lifecycleStatus?.trim().toLowerCase() === "active" &&
      IOC_TYPES.has(iocType) &&
      acc.normalizedValue
    ) {
      identifier = iocIdentifier(iocType, acc.normalizedValue);
    }
  }
  if (!identifier) return null;
  const provenance = sourceObservationProvenance(acc);
  const severity = normalizeSeverity(acc.severity ?? provenance.severity, "high");
  const name = acc.name || acc.description || acc.normalizedValue || identifier;
  if (identifier.startsWith("injection:")) {
    if (!acc.pattern) return null;
    return {
      category: "injection",
      key: identifier,
      rule: {
        identifier,
        pattern: acc.pattern,
        severity,
        name,
        owaspCategory: acc.owaspCategory,
        source,
      },
    };
  }
  if (identifier.startsWith("escalation:")) {
    if (!acc.toolName || !acc.argShape) return null;
    return {
      category: "escalation",
      key: identifier,
      rule: { identifier, toolName: acc.toolName, argShape: acc.argShape, severity, name, source },
    };
  }
  if (identifier.startsWith("dep:")) {
    let eco = (acc.packageEcosystem || "").toLowerCase();
    let pkg = (acc.packageName || "").toLowerCase();
    let ver = acc.packageVersion || "";
    if (!(eco && pkg && ver)) {
      // Fall back to parsing the identifier: dep:{eco}:{name}@{version}.
      // Mirrors Python: rest.split(":", 1) then tail.rsplit("@", 1).
      const rest = identifier.slice("dep:".length);
      const ci = rest.indexOf(":");
      if (ci < 0) return null;
      const tail = rest.slice(ci + 1);
      const at = tail.lastIndexOf("@");
      if (at < 0) return null;
      eco = rest.slice(0, ci).toLowerCase();
      pkg = tail.slice(0, at).toLowerCase();
      ver = tail.slice(at + 1);
    }
    return {
      category: "dependency",
      key: `${eco}:${pkg}@${ver}`,
      rule: { identifier, severity, advisoryId: acc.advisoryId, kind: acc.kind || undefined, name, source },
    };
  }
  if (identifier.startsWith("fileaccess:")) {
    // Prefer explicit predicates; fall back to parsing fileaccess:{tool}:{category}.
    let toolName = acc.toolName;
    let category = acc.category;
    if (!toolName || !category) {
      const parts = identifier.split(":");
      // ["fileaccess", tool, category] — mirror Python identifier.split(":", 2).
      if (parts.length >= 3) {
        toolName = parts[1];
        category = parts.slice(2).join(":");
      }
    }
    if (!toolName || !category) return null;
    return {
      category: "fileaccess",
      key: identifier,
      rule: {
        identifier,
        toolName: toolName.trim().toLowerCase(),
        category: category.trim().toLowerCase(),
        severity,
        name,
        source,
      },
    };
  }
  if (identifier.startsWith("skill:")) {
    // Skill rules are built unconditionally (fields optional), like Python.
    return {
      category: "skill",
      key: identifier,
      rule: {
        identifier,
        skillName: acc.skillName && SKILL_PACKAGE_NAME_RE.test(acc.skillName)
          ? acc.skillName
          : skillNameFromTitle(name),
        skillVersion: acc.skillVersion ?? "",
        dangerShape: acc.dangerShape ?? "",
        severity,
        name,
        source,
      },
    };
  }
  if (identifier.startsWith("ioc:")) {
    const isObservation = acc.rdfType === SOURCE_OBSERVATION;
    const parts = identifier.split(":", 3);
    const iocType = (
      (isObservation ? acc.canonicalType : acc.category) || parts[1] || ""
    ).trim().toLowerCase();
    const value = isObservation
      ? identifier.slice(`ioc:${parts[1] ?? ""}:`.length)
      : acc.iocValue || identifier.slice(`ioc:${parts[1] ?? ""}:`.length);
    if (!iocType || !value) return null;
    return {
      category: "ioc",
      key: identifier,
      rule: {
        identifier,
        severity,
        name,
        iocType,
        value,
        kind: (isObservation ? acc.observationCategory : acc.kind) || undefined,
        sourceId: isObservation ? acc.sourceId : undefined,
        source,
      },
    };
  }
  return null;
}

/**
 * Build one merged `Ruleset` from per-tier threat accumulations, in tier
 * order (public first). Precedence is identifier-first-wins in every category
 * INCLUDING the dependency map, so with public processed first a community
 * row can never shadow (or escalate/downgrade) a curated public rule. Port of
 * Python `build_from_rows`.
 */
function buildRuleset(tiers: ReadonlyArray<readonly [ThreatAccum[], RuleSource]>): Ruleset {
  const ruleset = emptyRuleset();
  ruleset.fetchedAt = Date.now();
  const suppressedSubjects = new Set<string>();
  for (const [accums, source] of tiers) {
    if (source !== "public") continue;
    for (const acc of accums) {
      if (
        acc.rdfType === DEFENDER_CORRECTION_TYPE_IRI &&
        acc.correctionAction?.trim().toLowerCase() === DEFENDER_CORRECTION_SUPPRESS &&
        acc.targetSubject
      ) {
        suppressedSubjects.add(acc.targetSubject);
      }
    }
  }
  const seen: Record<MappedRule["category"], Set<string>> = {
    injection: new Set(),
    escalation: new Set(),
    dependency: new Set(),
    fileaccess: new Set(),
    skill: new Set(),
    ioc: new Set(),
  };
  for (const [accums, source] of tiers) {
    for (const acc of accums) {
      if (acc.subject && suppressedSubjects.has(acc.subject)) continue;
      const mapped = accumToRule(acc, source);
      if (!mapped || seen[mapped.category].has(mapped.key)) continue;
      seen[mapped.category].add(mapped.key);
      switch (mapped.category) {
        case "injection": ruleset.injection.push(mapped.rule); break;
        case "escalation": ruleset.escalation.push(mapped.rule); break;
        case "dependency": ruleset.dependency[mapped.key] = mapped.rule; break;
        case "fileaccess": ruleset.fileaccess.push(mapped.rule); break;
        case "skill": ruleset.skill.push(mapped.rule); break;
        case "ioc": ruleset.ioc[mapped.key] = mapped.rule; break;
      }
    }
  }
  return ruleset;
}

export interface RulesetCacheOptions {
  client: DkgClient;
  contextGraphId: string;
  stateDir?: string;
  /** Optional read-only fallback cache (for an attached Hermes Blackbox home). */
  seedStateDir?: string;
  /** TTL seconds; below this a get() serves the cache without a refresh. */
  ttlSeconds?: number;
}

/**
 * Lazy, TTL'd ruleset cache. `get()` returns the in-memory ruleset immediately
 * and triggers a background refresh when stale; the refresh is fail-open.
 */
export class RulesetCache {
  private readonly client: DkgClient;
  private readonly contextGraphId: string;
  private readonly cachePath: string;
  private readonly ttlMs: number;
  private ruleset: Ruleset;
  private refreshing = false;

  constructor(opts: RulesetCacheOptions) {
    this.client = opts.client;
    this.contextGraphId = opts.contextGraphId;
    this.ttlMs = (opts.ttlSeconds ?? 300) * 1000;
    this.cachePath = join(resolveStateDir(opts.stateDir), "ruleset.json");
    const seedPath = opts.seedStateDir ? join(opts.seedStateDir, "ruleset.json") : "";
    this.ruleset = this.loadFromDisk(this.cachePath) ?? (seedPath ? this.loadFromDisk(seedPath) : null) ?? emptyRuleset();
  }

  private loadFromDisk(path: string): Ruleset | null {
    try {
      const parsed = JSON.parse(readFileSync(path, "utf8")) as Partial<Ruleset> & {
        synced_at?: number;
        injection?: Array<InjectionRule & { pattern_src?: string }>;
      };
      if (parsed && Array.isArray(parsed.injection)) {
        const publicOnly = <T extends { source?: RuleSource }>(rows: T[] | undefined): T[] =>
          (rows ?? []).filter((row) => row.source !== "community");
        const dependencies = Object.fromEntries(
          Object.entries(parsed.dependency ?? {}).filter(
            ([, rule]) => rule?.source !== "community",
          ),
        );
        // Backfill arrays absent from caches written before fileaccess/skill
        // support and drop SWM rows written by pre-VM-only releases.
        return {
          ...emptyRuleset(),
          ...parsed,
          // Hermes persists the regex source as `pattern_src` because its
          // in-memory `pattern` is a compiled Python regex. Treat that cache as
          // a read-only seed and normalize it to the TypeScript shape.
          injection: publicOnly(parsed.injection)
            .map((rule) => ({ ...rule, pattern: rule.pattern || rule.pattern_src || "" }))
            .filter((rule) => rule.pattern),
          escalation: publicOnly(parsed.escalation),
          dependency: dependencies,
          fileaccess: publicOnly(parsed.fileaccess),
          skill: publicOnly(parsed.skill).map((rule) => ({
            ...rule,
            skillName: rule.skillVersion
              ? rule.skillName
              : skillNameFromTitle(rule.name || rule.skillName) || rule.skillName,
          })),
          ioc: Object.fromEntries(
            Object.entries(parsed.ioc ?? {}).filter(([, rule]) => rule?.source !== "community"),
          ),
          fetchedAt: parsed.fetchedAt ?? (parsed.synced_at ? parsed.synced_at * 1000 : 0),
        } as Ruleset;
      }
    } catch {
      /* no cache yet */
    }
    return null;
  }

  private saveToDisk(rs: Ruleset): void {
    try {
      mkdirSync(dirname(this.cachePath), { recursive: true });
      writeFileSync(this.cachePath, JSON.stringify(rs), "utf8");
    } catch {
      /* best effort */
    }
  }

  private isStale(): boolean {
    return Date.now() - this.ruleset.fetchedAt > this.ttlMs;
  }

  /**
   * Force a synchronous sync from the node. Fail-open (returns current on
   * error). One query per sync reads verifiable-memory. If nothing comes back,
   * the last-good public ruleset keeps serving. Mirrors Python `ruleset.refresh`.
   */
  async sync(): Promise<Ruleset> {
    if (this.refreshing) return this.ruleset;
    this.refreshing = true;
    try {
      const tierAccums: Array<readonly [ThreatAccum[], RuleSource]> = [];
      let gotAny = false;
      for (const [view, source] of TIERS) {
        try {
          const resp = await this.client.query(rulesetQuery(), this.contextGraphId, view);
          const accums = collectThreats(resp);
          if (accums.length > 0) gotAny = true;
          tierAccums.push([accums, source]);
        } catch (err) {
          if (!(err instanceof DkgError)) throw err;
          // this view unreachable/failed — skip it, keep the other tier.
        }
      }
      if (!gotAny) {
        // Nothing came back — keep serving the last ruleset, bump fetchedAt so
        // we don't hammer a down node every tool call.
        this.ruleset = { ...this.ruleset, fetchedAt: Date.now() };
      } else {
        const next = buildRuleset(tierAccums);
        this.ruleset = next;
        this.saveToDisk(next);
      }
    } finally {
      this.refreshing = false;
    }
    return this.ruleset;
  }

  /** Cached ruleset; kicks off a fire-and-forget refresh when stale. */
  get(): Ruleset {
    if (this.isStale() && !this.refreshing) {
      void this.sync();
    }
    return this.ruleset;
  }

  counts(): {
    injection: number;
    escalation: number;
    dependency: number;
    fileaccess: number;
    skill: number;
    ioc: number;
  } {
    return {
      injection: this.ruleset.injection.length,
      escalation: this.ruleset.escalation.length,
      dependency: Object.keys(this.ruleset.dependency).length,
      fileaccess: this.ruleset.fileaccess.length,
      skill: this.ruleset.skill.length,
      ioc: Object.keys(this.ruleset.ioc).length,
    };
  }
}
