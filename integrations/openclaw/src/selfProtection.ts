/**
 * Blackbox's own core, for the minutes its service is not answering (2026-11-20).
 *
 * The rule that keeps an agent from switching off, reconfiguring, editing or stopping Blackbox
 * lives in the Python (`detection/paths/guard_settings.py`) and reaches this plugin through the
 * verdict service, like every other judgement. This file is NOT a copy of it: it is the stricter
 * stand-in used only while the service cannot be asked, so that an outage — or an agent that
 * caused one — is not a window for changing Blackbox. While it applies, a tool call that NAMES
 * one of Blackbox's own things is refused unless it is a plain read; the refusal says why.
 *
 * Imports nothing, so Node runs it as it is (`test/self-protection.mjs`).
 *
 * Usage:
 *   ownCoreTouched("exec", { command: "rm -rf ~/.hermes/blackbox" }, "http://127.0.0.1:9700")
 *     // -> "names Blackbox's own files or commands"
 *   ownCoreTouched("exec", { command: "cat ~/.hermes/config.yaml" }, "http://127.0.0.1:9700")   // -> null
 */

/** The rule's name in a finding (`fileaccess:<tool>:blackbox-settings`, as the Python names it). */
export const OWN_RULE = "blackbox-settings";

/** What the agent is told when this stand-in refuses a call. */
export const OUTAGE_MESSAGE =
  "Blackbox blocked this action: Blackbox's own service is not answering, and until it is back nothing that touches " +
  "Blackbox itself (its settings, files, services or control page) is allowed. Ask the person to check Blackbox.";

/** Blackbox's own things, by name: its folders and configs, its services, its switches, its variables. */
const OWN_THINGS = new RegExp(
  [
    String.raw`\.hermes\b`, // Hermes' home: its config, its plugins, Blackbox's data
    String.raw`\.openclaw[\w-]*[\\/]+(?:openclaw\.json|extensions|plugins)|openclaw\.json`,
    String.raw`plugins[\\/]+blackbox|integrations[\\/]+openclaw|bin[\\/]+blackbox\b`,
    String.raw`ai\.umanitek|blackbox-(?:dashboard|dkg)`,
    String.raw`\bblackbox\s+(?:detach|uninstall|settings|rules|attach|setup)\b`,
    String.raw`\b(?:pkill|killall|kill|taskkill)\b[^\n]*(?:blackbox|hermes|\bdkg\b|oxigraph)`,
    String.raw`\b(?:HERMES_HOME|OPENCLAW_(?:CONFIG_PATH|STATE_DIR|HOME))\s*=`,
    String.raw`\bplugins?\s+(?:disable|remove|uninstall|rm|delete)\b`,
    String.raw`\bconfig\s+(?:set|unset|edit|delete|remove)\b[^|;&\n]*plugins`,
  ].join("|"),
  "i",
);
/** One of Blackbox's own variables (capitals only: a file called `blackbox_notes` is not one). */
const OWN_VARIABLE = /\bBLACKBOX_[A-Z0-9_]+/;
/** One reading command and nothing else: no pipe, no redirect, no second command, nothing built at run time. */
const PLAIN_READ = /^\s*(?:cat|less|more|head|tail|ls|stat|file|wc|grep|rg|diff|jq|du|tree|pwd)\b[^|;&<>`$\n]*$/;
/** One plain fetch of a page: no method, no body, no token route. */
const PLAIN_FETCH = /^\s*(?:curl|wget)\b(?![^\n]*(?:\s-(?:X|d|F|T)\b|--(?:request|data|form|json|upload|post|method|body)|\/api\/session))[^|;&<>`$\n]*$/;
/** Tools that only read (by the start of their name). */
const READ_TOOL = /^(?:read|view|list|ls|glob|grep|search|find)/i;
const MAX_DEPTH = 4;

function texts(value: unknown, out: string[] = [], depth = 0): string[] {
  if (typeof value === "string") out.push(value);
  else if (depth < MAX_DEPTH && Array.isArray(value)) for (const item of value.slice(0, 200)) texts(item, out, depth + 1);
  else if (depth < MAX_DEPTH && value && typeof value === "object") for (const item of Object.values(value)) texts(item, out, depth + 1);
  return out;
}

/** The port Blackbox's dashboard answers on, from its address ("" when none is configured). */
function portOf(dashboardUrl: string): string {
  return /:(\d{2,5})(?:\/|$)/.exec(dashboardUrl || "")?.[1] ?? "";
}

/**
 * Why this call touches Blackbox's own core, or null when it does not (or only reads it).
 * `params` is the tool's arguments as given; every string in them is read.
 */
export function ownCoreTouched(toolName: string, params: unknown, dashboardUrl: string): string | null {
  const text = texts(params).join("\n");
  if (!text) return null;
  const port = portOf(dashboardUrl);
  // The port as a word of its own: in an address (`:9700/`) or handed to a program (`http.server 9700`).
  const namesPage = port !== "" && new RegExp(`(?<![\\w.])${port}(?![\\w.])`).test(text);
  const namesOwn = OWN_THINGS.test(text) || OWN_VARIABLE.test(text);
  if (!namesPage && !namesOwn) return null;
  const tool = (toolName || "").trim();
  const strings = texts(params);
  if (READ_TOOL.test(tool) && strings.length <= 3 && !/\n/.test(text)) return null;
  if (strings.length === 1 && (PLAIN_READ.test(text) || (namesPage && !namesOwn && PLAIN_FETCH.test(text)))) return null;
  return namesPage ? "uses Blackbox's own control page" : "names Blackbox's own files or commands";
}
