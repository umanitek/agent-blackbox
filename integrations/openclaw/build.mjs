/**
 * Build the ONE file OpenClaw loads: dist/index.js (plus the word list it reads beside it).
 *
 * WHY a bundle (2026-11-20): OpenClaw 2026.11.6 prepares a plugin's source in a worker, and for
 * every sibling file a plugin imports the worker asks OpenClaw's main process to map it, waiting
 * at most 15 s. While OpenClaw starts on a busy machine that answer arrives late, the load fails
 * with "Plugin preparation callback timed out", and OpenClaw then refuses to run the agent at
 * all. A file with no sibling imports never asks. The 22 source files in src/ stay the source of
 * truth; this bundle is what ships and what package.json's `openclaw.extensions` names.
 *
 * The bundle's first line carries a fingerprint of src/ (see `sourceFingerprint`). The Python
 * suite recomputes it (tests/plugins/test_blackbox_openclaw_bundle.py), so a change to src/
 * without a rebuild fails the ordinary test run — no Node or esbuild needed to notice.
 *
 * Usage (from integrations/openclaw):
 *   npm install --no-save --no-audit --no-fund --ignore-scripts esbuild@0.25.10
 *   npm run build            # writes dist/index.js and dist/bip39-english.txt
 *   npm run build -- --check # exit 1 if dist/ is not what src/ builds to (writes nothing)
 */
import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = join(HERE, "src");
const DIST = join(HERE, "dist");
const BUNDLE = join(DIST, "index.js");
/** Read at runtime beside the bundle (seedPhrase.ts: `new URL("./bip39-english.txt", import.meta.url)`). */
const RUNTIME_FILES = ["bip39-english.txt"];
const BANNER_PREFIX = "/* @umanitek/blackbox-openclaw — built from src/ by `npm run build`; do not edit. source sha256:";

function sourceFiles(dir = SRC) {
  return readdirSync(dir).sort().flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? sourceFiles(path) : [path];
  });
}

/**
 * sha256 over every file under src/, in sorted relative-path order: `path NUL bytes NUL`, with
 * CRLF read as LF so a Windows checkout gives the same answer. The Python test computes the same.
 */
export function sourceFingerprint() {
  const hash = createHash("sha256");
  for (const path of sourceFiles()) {
    hash.update(relative(SRC, path).split(sep).join("/"));
    hash.update("\0");
    hash.update(readFileSync(path, "latin1").replaceAll("\r\n", "\n"), "latin1");
    hash.update("\0");
  }
  return hash.digest("hex");
}

async function bundleText() {
  const { build } = await import("esbuild");
  const result = await build({
    entryPoints: [join(SRC, "index.ts")],
    bundle: true,
    write: false,
    platform: "node",
    format: "esm",
    target: "node22",
    // The host's own SDK is resolved by OpenClaw at load time, never bundled.
    external: ["openclaw", "openclaw/*"],
    legalComments: "none",
    banner: { js: `${BANNER_PREFIX}${sourceFingerprint()} */` },
  });
  return result.outputFiles[0].text;
}

const text = await bundleText();
if (process.argv.includes("--check")) {
  const current = (() => { try { return readFileSync(BUNDLE, "utf8"); } catch { return ""; } })();
  const stale = current !== text || RUNTIME_FILES.some((name) => {
    try { return !readFileSync(join(DIST, name)).equals(readFileSync(join(SRC, name))); } catch { return true; }
  });
  if (stale) {
    console.error("dist/ is not what src/ builds to — run `npm run build` and commit dist/.");
    process.exit(1);
  }
  console.log("dist/ is up to date.");
} else {
  mkdirSync(DIST, { recursive: true });
  const { writeFileSync } = await import("node:fs");
  writeFileSync(BUNDLE, text, "utf8");
  for (const name of RUNTIME_FILES) copyFileSync(join(SRC, name), join(DIST, name));
  console.log(`built dist/index.js (${text.length} bytes) from src/ ${sourceFingerprint().slice(0, 12)}`);
}
