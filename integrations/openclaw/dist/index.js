/* @umanitek/blackbox-openclaw — built from src/ by `npm run build`; do not edit. source sha256:f04a6ebcc0bb67f3f4d1ada3f2161ba062be422f582affd92b3000e2a1c4d43f */

// src/consent.ts
import { readFileSync } from "node:fs";
import { join } from "node:path";
var RECORD_FILE = "sharing_consent.json";
function sharingConsentInForce(blackboxHome) {
  let raw;
  try {
    raw = JSON.parse(readFileSync(join(blackboxHome, RECORD_FILE), "utf8"));
  } catch {
    return false;
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return false;
  const record = raw;
  const text = (value) => typeof value === "string" ? value : "";
  return text(record.accepted_at) !== "" && text(record.withdrawn_at) === "";
}

// src/membership.ts
var RETRY_MS = 6e5;
var FAILED_RETRY_MS = 6e4;
function includesSharedMemory(reply) {
  const catchup = reply?.catchup;
  if (!catchup || typeof catchup !== "object") return true;
  return (catchup.includeSharedMemory ?? catchup.includeWorkspace) !== false;
}
async function ensureCommunitySubscription(client, graph, state, log, now = Date.now()) {
  if (!graph) return false;
  if (state.confirmedAt !== void 0 && now - state.confirmedAt < RETRY_MS) return true;
  if (state.lastAttemptAt !== void 0 && now - state.lastAttemptAt < FAILED_RETRY_MS) return false;
  state.lastAttemptAt = now;
  try {
    if (state.withSharedMemory) {
      const listed = (await client.contextGraphs()).find((e) => e.id === graph);
      if (listed?.subscribed) {
        state.confirmedAt = now;
        return true;
      }
    }
    const reply = await client.subscribeContextGraph(graph, true);
    if (!includesSharedMemory(reply)) return true;
    state.withSharedMemory = true;
    state.confirmedAt = now;
    return true;
  } catch (err) {
    log(`blackbox: subscribe with shared memory failed (retry in ${FAILED_RETRY_MS / 1e3}s): ${err.message}`);
    return false;
  }
}

// src/reportEvidence.ts
var FETCH_TOOL_PREFIXES = ["web_", "browser_"];
function isFetchTool(toolName) {
  return FETCH_TOOL_PREFIXES.some((p) => (toolName ?? "").startsWith(p));
}
function injectionContext(event, toolName) {
  if (event === "post_tool_call") return isFetchTool(toolName) ? "in-fetched-page" : "in-tool-output";
  if (event === "before_agent_run" || event === "message_received") return "in-user-prompt";
  return void 0;
}
function iocContext(event, toolName) {
  if (event === "post_tool_call") return isFetchTool(toolName) ? "fetched-by-tool" : "in-tool-output";
  if (event === "before_tool_call") return isFetchTool(toolName) ? "fetched-by-tool" : "in-prompt";
  if (event === "before_agent_run" || event === "message_received") return "in-prompt";
  return void 0;
}
function evidenceFor(finding, event, toolName) {
  const f = finding.fields;
  switch (finding.category) {
    case "injection":
      return { context: injectionContext(event, toolName), owasp_category: f.owaspCategory };
    case "escalation":
      return { tool_name: f.toolName, arg_shape: f.argShape };
    case "dependency":
      return {
        ecosystem: f.ecosystem,
        package_name: f.packageName,
        package_version: f.packageVersion,
        advisory_id: f.advisoryId,
        kind: finding.kind ?? f.kind,
        reason: f.reason ?? (f.advisoryId ? `advisory:${f.advisoryId}` : void 0)
      };
    case "fileaccess":
      return { tool_name: f.toolName, file_category: f.fileCategory };
    case "skill":
      return f.artifactHash ? { artifact_hash: f.artifactHash, danger_shape: f.dangerShape } : { registry: f.registry, skill_name: f.skillName, skill_version: f.skillVersion };
    case "ioc":
      return { ioc_type: f.iocType, ioc_context: iocContext(event, toolName) };
    default:
      return {};
  }
}

// src/detection.ts
import { createHash as createHash2 } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// src/shellFiles.ts
var READ_COMMANDS = /* @__PURE__ */ new Set([
  "cat",
  "less",
  "more",
  "head",
  "tail",
  "bat",
  "xxd",
  "hexdump",
  "strings",
  "od",
  "nl",
  "base64",
  "base32",
  "sqlite3",
  "jq",
  "awk",
  "gawk",
  "sed",
  "sort",
  "uniq",
  "wc",
  "cut",
  "paste",
  "rev",
  "tac",
  "column",
  "fold",
  "iconv",
  "diff",
  "cmp",
  "md5",
  "md5sum",
  "shasum",
  "sha1sum",
  "sha256sum",
  "file",
  "zcat",
  "gzcat",
  "bzcat",
  "xzcat",
  "zless",
  "vim",
  "vi",
  "view",
  "nano",
  "emacs",
  "open",
  "xdg-open",
  "code",
  "pbcopy",
  "type",
  "get-content",
  "gc"
]);
var UPLOAD_COMMANDS = /* @__PURE__ */ new Set(["curl", "wget", "http", "https"]);
var UPLOAD_FILE_OPTIONS = /* @__PURE__ */ new Set(["-T", "--upload-file", "--post-file", "--body-file"]);
var ASSIGNMENT = /^([A-Za-z_][A-Za-z0-9_]*)=([\s\S]*)$/;
var VARIABLE_USE = /\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))/g;
var NAMING_COMMANDS = /* @__PURE__ */ new Set(["echo", "printf"]);
var RECURSIVE_COMMANDS = /* @__PURE__ */ new Set([
  "cp",
  "scp",
  "rsync",
  "tar",
  "zip",
  "7z",
  "7za",
  "rar",
  "ditto",
  "mv",
  "gzip",
  "rg",
  "ln",
  "link",
  "copy",
  "xcopy",
  "robocopy",
  "copy-item",
  "cpi",
  "compress-archive",
  "move-item"
]);
var RECURSIVE_WITH_FLAG = {
  grep: ["-r", "-R", "--recursive"],
  egrep: ["-r", "-R"],
  fgrep: ["-r", "-R"]
};
var SEPARATORS = /* @__PURE__ */ new Set([";", "&&", "||", "|", "&", ">", ">>", "<", "|&"]);
var COPY_COMMANDS = /* @__PURE__ */ new Set([
  "cp",
  "scp",
  "rsync",
  "mv",
  "ditto",
  "copy",
  "xcopy",
  "robocopy",
  "copy-item",
  "cpi",
  "move-item",
  "ln",
  "link"
]);
var ARCHIVE_FIRST = /* @__PURE__ */ new Set(["zip", "7z", "7za", "rar"]);
var INTERPRETERS = {
  python: ["-c"],
  python3: ["-c"],
  python2: ["-c"],
  py: ["-c"],
  node: ["-e", "--eval", "-p", "--print"],
  nodejs: ["-e", "--eval", "-p", "--print"],
  bun: ["-e", "--eval"],
  deno: ["eval"],
  ruby: ["-e"],
  perl: ["-e", "-E"],
  php: ["-r"],
  osascript: ["-e"]
};
var LITERAL = /(['"`])((?:\\.|(?!\1).){1,1024}?)\1/g;
var WHOLE_FOLDER_CODE = /copytree|make_archive|tarfile|zipfile|os\.walk|\bwalk\(|rglob|glob\(|readdirSync|readdir\(|cpSync|archiver|ZipFile|Dir\.glob|File\.find/;
var HOME_CODE = /homedir\(|expanduser|Path\.home|environ\[.HOME.\]|getenv\(.HOME.\)|env\.HOME|ENV\[.HOME.\]|Dir\.home/;
var HEREDOC = /^[^\n]*?\b(python[23]?|node|ruby|perl|php|bun)\b[^\n]*<<-?\s*(['"]?)(\w+)\2[^\n]*\n([\s\S]*?)\n\s*\3\s*$/gm;
var FIND_EXEC = /* @__PURE__ */ new Set(["-exec", "-execdir", "-ok", "-okdir"]);
var WINDOWS_PATH = /[A-Za-z]:\\|%[A-Za-z_]+%\\/;
var WHITESPACE = " 	\r\n";
var PUNCTUATION = ";&|<>";
var QUOTES = `'"`;
var SplitError = class extends Error {
};
var ShlexReader = class {
  position = 0;
  pushback = [];
  state = " ";
  token = "";
  quoted = false;
  escapedState = " ";
  command;
  posix;
  // Plain fields, not constructor parameter properties: Node's type stripping (how the parity
  // test loads this file without a build) only accepts syntax it can erase.
  constructor(command, posix) {
    this.command = command;
    this.posix = posix;
  }
  /** Every word of the command, in order. */
  words() {
    const out = [];
    for (; ; ) {
      const word = this.readWord();
      if (word !== null) out.push(word);
      if (this.state === null) return out;
    }
  }
  /** The next word, or null when nothing was read (the end, or only a comment). */
  readWord() {
    this.token = "";
    this.quoted = false;
    this.escapedState = " ";
    while (!this.step(this.read())) {
    }
    const empty = this.token === "" && !(this.posix && this.quoted);
    return empty ? null : this.token;
  }
  read() {
    return this.pushback.pop() ?? (this.position < this.command.length ? this.command[this.position++] : "");
  }
  skipLine() {
    const end = this.command.indexOf("\n", this.position);
    this.position = end === -1 ? this.command.length : end + 1;
  }
  /** True when a word boundary ends a word that has content (an empty quoted word counts in POSIX mode). */
  wordIsComplete() {
    return this.token !== "" || this.posix && this.quoted;
  }
  step(next) {
    if (this.state === null) {
      this.token = "";
      return true;
    }
    if (this.state === " ") return this.betweenWords(next);
    if (QUOTES.includes(this.state)) return this.insideQuote(next, this.state);
    if (this.state === "\\") return this.afterBackslash(next, this.state);
    return this.insideWord(next);
  }
  betweenWords(next) {
    if (!next) {
      this.state = null;
      return true;
    }
    if (WHITESPACE.includes(next)) return this.wordIsComplete();
    if (next === "#") {
      this.skipLine();
      return false;
    }
    if (this.posix && next === "\\") {
      this.escapedState = "a";
      this.state = next;
      return false;
    }
    if (PUNCTUATION.includes(next)) {
      this.token = next;
      this.state = "c";
      return false;
    }
    if (QUOTES.includes(next)) {
      if (!this.posix) this.token = next;
      this.state = next;
      return false;
    }
    this.token = next;
    this.state = "a";
    return false;
  }
  insideQuote(next, quote) {
    this.quoted = true;
    if (!next) throw new SplitError("No closing quotation");
    if (next === quote) {
      if (this.posix) {
        this.state = "a";
        return false;
      }
      this.token += next;
      this.state = " ";
      return true;
    }
    if (this.posix && next === "\\" && quote === '"') {
      this.escapedState = quote;
      this.state = next;
      return false;
    }
    this.token += next;
    return false;
  }
  afterBackslash(next, backslash) {
    if (!next) throw new SplitError("No escaped character");
    if (QUOTES.includes(this.escapedState) && next !== backslash && next !== this.escapedState) this.token += backslash;
    this.token += next;
    this.state = this.escapedState;
    return false;
  }
  /** In a word ("a") or a run of punctuation ("c"). */
  insideWord(next) {
    if (!next) {
      this.state = null;
      return true;
    }
    if (WHITESPACE.includes(next)) {
      this.state = " ";
      return this.wordIsComplete();
    }
    if (next === "#") return this.commentInWord();
    if (this.state === "c") return this.insidePunctuation(next);
    if (this.posix && QUOTES.includes(next)) {
      this.state = next;
      return false;
    }
    if (this.posix && next === "\\") {
      this.escapedState = "a";
      this.state = next;
      return false;
    }
    if (!PUNCTUATION.includes(next)) {
      this.token += next;
      return false;
    }
    this.pushback.push(next);
    this.state = " ";
    return this.wordIsComplete();
  }
  commentInWord() {
    this.skipLine();
    if (!this.posix) return false;
    this.state = " ";
    return this.wordIsComplete();
  }
  insidePunctuation(next) {
    if (PUNCTUATION.includes(next)) {
      this.token += next;
      return false;
    }
    this.pushback.push(next);
    this.state = " ";
    return true;
  }
};
function shlexSplit(command, posix) {
  return new ShlexReader(command, posix).words();
}
function stripQuotes(word) {
  return word.replace(/^["']+|["']+$/g, "");
}
function splitWords(command) {
  try {
    if (WINDOWS_PATH.test(command)) return shlexSplit(command, false).map(stripQuotes);
    return shlexSplit(command, true);
  } catch (error) {
    if (!(error instanceof SplitError)) throw error;
    return command.split(/\s+/).filter(Boolean);
  }
}
function baseName(word) {
  return word.slice(word.lastIndexOf("/") + 1).toLowerCase();
}
function looksLikePath(word) {
  return word.includes("/") || word.includes("\\") || /^(?:~|\.|\$HOME|%)/.test(word) || word.includes(".");
}
function isAlpha(word) {
  return new RegExp("^\\p{L}+$", "u").test(word);
}
function segmentEnd(words, start) {
  let end = start;
  while (end < words.length && !SEPARATORS.has(words[end])) end += 1;
  return end;
}
function readsFiles(name) {
  return READ_COMMANDS.has(name) || RECURSIVE_COMMANDS.has(name) || name in RECURSIVE_WITH_FLAG;
}
function isAnchored(path2) {
  return /^(?:\/|~|\$HOME|%)/.test(path2) || /^[A-Za-z]:[\\/]/.test(path2);
}
function withoutDotSlash(path2) {
  return path2.startsWith("./") ? path2.slice(2) : path2;
}
function trimTrailingSlashes(path2) {
  return path2.replace(/\/+$/, "");
}
function destinations(name, args, paths) {
  if (COPY_COMMANDS.has(name)) {
    for (let i = 0; i + 1 < args.length; i += 1) {
      if (args[i] === "-t" || args[i] === "--target-directory") return /* @__PURE__ */ new Set([args[i + 1]]);
    }
    const target = args.find((word) => word.startsWith("--target-directory="));
    if (target) return /* @__PURE__ */ new Set([target.slice(target.indexOf("=") + 1)]);
    return paths.length >= 2 ? /* @__PURE__ */ new Set([paths[paths.length - 1]]) : /* @__PURE__ */ new Set();
  }
  if (name === "tar") {
    const clusters = args.filter((word, position) => word.startsWith("-") && !word.startsWith("--") || position === 0 && isAlpha(word)).map((word) => word.replace(/^-+/, ""));
    if (clusters.some((cluster) => /[xt]/.test(cluster)) || args.some((word) => ["--extract", "--list", "--get"].includes(word))) {
      return /* @__PURE__ */ new Set();
    }
    for (let i = 0; i + 1 < args.length; i += 1) {
      const flag = args[i];
      const letters = flag.replace(/^-+/, "");
      if (!flag.startsWith("--") && letters.includes("f") && isAlpha(letters)) return /* @__PURE__ */ new Set([args[i + 1]]);
    }
    return /* @__PURE__ */ new Set();
  }
  if (ARCHIVE_FIRST.has(name)) {
    if (paths.length === 0) return /* @__PURE__ */ new Set();
    if (args.slice(0, args.indexOf(paths[0])).includes("-")) return /* @__PURE__ */ new Set();
    return /* @__PURE__ */ new Set([paths[0]]);
  }
  if (name === "compress-archive") {
    const position = args.map((word) => word.toLowerCase()).indexOf("-destinationpath");
    if (position !== -1) return position + 1 < args.length ? /* @__PURE__ */ new Set([args[position + 1]]) : /* @__PURE__ */ new Set();
  }
  return /* @__PURE__ */ new Set();
}
function withVariables(words) {
  const values = /* @__PURE__ */ new Map();
  return words.map((word) => {
    const assignment = ASSIGNMENT.exec(word);
    if (assignment) {
      values.set(assignment[1], assignment[2]);
      return word;
    }
    if (values.size === 0 || !word.includes("$")) return word;
    return word.replace(VARIABLE_USE, (whole, braced, bare) => values.get(braced ?? bare ?? "") ?? whole);
  });
}
function redirectedIn(words, index) {
  if (index + 1 >= words.length || SEPARATORS.has(words[index + 1])) return [[], index + 1];
  return [[{ path: words[index + 1], command: "<", recursive: false, destination: false }], index + 2];
}
function xargsArgs(words, index, named) {
  const end = segmentEnd(words, index + 1);
  const command = words.slice(index + 1, end).find((word) => !word.startsWith("-") && word !== "{}") ?? "";
  const reader = baseName(command);
  if (!readsFiles(reader)) return [[], end];
  const recursive = RECURSIVE_COMMANDS.has(reader);
  return [named.filter(looksLikePath).map((word) => ({ path: word, command: reader, recursive, destination: false })), end];
}
function uploadArgs(name, args) {
  const paths = [];
  args.forEach((word, position) => {
    if (word.startsWith("file://")) paths.push(word.slice("file://".length));
    else if (word.includes("@") && !word.startsWith("-") && (word.startsWith("@") || word.includes("=@"))) paths.push(word.slice(word.indexOf("@") + 1));
    else if (UPLOAD_FILE_OPTIONS.has(word) && position + 1 < args.length) paths.push(args[position + 1]);
  });
  return paths.filter(Boolean).map((path2) => ({ path: path2, command: name, recursive: false, destination: false }));
}
function commandArgs(name, words, index, inKnownFolder = false) {
  if (UPLOAD_COMMANDS.has(name)) {
    const stop = segmentEnd(words, index + 1);
    return [uploadArgs(name, words.slice(index + 1, stop)), stop];
  }
  if (name === "dd") {
    const stop = segmentEnd(words, index + 1);
    const inputs = words.slice(index + 1, stop).filter((word) => word.startsWith("if=") && word.length > 3);
    return [inputs.map((word) => ({ path: word.slice(3), command: "dd", recursive: false, destination: false })), stop];
  }
  const reads = READ_COMMANDS.has(name);
  let recursive = RECURSIVE_COMMANDS.has(name);
  const flags = RECURSIVE_WITH_FLAG[name];
  if (!(reads || recursive || flags)) return [[], index + 1];
  const end = segmentEnd(words, index + 1);
  const args = words.slice(index + 1, end);
  if (flags) {
    recursive = args.some((word) => flags.includes(word) || word.startsWith("-") && !word.startsWith("--") && /[rR]/.test(word));
  }
  const oldStyleTarFlags = name === "tar" && args.length > 0 && isAlpha(args[0]);
  const paths = args.filter((word, position) => !word.startsWith("-") && !(oldStyleTarFlags && position === 0) && (looksLikePath(word) || (RECURSIVE_COMMANDS.has(name) || inKnownFolder) && word !== "{}"));
  const written = destinations(name, args, paths);
  return [paths.map((word) => ({ path: word, command: name, recursive, destination: written.has(word) })), end];
}
function xargsFeedsAReader(words, position) {
  if (position >= words.length || words[position] !== "|") return false;
  const xargs = position + 1;
  if (xargs >= words.length || words[xargs].slice(words[xargs].lastIndexOf("/") + 1) !== "xargs") return false;
  const command = words.slice(xargs + 1, segmentEnd(words, xargs + 1)).find((word) => !word.startsWith("-") && word !== "{}") ?? "";
  return readsFiles(baseName(command));
}
function findArgs(words, index) {
  let position = index + 1;
  const roots = [];
  while (position < words.length && !/^[-(!]/.test(words[position]) && !SEPARATORS.has(words[position])) {
    roots.push(words[position]);
    position += 1;
  }
  let feedsAReader = false;
  while (position < words.length && (words[position] === ";" || !SEPARATORS.has(words[position]))) {
    if (FIND_EXEC.has(words[position]) && position + 1 < words.length) {
      feedsAReader = feedsAReader || readsFiles(baseName(words[position + 1]));
      while (position < words.length && words[position] !== ";" && words[position] !== "+") position += 1;
    } else if (words[position] === ";") {
      break;
    }
    position += 1;
  }
  feedsAReader = feedsAReader || xargsFeedsAReader(words, position);
  if (!feedsAReader) return [[], position];
  return [roots.map((root) => ({ path: root, command: "find", recursive: true, destination: false })), position];
}
function pathsInCode(interpreter, code) {
  const recursive = WHOLE_FOLDER_CODE.test(code);
  const joinsHome = HOME_CODE.test(code);
  const found = [];
  for (const match of code.matchAll(LITERAL)) {
    const literal2 = match[2];
    if (literal2.includes("://") || !(literal2.includes("/") || literal2.includes("\\") || literal2.startsWith("~"))) continue;
    found.push({ path: literal2, command: interpreter, recursive, destination: false });
    if (joinsHome && !/^[/~$%]/.test(literal2) && !/^[A-Za-z]:/.test(literal2)) {
      found.push({ path: "~/" + withoutDotSlash(literal2), command: interpreter, recursive, destination: false });
    }
  }
  return found;
}
function scriptArgs(name, words, index) {
  const end = segmentEnd(words, index + 1);
  const options = INTERPRETERS[name];
  const found = [];
  for (let position = index + 1; position < end - 1; position += 1) {
    if (options.includes(words[position])) found.push(...pathsInCode(name, words[position + 1]));
  }
  return [found, end];
}
function cd(words, index, folder) {
  const end = segmentEnd(words, index + 1);
  const targets = words.slice(index + 1, end).filter((word) => !word.startsWith("-") || word === "-");
  const target = targets[0] ?? "~";
  if (target === "-" || target.startsWith("$") && !target.startsWith("$HOME")) return ["", end];
  if (isAnchored(target)) return [trimTrailingSlashes(target) || "/", end];
  return [folder ? trimTrailingSlashes(folder) + "/" + target : "", end];
}
var HOME_VARIABLE = /^(?:\$HOME(?![A-Za-z0-9_])|\$\{HOME\}|%USERPROFILE%)/;
function homeAsTilde(path2) {
  return path2.replace(HOME_VARIABLE, "~");
}
function fromFolder(arg, folder) {
  let path2 = arg.path;
  if (folder && !isAnchored(path2)) {
    const relative = withoutDotSlash(path2);
    path2 = relative === "." || relative === "" ? folder : trimTrailingSlashes(folder) + "/" + relative;
  }
  path2 = homeAsTilde(path2);
  return path2 === arg.path ? arg : { ...arg, path: path2 };
}
function shellFileArgs(command) {
  if (!command) return [];
  const words = withVariables(splitWords(command));
  const out = [];
  const seen = /* @__PURE__ */ new Set();
  let folder = "";
  let named = [];
  const keep = (found) => {
    for (const each of found) {
      const arg = fromFolder(each, folder);
      if (!seen.has(arg.path)) {
        seen.add(arg.path);
        out.push(arg);
      }
    }
  };
  let index = 0;
  while (index < words.length) {
    const name = baseName(words[index]);
    let found;
    if (name === "cd" || name === "pushd") {
      [folder, index] = cd(words, index, folder);
      continue;
    }
    if (name === "find") [found, index] = findArgs(words, index);
    else if (name in INTERPRETERS) [found, index] = scriptArgs(name, words, index);
    else if (name === "<") [found, index] = redirectedIn(words, index);
    else if (NAMING_COMMANDS.has(name)) {
      const end = segmentEnd(words, index + 1);
      named = words.slice(index + 1, end);
      found = [];
      index = end;
    } else if (name === "xargs") [found, index] = xargsArgs(words, index, named);
    else [found, index] = commandArgs(name, words, index, Boolean(folder));
    keep(found);
  }
  for (const match of command.matchAll(HEREDOC)) keep(pathsInCode(match[1], match[4]));
  return out;
}
function codeFileArgs(code, language = "python") {
  return pathsInCode(language, code || "").map((arg) => fromFolder(arg, ""));
}

// src/signing.ts
import { createPublicKey, sign as cryptoSign } from "node:crypto";
var ENVELOPE_VERSION = 2;
var MAX_ENVELOPE_CHARS = 4096;
var REPORT_STATEMENT = "blackbox.report";
var STATEMENT_SCHEMA_VERSION = 1;
var DOMAIN_TAG = "blackbox-signed-statement\n";
function canonicalJson(value) {
  const sorted = (v) => {
    if (Array.isArray(v)) return v.map(sorted);
    if (v && typeof v === "object") {
      const out = {};
      for (const key of Object.keys(v).sort()) out[key] = sorted(v[key]);
      return out;
    }
    return v;
  };
  return JSON.stringify(sorted(value)).replace(/[^\x00-\x7f]/g, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, "0")}`);
}
function publicKeyHex(key) {
  const spki = createPublicKey(key).export({ type: "spki", format: "der" });
  return spki.subarray(spki.length - 32).toString("hex");
}
function domainDocument(domain, payload) {
  return {
    v: ENVELOPE_VERSION,
    type: domain.statementType,
    env: domain.environment,
    graph: domain.graph,
    chain: domain.chain ?? "",
    epoch: domain.rootEpoch ?? 0,
    seq: domain.sequence ?? 0,
    schema: domain.schemaVersion ?? STATEMENT_SCHEMA_VERSION,
    payload: { ...payload }
  };
}
function signedMessage(domain, payload) {
  return Buffer.concat([Buffer.from(DOMAIN_TAG, "ascii"), Buffer.from(canonicalJson(domainDocument(domain, payload)), "ascii")]);
}
function signEnvelope(privateKey, domain, payload) {
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
var ReportSigner = class {
  constructor(privateKey, environment, graph) {
    this.privateKey = privateKey;
    this.environment = environment;
    this.graph = graph;
  }
  sign(statementType, payload) {
    return signEnvelope(this.privateKey, { statementType, environment: this.environment, graph: this.graph }, payload);
  }
  get signerHex() {
    return publicKeyHex(this.privateKey);
  }
};

// src/quads.ts
import { createHash } from "node:crypto";
var SEVERITY_RANK = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};
var BLACKBOX_ONTOLOGY = "http://umanitek.ai/ontology/guardian/";
var BLACKBOX_THREAT_TYPE_IRI = `${BLACKBOX_ONTOLOGY}Threat`;
var BLACKBOX_DEP_THREAT_TYPE_IRI = `${BLACKBOX_ONTOLOGY}VulnerabilityAdvisory`;
var BLACKBOX_INJECTION_THREAT_TYPE_IRI = `${BLACKBOX_ONTOLOGY}PromptInjectionThreat`;
var BLACKBOX_ESCALATION_THREAT_TYPE_IRI = `${BLACKBOX_ONTOLOGY}EscalationThreat`;
var BLACKBOX_FILE_ACCESS_THREAT_TYPE_IRI = `${BLACKBOX_ONTOLOGY}FileAccessThreat`;
var BLACKBOX_SUSPICIOUS_SKILL_THREAT_TYPE_IRI = `${BLACKBOX_ONTOLOGY}SuspiciousSkillThreat`;
var BLACKBOX_REPORT_TYPE_IRI = `${BLACKBOX_ONTOLOGY}ThreatReport`;
var BLACKBOX_IDENTIFIER_PRED = `${BLACKBOX_ONTOLOGY}identifier`;
var BLACKBOX_CURATED_PRED = `${BLACKBOX_ONTOLOGY}curated`;
var BLACKBOX_SEVERITY_PRED = `${BLACKBOX_ONTOLOGY}severity`;
var BLACKBOX_PATTERN_PRED = `${BLACKBOX_ONTOLOGY}pattern`;
var BLACKBOX_TOOL_NAME_PRED = `${BLACKBOX_ONTOLOGY}toolName`;
var BLACKBOX_ARG_SHAPE_PRED = `${BLACKBOX_ONTOLOGY}argShape`;
var BLACKBOX_OWASP_CATEGORY_PRED = `${BLACKBOX_ONTOLOGY}owaspCategory`;
var BLACKBOX_REPORTS_THREAT_PRED = `${BLACKBOX_ONTOLOGY}reportsThreat`;
var BLACKBOX_REPORTER_PRED = `${BLACKBOX_ONTOLOGY}reporter`;
var BLACKBOX_FRAMEWORK_PRED = `${BLACKBOX_ONTOLOGY}framework`;
var BLACKBOX_PACKAGE_NAME_PRED = `${BLACKBOX_ONTOLOGY}packageName`;
var BLACKBOX_PACKAGE_VERSION_PRED = `${BLACKBOX_ONTOLOGY}packageVersion`;
var BLACKBOX_PACKAGE_ECOSYSTEM_PRED = `${BLACKBOX_ONTOLOGY}packageEcosystem`;
var BLACKBOX_KIND_PRED = `${BLACKBOX_ONTOLOGY}kind`;
var KIND_VULNERABILITY = "vulnerability";
var BLACKBOX_CATEGORY_PRED = `${BLACKBOX_ONTOLOGY}category`;
var BLACKBOX_SKILL_NAME_PRED = `${BLACKBOX_ONTOLOGY}skillName`;
var BLACKBOX_SKILL_VERSION_PRED = `${BLACKBOX_ONTOLOGY}skillVersion`;
var BLACKBOX_DANGER_SHAPE_PRED = `${BLACKBOX_ONTOLOGY}dangerShape`;
var BLACKBOX_INJECTION_CONTEXT_PRED = `${BLACKBOX_ONTOLOGY}injectionContext`;
var BLACKBOX_SKILL_ARTIFACT_HASH_PRED = `${BLACKBOX_ONTOLOGY}skillArtifactHash`;
var BLACKBOX_SKILL_REGISTRY_PRED = `${BLACKBOX_ONTOLOGY}skillRegistry`;
var BLACKBOX_IOC_TYPE_PRED = `${BLACKBOX_ONTOLOGY}iocType`;
var BLACKBOX_IOC_CONTEXT_PRED = `${BLACKBOX_ONTOLOGY}iocContext`;
var BLACKBOX_REPORT_REASON_PRED = `${BLACKBOX_ONTOLOGY}reportReason`;
var BLACKBOX_SIGNED_STATEMENT_PRED = `${BLACKBOX_ONTOLOGY}signedStatement`;
var DEFENDER_CORRECTION_TYPE_IRI = "urn:defender:CorrectionSignal";
var DEFENDER_CORRECTION_TARGET_PRED = "urn:defender:p:targetSubject";
var DEFENDER_CORRECTION_ACTION_PRED = "urn:defender:p:action";
var DEFENDER_CORRECTION_SUPPRESS = "suppress";
var RDF_TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
var SCHEMA_NAME = "http://schema.org/name";
var SCHEMA_DESCRIPTION = "http://schema.org/description";
var SCHEMA_DATE_MODIFIED = "http://schema.org/dateModified";
var SCHEMA_IDENTIFIER = "http://schema.org/identifier";
var XSD_DATETIME = "http://www.w3.org/2001/XMLSchema#dateTime";
var MAX_LITERAL_BYTES = 5e4;
var TRUNCATION_MARKER = " ...[truncated]";
function stableHash(value, length = 24) {
  return createHash("sha256").update(value, "utf8").digest("hex").slice(0, length);
}
function slug(value) {
  const lowered = String(value).toLowerCase().replace(/[^a-z0-9._-]+/g, "-");
  const trimmed = lowered.replace(/^-+|-+$/g, "").slice(0, 96);
  return trimmed || "unknown";
}
function normalizeSeverity(value, fallback = "info") {
  const raw = String(value ?? "").trim().toLowerCase();
  if (raw === "moderate") return "medium";
  return raw in SEVERITY_RANK ? raw : fallback;
}
function threatUri(identifier) {
  return `urn:guardian:threat:${slug(identifier)}`;
}
var EVM_ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/;
function isAgentAddress(value) {
  return EVM_ADDRESS_RE.test(String(value ?? "").trim());
}
function reportUri(identifier, agentAddress) {
  if (!isAgentAddress(agentAddress)) throw new Error("a report subject needs a resolved reporter address");
  const addr = agentAddress.trim().toLowerCase();
  return `urn:guardian:report:${addr}:${stableHash(identifier, 16)}`;
}
function canonicalPackageName(ecosystem, name) {
  const canon = name.trim().toLowerCase();
  return ecosystem.trim().toLowerCase() === "pypi" ? canon.replace(/[-_.]+/g, "-") : canon;
}
function dependencyIdentifier(ecosystem, name, version) {
  const eco = ecosystem.trim().toLowerCase();
  return `dep:${eco}:${canonicalPackageName(eco, name)}@${version.trim()}`;
}
function skillArtifactIdentifier(artifactHash, dangerShape) {
  return `skill:artifact:${artifactHash.trim().toLowerCase()}:${dangerShape.trim().toLowerCase()}`;
}
function injectionIdentifier(pattern) {
  return `injection:${stableHash(pattern, 24)}`;
}
function escalationIdentifier(toolName, argShape) {
  return `escalation:${toolName.trim().toLowerCase()}:${argShape.trim()}`;
}
function fileaccessIdentifierFor(toolName, category) {
  return `fileaccess:${toolName.trim().toLowerCase()}:${category.trim().toLowerCase()}`;
}
function skillVersionIdentifierFor(name, version) {
  return `skill:${name.trim().toLowerCase()}@${version.trim()}`;
}
function skillShapeIdentifierFor(name, dangerShape) {
  return `skill:${name.trim().toLowerCase()}:${dangerShape.trim()}`;
}
function canonicalIp(raw) {
  if ((raw.match(/:/g) || []).length < 2) return raw.split(":", 1)[0];
  let candidate = raw;
  if (candidate.startsWith("[")) candidate = candidate.slice(1).split("]", 1)[0];
  candidate = candidate.split("%", 1)[0].toLowerCase();
  if (!/^[0-9a-f:.]+$/.test(candidate) || candidate.includes(":::")) return raw;
  const halves = candidate.split("::");
  if (halves.length > 2) return raw;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const groups = [...head, ...tail];
  const last = groups[groups.length - 1];
  if (last && last.includes(".")) {
    const octets = last.split(".").map((o) => Number(o));
    if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) return raw;
    groups.splice(groups.length - 1, 1, (octets[0] << 8 | octets[1]).toString(16), (octets[2] << 8 | octets[3]).toString(16));
    if (halves.length === 2 && halves[1]) tail.splice(tail.length - 1, 1, groups[groups.length - 2], groups[groups.length - 1]);
  }
  if (groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return raw;
  const missing = 8 - groups.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return raw;
  const headGroups = halves.length === 2 ? head : groups;
  const full = halves.length === 2 ? [...headGroups, ...Array(missing).fill("0"), ...tail.map((g) => g)] : groups;
  const words = full.map((g) => parseInt(g, 16));
  if (words.slice(0, 5).every((w) => w === 0) && words[5] === 65535) {
    return `::ffff:${words[6] >> 8}.${words[6] & 255}.${words[7] >> 8}.${words[7] & 255}`;
  }
  let bestStart = -1, bestLen = 0;
  for (let i = 0; i < words.length; ) {
    if (words[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < words.length && words[j] === 0) j++;
    if (j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = words.map((w) => w.toString(16));
  if (bestLen < 2) return hex.join(":");
  const left = hex.slice(0, bestStart).join(":");
  const right = hex.slice(bestStart + bestLen).join(":");
  return `${left}::${right}`;
}
function normalizeIocValue(iocType, value) {
  const type = (iocType || "").trim().toLowerCase();
  let raw = String(value || "").trim();
  if (!raw) return "";
  if (type === "domain") return raw.replace(/\.+$/, "").toLowerCase();
  if (type === "url") {
    const parts = raw.split("://", 2);
    if (parts.length === 2) {
      const slash = parts[1].indexOf("/");
      const host = (slash >= 0 ? parts[1].slice(0, slash) : parts[1]).toLowerCase();
      const rest = slash >= 0 ? parts[1].slice(slash) : "";
      raw = `${parts[0].toLowerCase()}://${host}${rest}`;
    }
    return raw.replace(/\/+$/, "");
  }
  if (type === "ip") return canonicalIp(raw);
  if (type === "hash") return raw.toLowerCase();
  if (type === "wallet" || type === "contract") {
    return /^0x[a-fA-F0-9]{40}$/.test(raw) ? raw.toLowerCase() : raw;
  }
  return raw;
}
var HOST_SHAPE = "(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.){1,16}[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?";
var IPV4_SHAPE = "(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)";
var IOC_VALUE_SHAPES = {
  domain: new RegExp(`^${HOST_SHAPE}$`),
  url: new RegExp(`^https?://(?:${HOST_SHAPE}|${IPV4_SHAPE})(?::\\d{1,5})?(?:[/?#][^\\s<>"'\`\\\\^{}|\\[\\]]*)?$`),
  ip: new RegExp(`^${IPV4_SHAPE}$`),
  // bare hex, or algorithm-prefixed at that algorithm's length (KI-354, mirrors Python).
  hash: /^(?:md5:[a-f0-9]{32}|sha1:[a-f0-9]{40}|sha256:[a-f0-9]{64}|sha512:[a-f0-9]{128}|[a-f0-9]{32,128})$/,
  wallet: /^[A-Za-z0-9]{20,128}$/,
  contract: /^[A-Za-z0-9]{20,128}$/
};
var MAX_IOC_VALUE_CHARS = 2048;
function iocValueIsWellFormed(iocType, value) {
  const kind = (iocType || "").trim().toLowerCase();
  const shape = IOC_VALUE_SHAPES[kind];
  if (!shape || !value || value.length > MAX_IOC_VALUE_CHARS) return false;
  if (kind === "ip" && value.includes(":")) return canonicalIp(value) === value && /^[0-9a-f:]+$/.test(value);
  if (kind === "domain" && value.length > 253) return false;
  return shape.test(value);
}
function iocIdentifier(iocType, value) {
  const type = (iocType || "").trim().toLowerCase();
  return `ioc:${type}:${normalizeIocValue(type, value)}`;
}
function q(subject, predicate, object) {
  return { subject, predicate, object };
}
function iri(value) {
  return value;
}
function literal(value) {
  return literalTermForValue(capLiteralValue(String(value)));
}
function javaModifiedUtf8ByteLength(value) {
  let bytes = 0;
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code === 0) bytes += 2;
    else if (code <= 127) bytes += 1;
    else if (code <= 2047) bytes += 2;
    else bytes += 3;
  }
  return bytes;
}
function escapeLiteralText(value) {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n").replace(/\r/g, "\\r").replace(/\t/g, "\\t");
}
function literalTermForValue(value) {
  return `"${escapeLiteralText(value)}"`;
}
function literalValueTermMutf8Bytes(value) {
  return javaModifiedUtf8ByteLength(literalTermForValue(value));
}
function capLiteralValue(value) {
  if (literalValueTermMutf8Bytes(value) <= MAX_LITERAL_BYTES) return value;
  const chars = Array.from(value);
  let lo = 0;
  let hi = chars.length;
  let best = TRUNCATION_MARKER;
  while (lo <= hi) {
    const mid = Math.floor((lo + hi) / 2);
    const candidate = `${chars.slice(0, mid).join("")}${TRUNCATION_MARKER}`;
    if (literalValueTermMutf8Bytes(candidate) <= MAX_LITERAL_BYTES) {
      best = candidate;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return best;
}
var EVIDENCE_FIELDS = {
  injection: [["context", BLACKBOX_INJECTION_CONTEXT_PRED], ["owasp_category", BLACKBOX_OWASP_CATEGORY_PRED]],
  escalation: [["tool_name", BLACKBOX_TOOL_NAME_PRED], ["arg_shape", BLACKBOX_ARG_SHAPE_PRED]],
  dependency: [
    ["package_name", BLACKBOX_PACKAGE_NAME_PRED],
    ["package_version", BLACKBOX_PACKAGE_VERSION_PRED],
    ["ecosystem", BLACKBOX_PACKAGE_ECOSYSTEM_PRED],
    ["advisory_id", SCHEMA_IDENTIFIER],
    ["kind", BLACKBOX_KIND_PRED],
    ["reason", BLACKBOX_REPORT_REASON_PRED]
  ],
  fileaccess: [["tool_name", BLACKBOX_TOOL_NAME_PRED], ["file_category", BLACKBOX_CATEGORY_PRED]],
  skill: [
    ["artifact_hash", BLACKBOX_SKILL_ARTIFACT_HASH_PRED],
    ["registry", BLACKBOX_SKILL_REGISTRY_PRED],
    ["skill_name", BLACKBOX_SKILL_NAME_PRED],
    ["skill_version", BLACKBOX_SKILL_VERSION_PRED],
    ["danger_shape", BLACKBOX_DANGER_SHAPE_PRED]
  ],
  ioc: [["ioc_type", BLACKBOX_IOC_TYPE_PRED], ["ioc_context", BLACKBOX_IOC_CONTEXT_PRED]]
};
function dayLiteral(ts) {
  const day = new Date(ts ?? Date.now()).toISOString().slice(0, 10);
  return { day, literal: `${literal(`${day}T00:00:00Z`)}^^${XSD_DATETIME}` };
}
function buildReportQuads(input) {
  const record = validateReport({
    identifier: input.identifier,
    category: input.category,
    severity: input.severity,
    framework: input.framework,
    evidence: input.evidence ?? {}
  });
  const subj = reportUri(record.identifier, input.reporter);
  const threat = threatUri(record.identifier);
  const reporter = input.reporter.trim().toLowerCase();
  const { day, literal: dayLit } = dayLiteral(input.ts);
  const values = Object.fromEntries(record.evidence);
  const fields = (EVIDENCE_FIELDS[record.category] ?? []).filter(([name]) => name in values).map(([name, pred]) => [name, pred, values[name]]);
  const out = [
    q(subj, RDF_TYPE, iri(BLACKBOX_REPORT_TYPE_IRI)),
    q(subj, BLACKBOX_REPORTS_THREAT_PRED, iri(threat)),
    q(subj, BLACKBOX_IDENTIFIER_PRED, literal(record.identifier)),
    q(subj, BLACKBOX_REPORTER_PRED, literal(reporter)),
    q(subj, BLACKBOX_FRAMEWORK_PRED, literal(record.framework)),
    q(subj, BLACKBOX_SEVERITY_PRED, literal(record.severity)),
    q(subj, SCHEMA_DATE_MODIFIED, dayLit)
  ];
  for (const [, pred, value] of fields) out.push(q(subj, pred, literal(value)));
  if (input.signer) {
    const payload = {
      subject: subj,
      identifier: record.identifier,
      category: record.category,
      severity: record.severity,
      reporter,
      framework: record.framework,
      day
    };
    for (const [name, , value] of fields) payload[name] = value;
    out.push(q(subj, BLACKBOX_SIGNED_STATEMENT_PRED, literal(input.signer.sign(REPORT_STATEMENT, payload))));
  }
  return out;
}

// src/detection.ts
function ruleSource(rule) {
  const src = String(rule.source ?? "public").toLowerCase();
  return src === "community" ? "community" : "public";
}
function emptyRuleset() {
  return {
    injection: [],
    escalation: [],
    dependency: {},
    fileaccess: [],
    skill: [],
    ioc: {},
    fetchedAt: 0
  };
}
var MAX_TEXT = 5e4;
var regexCache = /* @__PURE__ */ new Map();
function compile(source) {
  if (regexCache.has(source)) return regexCache.get(source) ?? null;
  let re = null;
  try {
    const normalized = source.replace(/\\\\/g, "\\").replace(/^\(\?i\)/, "");
    re = new RegExp(normalized, "i");
  } catch {
    re = null;
  }
  regexCache.set(source, re);
  return re;
}
function detectInjection(text, ruleset) {
  if (!text) return [];
  const capped = text.length > MAX_TEXT ? text.slice(0, MAX_TEXT) : text;
  const out = [];
  const seen = /* @__PURE__ */ new Set();
  for (const rule of ruleset.injection) {
    if (seen.has(rule.identifier)) continue;
    const re = compile(rule.pattern);
    if (!re) continue;
    try {
      if (re.test(capped)) {
        seen.add(rule.identifier);
        const src = ruleSource(rule);
        out.push({
          identifier: rule.identifier,
          category: "injection",
          severity: rule.severity,
          title: rule.name || "Prompt injection pattern matched",
          toolName: null,
          matched: rule.pattern,
          evidence: sampleAround(capped, re),
          confirmed: src === "public",
          source: src,
          // Community matches carry the promotion fields so our sighting
          // strengthens the community signal. Mirrors Python detect_injection.
          fields: src === "community" ? { pattern: rule.pattern } : {}
        });
      }
    } catch {
    }
  }
  return out;
}
function detectEscalation(toolName, args, ruleset) {
  const shape = normalizeArgShape(toolName, args);
  if (!shape) return [];
  const tool = (toolName || "").trim().toLowerCase();
  const out = [];
  const seen = /* @__PURE__ */ new Set();
  for (const rule of ruleset.escalation) {
    if (seen.has(rule.identifier)) continue;
    if (rule.toolName.trim().toLowerCase() !== tool) continue;
    if (rule.argShape.trim() !== shape) continue;
    seen.add(rule.identifier);
    const src = ruleSource(rule);
    out.push({
      identifier: rule.identifier,
      category: "escalation",
      severity: rule.severity,
      title: rule.name || `Dangerous ${tool} call (${shape})`,
      toolName: toolName || "",
      matched: shape,
      evidence: shape,
      confirmed: src === "public",
      source: src,
      fields: src === "community" ? { toolName: tool, argShape: shape } : {}
    });
  }
  if (out.length === 0) {
    out.push({
      identifier: escalationIdentifier(tool, shape),
      category: "escalation",
      severity: "high",
      title: `Suspicious ${tool} call (${shape})`,
      toolName: toolName || "",
      matched: shape,
      evidence: shape,
      confirmed: false,
      source: "heuristic",
      fields: { toolName: tool, argShape: shape }
    });
  }
  return out;
}
function commandText(args) {
  if (typeof args === "string") return args;
  if (args == null || typeof args !== "object" || Array.isArray(args)) return "";
  const obj = args;
  for (const key of COMMAND_KEYS) {
    const val = obj[key];
    if (typeof val === "string" && val) return val;
  }
  return Object.values(obj).filter((v) => typeof v === "string").join(" ");
}
function detectDependency(toolName, args, ruleset) {
  const command = commandText(args);
  if (!command) return [];
  const dependencyRules = ruleset.dependency ?? {};
  if (Object.keys(dependencyRules).length === 0) return [];
  const installs = parseDependencyInstalls(command);
  const out = [];
  const seen = /* @__PURE__ */ new Set();
  for (const dep of installs) {
    const eco = dep.ecosystem.toLowerCase();
    const name = dep.name.toLowerCase();
    const candidates2 = dep.version ? [`${eco}:${name}@${dep.version}`] : [];
    candidates2.push(`${eco}:${name}@*`);
    const key = candidates2.find((k) => dependencyRules[k]);
    if (!key || seen.has(key)) continue;
    seen.add(key);
    const rule = dependencyRules[key];
    const src = ruleSource(rule);
    const shown = dep.version || "*";
    out.push({
      identifier: rule.identifier || `dep:${key}`,
      category: "dependency",
      severity: rule.severity,
      title: rule.name || `Vulnerable dependency ${name}@${shown}`,
      toolName: toolName || "",
      matched: key,
      evidence: rule.advisoryId ? `${dep.ecosystem}:${dep.name}@${shown} (${rule.advisoryId})` : `${dep.ecosystem}:${dep.name}@${shown}`,
      confirmed: src === "public",
      source: src,
      kind: rule.kind,
      fields: src === "community" ? {
        ecosystem: eco,
        packageName: name,
        packageVersion: dep.version || "*",
        advisoryId: rule.advisoryId
      } : {}
    });
  }
  return out;
}
var REMOTE_SCRIPT_RE = /\b(?:curl|wget)\b[\s\S]{0,500}\|\s*(?:sh|bash|zsh|python|python3|node)\b/i;
var RM_RF_SYSTEM_RE = /\brm\s+(?:-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|-r\s+-f|-f\s+-r|--recursive\s+--force|--force\s+--recursive|-r\s+--force|--recursive\s+-f)\b[\s\S]{0,200}(?:\s\/(?:etc|usr|bin|sbin|opt|private|System|Library)\b|\s\/var(?!\/(?:tmp|folders))\b|\s\/\s*(?=[;&|]|$)|\s(?:~|\$HOME)\/?(?=\s|[;&|]|$)|\s(?:~|\$HOME)\/\.(?:ssh|aws|gnupg|gpg|kube|docker|password-store)\b)/i;
var CHMOD_WORLD_RE = /\bchmod\s+(?:-R\s+)?0?777\b[\s\S]{0,200}(?:\s\/(?:etc|usr|bin|sbin|var|opt|private|System|Library)\b|\s\/\s*(?=[;&|]|$)|\s(?:~|\$HOME)\/?\.?(?:ssh|aws|gnupg))/i;
var CURL_EVAL_RE = /\b(?:curl|wget)\b[\s\S]{0,300}\|\s*eval\b/i;
var INSECURE_FETCH_RE = /\bcurl\b[\s\S]{0,200}(?:--insecure|--no-check-certificate|\s-[a-z]*k[a-z]*\b)|\bwget\b[\s\S]{0,200}--no-check-certificate/i;
var LOCAL_HOST_RE = /(?:localhost|127\.0\.0\.\d+|0\.0\.0\.0|\[::1\]|\b10\.\d+\.\d+\.\d+|\b192\.168\.\d+\.\d+|\b172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|\.local\b|\.internal\b)/i;
var SHELL_SHAPE_RULES = [
  ["remote-script-pipe", REMOTE_SCRIPT_RE],
  ["remote-eval-pipe", CURL_EVAL_RE],
  ["rm-rf-system-paths", RM_RF_SYSTEM_RE],
  ["chmod-world-writable", CHMOD_WORLD_RE],
  ["insecure-tls-fetch", INSECURE_FETCH_RE]
];
var SHELL_TOOLS = /* @__PURE__ */ new Set(["terminal", "shell", "bash", "run_command", "exec", "command"]);
var ESCALATION_SHAPES = new Set(SHELL_SHAPE_RULES.map(([shape]) => shape));
var COMMAND_KEYS = ["command", "cmd", "shell", "script", "input"];
var MAX_SHAPE_SCAN = 8e3;
function commandFromArgs(toolName, args) {
  if (typeof args === "string") return args.slice(0, MAX_SHAPE_SCAN);
  if (args == null || typeof args !== "object" || Array.isArray(args)) return "";
  const obj = args;
  for (const key of COMMAND_KEYS) {
    const val = obj[key];
    if (typeof val === "string" && val) return val.slice(0, MAX_SHAPE_SCAN);
  }
  if (SHELL_TOOLS.has((toolName || "").toLowerCase())) {
    const parts = Object.values(obj).filter((v) => typeof v === "string");
    return parts.join(" ").slice(0, MAX_SHAPE_SCAN);
  }
  return "";
}
function isShellTool(toolName) {
  return SHELL_TOOLS.has((toolName || "").trim().toLowerCase());
}
function normalizeArgShape(toolName, args) {
  const command = commandFromArgs(toolName, args);
  if (!command) return null;
  for (const [shape, pattern] of SHELL_SHAPE_RULES) {
    try {
      if (pattern.test(command)) {
        if (shape === "insecure-tls-fetch" && LOCAL_HOST_RE.test(command)) continue;
        return shape;
      }
    } catch {
    }
  }
  return null;
}
var INJECTION_HEURISTICS = [
  // OpenClaw replaces model-control delimiters in external content with this
  // marker before plugins see the result. Preserve the security signal.
  ["high", "LLM01", /\[REMOVED_SPECIAL_TOKEN\]/],
  // "ignore all previous instructions" and close variants (see detection/content_scanners.py).
  ["high", "LLM01", /(?:ignore|disregard|forget|skip|override)\s+(?:all\s+|any\s+|the\s+|these\s+)?(?:previous|prior|above|earlier|preceding|prior\s+)\s*(?:instruction|message|prompt|rule|context|direction|directive|command|guideline)s?/i],
  // Exfiltrate the system prompt / instructions.
  ["high", "LLM06", /(?:reveal|show|print|repeat|disclose|give|tell|share|send|output|expose|leak|what(?:'s|\s+is|\s+are)?|display)\b[\s\S]{0,40}\b(?:system\s+prompt|system\s+message|initial\s+(?:instruction|prompt)s?|your\s+(?:instructions|prompt|system\s+prompt|guidelines))/i],
  ["high", "LLM01", /you\s+are\s+now\b[\s\S]{0,40}\b(?:DAN|developer\s+mode|jailbroken|unrestricted)/i],
  ["high", "LLM01", /(?:pretend|act\s+as|roleplay|imagine)\s+(?:to\s+be\s+|you(?:'re|\s+are)\s+|as\s+)?[\s\S]{0,40}\b(?:no\s+restrictions|unrestricted|without\s+rules|no\s+rules|jailbroken|DAN\b)/i],
  ["high", "LLM06", /(?:exfiltrate|exfil|smuggle)\b[\s\S]{0,40}\b(?:api\s*key|secret|token|credentials|password|env(?:ironment)?\s+variables?|\.env)/i],
  ["high", "LLM06", /\b(?:leak|upload|steal|send|post)(?:s|ing|ed)?\s+(?:the\s+|my\s+|our\s+|your\s+|all\s+(?:the\s+)?)?(?:api\s*key|secret|token|credentials|password|env(?:ironment)?\s+variables?|\.env)/i]
];
var INJECTION_PHRASE_CAP = 120;
var MAX_INJECTION_SCAN = 5e4;
function scanInjectionHeuristics(text) {
  if (!text) return [];
  const scan = text.length > MAX_INJECTION_SCAN ? text.slice(0, MAX_INJECTION_SCAN) : text;
  const out = [];
  const seen = /* @__PURE__ */ new Set();
  for (const [severity2, owasp, pattern] of INJECTION_HEURISTICS) {
    let m = null;
    try {
      m = scan.match(pattern);
    } catch {
      continue;
    }
    if (!m) continue;
    const signature = pattern.source;
    if (seen.has(signature)) continue;
    seen.add(signature);
    out.push({
      pattern: signature,
      phrase: m[0].slice(0, INJECTION_PHRASE_CAP),
      severity: severity2,
      owasp
    });
  }
  return out;
}
function discoverInjection(text, ruleset) {
  const known = /* @__PURE__ */ new Set();
  for (const rule of ruleset.injection ?? []) {
    if (rule.identifier) known.add(rule.identifier);
  }
  const out = [];
  const seen = /* @__PURE__ */ new Set();
  for (const hit of scanInjectionHeuristics(text || "")) {
    const identifier = injectionIdentifier(hit.pattern);
    if (known.has(identifier) || seen.has(identifier)) continue;
    seen.add(identifier);
    out.push({
      identifier,
      category: "injection",
      severity: hit.severity,
      title: "Suspicious prompt-injection phrase",
      toolName: null,
      matched: hit.phrase,
      evidence: hit.phrase,
      confirmed: false,
      source: "heuristic",
      fields: { pattern: hit.pattern, owaspCategory: hit.owasp }
    });
  }
  return out;
}
var SENSITIVE_PATH_RULES = [
  ["ssh-private-key", "critical", /(?:^|\/)\.ssh\/(?!(?:config|known_hosts|authorized_keys)$)(?!.*\.pub$).+|(?:^|\/)id_(?:rsa|ed25519|ecdsa|dsa)\b(?!\.pub)/i],
  ["env-file", "high", /(?:^|\/)\.env(?:\.[\w.-]+)?$(?<!\.example)(?<!\.sample)(?<!\.template)(?<!\.dist)(?<!\.default)/i],
  [
    "credentials",
    "critical",
    /(?:^|\/)\.aws\/credentials$|(?:^|\/)\.netrc$|(?:^|\/)\.npmrc$|(?:^|\/)\.docker\/config\.json$|(?:^|\/)\.kube\/config$|(?:^|\/)\.config\/gcloud(?:\/|$)/i
  ],
  ["password-store", "critical", /(?:^|\/)\.password-store(?:\/|$)|(?:^|\/)\.pgpass$/i],
  [
    "browser-cookies",
    "high",
    /(?:Chrome|Chromium|Brave|Edge|Opera|Vivaldi|BraveSoftware)[\s\S]{0,120}\/(?:Cookies|Login Data)$|(?:^|\/)cookies\.sqlite$|(?:^|\/)Cookies\.binarycookies$|(?:^|\/)Library\/Keychains(?:\/|$)|(?:^|\/)login\.keychain/i
  ],
  ["system-shadow", "critical", /^\/etc\/(?:shadow|passwd|sudoers)$/i]
];
var FILE_ACCESS_TOOLS = {
  read: "read",
  write: "write",
  read_file: "read",
  write_file: "write",
  edit_file: "write",
  edit: "write",
  patch: "write",
  apply_patch: "write",
  create_file: "write",
  delete_file: "write",
  open_file: "read",
  cat: "read",
  skill_manage: "write"
};
var PATH_KEYS = ["path", "file", "file_path", "filepath", "filename", "target", "target_file"];
function npmrcHasToken(args) {
  let text = typeof args === "string" ? args : "";
  if (args != null && typeof args === "object" && !Array.isArray(args)) {
    for (const v of Object.values(args)) {
      if (typeof v === "string") text += "\n" + v;
    }
  }
  return text.toLowerCase().includes("_authtoken");
}
var SENSITIVE_PATH_CATEGORIES = new Set(SENSITIVE_PATH_RULES.map(([category]) => category));
function fileAccessArg(toolName, args) {
  const tool = (toolName || "").trim().toLowerCase();
  const mode2 = FILE_ACCESS_TOOLS[tool];
  if (!mode2 || args == null || typeof args !== "object" || Array.isArray(args)) return null;
  const obj = args;
  let path2 = "";
  for (const key of PATH_KEYS) {
    const val = obj[key];
    if (typeof val === "string" && val.trim()) {
      path2 = val.trim();
      break;
    }
  }
  if (!path2) return null;
  return { tool, path: path2, mode: mode2 };
}
function sensitivePathCategory(path2, args) {
  if (!path2) return null;
  const p = path2.trim();
  if (p.endsWith(".npmrc")) {
    return npmrcHasToken(args) ? { category: "credentials", severity: "critical" } : null;
  }
  for (const [category, severity2, pattern] of SENSITIVE_PATH_RULES) {
    try {
      if (pattern.test(p)) return { category, severity: severity2 };
    } catch {
      continue;
    }
  }
  return null;
}
function detectFileaccess(toolName, args, ruleset) {
  const access = fileAccessArg(toolName, args);
  if (!access) return [];
  const hit = sensitivePathCategory(access.path, args);
  if (!hit) return [];
  const tool = access.tool;
  const category = hit.category;
  let identifier = fileaccessIdentifierFor(tool, category);
  let severity2 = hit.severity;
  let source = "heuristic";
  let name;
  for (const rule of ruleset.fileaccess ?? []) {
    if (String(rule.toolName || "").toLowerCase() === tool && String(rule.category || "").toLowerCase() === category) {
      source = ruleSource(rule);
      severity2 = rule.severity ?? severity2;
      name = rule.name;
      identifier = rule.identifier || identifier;
      break;
    }
  }
  return [
    {
      identifier,
      category: "fileaccess",
      severity: severity2,
      title: name || `Sensitive file access (${category})`,
      toolName: tool,
      matched: category,
      evidence: `${access.mode} ${category}`,
      confirmed: source === "public",
      source,
      fields: { toolName: tool, fileCategory: category }
    }
  ];
}
var SKILL_CODE_RULES = [
  [
    "shell-exec",
    "high",
    /\b(?:os\.system|subprocess\.(?:run|call|Popen|check_output)|child_process|exec(?:Sync)?\s*\(|spawn(?:Sync)?\s*\()/i
  ],
  ["remote-script-pipe", "critical", REMOTE_SCRIPT_RE],
  [
    "credential-exfil",
    "critical",
    /(?:os\.environ|process\.env|getenv)\b[\s\S]{0,120}\b(?:requests\.(?:post|get)|fetch\s*\(|urlopen|http[s]?:\/\/)/i
  ],
  [
    "obfuscation",
    "high",
    /\b(?:eval|exec)\s*\(\s*(?:base64|atob|Buffer\.from|codecs\.decode)|\bbase64\.b64decode\b[\s\S]{0,40}\b(?:eval|exec)/i
  ]
];
var SKILL_PERMISSION_RULES = [
  ["over-broad-filesystem", "high", /\b(?:filesystem[:_-]?\*|fs[:_-]?full|read[_-]?write[_-]?all|allowallpaths)/i],
  ["over-broad-shell", "high", /\b(?:arbitrary[_-]?shell|shell[:_-]?\*|exec[:_-]?any|allowshell)/i],
  ["over-broad-network", "medium", /\b(?:network[:_-]?\*|raw[_-]?socket|allowallhosts|net[:_-]?any)/i]
];
var SKILL_DANGER_SHAPES = new Set([...SKILL_CODE_RULES, ...SKILL_PERMISSION_RULES].map(([shape]) => shape));
var SKILL_TOOLS = /* @__PURE__ */ new Set([
  "skill_manage",
  "skill_install",
  "install_skill",
  "plugin_install",
  "install_plugin",
  "skill_workshop"
]);
var SKILL_NAME_KEYS = ["name", "skill", "skill_name", "id", "plugin"];
var SKILL_VERSION_KEYS = ["version", "skill_version", "ver"];
var SKILL_CODE_KEYS = ["code", "content", "source", "body", "script"];
var SKILL_PERM_KEYS = ["permissions", "capabilities", "scopes", "allow", "grants"];
var MAX_SKILL_SCAN = 2e4;
function stringify(value) {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map((v) => stringify(v)).join(" ");
  if (value != null && typeof value === "object") {
    return Object.entries(value).map(([k, v]) => `${k} ${stringify(v)}`).join(" ");
  }
  return value != null ? String(value) : "";
}
function skillInstallArg(toolName, args) {
  const tool = (toolName || "").trim().toLowerCase();
  if (isShellTool(tool)) {
    const tokens = tokenizeShell(commandText(args));
    for (let i = 0; i + 3 < tokens.length; i += 1) {
      if (tokens[i]?.toLowerCase() !== "openclaw" || tokens[i + 1]?.toLowerCase() !== "skills" || tokens[i + 2]?.toLowerCase() !== "install") continue;
      const name2 = tokens[i + 3] ?? "";
      if (!name2 || name2.startsWith("-")) return null;
      let version2 = "";
      for (let j = i + 4; j < tokens.length; j += 1) {
        if (tokens[j] === "--version") version2 = tokens[j + 1] ?? "";
        else if (tokens[j]?.startsWith("--version=")) version2 = tokens[j].slice(10);
      }
      return { name: name2, version: version2, code: "", permissions: "" };
    }
    return null;
  }
  if (!SKILL_TOOLS.has(tool) || args == null || typeof args !== "object" || Array.isArray(args)) {
    return null;
  }
  const obj = args;
  if (tool === "skill_workshop" && !(/* @__PURE__ */ new Set(["create", "update", "revise"])).has(String(obj.action ?? "").toLowerCase())) return null;
  let name = "";
  for (const key of SKILL_NAME_KEYS) {
    const val = obj[key];
    if (typeof val === "string" && val.trim()) {
      name = val.trim();
      break;
    }
  }
  if (!name) return null;
  let version = "";
  for (const key of SKILL_VERSION_KEYS) {
    const val = obj[key];
    if (typeof val === "string" && val.trim()) {
      version = val.trim();
      break;
    }
  }
  const code = [...SKILL_CODE_KEYS, "proposal_content"].filter((k) => obj[k]).map((k) => stringify(obj[k])).join(" ");
  const perms = SKILL_PERM_KEYS.filter((k) => obj[k]).map((k) => stringify(obj[k])).join(" ");
  return {
    name,
    version,
    code: code.slice(0, MAX_SKILL_SCAN),
    permissions: perms.slice(0, MAX_SKILL_SCAN)
  };
}
function scanSkillDangers(code, permissions) {
  const out = [];
  const seen = /* @__PURE__ */ new Set();
  const passes = [
    [code || "", SKILL_CODE_RULES],
    [permissions || "", SKILL_PERMISSION_RULES]
  ];
  for (const [text, rules] of passes) {
    if (!text) continue;
    for (const [shape, severity2, pattern] of rules) {
      if (seen.has(shape)) continue;
      try {
        if (pattern.test(text)) {
          seen.add(shape);
          out.push({ dangerShape: shape, severity: severity2 });
        }
      } catch {
        continue;
      }
    }
  }
  return out;
}
function detectSkill(toolName, args, ruleset) {
  const skill2 = skillInstallArg(toolName, args);
  if (!skill2) return [];
  const out = [];
  const seen = /* @__PURE__ */ new Set();
  const name = skill2.name;
  const version = skill2.version;
  for (const rule of ruleset.skill ?? []) {
    const ruleName = String(rule.skillName || "").trim().toLowerCase();
    const ruleVer = String(rule.skillVersion || "").trim();
    if (ruleName && ruleName === name.toLowerCase() && (!ruleVer || ruleVer === version)) {
      const ident = rule.identifier || skillVersionIdentifierFor(name, version);
      if (seen.has(ident)) continue;
      seen.add(ident);
      const src = ruleSource(rule);
      const historical = !ruleVer;
      out.push({
        identifier: ident,
        category: "skill",
        severity: historical ? "medium" : rule.severity ?? "high",
        title: historical ? `Historical threat report for ${name} (version unspecified)` : rule.name || `Known-bad skill ${name}`,
        // Python: skill.get("tool", "") or (tool_name or "").lower(); the
        // install descriptor has no `tool` key so this is always the tool name.
        toolName: (toolName || "").toLowerCase(),
        matched: name,
        evidence: historical ? `Skill ${name} was exploited in the past; the graph does not specify an affected version, so the issue may be fixed in newer releases.` : `known-bad skill ${name}`,
        confirmed: src === "public",
        source: src,
        kind: historical ? "historical" : void 0,
        fields: { skillName: name, skillVersion: version }
      });
    }
  }
  for (const danger of scanSkillDangers(skill2.code, skill2.permissions)) {
    const shape = danger.dangerShape;
    const ident = skillShapeIdentifierFor(name, shape);
    if (seen.has(ident)) continue;
    seen.add(ident);
    out.push({
      identifier: ident,
      category: "skill",
      severity: danger.severity ?? "high",
      title: `Suspicious skill ${name} (${shape})`,
      toolName: (toolName || "").toLowerCase(),
      matched: shape,
      evidence: `skill ${name}: ${shape}`,
      confirmed: false,
      source: "heuristic",
      fields: {
        skillName: name,
        skillVersion: version,
        dangerShape: shape,
        artifactHash: createHash2("sha256").update(skill2.code ?? "", "utf8").digest("hex")
      }
    });
  }
  return out;
}
var IOC_URL_RE = /https?:\/\/[^\s'"<>|\\)}\]]+/gi;
var IOC_IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
var IOC_DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;
var IOC_SHA256_RE = /\b[a-fA-F0-9]{64}\b/g;
var IOC_SHA1_RE = /\b[a-fA-F0-9]{40}\b/g;
var IOC_MD5_RE = /\b[a-fA-F0-9]{32}\b/g;
var IOC_EVM_RE = /0x[a-fA-F0-9]{40}/g;
var IOC_BTC_RE = /\b(?:bc1[023-9ac-hj-np-z]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,39})\b/g;
var IOC_SOL_RE = /\b[1-9A-HJ-NP-Za-km-z]{32,44}\b/g;
var MAX_IOC_CANDIDATES = 4e3;
function hostSuffixes(host) {
  const clean = host.replace(/^\.+|\.+$/g, "").toLowerCase();
  if (!clean) return [];
  const out = [clean];
  if (clean.startsWith("www.")) out.push(clean.slice(4));
  const labels = clean.split(".");
  for (let i = 1; i < labels.length - 1; i += 1) out.push(labels.slice(i).join("."));
  return [...new Set(out)];
}
function iterIocCandidates(input) {
  const text = (input || "").slice(0, MAX_TEXT);
  if (!text) return [];
  const out = [];
  const seen = /* @__PURE__ */ new Set();
  const add = (type, value) => {
    if (out.length >= MAX_IOC_CANDIDATES) return;
    const identifier = iocIdentifier(type, value);
    if (!seen.has(identifier)) {
      seen.add(identifier);
      out.push(identifier);
    }
  };
  for (const match of text.matchAll(IOC_URL_RE)) {
    const clean = match[0].replace(/[.,);'" ]+$/g, "");
    add("url", clean);
    const host = clean.split("://", 2).at(-1)?.split("/", 1)[0].split("@").at(-1)?.split(":", 1)[0] ?? "";
    for (const suffix of hostSuffixes(host)) add("domain", suffix);
  }
  for (const match of text.matchAll(IOC_DOMAIN_RE)) {
    for (const suffix of hostSuffixes(match[0])) add("domain", suffix);
  }
  for (const match of text.matchAll(IOC_IPV4_RE)) add("ip", match[0]);
  for (const match of text.matchAll(IOC_SHA256_RE)) add("hash", `sha256:${match[0]}`);
  for (const match of text.matchAll(IOC_SHA1_RE)) add("hash", `sha1:${match[0]}`);
  for (const match of text.matchAll(IOC_MD5_RE)) add("hash", `md5:${match[0]}`);
  for (const re of [IOC_EVM_RE, IOC_BTC_RE, IOC_SOL_RE]) {
    for (const match of text.matchAll(re)) {
      add("wallet", match[0]);
      add("contract", match[0]);
    }
  }
  return out;
}
function detectIoc(toolName, args, ruleset) {
  if (!ruleset.ioc) return [];
  const text = typeof args === "string" ? args : collectText(args).join("\n");
  if (!text) return [];
  const out = [];
  for (const identifier of iterIocCandidates(text)) {
    const rule = ruleset.ioc[identifier];
    if (!rule) continue;
    const src = ruleSource(rule);
    const parts = identifier.split(":", 3);
    const iocType = rule.iocType || parts[1] || "indicator";
    const value = identifier.slice(`ioc:${parts[1] ?? ""}:`.length);
    out.push({
      identifier,
      category: "ioc",
      severity: rule.severity ?? "high",
      title: rule.name || `Known-bad ${iocType}`,
      toolName: toolName || "",
      matched: value.slice(0, 200),
      evidence: `${iocType} ${value}`.slice(0, 200),
      confirmed: src === "public",
      source: src,
      kind: rule.kind,
      fields: src === "community" ? { iocType } : {}
    });
  }
  return out;
}
var SHELL_INSTALL_PATTERNS = [
  /\b(?:python(?:3)?\s+-m\s+)?pip3?\s+install\b/i,
  /\buv\s+pip\s+install\b/i,
  /\buv\s+add\b/i,
  /\buvx\b/i,
  /\bnpm\s+(?:install|i|add)\b/i,
  /\bpnpm\s+add\b/i,
  /\byarn\s+add\b/i,
  /\bbun\s+add\b/i,
  /\bcargo\s+add\b/i,
  /\bgem\s+install\b/i,
  /\bbrew\s+install\b/i
];
var TOKEN_RE = /"([^"]*)"|'([^']*)'|(\S+)/g;
function tokenizeShell(command) {
  const out = [];
  for (const m of command.matchAll(TOKEN_RE)) {
    out.push(m[1] ?? m[2] ?? m[3] ?? "");
  }
  return out;
}
var SHELL_READ_COMMANDS = /* @__PURE__ */ new Set([
  "cat",
  "less",
  "more",
  "head",
  "tail",
  "bat",
  "xxd",
  "hexdump",
  "strings",
  "od",
  "nl"
]);
function looksLikePath2(token2) {
  return token2.includes("/") || token2.startsWith("~") || token2.startsWith(".") || token2.includes(".");
}
function parseShellReads(command) {
  if (!command || ![...SHELL_READ_COMMANDS].some((name) => ` ${command} `.includes(` ${name} `))) return [];
  const tokens = tokenizeShell(command);
  const out = [];
  let i = 0;
  while (i < tokens.length) {
    if (SHELL_READ_COMMANDS.has((tokens[i] ?? "").toLowerCase())) {
      let j = i + 1;
      while (j < tokens.length && ![";", "&&", "||", "|", ">", ">>", "<"].includes(tokens[j] ?? "")) {
        const token2 = tokens[j] ?? "";
        if (!token2.startsWith("-") && looksLikePath2(token2)) out.push(token2);
        j += 1;
      }
      i = j;
    } else {
      i += 1;
    }
  }
  return [...new Set(out)];
}
function parseDownloads(command) {
  if (!command || !/\b(?:curl|wget)\b/i.test(command)) return [];
  return [...new Set(command.match(/https?:\/\/[^\s;'"|&>]+/gi) ?? [])];
}
function parsePackageToken(raw, ecosystem) {
  const token2 = raw.replace(/,/g, "").replace(/;/g, "").trim();
  if (!token2 || token2.startsWith("http://") || token2.startsWith("https://") || token2.startsWith("/") || token2.startsWith(".") || token2.startsWith("@git")) {
    return null;
  }
  if (ecosystem === "pypi" || ecosystem === "rubygems") {
    const exact = /^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9._+!-]+)$/.exec(token2);
    if (exact) return { name: exact[1], version: exact[2] };
    const loose = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?$/.exec(token2);
    if (loose) return { name: loose[1], version: "" };
    return null;
  }
  if (ecosystem === "npm") {
    const idx2 = token2.lastIndexOf("@");
    if (idx2 > 0) return { name: token2.slice(0, idx2), version: token2.slice(idx2 + 1) };
    if (/^(?:@[A-Za-z0-9._-]+\/)?[A-Za-z0-9._-]+$/.test(token2)) return { name: token2, version: "" };
    return null;
  }
  const idx = token2.lastIndexOf("@");
  if (idx > 0) return { name: token2.slice(0, idx), version: token2.slice(idx + 1) };
  if (/^[A-Za-z0-9._+/-]+$/.test(token2)) return { name: token2, version: "" };
  return null;
}
var MANAGER_SPECS_PAIR = {
  "pip|install": { eco: "pypi", skip: 2 },
  "pip3|install": { eco: "pypi", skip: 2 },
  "uv|pip": { eco: "pypi", skip: 3 },
  // `uv pip install <pkg>`
  "uv|add": { eco: "pypi", skip: 2 },
  "pnpm|add": { eco: "npm", skip: 2 },
  "yarn|add": { eco: "npm", skip: 2 },
  "bun|add": { eco: "npm", skip: 2 },
  "cargo|add": { eco: "cargo", skip: 2 },
  "gem|install": { eco: "rubygems", skip: 2 },
  "brew|install": { eco: "homebrew", skip: 2 }
};
var MANAGER_SPECS_SINGLE = {
  uvx: { eco: "pypi", skip: 1 }
  // `npm install|i|add` is handled explicitly below (the Python `("npm", None)` entry).
};
function parseDependencyInstalls(command) {
  if (!command || !SHELL_INSTALL_PATTERNS.some((re) => re.test(command))) return [];
  const tokens = tokenizeShell(command);
  const out = [];
  const seen = /* @__PURE__ */ new Set();
  let i = 0;
  while (i < tokens.length) {
    const tok = (tokens[i] ?? "").toLowerCase();
    const nxt = i + 1 < tokens.length ? (tokens[i + 1] ?? "").toLowerCase() : null;
    let ecosystem = "";
    let start = -1;
    if (MANAGER_SPECS_PAIR[`${tok}|pip`] && nxt === "pip") {
      const spec = MANAGER_SPECS_PAIR[`${tok}|pip`];
      ecosystem = spec.eco;
      start = i + spec.skip;
    } else if (nxt !== null && MANAGER_SPECS_PAIR[`${tok}|${nxt}`]) {
      const spec = MANAGER_SPECS_PAIR[`${tok}|${nxt}`];
      ecosystem = spec.eco;
      start = i + spec.skip;
    } else if (MANAGER_SPECS_SINGLE[tok]) {
      const spec = MANAGER_SPECS_SINGLE[tok];
      ecosystem = spec.eco;
      start = i + spec.skip;
    } else if (tok === "npm" && (nxt === "install" || nxt === "i" || nxt === "add")) {
      ecosystem = "npm";
      start = i + 2;
    }
    if (start < 0 || !ecosystem) {
      i += 1;
      continue;
    }
    let j = start;
    while (j < tokens.length) {
      const raw = tokens[j] ?? "";
      if (raw === ";" || raw === "&&" || raw === "||" || raw === "|") break;
      if (raw.startsWith("-") || raw === "install" || raw === "add" || raw === "i") {
        j += 1;
        continue;
      }
      const parsed = parsePackageToken(raw, ecosystem);
      if (parsed && parsed.name) {
        const key = `${ecosystem}:${parsed.name.toLowerCase()}:${parsed.version}`;
        if (!seen.has(key)) {
          seen.add(key);
          out.push({ ecosystem, name: parsed.name, version: parsed.version });
        }
      }
      j += 1;
    }
    i = j;
  }
  return out;
}
function collectText(value, out = [], depth = 0) {
  if (value == null || depth > 6) return out;
  if (typeof value === "string") {
    if (value.trim()) out.push(value);
    return out;
  }
  if (Array.isArray(value)) {
    for (const item of value.slice(0, 100)) collectText(item, out, depth + 1);
    return out;
  }
  if (typeof value === "object") {
    for (const child of Object.values(value)) {
      collectText(child, out, depth + 1);
    }
  }
  return out;
}
function sampleAround(text, re) {
  try {
    const m = text.match(new RegExp(re.source, "i"));
    if (m && typeof m.index === "number") {
      const start = Math.max(0, m.index - 40);
      return text.slice(start, m.index + m[0].length + 40);
    }
  } catch {
  }
  return text.slice(0, 120);
}
async function discoverDependencyCandidates(toolName, args, ruleset, osvLookup) {
  const command = commandText(args);
  if (!command) return [];
  const dependencyRules = ruleset.dependency ?? {};
  const out = [];
  const seen = /* @__PURE__ */ new Set();
  for (const dep of parseDependencyInstalls(command)) {
    const version = dep.version || "";
    if (!version) continue;
    const eco = dep.ecosystem.toLowerCase();
    const name = dep.name;
    const key = `${eco}:${name.toLowerCase()}@${version}`;
    if (key in dependencyRules || seen.has(key)) continue;
    seen.add(key);
    let hit = null;
    try {
      hit = await osvLookup(eco, name, version);
    } catch {
      hit = null;
    }
    if (!hit) continue;
    out.push({
      identifier: dependencyIdentifier(eco, name, version),
      category: "dependency",
      severity: hit.severity ?? "high",
      title: `OSV-vulnerable dependency ${name}@${version}`,
      toolName: toolName || "",
      matched: key,
      evidence: `${eco}:${name}@${version} (${hit.advisoryId})`,
      confirmed: false,
      source: "heuristic",
      fields: {
        ecosystem: eco,
        packageName: name,
        packageVersion: version,
        advisoryId: hit.advisoryId
      }
    });
  }
  return out;
}
function expandUser(p) {
  if (p === "~") return os.homedir();
  if (p.startsWith("~/") || p.startsWith("~\\")) return path.join(os.homedir(), p.slice(2));
  const named = /^~([^/\\]+)(?:[/\\](.*))?$/.exec(p);
  if (named && named[1] === currentUserName()) return path.join(os.homedir(), named[2] ?? "");
  return p;
}
function currentUserName() {
  try {
    return os.userInfo().username;
  } catch {
    return "";
  }
}
function fnmatchToRegExp(pattern) {
  let re = "";
  let i = 0;
  const n = pattern.length;
  while (i < n) {
    const c = pattern[i];
    i += 1;
    if (c === "*") {
      re += ".*";
    } else if (c === "?") {
      re += ".";
    } else if (c === "[") {
      let j = i;
      if (j < n && (pattern[j] === "!" || pattern[j] === "]")) j += 1;
      while (j < n && pattern[j] !== "]") j += 1;
      if (j >= n) {
        re += "\\[";
      } else {
        let stuff = pattern.slice(i, j);
        stuff = stuff.replace(/\\/g, "\\\\");
        i = j + 1;
        if (stuff.startsWith("!")) stuff = "^" + stuff.slice(1);
        else if (stuff.startsWith("^")) stuff = "\\" + stuff;
        re += "[" + stuff + "]";
      }
    } else {
      re += c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    }
  }
  const flags = os.platform() === "win32" ? "is" : "s";
  return new RegExp(`^(?:${re})$`, flags);
}
function fnmatch(name, pattern) {
  try {
    return fnmatchToRegExp(pattern).test(name);
  } catch {
    return false;
  }
}
function protectedPathMatch(p, pattern) {
  try {
    const normPath = path.normalize(expandUser(String(p ?? "")));
    const normPat = path.normalize(expandUser(String(pattern ?? "")));
    if (!normPath || !normPat) return false;
    if (isTemplate(normPath) && !isTemplate(normPat)) return false;
    if (fnmatch(normPath, normPat)) return true;
    if (fnmatch(path.basename(normPath), normPat)) return true;
    if (!/[*?[]/.test(normPat) && (normPath === normPat || normPath.startsWith(normPat.replace(/[/\\]+$/, "") + path.sep))) {
      return true;
    }
  } catch {
    return false;
  }
  return false;
}
function detectCustomFileAccess(toolName, args, protectedPaths) {
  const patterns = [...protectedPaths ?? []].filter((p) => String(p ?? "").trim());
  if (patterns.length === 0) return [];
  for (const access of fileAccesses(toolName, args)) {
    for (const pattern of patterns) {
      if (!protects(access.path, access.mode, pattern)) continue;
      return [
        {
          identifier: fileaccessIdentifierFor(access.tool, "user-protected"),
          category: "fileaccess",
          severity: "critical",
          title: "Access to a user-protected path",
          toolName: access.tool,
          matched: "user-protected",
          evidence: `${access.mode} path matching protected pattern ${String(pattern).slice(0, 120)}`,
          confirmed: false,
          source: "custom",
          fields: {}
        }
      ];
    }
  }
  return [];
}
var CODE_TOOLS = /* @__PURE__ */ new Set(["execute_code", "code_execution", "run_code", "run_python", "python"]);
var MAX_GLOB_FILES = 64;
var GLOB_CHARS = /[*?[]/;
var TEMPLATE_SUFFIXES = [".example", ".sample", ".template", ".dist", ".default"];
function isTemplate(file) {
  const lowered = file.toLowerCase();
  return TEMPLATE_SUFFIXES.some((suffix) => lowered.endsWith(suffix));
}
function fileAccesses(toolName, args) {
  const access = fileAccessArg(toolName, args);
  if (access) return [{ tool: access.tool, path: access.path, mode: access.mode }];
  const tool = (toolName || "").trim().toLowerCase();
  const code = args && typeof args === "object" ? args.code : void 0;
  if (CODE_TOOLS.has(tool) && typeof code === "string") {
    return codeFileArgs(code).map((arg) => ({ tool, path: arg.path, mode: arg.recursive ? "copy" : "read" }));
  }
  if (!SHELL_TOOLS.has(tool)) return [];
  return shellFileArgs(commandFromArgs(toolName, args)).filter((arg) => !arg.destination).map((arg) => ({ tool, path: arg.path, mode: arg.recursive ? "copy" : "read" }));
}
function candidates(file) {
  const found = [file];
  const expanded = expandUser(String(file ?? ""));
  if (!path.isAbsolute(expanded)) return found;
  try {
    if (GLOB_CHARS.test(expanded) && typeof fs.globSync === "function") {
      found.push(...fs.globSync(expanded).slice(0, MAX_GLOB_FILES).map(String));
    }
    for (const each of [...found]) {
      const real = expandUser(each);
      if (fs.lstatSync(real, { throwIfNoEntry: false })?.isSymbolicLink()) found.push(fs.realpathSync(real));
    }
  } catch {
  }
  return found;
}
function nameGlobHits(file, pattern) {
  const name = path.basename(path.normalize(expandUser(String(file ?? ""))));
  return GLOB_CHARS.test(name) && !GLOB_CHARS.test(pattern) && fnmatch(path.basename(pattern.replace(/\/+$/, "")), name);
}
function folderHolds(folder, pattern) {
  const expanded = expandUser(String(pattern ?? ""));
  if (!path.isAbsolute(expanded)) return false;
  const stem = expanded.split(/[*?[]/, 1)[0];
  const place = path.normalize(stem.endsWith(path.sep) || stem === expanded ? stem : path.dirname(stem));
  const normFolder = path.normalize(expandUser(String(folder ?? "")));
  if (!path.isAbsolute(normFolder)) return false;
  const trimmedPlace = place.length > 1 ? place.replace(/[/\\]+$/, "") : place;
  const trimmedFolder = normFolder.length > 1 ? normFolder.replace(/[/\\]+$/, "") : normFolder;
  return trimmedPlace === trimmedFolder || trimmedPlace.startsWith(trimmedFolder.replace(/[/\\]+$/, "") + path.sep);
}
function protects(file, mode2, pattern) {
  return candidates(file).some((candidate) => protectedPathMatch(candidate, pattern)) || nameGlobHits(file, pattern) || mode2 === "copy" && folderHolds(file, pattern);
}
function detectAll(toolName, args, ruleset, discover = true) {
  const findings = [];
  findings.push(...detectEscalation(toolName, args, ruleset));
  findings.push(...detectDependency(toolName, args, ruleset));
  const argsText = typeof args === "string" ? args : collectText(args).join("\n");
  findings.push(...detectInjection(argsText, ruleset));
  if (discover) {
    findings.push(...discoverInjection(argsText, ruleset));
  }
  findings.push(...detectFileaccess(toolName, args, ruleset));
  findings.push(...detectSkill(toolName, args, ruleset));
  findings.push(...detectIoc(toolName, args, ruleset));
  return discover ? findings : findings.filter((f) => f.source !== "heuristic");
}

// src/reportSchema.ts
var SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"];
var REPORT_FRAMEWORKS = ["hermes", "openclaw"];
var INJECTION_CONTEXTS = ["in-fetched-page", "in-tool-output", "in-user-prompt", "in-skill"];
var IOC_CONTEXTS = ["fetched-by-tool", "in-prompt", "in-tool-output", "in-dependency", "in-skill"];
var DEPENDENCY_REASONS = ["typosquat", "install-hook", "exfil", "internal-mirror-collision"];
var WHOLE_PACKAGE_REASONS = ["typosquat", "internal-mirror-collision"];
var ADVISORY_REASON_PREFIX = "advisory:";
var SKILL_REGISTRIES = ["mcp-registry", "clawhub", "npm", "pypi", "oci", "mcpb"];
var DEPENDENCY_ECOSYSTEMS = ["npm", "pypi", "cargo", "rubygems"];
var IOC_TYPES = ["domain", "url", "ip", "hash", "wallet", "contract"];
var OWASP_LLM_CATEGORIES = Array.from({ length: 10 }, (_, i) => `LLM${String(i + 1).padStart(2, "0")}`);
var KIND_MALWARE = "malware";
var MAX_IDENTIFIER_CHARS = 512;
var MAX_VALUE_CHARS = 128;
var SAFE_TOKEN = /^[A-Za-z0-9._@:/+~-]+$/;
var SHA256_HEX = /^[0-9a-f]{64}$/;
var INJECTION_ID = /^injection:[a-z0-9][a-z0-9._-]{0,63}$/;
var CONTROL_OR_FORMAT = /[\p{Cc}\p{Cf}]/u;
var ReportValidationError = class extends Error {
};
function fail(message) {
  throw new ReportValidationError(message);
}
function token(name, value, required = true) {
  const text = String(value ?? "").trim();
  if (!text) {
    if (required) fail(`${name} is required`);
    return "";
  }
  if (text.length > MAX_VALUE_CHARS || !SAFE_TOKEN.test(text)) fail(`${name} must be a short token without spaces or control characters`);
  return text;
}
function oneOf(name, value, allowed) {
  const text = String(value ?? "").trim().toLowerCase();
  const set = new Set([...allowed].map((a) => a.toLowerCase()));
  if (!set.has(text)) fail(`${name} must be one of: ${[...set].sort().join(", ")}`);
  return text;
}
function injection(ev) {
  const out = { context: oneOf("context", ev.context, INJECTION_CONTEXTS) };
  if (ev.owasp_category) out.owasp_category = oneOf("owasp_category", ev.owasp_category, OWASP_LLM_CATEGORIES).toUpperCase();
  return [null, out];
}
function escalation(ev) {
  const tool = oneOf("tool_name", ev.tool_name, SHELL_TOOLS);
  const shape = oneOf("arg_shape", ev.arg_shape, ESCALATION_SHAPES);
  return [escalationIdentifier(tool, shape), { tool_name: tool, arg_shape: shape }];
}
function dependencyReason(ev) {
  const reason = String(ev.reason ?? "").trim();
  const advisory = token("advisory_id", ev.advisory_id, false);
  if (reason.toLowerCase().startsWith(ADVISORY_REASON_PREFIX)) {
    const cited = token("advisory id in reason", reason.slice(ADVISORY_REASON_PREFIX.length));
    if (advisory && advisory !== cited) fail("the reason's advisory and advisory_id differ");
    return [ADVISORY_REASON_PREFIX + cited, cited];
  }
  return [oneOf("reason", reason, [...DEPENDENCY_REASONS, `${ADVISORY_REASON_PREFIX}<id>`]), advisory];
}
function dependency(ev) {
  const eco = oneOf("ecosystem", ev.ecosystem, DEPENDENCY_ECOSYSTEMS);
  const name = canonicalPackageName(eco, token("package_name", ev.package_name));
  if (String(ev.kind ?? "").toLowerCase() !== KIND_MALWARE) fail("a dependency report must be kind=malware (vulnerabilities stay local \u2014 decision 22)");
  const [reason, advisory] = dependencyReason(ev);
  let version = String(ev.package_version ?? "").trim();
  if (version === "*") {
    if (!WHOLE_PACKAGE_REASONS.includes(reason)) fail(`a whole-package (*) report needs reason ${WHOLE_PACKAGE_REASONS.join(" or ")}`);
  } else {
    version = token("package_version", version);
  }
  const out = { ecosystem: eco, package_name: name, package_version: version, kind: KIND_MALWARE, reason };
  if (advisory) out.advisory_id = advisory;
  return [dependencyIdentifier(eco, name, version), out];
}
function fileaccess(ev) {
  const tool = token("tool_name", ev.tool_name).toLowerCase();
  const category = oneOf("file_category", ev.file_category, SENSITIVE_PATH_CATEGORIES);
  return [fileaccessIdentifierFor(tool, category), { tool_name: tool, file_category: category }];
}
function skill(ev) {
  if (ev.artifact_hash || ev.danger_shape) {
    if (ev.skill_name || ev.skill_version || ev.registry) fail("a local skill is reported by artifact hash + danger shape, never by name or version (KI-159)");
    const digest = String(ev.artifact_hash ?? "").trim().toLowerCase();
    if (!SHA256_HEX.test(digest)) fail("artifact_hash must be the sha256 hex of the skill's code");
    const shape = oneOf("danger_shape", ev.danger_shape, SKILL_DANGER_SHAPES);
    return [skillArtifactIdentifier(digest, shape), { artifact_hash: digest, danger_shape: shape }];
  }
  const registry = oneOf("registry", ev.registry, SKILL_REGISTRIES);
  const name = token("skill_name", ev.skill_name);
  const version = token("skill_version", ev.skill_version);
  return [skillVersionIdentifierFor(name, version), { registry, skill_name: name, skill_version: version }];
}
function ioc(ev) {
  return [null, { ioc_type: oneOf("ioc_type", ev.ioc_type, IOC_TYPES), ioc_context: oneOf("ioc_context", ev.ioc_context, IOC_CONTEXTS) }];
}
var VALIDATORS = { injection, escalation, dependency, fileaccess, skill, ioc };
function isCleanToken(identifier) {
  return Boolean(identifier) && identifier.length <= MAX_IDENTIFIER_CHARS && !identifier.includes(" ") && !CONTROL_OR_FORMAT.test(identifier);
}
function checkIdentifier(category, identifier, derived, evidence) {
  if (!isCleanToken(identifier)) fail("identifier must be a short single token without control or format characters");
  if (derived !== null && identifier !== derived) fail(`identifier does not match its fields (expected ${derived})`);
  if (category === "injection" && !INJECTION_ID.test(identifier)) fail("an injection identifier is a slug (injection:<pattern hash or corpus id>), never free text");
  if (category === "ioc") {
    const prefix = `ioc:${evidence.ioc_type}:`;
    const value = identifier.startsWith(prefix) ? identifier.slice(prefix.length) : "";
    if (!value || iocIdentifier(evidence.ioc_type, value) !== identifier) fail("an ioc identifier must be the canonical ioc:<type>:<value>");
    if (!iocValueIsWellFormed(evidence.ioc_type, value)) fail(`the ${evidence.ioc_type} value does not have the shape that type allows`);
  }
}
function validateReport(input) {
  const validator = VALIDATORS[input.category];
  if (!validator) fail(`category must be one of: ${Object.keys(VALIDATORS).sort().join(", ")}`);
  const severity2 = String(input.severity ?? "").trim().toLowerCase();
  if (!SEVERITY_ORDER.includes(severity2)) fail(`severity must be one of: ${SEVERITY_ORDER.join(", ")}`);
  const framework = oneOf("framework", input.framework, REPORT_FRAMEWORKS);
  const given = {};
  for (const [k, v] of Object.entries(input.evidence)) if (v !== void 0 && v !== null && v !== "") given[k] = String(v);
  const [derived, out] = validator(given);
  const unknown = Object.keys(given).filter((k) => !(k in out)).sort();
  if (unknown.length) fail(`fields not allowed in a ${input.category} report: ${unknown.join(", ")}`);
  const identifier = String(input.identifier ?? "").trim();
  checkIdentifier(input.category, identifier, derived, out);
  return {
    identifier,
    category: input.category,
    severity: severity2,
    framework,
    evidence: Object.entries(out).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
  };
}

// src/reporterKey.ts
import { generateKeyPairSync, createPrivateKey } from "node:crypto";
import { existsSync, mkdirSync, readFileSync as readFileSync2, renameSync, writeFileSync } from "node:fs";
import { join as join2 } from "node:path";
var REPORTER_KEY_FILE = "reporter_key.pem";
function reporterKeyPath(blackboxHome) {
  return join2(blackboxHome, REPORTER_KEY_FILE);
}
function loadOrCreateReporterKey(blackboxHome) {
  const path2 = reporterKeyPath(blackboxHome);
  if (existsSync(path2)) return createPrivateKey(readFileSync2(path2));
  mkdirSync(blackboxHome, { recursive: true });
  const { privateKey } = generateKeyPairSync("ed25519");
  const pem = privateKey.export({ type: "pkcs8", format: "pem" });
  const tmp = `${path2}.tmp.${process.pid}.${Date.now()}`;
  writeFileSync(tmp, pem, { mode: 384, flag: "wx" });
  try {
    renameSync(tmp, path2);
  } catch (err) {
    if (existsSync(path2)) return createPrivateKey(readFileSync2(path2));
    throw err;
  }
  return privateKey;
}

// src/index.ts
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

// src/dkgClient.ts
import { readFileSync as readFileSync3 } from "node:fs";
import { homedir } from "node:os";
import { join as join3 } from "node:path";
var DkgError = class extends Error {
  status;
  constructor(message, status) {
    super(message);
    this.name = "DkgError";
    this.status = status;
  }
};
var COMMUNITY_SUB_GRAPH = "reports";
var DEFAULT_DKG_PORT = 9320;
var DEFAULT_URL = `http://127.0.0.1:${DEFAULT_DKG_PORT}`;
var DEFAULT_TIMEOUT_MS = 3e3;
var QUERY_TIMEOUT_MS = 3e4;
function resolveDkgUrl(explicit) {
  const envUrl = process.env.BLACKBOX_DKG_DAEMON_URL || process.env.BLACKBOX_DKG_URL;
  const port = Number(process.env.BLACKBOX_DKG_PORT);
  const fallback = Number.isFinite(port) && port > 0 ? `http://127.0.0.1:${port}` : DEFAULT_URL;
  return (explicit || envUrl || fallback).replace(/\/+$/, "");
}
function defaultDkgHome() {
  if (process.env.BLACKBOX_DKG_HOME) return process.env.BLACKBOX_DKG_HOME;
  if (process.env.BLACKBOX_HOME) return join3(process.env.BLACKBOX_HOME, "dkg");
  const hermesHome = process.env.HERMES_HOME || join3(homedir(), ".hermes");
  return join3(hermesHome, "blackbox", "dkg");
}
function resolveDkgToken(explicit, dkgHome) {
  if (explicit) return explicit;
  const env = process.env.BLACKBOX_DKG_API_TOKEN || process.env.BLACKBOX_DKG_AUTH_TOKEN;
  if (env) return env;
  const home = dkgHome || defaultDkgHome();
  try {
    for (const raw of readFileSync3(join3(home, "auth.token"), "utf8").split(/\r?\n/)) {
      const line = raw.trim();
      if (line && !line.startsWith("#")) return line;
    }
  } catch {
  }
  return void 0;
}
function isAlreadyFinalized(err) {
  const msg = err.message.toLowerCase();
  return msg.includes("already finalized") || msg.includes("already exists") || msg.includes("is not an active working memory draft");
}
function jobIdFromError(err) {
  for (const key of ["existingJobId", "jobId", "id"]) {
    const m = new RegExp(`"${key}"\\s*:\\s*"([^"]+)"`).exec(err.message);
    if (m) return m[1];
  }
  return void 0;
}
function shareJobId(result) {
  const job = result.job && typeof result.job === "object" ? result.job : result;
  for (const key of ["jobId", "id", "job_id", "shareJobId", "existingJobId"]) {
    if (job[key]) return String(job[key]);
  }
  return void 0;
}
var DkgClient = class {
  url;
  token;
  timeoutMs;
  /** Cached reporter agent address (see `reporterAddress()`). */
  cachedReporter;
  constructor(opts = {}) {
    this.url = resolveDkgUrl(opts.url);
    this.token = resolveDkgToken(opts.token, opts.dkgHome);
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }
  async request(path2, body, method = "POST", timeoutMs = this.timeoutMs) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const headers = { "content-type": "application/json" };
      if (this.token) headers.authorization = `Bearer ${this.token}`;
      const res = await fetch(`${this.url}${path2}`, {
        method,
        headers,
        body: body === void 0 ? void 0 : JSON.stringify(body),
        signal: controller.signal
      });
      const text = await res.text();
      if (!res.ok) {
        throw new DkgError(`DKG ${method} ${path2} -> ${res.status}: ${text.slice(0, 300)}`, res.status);
      }
      return text ? JSON.parse(text) : {};
    } catch (err) {
      if (err instanceof DkgError) throw err;
      throw new DkgError(`DKG ${method} ${path2} failed: ${err.message}`);
    } finally {
      clearTimeout(timer);
    }
  }
  /** The node's listing of context graphs (id, subscribed, accessPolicy, …). */
  async contextGraphs() {
    const resp = await this.request("/api/context-graphs", void 0, "GET");
    const list = Array.isArray(resp) ? resp : resp?.contextGraphs ?? resp?.items ?? [];
    return Array.isArray(list) ? list : [];
  }
  /** The DKG network id the node runs on ("" when unknown) — the signing environment (Python `network_environment`). */
  async networkId() {
    const status = await this.status();
    return String(status?.networkId ?? "");
  }
  /** Subscribe the node to a context graph (idempotent on the daemon). */
  async subscribeContextGraph(contextGraphId, includeSharedMemory = true) {
    return this.request("/api/context-graph/subscribe", { contextGraphId, includeSharedMemory });
  }
  /**
   * The explicit v10 share lifecycle Python `share_knowledge_asset` uses: write/seal the
   * asset in WM (`alsoShareSwm:false`), then queue `/swm/share-async` and poll the job — both
   * in the community sub-graph ({@link COMMUNITY_SUB_GRAPH}), never the graph's root.
   * An asset the node already holds sealed is shared as-is; a `{ idempotent: true }`
   * result means "already on the network", which callers report as not-new (KI-104).
   */
  async shareReport(contextGraphId, name, quads, opts = {}) {
    try {
      await this.request("/api/knowledge-assets", {
        contextGraphId,
        name,
        quads,
        alsoShareSwm: false,
        subGraphName: COMMUNITY_SUB_GRAPH
      });
    } catch (err) {
      if (!(err instanceof DkgError) || !isAlreadyFinalized(err)) throw err;
    }
    const enc = encodeURIComponent(name);
    let queued;
    try {
      queued = await this.request(`/api/knowledge-assets/${enc}/swm/share-async`, {
        contextGraphId,
        entities: "all",
        subGraphName: COMMUNITY_SUB_GRAPH
      });
    } catch (err) {
      if (err instanceof DkgError && isAlreadyFinalized(err)) return { name, idempotent: true };
      const existing = err instanceof DkgError ? jobIdFromError(err) : void 0;
      if (!existing) throw err;
      queued = { jobId: existing, state: "existing" };
    }
    const jobId = shareJobId(queued);
    if (!jobId) return queued;
    const deadline = Date.now() + (opts.timeoutMs ?? 6e5);
    const poll = opts.pollMs ?? 5e3;
    for (; ; ) {
      const job = await this.request(`/api/knowledge-assets/swm/share-jobs/${encodeURIComponent(jobId)}`, void 0, "GET");
      const state = String(job.state ?? job.status ?? job.phase ?? "unknown").toLowerCase();
      if (["succeeded", "success", "completed", "complete"].includes(state)) return job;
      if (["failed", "error", "cancelled", "canceled"].includes(state)) throw new DkgError(`SWM share job ${jobId} failed: ${JSON.stringify(job).slice(0, 1e3)}`);
      if (Date.now() >= deadline) throw new DkgError(`SWM share job ${jobId} timed out (last state=${state})`);
      await new Promise((r) => setTimeout(r, Math.max(1e3, poll)));
    }
  }
  /** Node liveness probe — public, no-auth `GET /api/status`. */
  async status() {
    return this.request("/api/status", void 0, "GET");
  }
  /**
   * Resolve the node's reporter agent address, cached. Prefers the definitive
   * `GET /api/agent/identity` → `{agentAddress}`; falls back to `GET /api/status`
   * (which may surface an agent address). Fails open to "node" so a report URI
   * can always be namespaced. NEVER derived from the auth token string.
   */
  async reporterAddress() {
    if (this.cachedReporter !== void 0) return this.cachedReporter;
    const pick = (resp) => {
      const r = resp;
      const addr = r?.agentAddress ?? r?.agent_address ?? r?.address;
      return typeof addr === "string" && addr.trim() ? addr.trim() : void 0;
    };
    try {
      const addr = pick(await this.request("/api/agent/identity", void 0, "GET"));
      if (addr) return this.cachedReporter = addr;
    } catch {
    }
    try {
      const addr = pick(await this.status());
      if (addr) return this.cachedReporter = addr;
    } catch {
    }
    return this.cachedReporter = "node";
  }
  /**
   * One-shot create + write + seal (+ share to SWM). This is the report path:
   * `POST /api/knowledge-assets {contextGraphId, name, quads, alsoShareSwm:true}`.
   * Quads carry NO per-quad graph (the CG scopes them).
   */
  async shareKnowledgeAsset(contextGraphId, name, quads) {
    return this.request("/api/knowledge-assets", {
      contextGraphId,
      name,
      quads,
      alsoShareSwm: true
    });
  }
  /** SPARQL query against a memory view. Blackbox defaults to durable VM. */
  async query(sparql, contextGraphId, view = "verifiable-memory") {
    return this.request("/api/query", { sparql, contextGraphId, view }, "POST", QUERY_TIMEOUT_MS);
  }
};

// src/audit.ts
import { appendFileSync, mkdirSync as mkdirSync2, readFileSync as readFileSync5, statSync, writeFileSync as writeFileSync2 } from "node:fs";
import { homedir as homedir2 } from "node:os";
import { basename, dirname, isAbsolute, join as join4, resolve } from "node:path";

// src/seedPhrase.ts
import { createHash as createHash3 } from "node:crypto";
import { readFileSync as readFileSync4 } from "node:fs";

// src/textView.ts
var EDITS = /%(?:25)*([0-9A-Fa-f]{2})|([\u00ad\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\ufeff])|([\uff01-\uff5e])|(&(?:[A-Za-z]{2,8}|#[0-9]{1,6}|#[xX][0-9A-Fa-f]{1,6});)|(?<=[a-z])(?=[A-Z])/g;
var FULLWIDTH_OFFSET = 65248;
var PERCENT = /%(?:25)*([0-9A-Fa-f]{2})/g;
function percentDecoded(text) {
  return text.includes("%") ? text.replace(PERCENT, (_whole, hex) => String.fromCharCode(parseInt(hex, 16))) : text;
}
var INVISIBLE = /[\u00ad\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\ufeff]/;
function replacement(match, invisible) {
  const [, percent, hidden, fullwidth] = match;
  if (percent !== void 0) return String.fromCharCode(parseInt(percent, 16));
  if (fullwidth !== void 0) return String.fromCharCode(fullwidth.charCodeAt(0) - FULLWIDTH_OFFSET);
  if (hidden !== void 0) return invisible;
  return " ";
}
function readings(text) {
  return INVISIBLE.test(text) ? [normalised(text), normalised(text, " ")] : [normalised(text)];
}
function normalised(text, invisible = "") {
  const pieces = [];
  const segments = [];
  let view = 0;
  let original = 0;
  for (const match of text.matchAll(EDITS)) {
    const start = match.index ?? 0;
    if (start > original) {
      const length = start - original;
      pieces.push(text.slice(original, start));
      segments.push([view, length, original, length]);
      view += length;
    }
    const piece = replacement(match, invisible);
    if (piece) {
      pieces.push(piece);
      segments.push([view, 1, start, match[0].length]);
      view += 1;
    }
    original = start + match[0].length;
  }
  if (original < text.length || segments.length === 0) {
    const length = text.length - original;
    pieces.push(text.slice(original));
    segments.push([view, length, original, length]);
  }
  const segmentAt = (offset) => {
    let low = 0;
    let high = segments.length - 1;
    while (low < high) {
      const middle = low + high + 1 >> 1;
      if (segments[middle][0] <= offset) low = middle;
      else high = middle - 1;
    }
    return segments[low];
  };
  return {
    text: pieces.join(""),
    originalSpan(start, end) {
      const [viewStart, viewLength, originalStart, originalLength] = segmentAt(start);
      const begin = viewLength === originalLength ? originalStart + (start - viewStart) : originalStart;
      const [lastStart, lastLength, lastOriginal, lastOriginalLength] = segmentAt(end - 1);
      const finish = lastLength === lastOriginalLength ? lastOriginal + (end - 1 - lastStart) + 1 : lastOriginal + lastOriginalLength;
      return [begin, finish];
    }
  };
}

// src/seedPhrase.ts
var SEED_PHRASE_MARKER = "[REDACTED_SEED_PHRASE]";
var WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";
var MIN_WORDS = 12;
var WORD_RE = /[A-Za-z]+/g;
var BASE64_RE = /(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{64,4096}={0,2}(?![A-Za-z0-9+/=_-])/g;
var MAX_ENCODED = 16;
var wordlist;
function loadWordlist() {
  if (wordlist !== void 0) return wordlist;
  try {
    const data = readFileSync4(new URL("./bip39-english.txt", import.meta.url));
    if (createHash3("sha256").update(data).digest("hex") !== WORDLIST_SHA256) {
      console.warn("blackbox: BIP-39 wordlist does not match its pinned SHA-256; seed-phrase redaction is OFF");
      wordlist = null;
    } else {
      wordlist = new Set(data.toString("ascii").split(/\s+/).filter(Boolean));
    }
  } catch (error) {
    console.warn(`blackbox: BIP-39 wordlist unreadable (${String(error)}); seed-phrase redaction is OFF`);
    wordlist = null;
  }
  return wordlist;
}
var prefixes;
function loadPrefixes(words) {
  if (!prefixes) prefixes = new Set([...words].filter((word) => word.length > 4).map((word) => word.slice(0, 4)));
  return prefixes;
}
function runSpans(text, words) {
  const shortForms = loadPrefixes(words);
  const spans = [];
  let runStart = -1;
  let runEnd = -1;
  let count = 0;
  for (const match of text.matchAll(WORD_RE)) {
    const token2 = match[0].toLowerCase();
    const listed = words.has(token2) || token2.length === 4 && shortForms.has(token2);
    if (!listed) {
      if (count >= MIN_WORDS) spans.push([runStart, runEnd]);
      count = 0;
      continue;
    }
    const start = match.index ?? 0;
    if (count === 0) runStart = start;
    runEnd = start + match[0].length;
    count += 1;
  }
  if (count >= MIN_WORDS) spans.push([runStart, runEnd]);
  return spans;
}
function seedPhraseSpans(text, words) {
  return readings(text).flatMap((view) => runSpans(view.text, words).map(([start, end]) => view.originalSpan(start, end)));
}
function decodedText(blob) {
  const core = blob.replace(/=+$/, "");
  if (core.length % 4 === 1) return null;
  const raw = Buffer.from(core.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  for (const byte of raw) if (!(byte >= 32 && byte < 127 || byte === 9 || byte === 10 || byte === 13)) return null;
  return raw.toString("ascii");
}
function allSeedPhraseSpans(text) {
  const words = loadWordlist();
  if (!text || !words) return [];
  const spans = seedPhraseSpans(text, words);
  for (const match of [...text.matchAll(BASE64_RE)].slice(0, MAX_ENCODED)) {
    const decoded = decodedText(match[0]);
    if (decoded && seedPhraseSpans(decoded, words).length) spans.push([match.index ?? 0, (match.index ?? 0) + match[0].length]);
  }
  const merged2 = [];
  for (const [start, end] of spans.sort((a, b) => a[0] - b[0] || a[1] - b[1])) {
    const last = merged2[merged2.length - 1];
    if (last && start < last[1]) last[1] = Math.max(end, last[1]);
    else merged2.push([start, end]);
  }
  return merged2;
}
function redactSeedPhrases(text) {
  let out = text;
  for (const [start, end] of allSeedPhraseSpans(text).reverse()) out = out.slice(0, start) + SEED_PHRASE_MARKER + out.slice(end);
  return out;
}

// src/solanaKey.ts
import { createPrivateKey as createPrivateKey2, createPublicKey as createPublicKey2 } from "node:crypto";

// src/base58.ts
var BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58Decode(text) {
  let value = 0n;
  for (const char of text) value = value * 58n + BigInt(BASE58_ALPHABET.indexOf(char));
  const hex = value === 0n ? "" : value.toString(16);
  const body = Buffer.from(hex.length % 2 ? "0" + hex : hex, "hex");
  const zeros = text.length - text.replace(/^1+/, "").length;
  return Buffer.concat([Buffer.alloc(zeros), body]);
}

// src/solanaKey.ts
var SOLANA_KEY_MARKER = "[REDACTED_SOLANA_KEY]";
var BASE58_KEY = /(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{86,89}(?![1-9A-HJ-NP-Za-km-z])/g;
var JSON_KEY = /\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*\]/g;
var HEX_KEY = /(?<![0-9A-Fa-f])[0-9A-Fa-f]{128}(?![0-9A-Fa-f])/g;
var BASE64_KEY = /(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{86}(?:==)?(?![A-Za-z0-9+/_=-])/g;
var CUT_BASE58 = /(?<![0-9A-Za-z])(?=[0-9A-Za-z]{0,107}[g-km-zG-HJ-NP-Z])[1-9A-HJ-NP-Za-km-z]{45,89}$(?![\s\S])/;
var CUT_JSON = /\[\s*(?:\d{1,3}\s*,\s*){31,63}\d{0,3}\s*$(?![\s\S])/;
var CUT_HEX = /(?<![0-9A-Za-z])(?:0x)?[0-9A-Fa-f]{65,127}$(?![\s\S])/;
var MAX_CANDIDATES = 256;
var SEED_BYTES = 32;
var PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
function jsonBytes(text) {
  const values = (text.match(/\d+/g) ?? []).map(Number);
  return values.every((v) => v < 256) ? Buffer.from(values) : null;
}
function hexBytes(text) {
  return Buffer.from(text, "hex");
}
function base64Bytes(text) {
  return Buffer.from(text.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}
var DECODERS = [
  [BASE58_KEY, base58Decode],
  [JSON_KEY, jsonBytes],
  [HEX_KEY, hexBytes],
  [BASE64_KEY, base64Bytes]
];
function publicKey(seed) {
  const privateKey = createPrivateKey2({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: "der", type: "pkcs8" });
  const jwk = createPublicKey2(privateKey).export({ format: "jwk" });
  return Buffer.from(jwk.x, "base64url");
}
function isSolanaSecretKey(material) {
  if (!material || material.length !== 2 * SEED_BYTES) return false;
  return publicKey(material.subarray(0, SEED_BYTES)).equals(material.subarray(SEED_BYTES));
}
function scanSolanaKeys(text) {
  const candidates2 = [];
  DECODERS.forEach(([pattern], index) => {
    for (const m of text.matchAll(pattern)) candidates2.push([m.index ?? 0, (m.index ?? 0) + m[0].length, m[0], index]);
  });
  candidates2.sort((a, b) => b[0] - a[0]);
  const verdicts = /* @__PURE__ */ new Map();
  const keys = /* @__PURE__ */ new Map();
  const unchecked = /* @__PURE__ */ new Map();
  for (const [start, end, value, index] of candidates2) {
    const id = `${index}:${value}`;
    if (!verdicts.has(id)) {
      if (verdicts.size >= MAX_CANDIDATES) {
        unchecked.set(`${start}:${end}`, [start, end]);
        continue;
      }
      verdicts.set(id, isSolanaSecretKey(DECODERS[index][1](value)));
    }
    if (verdicts.get(id)) keys.set(`${start}:${end}`, [start, end]);
  }
  for (const id of keys.keys()) unchecked.delete(id);
  const order = (a, b) => a[0] - b[0] || a[1] - b[1];
  return { keys: [...keys.values()].sort(order), unchecked: [...unchecked.values()].sort(order) };
}
function merged(spans) {
  const out = [];
  for (const [start, end] of [...spans].sort((a, b) => a[0] - b[0] || a[1] - b[1])) {
    const last = out[out.length - 1];
    if (last && start < last[1]) last[1] = Math.max(end, last[1]);
    else out.push([start, end]);
  }
  return out;
}
function redactSolanaKeys(text) {
  if (!text) return text;
  const scan = scanSolanaKeys(text);
  let out = text;
  for (const [start, end] of merged([...scan.keys, ...scan.unchecked]).reverse()) {
    out = out.slice(0, start) + SOLANA_KEY_MARKER + out.slice(end);
  }
  for (const cut of [CUT_BASE58, CUT_JSON, CUT_HEX]) out = out.replace(cut, SOLANA_KEY_MARKER);
  return out;
}

// src/bitcoinKey.ts
import { createHash as createHash4 } from "node:crypto";
var WIF_MARKER = "[REDACTED_BITCOIN_PRIVATE_KEY]";
var EXTENDED_MARKER = "[REDACTED_EXTENDED_PRIVATE_KEY]";
var B58 = "1-9A-HJ-NP-Za-km-z";
var WIF = new RegExp(`(?<![${B58}])[59KLc][${B58}]{50,51}(?![${B58}])`, "g");
var EXTENDED = new RegExp(`(?<![${B58}])[xyztuvYZ]prv[${B58}]{107}(?![${B58}])`, "g");
var CUT_WIF = new RegExp(`(?<![0-9A-Za-z])(?=[0-9A-Za-z]{0,107}[g-km-zG-HJ-NP-Z])[59KLc][${B58}]{29,51}$(?![\\s\\S])`);
var CUT_EXTENDED = new RegExp(`(?<![0-9A-Za-z])[xyztuvYZ]prv[${B58}]{0,107}$(?![\\s\\S])`);
var WIF_VERSIONS = /* @__PURE__ */ new Set([128, 239]);
var EXTENDED_VERSIONS = /* @__PURE__ */ new Set(["0488ade4", "049d7878", "04b2430c", "04358394", "044a4e28", "045f18bc", "0295b005", "02aa7a99"]);
var CURVE_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
function sha256(data) {
  return createHash4("sha256").update(data).digest();
}
function checkDecode(text) {
  const raw = base58Decode(text);
  if (raw.length < 5) return null;
  const body = raw.subarray(0, raw.length - 4);
  return sha256(sha256(body)).subarray(0, 4).equals(raw.subarray(raw.length - 4)) ? body : null;
}
function inRange(key) {
  const value = BigInt("0x" + (key.toString("hex") || "0"));
  return value > 0n && value < CURVE_ORDER;
}
function isWif(text) {
  const body = checkDecode(text);
  if (!body || !WIF_VERSIONS.has(body[0])) return false;
  const compressed = body.length === 34 && body[33] === 1;
  return (body.length === 33 || compressed) && inRange(body.subarray(1, 33));
}
function isExtended(text) {
  const body = checkDecode(text);
  return !!body && body.length === 78 && EXTENDED_VERSIONS.has(body.subarray(0, 4).toString("hex")) && body[45] === 0 && inRange(body.subarray(46, 78));
}
function redactBitcoinKeys(text) {
  const found = [];
  for (const m of text.matchAll(WIF)) if (isWif(m[0])) found.push([m.index ?? 0, (m.index ?? 0) + m[0].length, WIF_MARKER]);
  for (const m of text.matchAll(EXTENDED)) if (isExtended(m[0])) found.push([m.index ?? 0, (m.index ?? 0) + m[0].length, EXTENDED_MARKER]);
  found.sort((a, b) => a[0] - b[0]);
  let out = text;
  for (const [start, end, marker2] of found.reverse()) out = out.slice(0, start) + marker2 + out.slice(end);
  return out.replace(CUT_EXTENDED, EXTENDED_MARKER).replace(CUT_WIF, WIF_MARKER);
}

// src/redact.ts
var SECRET_VALUE_RULES = [
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
  ["wallet-private-key", /\b[A-Za-z0-9_]{0,32}?(?:sol(?:ana)?|phantom|keypair)[_ -]?(?:private|secret)?[_ -]?(?:key|seed)[A-Za-z0-9_]{0,32}["']?[ \t]*[:=][ \t]*["']?[1-9A-HJ-NP-Za-km-z]{43,44}(?![1-9A-HJ-NP-Za-km-z])/gi]
];
var REDACTION_ONLY_RULES = [
  ["api-key", /\bsk-[A-Za-z0-9_-]{16,}/g],
  ["github-token", /\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{16,}/g]
];
var BEARER_RE = /Bearer\s+[A-Za-z0-9._~+/=-]+/gi;
var SECRET_ASSIGNMENT_RE = /(?<key>\b(?=[A-Za-z0-9_-]{0,64}?(?:api[_-]?key|token|secret|password|passwd|credential|private[_-]?key|client[_-]?secret|access[_-]?key))(?=(?<name>[A-Za-z0-9_-]{1,64}))\k<name>["']?)(?<sep>\s*[:=]\s*["']?)(?<value>[^\s"'[\],;]{8,})/gi;
var SECRET_KEY_RE = /(api[_-]?key|token|secret|password|passwd|credential|authorization|private[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token)/i;
function marker(secretType) {
  return `[REDACTED_${secretType.toUpperCase().replace(/-/g, "_")}]`;
}
function redactSecretValues(text) {
  let out = percentDecoded(String(text));
  out = redactSeedPhrases(out);
  out = redactSolanaKeys(out);
  out = redactBitcoinKeys(out);
  for (const [secretType, pattern] of SECRET_VALUE_RULES) out = out.replace(pattern, marker(secretType));
  for (const [secretType, pattern] of REDACTION_ONLY_RULES) out = out.replace(pattern, marker(secretType));
  out = out.replace(BEARER_RE, "Bearer [REDACTED]");
  return out.replace(SECRET_ASSIGNMENT_RE, "$<key>$<sep>[REDACTED]");
}
var REDACTION_MARGIN = 8192;
var CUT_GUARD = 1024;
function sanitizeText(value, maxLength = 2e3) {
  let text = String(value);
  const precut = text.length > maxLength + REDACTION_MARGIN;
  if (precut) text = text.slice(0, maxLength + REDACTION_MARGIN);
  let redacted = redactSecretValues(text);
  if (precut) redacted = redacted.slice(0, Math.max(0, redacted.length - CUT_GUARD));
  return precut || redacted.length > maxLength ? `${redacted.slice(0, maxLength)}...[truncated]` : redacted;
}
var MAX_DEPTH = 5;
var MAX_ITEMS = 50;
var SOLANA_KEY_BYTES = 64;
function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function walk(value, depth, visit) {
  if (depth > MAX_DEPTH) return value;
  if (typeof value === "string") return visit("value", value) ?? value;
  if (Array.isArray(value)) {
    if (value.length === SOLANA_KEY_BYTES && value.every((item) => Number.isInteger(item) && item >= 0 && item < 256)) {
      return visit("bytes", value) ?? value;
    }
    return value.slice(0, MAX_ITEMS).map((item) => walk(item, depth + 1, visit));
  }
  if (isPlainObject(value)) {
    const out = {};
    for (const [key, child] of Object.entries(value)) out[visit("key", key) ?? key] = walk(child, depth + 1, visit);
    return out;
  }
  return value;
}
function hitPieces(pieces) {
  const starts = [];
  let text = "";
  for (const piece of pieces) {
    starts.push(text.length);
    text += piece + " ";
  }
  const hits = /* @__PURE__ */ new Set();
  for (const [start, end] of allSeedPhraseSpans(text)) {
    starts.forEach((pieceStart, index) => {
      if (pieceStart < end && pieceStart + pieces[index].length > start) hits.add(index);
    });
  }
  return hits;
}
function blankAssembledSecrets(value) {
  const pieces = { value: [], key: [], bytes: [] };
  walk(value, 0, (kind, piece) => {
    pieces[kind].push(piece);
    return void 0;
  });
  const hits = { value: hitPieces(pieces.value), key: hitPieces(pieces.key) };
  if (!hits.value.size && !hits.key.size && !pieces.bytes.length) return value;
  const seen = { value: 0, key: 0 };
  return walk(value, 0, (kind, piece) => {
    if (kind === "bytes") return isSolanaSecretKey(Buffer.from(piece)) ? SOLANA_KEY_MARKER : void 0;
    const index = seen[kind]++;
    if (!hits[kind].has(index)) return void 0;
    return kind === "value" ? SEED_PHRASE_MARKER : `${SEED_PHRASE_MARKER}#${index}`;
  });
}
function redact(value, depth = 0) {
  if (depth === 0 && (Array.isArray(value) || isPlainObject(value))) value = blankAssembledSecrets(value);
  if (depth > 5) return "[truncated-depth]";
  if (value == null) return value;
  if (typeof value === "string") return sanitizeText(value);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) return value.slice(0, 50).map((item) => redact(item, depth + 1));
  if (typeof value === "object") {
    const out = {};
    for (const [rawKey, child] of Object.entries(value)) {
      const key = sanitizeText(rawKey, 200);
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

// src/audit.ts
var FRAMEWORK = "openclaw";
var LOG_FILE = "findings.openclaw.jsonl";
var AUDIT_LOG_FILE = "audit.openclaw.jsonl";
var LOG_MAX_BYTES = 8 * 1024 * 1024;
var LOG_KEEP_BYTES = 4 * 1024 * 1024;
var CTX_MAX_TURNS = 16;
var CTX_TURN_CHARS = 3e3;
var CTX_FIELD_CHARS = 6e3;
function expandHome(path2) {
  if (path2 === "~") return homedir2();
  if (path2.startsWith("~/")) return join4(homedir2(), path2.slice(2));
  return path2;
}
function currentWorkspace() {
  const configPath = process.env.OPENCLAW_CONFIG_PATH?.trim();
  if (configPath) {
    const expanded = expandHome(configPath);
    const absolute = isAbsolute(expanded) ? expanded : resolve(expanded);
    return basename(absolute) === "openclaw.json" ? dirname(absolute) : absolute;
  }
  const stateDir = process.env.OPENCLAW_STATE_DIR?.trim();
  if (stateDir) return resolve(expandHome(stateDir));
  const openclawHome = process.env.OPENCLAW_HOME?.trim();
  if (openclawHome) return resolve(expandHome(openclawHome), ".openclaw");
  return join4(homedir2(), ".openclaw");
}
function boundedContext(ctx) {
  if (!ctx || typeof ctx !== "object") return void 0;
  const out = {};
  if (Array.isArray(ctx.turns) && ctx.turns.length) {
    const turns = [];
    for (const t of ctx.turns.slice(-CTX_MAX_TURNS)) {
      if (!t || typeof t !== "object") continue;
      const text = sanitizeText(String(t.text ?? ""), CTX_TURN_CHARS);
      if (!text) continue;
      turns.push({ role: String(t.role ?? "user").slice(0, 32), text });
    }
    if (turns.length) out.turns = turns;
  }
  if (typeof ctx.input === "string" && ctx.input) out.input = sanitizeText(ctx.input, CTX_FIELD_CHARS);
  if (typeof ctx.result === "string" && ctx.result) out.result = sanitizeText(ctx.result, CTX_FIELD_CHARS);
  if (!out.turns && !out.input && !out.result) return void 0;
  if (ctx.truncated) out.truncated = true;
  return out;
}
function isoNow() {
  return (/* @__PURE__ */ new Date()).toISOString().replace(/\.\d{3}Z$/, "Z");
}
function recordEvent(home, event, detail = {}) {
  try {
    if (!home) return;
    mkdirSync2(home, { recursive: true });
    const path2 = join4(home, AUDIT_LOG_FILE);
    appendFileSync(
      path2,
      JSON.stringify({
        ts: Date.now() / 1e3,
        iso: isoNow(),
        event,
        framework: FRAMEWORK,
        workspace: currentWorkspace(),
        detail: redact(detail)
      }) + "\n",
      "utf8"
    );
    trimIfNeeded(path2);
  } catch {
  }
}
function recordFinding(home, event, finding, toolName, context, outcome = {}) {
  try {
    if (!home) return;
    mkdirSync2(home, { recursive: true });
    const now = Date.now() / 1e3;
    const tool = toolName ?? finding.toolName ?? "";
    const detail = { tool_name: tool };
    if (outcome.decision) detail.decision = outcome.decision.slice(0, 40);
    if (outcome.agent) detail.agent = sanitizeText(outcome.agent, 120);
    if (outcome.sessionId) detail.session_id = sanitizeText(outcome.sessionId, 160);
    const ctx = boundedContext(context);
    if (ctx) detail.context = ctx;
    const line = {
      ts: now,
      iso: isoNow(),
      event,
      framework: FRAMEWORK,
      workspace: currentWorkspace(),
      detail,
      // Same nested shape Python writes so read_findings lifts these fields.
      finding: {
        identifier: finding.identifier,
        category: finding.category,
        severity: finding.severity,
        title: finding.title,
        tool_name: tool,
        evidence: sanitizeText(String(finding.evidence ?? ""), 700),
        confirmed: finding.confirmed,
        candidate: !finding.confirmed,
        source: finding.source,
        framework: FRAMEWORK,
        ts: now
      }
    };
    const path2 = join4(home, LOG_FILE);
    appendFileSync(path2, JSON.stringify(line) + "\n", "utf8");
    trimIfNeeded(path2);
  } catch {
  }
}
function trimIfNeeded(path2) {
  try {
    if (statSync(path2).size <= LOG_MAX_BYTES) return;
    const buf = readFileSync5(path2);
    let tail = buf.subarray(buf.length - LOG_KEEP_BYTES);
    const nl = tail.indexOf(10);
    if (nl !== -1) tail = tail.subarray(nl + 1);
    writeFileSync2(path2, tail);
  } catch {
  }
}

// src/verdictClient.ts
var VERDICT_TIMEOUT_MS = 1500;
var RETRY_AFTER_MS = 15e3;
var REFUSED = 403;
function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function readVerdict(body) {
  if (!isRecord(body) || !Array.isArray(body.findings) || !Array.isArray(body.blocked)) return null;
  const findings = [];
  for (const row of body.findings) {
    if (!isRecord(row)) return null;
    const { identifier, category, severity: severity2, title } = row;
    if (typeof identifier !== "string" || typeof category !== "string" || typeof severity2 !== "string" || typeof title !== "string") return null;
    findings.push(row);
  }
  const known = new Set(findings.map((finding) => finding.identifier));
  const blocked = body.blocked.filter((id) => typeof id === "string" && known.has(id));
  if (blocked.length !== body.blocked.length) return null;
  return {
    findings,
    blocked,
    decision: typeof body.decision === "string" ? body.decision : "",
    message: typeof body.message === "string" ? body.message : ""
  };
}
var VerdictClient = class {
  baseUrl;
  fetchImpl;
  now;
  token = "";
  silentUntil = 0;
  /** `fetchImpl` and `now` are seams for tests; an empty `baseUrl` means "never ask". */
  constructor(baseUrl, fetchImpl, now) {
    this.baseUrl = (baseUrl || "").replace(/\/+$/, "");
    this.fetchImpl = fetchImpl ?? globalThis.fetch;
    this.now = now ?? Date.now;
  }
  /** Blackbox's verdict for this call, or null when it could not be had in time. */
  async ask(toolName, args) {
    if (!this.baseUrl || typeof this.fetchImpl !== "function" || this.now() < this.silentUntil) return null;
    try {
      const verdict = await this.askOnce(toolName, args, AbortSignal.timeout(VERDICT_TIMEOUT_MS));
      if (verdict === null) this.silentUntil = this.now() + RETRY_AFTER_MS;
      return verdict;
    } catch {
      this.silentUntil = this.now() + RETRY_AFTER_MS;
      return null;
    }
  }
  async askOnce(toolName, args, signal) {
    for (const attempt of [1, 2]) {
      if (!this.token) this.token = await this.fetchToken(signal);
      if (!this.token) return null;
      const response = await this.fetchImpl(`${this.baseUrl}/api/guard/verdict`, {
        method: "POST",
        signal,
        headers: { "content-type": "application/json", accept: "application/json", "x-blackbox-token": this.token },
        body: JSON.stringify({ tool_name: toolName, args })
      });
      if (response.status === REFUSED && attempt === 1) {
        this.token = "";
        continue;
      }
      return response.ok ? readVerdict(await response.json()) : null;
    }
    return null;
  }
  async fetchToken(signal) {
    const response = await this.fetchImpl(`${this.baseUrl}/api/session`, { signal, headers: { accept: "application/json" } });
    if (!response.ok) return "";
    const body = await response.json();
    return isRecord(body) && typeof body.token === "string" ? body.token : "";
  }
};

// src/config.ts
import { homedir as homedir3 } from "node:os";
import { join as join5 } from "node:path";
var DETECTION_CATEGORIES = [
  "injection",
  "escalation",
  "dependency",
  "fileaccess",
  "skill",
  "ioc"
];
function defaultBlackboxHome() {
  const base = process.env.OPENCLAW_STATE_DIR || process.env.OPENCLAW_HOME || join5(homedir3(), ".openclaw");
  return join5(base, "blackbox");
}
function defaultBlackboxDkgHome() {
  const hermesHome = process.env.HERMES_HOME || join5(homedir3(), ".hermes");
  return join5(hermesHome, "blackbox", "dkg");
}
var DEFAULT_PROTECTED_PATHS = [
  "~/.ssh/*",
  // SSH private keys
  ".env",
  // environment files (any directory)
  ".env.*",
  // env variants (.env.local, .env.production, ...)
  "*.pem",
  // PEM-encoded keys / certificates
  "*.key",
  // private key files
  "*.p12",
  // PKCS#12 / PFX keystores
  "~/.aws/credentials"
  // cloud credential store
];
var DEFAULT_DAILY_REPORT_LIMIT = 100;
function effectiveDailyReportLimit(configured) {
  return configured !== void 0 && Number.isFinite(configured) && configured > 0 ? Math.floor(configured) : DEFAULT_DAILY_REPORT_LIMIT;
}
var DEFAULT_DKG_PORT2 = 9320;
var DEFAULT_DKG_URL = `http://127.0.0.1:${DEFAULT_DKG_PORT2}`;
var DEFAULTS = {
  mode: "audit",
  contextGraphId: "0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox-vm",
  dkgUrl: DEFAULT_DKG_URL,
  dashboardUrl: "http://127.0.0.1:9700",
  dkgHome: "",
  syncInterval: 300,
  report: false,
  dailyReportLimit: DEFAULT_DAILY_REPORT_LIMIT,
  reportMinSeverity: "high",
  blockSeverity: "critical",
  discover: true,
  osvLookup: true,
  categories: {},
  protectedPaths: [...DEFAULT_PROTECTED_PATHS],
  blackboxHome: ""
};
function str(value) {
  return typeof value === "string" && value.trim() ? value.trim() : void 0;
}
function num(value) {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim()) {
    const n = Number(value);
    if (Number.isFinite(n)) return n;
  }
  return void 0;
}
function bool(value) {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    const v = value.trim().toLowerCase();
    if (["true", "1", "yes", "on"].includes(v)) return true;
    if (["false", "0", "no", "off"].includes(v)) return false;
  }
  return void 0;
}
function dashboardUrl(pluginConfig) {
  const configured = pluginConfig.dashboardUrl ?? pluginConfig.dashboard_url;
  const chosen = str(process.env.BLACKBOX_DASHBOARD_URL) ?? (typeof configured === "string" ? configured.trim() : DEFAULTS.dashboardUrl);
  return chosen.replace(/\/+$/, "");
}
function envDkgUrl() {
  const explicit = str(process.env.BLACKBOX_DKG_DAEMON_URL) ?? str(process.env.BLACKBOX_DKG_URL);
  if (explicit) return explicit.replace(/\/+$/, "");
  const port = num(process.env.BLACKBOX_DKG_PORT);
  return port !== void 0 ? `http://127.0.0.1:${port}` : void 0;
}
function mode(value) {
  const v = str(value)?.toLowerCase();
  return v === "audit" || v === "block" ? v : void 0;
}
function severity(value) {
  const v = str(value)?.toLowerCase();
  return v && v in SEVERITY_RANK ? v : void 0;
}
function normalizeCategories(raw) {
  const out = {};
  if (raw == null || typeof raw !== "object" || Array.isArray(raw)) return out;
  const obj = raw;
  for (const category of DETECTION_CATEGORIES) {
    const item = obj[category];
    if (item == null || typeof item !== "object" || Array.isArray(item)) continue;
    const rec = item;
    const setting = {};
    const enabled = bool(rec.enabled);
    if (enabled !== void 0) setting.enabled = enabled;
    const minSev = severity(rec.minSeverity) ?? severity(rec.min_severity);
    if (minSev !== void 0) setting.minSeverity = minSev;
    if (Object.keys(setting).length > 0) out[category] = setting;
  }
  return out;
}
function normalizeProtectedPaths(raw) {
  if (raw == null) return [...DEFAULT_PROTECTED_PATHS];
  if (!Array.isArray(raw)) return [];
  const out = [];
  for (const item of raw) {
    const text = item == null ? "" : String(item).trim();
    if (text && !out.includes(text)) out.push(text);
  }
  return out.slice(0, 100);
}
function categorySetting(cfg, category) {
  const raw = cfg.categories[category];
  const minSeverity = raw && raw.minSeverity && raw.minSeverity in SEVERITY_RANK ? raw.minSeverity : "info";
  const enabled = raw && typeof raw.enabled === "boolean" ? raw.enabled : true;
  return { enabled, minSeverity };
}
function categoryAllows(cfg, category, sev) {
  const setting = categorySetting(cfg, category);
  if (!setting.enabled) return false;
  const floor = SEVERITY_RANK[setting.minSeverity];
  return (SEVERITY_RANK[sev] ?? -1) >= floor;
}
function resolveConfig(pluginConfig = {}) {
  const env = process.env;
  return {
    mode: mode(env.BLACKBOX_MODE) ?? mode(pluginConfig.mode) ?? DEFAULTS.mode,
    contextGraphId: str(env.BLACKBOX_CONTEXT_GRAPH_ID) ?? str(pluginConfig.contextGraphId) ?? str(pluginConfig.context_graph_id) ?? DEFAULTS.contextGraphId,
    dkgUrl: envDkgUrl() ?? str(pluginConfig.dkgUrl)?.replace(/\/+$/, "") ?? str(pluginConfig.dkg_url)?.replace(/\/+$/, "") ?? str(pluginConfig.daemonUrl)?.replace(/\/+$/, "") ?? DEFAULTS.dkgUrl,
    dashboardUrl: dashboardUrl(pluginConfig),
    dkgHome: str(env.BLACKBOX_DKG_HOME) ?? str(pluginConfig.dkgHome) ?? str(pluginConfig.dkg_home) ?? defaultBlackboxDkgHome(),
    syncInterval: num(env.BLACKBOX_SYNC_INTERVAL) ?? num(pluginConfig.syncInterval) ?? num(pluginConfig.sync_interval) ?? DEFAULTS.syncInterval,
    // KI-182 port: the bridge builds R1-schema, signed reports for the community (the shared
    // memory of contextGraphId), so the switch is wired. Still opt-in, and a consent record gates every send.
    report: bool(env.BLACKBOX_REPORT) ?? bool(pluginConfig.report) ?? DEFAULTS.report,
    dailyReportLimit: effectiveDailyReportLimit(
      num(env.BLACKBOX_DAILY_REPORT_LIMIT) ?? num(pluginConfig.dailyReportLimit) ?? num(pluginConfig.daily_report_limit)
    ),
    reportMinSeverity: severity(env.BLACKBOX_REPORT_MIN_SEVERITY) ?? severity(pluginConfig.reportMinSeverity) ?? severity(pluginConfig.report_min_severity) ?? DEFAULTS.reportMinSeverity,
    blockSeverity: severity(env.BLACKBOX_BLOCK_SEVERITY) ?? severity(pluginConfig.blockSeverity) ?? severity(pluginConfig.block_severity) ?? DEFAULTS.blockSeverity,
    discover: bool(env.BLACKBOX_DISCOVER) ?? bool(pluginConfig.discover) ?? DEFAULTS.discover,
    osvLookup: bool(env.BLACKBOX_OSV_LOOKUP) ?? bool(pluginConfig.osvLookup) ?? bool(pluginConfig.osv_lookup) ?? DEFAULTS.osvLookup,
    categories: normalizeCategories(pluginConfig.detection),
    protectedPaths: normalizeProtectedPaths(pluginConfig.protected_paths ?? pluginConfig.protectedPaths),
    blackboxHome: str(env.BLACKBOX_HOME) ?? str(pluginConfig.blackboxHome) ?? str(pluginConfig.blackbox_home) ?? defaultBlackboxHome()
  };
}

// src/ruleset.ts
import { mkdirSync as mkdirSync3, readFileSync as readFileSync6, writeFileSync as writeFileSync3 } from "node:fs";
import { homedir as homedir4 } from "node:os";
import { dirname as dirname2, join as join6 } from "node:path";
var SCHEMA_ADVISORY = "http://schema.org/identifier";
var DEFENDER = "urn:defender:";
var DEFENDER_P = "urn:defender:p:";
var SOURCE_OBSERVATION = "urn:blackbox:SourceObservation";
var SOURCE_OBSERVATION_P = "urn:blackbox:p:";
var IOC_TYPES2 = /* @__PURE__ */ new Set(["domain", "url", "ip", "hash", "wallet", "contract"]);
function rulesetQuery() {
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
var TIERS = [
  ["verifiable-memory", "public"]
];
function resolveStateDir(explicit) {
  if (explicit) return explicit;
  const base = process.env.OPENCLAW_STATE_DIR || process.env.OPENCLAW_HOME || join6(homedir4(), ".openclaw");
  return join6(base, "blackbox");
}
function extractBindings(resp) {
  const r = resp;
  const container = r?.result ?? r?.results ?? r;
  const bindings = container?.bindings ?? r?.bindings;
  return Array.isArray(bindings) ? bindings : [];
}
function bindingValue(v) {
  if (v == null) return void 0;
  if (typeof v === "object" && "value" in v) {
    return String(v.value);
  }
  const s = String(v);
  const m = s.match(/^"([\s\S]*)"(?:\^\^.*|@.*)?$/);
  return m ? m[1] : s;
}
function collectThreats(resp) {
  const bySubject = /* @__PURE__ */ new Map();
  for (const b of extractBindings(resp)) {
    const s = bindingValue(b.s);
    const p = bindingValue(b.p);
    const o = bindingValue(b.o);
    if (!s || !p || o === void 0) continue;
    const acc = bySubject.get(s) ?? {};
    acc.subject = s;
    switch (p) {
      case RDF_TYPE:
        acc.rdfType = o;
        break;
      case BLACKBOX_IDENTIFIER_PRED:
        acc.identifier = o;
        break;
      case BLACKBOX_SEVERITY_PRED:
      case `${DEFENDER_P}severity`:
        acc.severity = o;
        break;
      case SCHEMA_NAME:
        acc.name = o;
        break;
      case SCHEMA_DESCRIPTION:
        acc.description = o;
        break;
      case BLACKBOX_PATTERN_PRED:
      case `${DEFENDER_P}pattern`:
        acc.pattern = o;
        break;
      case BLACKBOX_OWASP_CATEGORY_PRED:
        acc.owaspCategory = o;
        break;
      case BLACKBOX_TOOL_NAME_PRED:
        acc.toolName = o;
        break;
      case BLACKBOX_ARG_SHAPE_PRED:
        acc.argShape = o;
        break;
      case BLACKBOX_PACKAGE_NAME_PRED:
      case `${DEFENDER_P}package`:
        acc.packageName = o;
        break;
      case BLACKBOX_PACKAGE_VERSION_PRED:
      case `${DEFENDER_P}version`:
        acc.packageVersion = o;
        break;
      case BLACKBOX_PACKAGE_ECOSYSTEM_PRED:
      case `${DEFENDER_P}ecosystem`:
        acc.packageEcosystem = o;
        break;
      case BLACKBOX_KIND_PRED:
      case `${DEFENDER_P}kind`:
        acc.kind = o;
        break;
      case SCHEMA_ADVISORY:
      case `${DEFENDER_P}advisoryId`:
        acc.advisoryId = o;
        break;
      case BLACKBOX_CATEGORY_PRED:
      case `${DEFENDER_P}iocType`:
        acc.category = o;
        break;
      case `${DEFENDER_P}value`:
        acc.iocValue = o;
        break;
      case BLACKBOX_SKILL_NAME_PRED:
        acc.skillName = o;
        break;
      case BLACKBOX_SKILL_VERSION_PRED:
        acc.skillVersion = o;
        break;
      case BLACKBOX_DANGER_SHAPE_PRED:
        acc.dangerShape = o;
        break;
      case DEFENDER_CORRECTION_TARGET_PRED:
        acc.targetSubject = o;
        break;
      case DEFENDER_CORRECTION_ACTION_PRED:
        acc.correctionAction = o;
        break;
      case `${SOURCE_OBSERVATION_P}canonicalType`:
        acc.canonicalType = o;
        break;
      case `${SOURCE_OBSERVATION_P}category`:
        acc.observationCategory = o;
        break;
      case `${SOURCE_OBSERVATION_P}lifecycleStatus`:
        acc.lifecycleStatus = o;
        break;
      case `${SOURCE_OBSERVATION_P}normalizedValue`:
        acc.normalizedValue = o;
        break;
      case `${SOURCE_OBSERVATION_P}provenanceJson`:
        acc.provenanceJson = o;
        break;
      case `${SOURCE_OBSERVATION_P}sourceId`:
        acc.sourceId = o;
        break;
      default:
        break;
    }
    bySubject.set(s, acc);
  }
  return [...bySubject.values()];
}
var QUOTED_SKILL_NAME_RE = /^["'`]([^"'`]+)["'`]/;
var SKILL_PACKAGE_NAME_RE = /^@?[a-z0-9][a-z0-9._-]*(?:\/[a-z0-9][a-z0-9._-]*)?$/i;
var TITLED_SKILL_NAME_RE = /^(@?[a-z0-9][a-z0-9._-]*(?:\/[a-z0-9][a-z0-9._-]*)?)\s+(?:\(|bcc\b)/i;
function skillNameFromTitle(title) {
  const value = (title || "").trim();
  return QUOTED_SKILL_NAME_RE.exec(value)?.[1]?.trim() ?? TITLED_SKILL_NAME_RE.exec(value)?.[1]?.trim() ?? "";
}
function sourceObservationProvenance(acc) {
  if (!acc.provenanceJson) return {};
  try {
    const value = JSON.parse(acc.provenanceJson);
    return value && typeof value === "object" && !Array.isArray(value) ? value : {};
  } catch {
    return {};
  }
}
function accumToRule(acc, source) {
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
    if (acc.lifecycleStatus?.trim().toLowerCase() === "active" && IOC_TYPES2.has(iocType) && acc.normalizedValue) {
      identifier = iocIdentifier(iocType, acc.normalizedValue);
    }
  }
  if (!identifier) return null;
  const provenance = sourceObservationProvenance(acc);
  const severity2 = normalizeSeverity(acc.severity ?? provenance.severity, "high");
  const name = acc.name || acc.description || acc.normalizedValue || identifier;
  if (identifier.startsWith("injection:")) {
    if (!acc.pattern) return null;
    return {
      category: "injection",
      key: identifier,
      rule: {
        identifier,
        pattern: acc.pattern,
        severity: severity2,
        name,
        owaspCategory: acc.owaspCategory,
        source
      }
    };
  }
  if (identifier.startsWith("escalation:")) {
    if (!acc.toolName || !acc.argShape) return null;
    return {
      category: "escalation",
      key: identifier,
      rule: { identifier, toolName: acc.toolName, argShape: acc.argShape, severity: severity2, name, source }
    };
  }
  if (identifier.startsWith("dep:")) {
    let eco = (acc.packageEcosystem || "").toLowerCase();
    let pkg = (acc.packageName || "").toLowerCase();
    let ver = acc.packageVersion || "";
    if (!(eco && pkg && ver)) {
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
      rule: { identifier, severity: severity2, advisoryId: acc.advisoryId, kind: acc.kind || void 0, name, source }
    };
  }
  if (identifier.startsWith("fileaccess:")) {
    let toolName = acc.toolName;
    let category = acc.category;
    if (!toolName || !category) {
      const parts = identifier.split(":");
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
        severity: severity2,
        name,
        source
      }
    };
  }
  if (identifier.startsWith("skill:")) {
    return {
      category: "skill",
      key: identifier,
      rule: {
        identifier,
        skillName: acc.skillName && SKILL_PACKAGE_NAME_RE.test(acc.skillName) ? acc.skillName : skillNameFromTitle(name),
        skillVersion: acc.skillVersion ?? "",
        dangerShape: acc.dangerShape ?? "",
        severity: severity2,
        name,
        source
      }
    };
  }
  if (identifier.startsWith("ioc:")) {
    const isObservation = acc.rdfType === SOURCE_OBSERVATION;
    const parts = identifier.split(":", 3);
    const iocType = ((isObservation ? acc.canonicalType : acc.category) || parts[1] || "").trim().toLowerCase();
    const value = isObservation ? identifier.slice(`ioc:${parts[1] ?? ""}:`.length) : acc.iocValue || identifier.slice(`ioc:${parts[1] ?? ""}:`.length);
    if (!iocType || !value) return null;
    return {
      category: "ioc",
      key: identifier,
      rule: {
        identifier,
        severity: severity2,
        name,
        iocType,
        value,
        kind: (isObservation ? acc.observationCategory : acc.kind) || void 0,
        sourceId: isObservation ? acc.sourceId : void 0,
        source
      }
    };
  }
  return null;
}
function buildRuleset(tiers) {
  const ruleset = emptyRuleset();
  ruleset.fetchedAt = Date.now();
  const suppressedSubjects = /* @__PURE__ */ new Set();
  for (const [accums, source] of tiers) {
    if (source !== "public") continue;
    for (const acc of accums) {
      if (acc.rdfType === DEFENDER_CORRECTION_TYPE_IRI && acc.correctionAction?.trim().toLowerCase() === DEFENDER_CORRECTION_SUPPRESS && acc.targetSubject) {
        suppressedSubjects.add(acc.targetSubject);
      }
    }
  }
  const seen = {
    injection: /* @__PURE__ */ new Set(),
    escalation: /* @__PURE__ */ new Set(),
    dependency: /* @__PURE__ */ new Set(),
    fileaccess: /* @__PURE__ */ new Set(),
    skill: /* @__PURE__ */ new Set(),
    ioc: /* @__PURE__ */ new Set()
  };
  for (const [accums, source] of tiers) {
    for (const acc of accums) {
      if (acc.subject && suppressedSubjects.has(acc.subject)) continue;
      const mapped = accumToRule(acc, source);
      if (!mapped || seen[mapped.category].has(mapped.key)) continue;
      seen[mapped.category].add(mapped.key);
      switch (mapped.category) {
        case "injection":
          ruleset.injection.push(mapped.rule);
          break;
        case "escalation":
          ruleset.escalation.push(mapped.rule);
          break;
        case "dependency":
          ruleset.dependency[mapped.key] = mapped.rule;
          break;
        case "fileaccess":
          ruleset.fileaccess.push(mapped.rule);
          break;
        case "skill":
          ruleset.skill.push(mapped.rule);
          break;
        case "ioc":
          ruleset.ioc[mapped.key] = mapped.rule;
          break;
      }
    }
  }
  return ruleset;
}
var RulesetCache = class {
  client;
  contextGraphId;
  cachePath;
  ttlMs;
  ruleset;
  refreshing = false;
  constructor(opts) {
    this.client = opts.client;
    this.contextGraphId = opts.contextGraphId;
    this.ttlMs = (opts.ttlSeconds ?? 300) * 1e3;
    this.cachePath = join6(resolveStateDir(opts.stateDir), "ruleset.json");
    const seedPath = opts.seedStateDir ? join6(opts.seedStateDir, "ruleset.json") : "";
    this.ruleset = this.loadFromDisk(this.cachePath) ?? (seedPath ? this.loadFromDisk(seedPath) : null) ?? emptyRuleset();
  }
  loadFromDisk(path2) {
    try {
      const parsed = JSON.parse(readFileSync6(path2, "utf8"));
      if (parsed && Array.isArray(parsed.injection)) {
        const publicOnly = (rows) => (rows ?? []).filter((row) => row.source !== "community");
        const dependencies = Object.fromEntries(
          Object.entries(parsed.dependency ?? {}).filter(
            ([, rule]) => rule?.source !== "community"
          )
        );
        return {
          ...emptyRuleset(),
          ...parsed,
          // Hermes persists the regex source as `pattern_src` because its
          // in-memory `pattern` is a compiled Python regex. Treat that cache as
          // a read-only seed and normalize it to the TypeScript shape.
          injection: publicOnly(parsed.injection).map((rule) => ({ ...rule, pattern: rule.pattern || rule.pattern_src || "" })).filter((rule) => rule.pattern),
          escalation: publicOnly(parsed.escalation),
          dependency: dependencies,
          fileaccess: publicOnly(parsed.fileaccess),
          skill: publicOnly(parsed.skill).map((rule) => ({
            ...rule,
            skillName: rule.skillVersion ? rule.skillName : skillNameFromTitle(rule.name || rule.skillName) || rule.skillName
          })),
          ioc: Object.fromEntries(
            Object.entries(parsed.ioc ?? {}).filter(([, rule]) => rule?.source !== "community")
          ),
          fetchedAt: parsed.fetchedAt ?? (parsed.synced_at ? parsed.synced_at * 1e3 : 0)
        };
      }
    } catch {
    }
    return null;
  }
  saveToDisk(rs) {
    try {
      mkdirSync3(dirname2(this.cachePath), { recursive: true });
      writeFileSync3(this.cachePath, JSON.stringify(rs), "utf8");
    } catch {
    }
  }
  isStale() {
    return Date.now() - this.ruleset.fetchedAt > this.ttlMs;
  }
  /**
   * Force a synchronous sync from the node. Fail-open (returns current on
   * error). One query per sync reads verifiable-memory. If nothing comes back,
   * the last-good public ruleset keeps serving. Mirrors Python `ruleset.refresh`.
   */
  async sync() {
    if (this.refreshing) return this.ruleset;
    this.refreshing = true;
    try {
      const tierAccums = [];
      let gotAny = false;
      for (const [view, source] of TIERS) {
        try {
          const resp = await this.client.query(rulesetQuery(), this.contextGraphId, view);
          const accums = collectThreats(resp);
          if (accums.length > 0) gotAny = true;
          tierAccums.push([accums, source]);
        } catch (err) {
          if (!(err instanceof DkgError)) throw err;
        }
      }
      if (!gotAny) {
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
  get() {
    if (this.isStale() && !this.refreshing) {
      void this.sync();
    }
    return this.ruleset;
  }
  counts() {
    return {
      injection: this.ruleset.injection.length,
      escalation: this.ruleset.escalation.length,
      dependency: Object.keys(this.ruleset.dependency).length,
      fileaccess: this.ruleset.fileaccess.length,
      skill: this.ruleset.skill.length,
      ioc: Object.keys(this.ruleset.ioc).length
    };
  }
};

// src/osv.ts
var OSV_URL = "https://api.osv.dev/v1/query";
var TIMEOUT_MS = 3e3;
var ECOSYSTEM_MAP = {
  npm: "npm",
  pypi: "PyPI",
  cargo: "crates.io",
  rubygems: "RubyGems"
};
var cache = /* @__PURE__ */ new Map();
function osvEcosystem(ecosystem) {
  return ECOSYSTEM_MAP[(ecosystem || "").trim().toLowerCase()] ?? null;
}
function severityOf(vuln) {
  const dbs = vuln.database_specific;
  if (dbs && typeof dbs === "object") {
    const raw = String(dbs.severity ?? "").trim().toLowerCase();
    if (raw) return raw;
  }
  const affected = Array.isArray(vuln.affected) ? vuln.affected : [];
  for (const aff of affected) {
    if (aff && typeof aff === "object") {
      const affDbs = aff.database_specific;
      if (affDbs && typeof affDbs === "object") {
        const raw = String(affDbs.severity ?? "").trim().toLowerCase();
        if (raw) return raw;
      }
    }
  }
  return "high";
}
async function query(osvEco, name, version) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(OSV_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ package: { ecosystem: osvEco, name }, version }),
      signal: controller.signal
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
async function lookup(ecosystem, name, version) {
  const eco = (ecosystem || "").trim().toLowerCase();
  const pkg = (name || "").trim();
  const ver = (version || "").trim();
  if (!pkg || !ver) return null;
  const osvEco = osvEcosystem(eco);
  if (!osvEco) return null;
  const key = `${eco}:${pkg.toLowerCase()}@${ver}`;
  if (cache.has(key)) return cache.get(key) ?? null;
  let result = null;
  const data = await query(osvEco, pkg, ver);
  if (data && typeof data === "object") {
    const vulns = data.vulns;
    if (Array.isArray(vulns) && vulns.length > 0) {
      const first = vulns[0] && typeof vulns[0] === "object" ? vulns[0] : {};
      const advisoryId = String(first.id ?? "OSV");
      result = { advisoryId, severity: severityOf(first) };
    }
  }
  cache.set(key, result);
  return result;
}

// src/index.ts
var PLUGIN_ID = "blackbox";
var FRAMEWORK2 = "openclaw";
var registeredApis = /* @__PURE__ */ new WeakSet();
var CONTEXT_TURNS = 12;
var MAX_TRACKED_SESSIONS = 256;
function sessionIdOf(event) {
  const sid = event?.sessionId;
  return typeof sid === "string" ? sid : "";
}
function agentOf(event, ctx = {}) {
  const fromEvent = event ?? {};
  if (typeof ctx.agentId === "string" && ctx.agentId) return ctx.agentId;
  if (typeof fromEvent.agentId === "string" && fromEvent.agentId) return fromEvent.agentId;
  const key = typeof fromEvent.sessionKey === "string" ? fromEvent.sessionKey : ctx.sessionKey ?? "";
  const parts = key.split(":");
  return parts[0] === "agent" && parts[1] ? parts[1] : "";
}
function sessionRefOf(event, ctx = {}) {
  const eventSessionKey = event?.sessionKey;
  return sessionIdOf(event) || ctx.sessionId || (typeof eventSessionKey === "string" ? eventSessionKey : "") || ctx.sessionKey || "";
}
function messageText(content) {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content.map(
      (it) => typeof it === "string" ? it : it && typeof it === "object" && typeof it.text === "string" ? it.text : ""
    ).filter(Boolean).join("\n");
  }
  return "";
}
function normalizeRole(role) {
  const r = String(role ?? "").toLowerCase();
  return r === "user" || r === "assistant" || r === "system" || r === "tool" ? r : "user";
}
function turnsFromMessages(messages, prompt) {
  const turns = [];
  const arr = Array.isArray(messages) ? messages : [];
  for (const m of arr.slice(-CONTEXT_TURNS * 3)) {
    if (!m || typeof m !== "object") continue;
    const text = messageText(m.content).trim();
    if (!text) continue;
    turns.push({ role: normalizeRole(m.role), text });
  }
  if (!turns.length) {
    const p = String(prompt ?? "").trim();
    if (p) turns.push({ role: "user", text: p });
  }
  return turns.slice(-CONTEXT_TURNS);
}
function setTranscript(rt, sessionId, turns) {
  if (!sessionId || !turns.length) return;
  if (!rt.transcript.has(sessionId) && rt.transcript.size >= MAX_TRACKED_SESSIONS) rt.transcript.clear();
  rt.transcript.set(sessionId, turns.slice(-CONTEXT_TURNS));
}
function appendTranscript(rt, sessionId, turn) {
  if (!sessionId || !turn.text) return;
  let buf = rt.transcript.get(sessionId);
  if (!buf) {
    if (rt.transcript.size >= MAX_TRACKED_SESSIONS) rt.transcript.clear();
    buf = [];
    rt.transcript.set(sessionId, buf);
  }
  buf.push(turn);
  if (buf.length > CONTEXT_TURNS) buf.splice(0, buf.length - CONTEXT_TURNS);
}
function recentTranscript(rt, sessionId) {
  return sessionId ? (rt.transcript.get(sessionId) ?? []).slice() : [];
}
var REPORT_COOLDOWN_MS = 6 * 3600 * 1e3;
function pruneRecentReports(rt, now) {
  if (rt.recentReports.size <= 2048) return;
  for (const [identifier, ts] of rt.recentReports) {
    if (now - ts >= REPORT_COOLDOWN_MS) rt.recentReports.delete(identifier);
  }
}
function flagWorthy(cfg, findings) {
  const out = [];
  for (const f of findings) {
    if (f.source === "custom") {
      out.push(f);
      continue;
    }
    if (!categoryAllows(cfg, f.category, f.severity)) continue;
    if (f.source === "heuristic" && SEVERITY_RANK[f.severity] < SEVERITY_RANK[cfg.reportMinSeverity]) {
      continue;
    }
    out.push(f);
  }
  return out;
}
function scanInjection(rt, text) {
  const ruleset = rt.ruleset.get();
  const findings = detectInjection(text, ruleset);
  if (rt.cfg.discover) findings.push(...discoverInjection(text, ruleset));
  return flagWorthy(rt.cfg, findings);
}
function recordToolActivity(rt, event, ctx, params) {
  try {
    const base = {
      session_id: sessionRefOf(event, ctx),
      run_id: event.runId ?? ctx.runId,
      tool_call_id: event.toolCallId
    };
    const access = fileAccessArg(event.toolName, params);
    if (access) {
      recordEvent(rt.cfg.blackboxHome, "file_access", {
        ...base,
        tool: access.tool,
        path: access.path,
        mode: access.mode
      });
      return;
    }
    if (!isShellTool(event.toolName)) return;
    const command = commandFromArgs(event.toolName, params);
    if (!command) return;
    for (const path2 of parseShellReads(command)) {
      recordEvent(rt.cfg.blackboxHome, "file_access", { ...base, tool: "shell", path: path2, mode: "read" });
    }
    for (const url of parseDownloads(command)) {
      recordEvent(rt.cfg.blackboxHome, "file_access", { ...base, tool: "shell", path: url, mode: "download" });
    }
    for (const dep of parseDependencyInstalls(command)) {
      recordEvent(rt.cfg.blackboxHome, "dependency_install", { ...base, ...dep, tool: "shell" });
    }
  } catch {
  }
}
async function resolveReporter(rt) {
  if (rt.reporterAddress !== void 0) return rt.reporterAddress || void 0;
  try {
    const addr = await rt.client.reporterAddress();
    rt.reporterAddress = isAgentAddress(addr) ? addr : "";
  } catch {
    rt.reporterAddress = "";
  }
  return rt.reporterAddress || void 0;
}
function today() {
  return (/* @__PURE__ */ new Date()).toISOString().slice(0, 10);
}
function underDailyCap(rt) {
  const d = today();
  if (rt.dailyReports.date !== d) {
    rt.dailyReports = { date: d, count: 0 };
  }
  return rt.dailyReports.count < rt.cfg.dailyReportLimit;
}
var NEVER_SHARED_SOURCES = /* @__PURE__ */ new Set(["custom", "llm", "secret"]);
function shareDecision(rt, finding, reporter, evidence) {
  if (!rt.cfg.report || !rt.cfg.contextGraphId) return [false, "community sharing disabled"];
  if (!sharingConsentInForce(rt.cfg.blackboxHome)) return [false, "community sharing is not turned on on this machine (`blackbox report --enable-sharing` turns it on)"];
  if (NEVER_SHARED_SOURCES.has(finding.source)) return [false, `source ${finding.source} never leaves the machine`];
  if ((finding.kind ?? finding.fields.kind) === "vulnerability" || finding.category === "dependency" && (finding.kind ?? finding.fields.kind) !== "malware") {
    return [false, "vulnerability findings stay in the local audit (decision 22)"];
  }
  if (finding.source === "community") return [false, "community-only match: flagged here, shared only by an explicit report"];
  if (!finding.identifier.trim()) return [false, "no identifier"];
  if (!reporter || !isAgentAddress(reporter)) return [false, "no resolved reporter identity"];
  try {
    validateReport({ identifier: finding.identifier, category: finding.category, severity: finding.severity, framework: FRAMEWORK2, evidence });
  } catch (err) {
    return [false, `not a valid report, stays local: ${err.message}`];
  }
  return [true, "ok"];
}
async function resolveSigner(rt) {
  if (rt.signer !== void 0) return rt.signer;
  try {
    const network = await rt.client.networkId();
    if (!network) {
      rt.log("warn", "blackbox: cannot sign reports \u2014 the node reports no network id");
      return rt.signer = null;
    }
    rt.signer = new ReportSigner(loadOrCreateReporterKey(rt.cfg.blackboxHome), network, rt.cfg.contextGraphId);
  } catch (err) {
    rt.log("warn", `blackbox: cannot sign reports \u2014 reporter key unusable: ${err.message}`);
    rt.signer = null;
  }
  return rt.signer;
}
async function reportSighting(rt, finding, event, toolName) {
  const reporter = await resolveReporter(rt);
  const evidence = evidenceFor(finding, event, toolName);
  const [ok, why] = shareDecision(rt, finding, reporter, evidence);
  if (!ok || reporter === void 0) {
    if (rt.cfg.report) rt.log("debug", `blackbox: not sharing ${finding.identifier}: ${why}`);
    return;
  }
  const now = Date.now();
  const last = rt.recentReports.get(finding.identifier);
  if (last !== void 0 && now - last < REPORT_COOLDOWN_MS) {
    rt.log("debug", `blackbox: report cooldown active for ${finding.identifier}`);
    return;
  }
  if (!underDailyCap(rt)) {
    rt.log("debug", "blackbox: daily report cap reached, dropping sighting");
    return;
  }
  rt.recentReports.set(finding.identifier, now);
  pruneRecentReports(rt, now);
  try {
    const signer = await resolveSigner(rt);
    if (!signer) return;
    const log = (msg) => rt.log("debug", msg);
    await ensureCommunitySubscription(rt.client, rt.cfg.contextGraphId, rt.membership, log);
    const quads = buildReportQuads({
      identifier: finding.identifier,
      category: finding.category,
      severity: finding.severity,
      reporter,
      framework: FRAMEWORK2,
      evidence,
      signer
    });
    const name = `report-${stableHash(finding.identifier + reporter, 16)}`;
    const result = await rt.client.shareReport(rt.cfg.contextGraphId, name, quads);
    if (result.idempotent) {
      rt.log("debug", `blackbox: report ${name} was already on the network (not re-sent)`);
      return;
    }
    rt.dailyReports.count += 1;
  } catch (err) {
    if (err instanceof DkgError) {
      rt.log("debug", `blackbox: sighting report failed (node): ${err.message}`);
      return;
    }
    rt.log("debug", `blackbox: sighting report error: ${err.message}`);
  }
}
function meetsBlock(finding, cfg) {
  return (finding.confirmed || finding.source === "custom") && finding.kind !== KIND_VULNERABILITY && finding.kind !== "historical" && finding.category !== "ioc" && SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[cfg.blockSeverity];
}
function maxSeverity(findings) {
  return findings.reduce(
    (best, f) => SEVERITY_RANK[f.severity] > SEVERITY_RANK[best] ? f.severity : best,
    "info"
  );
}
function blockMessage(findings) {
  const worst = maxSeverity(findings);
  const titles = [...new Set(findings.map((f) => f.title))].slice(0, 3).join("; ");
  return `Blackbox blocked this action (${worst}): ${titles}`;
}
function observe(rt, event, finding, toolName, context, outcome = {}) {
  try {
    recordFinding(rt.cfg.blackboxHome, event, finding, toolName, context, outcome);
  } catch {
  }
  void reportSighting(rt, finding, event, toolName);
}
var REMOTE_SOURCES = /* @__PURE__ */ new Set(["public", "community", "heuristic", "custom"]);
var SEVERITIES = new Set(Object.keys(SEVERITY_RANK));
function findingFromRemote(remote, toolName) {
  const source = REMOTE_SOURCES.has(remote.source ?? "") ? remote.source : "custom";
  return {
    identifier: remote.identifier,
    category: remote.category,
    severity: SEVERITIES.has(remote.severity) ? remote.severity : "high",
    title: remote.title,
    toolName: remote.tool_name ?? toolName,
    matched: String(remote.matched ?? ""),
    evidence: String(remote.evidence ?? ""),
    confirmed: remote.confirmed === true,
    source,
    ...remote.kind ? { kind: remote.kind } : {},
    fields: remote.fields ?? {}
  };
}
async function judgeToolCall(rt, toolName, params, ruleset) {
  const remote = await rt.verdicts.ask(toolName, params);
  if (remote) {
    const findings2 = remote.findings.map((row) => findingFromRemote(row, toolName));
    const blocked = new Set(remote.blocked);
    return { findings: findings2, blocking: findings2.filter((f) => blocked.has(f.identifier)), message: remote.message };
  }
  const raw = detectAll(toolName, params, ruleset, rt.cfg.discover);
  raw.push(...detectCustomFileAccess(toolName, params, rt.cfg.protectedPaths));
  const findings = flagWorthy(rt.cfg, raw);
  const blocking = rt.cfg.mode === "block" ? findings.filter((f) => meetsBlock(f, rt.cfg)) : [];
  return { findings, blocking, message: "" };
}
function makeBeforeToolCall(rt) {
  return async (event, hookCtx = {}) => {
    try {
      const ruleset = rt.ruleset.get();
      const params = event.params ?? {};
      recordEvent(rt.cfg.blackboxHome, "pre_tool_call", {
        agent: agentOf(event, hookCtx),
        session_id: sessionRefOf(event, hookCtx),
        run_id: event.runId ?? hookCtx.runId,
        tool_call_id: event.toolCallId,
        tool_name: event.toolName,
        args: params
      });
      recordToolActivity(rt, event, hookCtx, params);
      const judged = await judgeToolCall(rt, event.toolName, params, ruleset);
      const findings = judged.findings;
      if (rt.cfg.discover && rt.cfg.osvLookup) {
        void discoverDependencyCandidates(event.toolName, params, ruleset, lookup).then((candidates2) => {
          for (const f of flagWorthy(rt.cfg, candidates2)) observe(rt, "osv_discovery", f, event.toolName);
        }).catch(() => {
        });
      }
      if (findings.length === 0) return;
      const ctx = {};
      const turns = recentTranscript(rt, sessionIdOf(event));
      if (turns.length) ctx.turns = turns;
      const inputText = collectText(params).join("\n");
      if (inputText.trim()) ctx.input = inputText;
      const context = ctx.turns || ctx.input ? ctx : void 0;
      const agent = agentOf(event, hookCtx);
      const sessionId = sessionRefOf(event, hookCtx);
      for (const f of findings) {
        const decision = judged.blocking.includes(f) ? "block" : "flag";
        observe(rt, "before_tool_call", f, event.toolName, context, { decision, agent, sessionId });
      }
      if (judged.blocking.length > 0) {
        return { block: true, blockReason: judged.message || blockMessage(judged.blocking) };
      }
      return;
    } catch (err) {
      rt.log("debug", `blackbox: before_tool_call error: ${err.message}`);
      return;
    }
  };
}
function makeAfterToolCall(rt) {
  return async (event, ctx = {}) => {
    try {
      recordEvent(rt.cfg.blackboxHome, "post_tool_call", {
        session_id: sessionRefOf(event, ctx),
        run_id: event.runId ?? ctx.runId,
        tool_call_id: event.toolCallId,
        tool_name: event.toolName,
        args: event.params,
        result: event.result,
        error: event.error,
        duration_ms: event.durationMs
      });
      if (event.error) {
        rt.log("debug", `blackbox: tool ${event.toolName} errored`, { error: sanitizeText(event.error, 300) });
        return;
      }
      const resultText = collectText(event.result).join("\n");
      if (!resultText.trim()) return;
      const findings = scanInjection(rt, resultText);
      const inputIocs = new Set(detectIoc(event.toolName, event.params, rt.ruleset.get()).map((f) => f.identifier));
      findings.push(...flagWorthy(
        rt.cfg,
        detectIoc(event.toolName, event.result, rt.ruleset.get()).filter((f) => !inputIocs.has(f.identifier))
      ));
      const context = { input: resultText };
      for (const f of findings) observe(rt, "post_tool_call", f, event.toolName, context);
    } catch {
    }
  };
}
function makeBeforeAgentRun(rt) {
  return async (event, ctx = {}) => {
    try {
      recordEvent(rt.cfg.blackboxHome, "pre_api_request", {
        session_id: sessionRefOf(event, ctx),
        run_id: ctx.runId,
        provider: ctx.modelProviderId,
        model: ctx.modelId,
        channel: event.channelId ?? ctx.channelId
      });
      const text = [event.prompt ?? "", ...collectText(event.messages)].join("\n");
      const findings = scanInjection(rt, text);
      const turns = turnsFromMessages(event.messages, event.prompt);
      setTranscript(rt, sessionIdOf(event), turns);
      if (findings.length === 0) return { outcome: "pass" };
      const context = turns.length ? { turns } : void 0;
      for (const f of findings) observe(rt, "before_agent_run", f, void 0, context);
      if (rt.cfg.mode === "block") {
        const blocking = findings.filter((f) => meetsBlock(f, rt.cfg));
        if (blocking.length > 0) {
          return {
            outcome: "block",
            reason: `blackbox:prompt-injection:${blocking.map((f) => f.identifier).join(",")}`,
            message: "This request was blocked because it contained prompt-injection content."
          };
        }
      }
      return { outcome: "pass" };
    } catch (err) {
      rt.log("debug", `blackbox: before_agent_run error: ${err.message}`);
      return { outcome: "pass" };
    }
  };
}
function makeMessageReceived(rt) {
  return async (event, ctx = {}) => {
    try {
      const text = event.content ?? "";
      const sid = sessionRefOf(event, ctx);
      recordEvent(rt.cfg.blackboxHome, "message_received", {
        session_id: sid,
        run_id: event.runId ?? ctx.runId,
        message_id: event.messageId,
        channel: ctx.channelId,
        content_length: text.length
      });
      if (text) appendTranscript(rt, sid, { role: "user", text });
      const found = scanInjection(rt, text);
      if (!found.length) return;
      const turns = recentTranscript(rt, sid);
      const context = turns.length ? { turns } : text ? { turns: [{ role: "user", text }] } : void 0;
      for (const f of found) observe(rt, "message_received", f, void 0, context);
    } catch {
    }
  };
}
function makeSessionStart(rt) {
  return async (event, ctx = {}) => {
    rt.log("debug", `blackbox: session_start ${event.sessionId}`);
    recordEvent(rt.cfg.blackboxHome, "session_start", {
      session_id: event.sessionId,
      session_key: event.sessionKey ?? ctx.sessionKey,
      resumed_from: event.resumedFrom
    });
    try {
      await rt.ruleset.sync();
    } catch {
    }
  };
}
function makeSessionEnd(rt) {
  return async (event, ctx = {}) => {
    rt.log("debug", `blackbox: session_end ${event.sessionId} (${event.reason ?? "unknown"})`);
    recordEvent(rt.cfg.blackboxHome, "session_end", {
      session_id: event.sessionId,
      session_key: event.sessionKey ?? ctx.sessionKey,
      message_count: event.messageCount,
      duration_ms: event.durationMs,
      reason: event.reason ?? "unknown",
      next_session_id: event.nextSessionId
    });
    rt.transcript.delete(event.sessionId);
  };
}
function buildRuntime(api) {
  const cfg = resolveConfig(api.pluginConfig ?? {});
  const client = new DkgClient({ url: cfg.dkgUrl, dkgHome: cfg.dkgHome });
  const ruleset = new RulesetCache({
    client,
    contextGraphId: cfg.contextGraphId,
    ttlSeconds: cfg.syncInterval,
    seedStateDir: cfg.blackboxHome
  });
  const log = (level, msg, meta) => {
    try {
      const logger = api.logger;
      const fn = logger?.[level] ?? logger?.info;
      if (typeof fn === "function") fn(msg, meta);
    } catch {
    }
  };
  return {
    cfg,
    client,
    verdicts: new VerdictClient(cfg.dashboardUrl),
    ruleset,
    log,
    dailyReports: { date: today(), count: 0 },
    recentReports: /* @__PURE__ */ new Map(),
    membership: {},
    transcript: /* @__PURE__ */ new Map()
  };
}
function register(api) {
  if (registeredApis.has(api)) {
    try {
      api.logger?.debug?.(
        "blackbox: register() called again; skipping duplicate hook wiring"
      );
    } catch {
    }
    return;
  }
  registeredApis.add(api);
  const rt = buildRuntime(api);
  api.on("before_tool_call", makeBeforeToolCall(rt), { priority: 100 });
  api.on("after_tool_call", makeAfterToolCall(rt));
  api.on("before_agent_run", makeBeforeAgentRun(rt), { priority: 100 });
  api.on("message_received", makeMessageReceived(rt));
  api.on("session_start", makeSessionStart(rt));
  api.on("session_end", makeSessionEnd(rt));
  rt.log(
    "debug",
    `blackbox: registered (mode=${rt.cfg.mode}, cg=${rt.cfg.contextGraphId}, dkg=${rt.client.url})`
  );
}
function __resetRegistrationGuardForTests() {
  registeredApis = /* @__PURE__ */ new WeakSet();
}
var index_default = definePluginEntry({
  id: PLUGIN_ID,
  name: "Agent Blackbox",
  description: "Mirrors hermes blackbox detection in OpenClaw and reports sightings to the local DKG threat graph.",
  // No exclusive `kind` — hook-only plugin, must not claim a singleton slot
  // (memory | context-engine).
  register
});
export {
  __resetRegistrationGuardForTests,
  index_default as default,
  detectCustomFileAccess,
  register,
  resolveConfig
};
