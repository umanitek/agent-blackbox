/*
 * The dashboard's Security page (security_routes): the protection mode, what agents may do (the
 * shared permission card, permission-card.js), the threat checks, the limits and what is always
 * on — every setting explained where it is edited.
 *
 * Reads GET /api/settings and File Shield's `permissions`; every change goes to POST /api/settings
 * (only the field changed) or File Shield's permission endpoints, so a loosening is held by the
 * approval gate (428): approvals.js asks the person and sends it again once confirmed; still held,
 * the page says it waits for your approval and shows what is saved. All text is set with textContent.
 */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const FILE_SHIELD = "/api/shields/file-shield/api/";
  const HELD = 428;
  const SEVERITIES = ["info", "low", "medium", "high", "critical"];
  // What each check catches, and what switching it off means (the settings serve the names).
  const CHECKS = {
    injection: ["Hidden instructions and prompt-injection patterns in what tools read and what agents send.",
                "Text that tries to take over an agent is no longer flagged or refused."],
    escalation: ["Dangerous shell commands and attempts to gain more rights than the agent has.",
                 "Destructive or privilege-raising commands run without a finding."],
    dependency: ["Packages with known malware or a known vulnerability pulled into a project.",
                 "Packages install without being checked against the threat graph."],
    fileaccess: ["Reads and writes of sensitive files and credential stores (~/.ssh, .env, key files).",
                 "An agent reading or copying your keys and secret files is no longer flagged."],
    skill: ["Installed skills that behave suspiciously or not as described.",
            "A skill with hidden behaviour is no longer flagged."],
    secret: ["Real API keys, tokens and private keys an agent handles or sends off this machine.",
             "A key leaving this machine is no longer caught."],
    ioc: ["Hosts, addresses and file fingerprints threat intelligence lists as malicious.",
          "Contact with listed hosts and files is no longer flagged."],
  };
  const LIMITS_MB = [4, 16, 64];
  let settings = null;

  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
  }

  async function token() {
    try { return (await (await fetch("/api/session")).json()).token || ""; } catch (_) { return ""; }
  }

  async function post(path, body) {
    return fetch(path, { method: "POST", headers: { "Content-Type": "application/json", "X-Blackbox-Token": await token() },
                         body: JSON.stringify(body || {}) });
  }

  async function getJSON(path) {
    const response = await fetch(path, { cache: "no-store" });
    if (!response.ok) throw new Error(String(response.status));
    return response.json();
  }

  // One settings change: only *patch* is sent, so nothing the person did not touch is written.
  async function save(patch, noteId) {
    const note = $(noteId);
    note.textContent = "Saving…";
    try {
      const response = await post("/api/settings", patch);
      const answer = await response.json().catch(() => ({}));
      if (response.ok && answer.ok !== false) note.textContent = "Saved.";
      else if (response.status === HELD) {
        const reasons = (answer.approval && answer.approval.reasons) || answer.errors || [];
        note.textContent = `Waiting for your approval: ${reasons.join(" ")} Nothing changes until you confirm.`;
      } else note.textContent = (answer.errors || [answer.error || "Not saved."]).join(" ");
    } catch (_) {
      note.textContent = "Not saved: the dashboard did not answer.";
    }
    await loadSettings();
  }

  function severityOptions(select, selected) {
    select.replaceChildren();
    (settings.severity_order || SEVERITIES).forEach((severity) => {
      const option = el("option", severity.charAt(0).toUpperCase() + severity.slice(1));
      option.value = severity;
      option.selected = severity === selected;
      select.appendChild(option);
    });
  }

  function drawMode() {
    const mode = settings.mode;
    const known = mode === "audit" || mode === "block";
    [["audit", $("sec-mode-audit")], ["block", $("sec-mode-block")]].forEach(([name, button]) => {
      button.setAttribute("aria-pressed", mode === name ? "true" : "false");
      button.disabled = !known || mode === name;
    });
    $("sec-mode-help").textContent = !known ? "Reading the saved mode…" : mode === "block"
      ? `Block mode: verified threats at or above ${settings.block_severity} severity, your protected paths and secrets sent off this machine are refused.`
      : "Audit mode: threats are recorded and flagged but not stopped, except the rules listed below.";
    const severity = $("sec-block-severity");
    severityOptions(severity, settings.block_severity);
    severity.disabled = mode !== "block";
  }

  function checkRow(key, current) {
    const label = (settings.category_labels || {})[key] || key;
    const [catches, off] = CHECKS[key] || ["", ""];
    const row = el("div", undefined, "sec-row");
    const text = el("div", undefined, "sec-text");
    text.appendChild(el("b", label));
    if (catches) text.appendChild(el("small", catches));
    if (off) text.appendChild(el("small", `Off: ${off}`));
    text.appendChild(el("small", "Minimum severity: findings below it are not shown or refused in this check."));
    const controls = el("div", undefined, "sec-ctrl");
    const severity = el("select", undefined, "sec");
    severity.setAttribute("aria-label", `Minimum severity for ${label}`);
    severityOptions(severity, current.min_severity || "info");
    severity.disabled = current.enabled === false;
    const seg = el("div", undefined, "sec-seg");
    seg.setAttribute("role", "group");
    seg.setAttribute("aria-label", label);
    [["On", true], ["Off", false]].forEach(([word, on]) => {
      const button = el("button", word, on ? "" : "block");
      button.type = "button";
      button.setAttribute("aria-pressed", (current.enabled !== false) === on ? "true" : "false");
      button.addEventListener("click", () => saveCheck(key, { enabled: on }));
      seg.appendChild(button);
    });
    severity.addEventListener("change", () => saveCheck(key, { min_severity: severity.value }));
    controls.append(severity, seg);
    row.append(text, controls);
    return row;
  }

  function saveCheck(key, change) {
    const categories = {};
    Object.entries(settings.categories || {}).forEach(([name, value]) => { categories[name] = { ...value }; });
    categories[key] = { ...(categories[key] || {}), ...change };
    return save({ categories }, "sec-checks-note");
  }

  function drawChecks() {
    const host = $("sec-checks");
    host.replaceChildren();
    host.className = "";
    Object.entries(settings.categories || {}).forEach(([key, current]) => host.appendChild(checkRow(key, current || {})));
  }

  function drawLimits() {
    const section = $("sec-limits");
    const limit = settings.hook_payload_limit_mb;
    section.hidden = typeof limit !== "number";
    if (section.hidden) return;
    const select = $("sec-hook-limit");
    select.replaceChildren();
    LIMITS_MB.forEach((size) => {
      const option = el("option", `${size} MB${size === 16 ? " (default)" : ""}`);
      option.value = String(size);
      option.selected = size === limit;
      select.appendChild(option);
    });
  }

  async function loadSettings() {
    try {
      settings = await getJSON("/api/settings");
      drawMode();
      drawChecks();
      drawLimits();
    } catch (_) {
      $("sec-mode-help").textContent = "The dashboard did not answer.";
    }
  }

  function drawList(hostId, rows, extra) {
    const host = $(hostId);
    if (!host) return;
    host.replaceChildren();
    rows.forEach((row) => {
      const item = el("li");
      item.append(el("b", row.name), document.createTextNode(` — ${row.why}${extra ? extra(row) : ""}`));
      host.appendChild(item);
    });
  }

  function drawAlwaysOn(view) {
    drawList("sec-always", view.always_on || []);
    // The guard's own every-mode list, served by the engine so this page can not drift from it.
    const relaxable = (row) => (row.permission ? " (an agent outside the sandbox can be let through below)" : "");
    drawList("sec-audit-too", view.always_blocked || [], relaxable);
  }

  const card = BlackboxPermissionCard.mount({
    api: FILE_SHIELD,
    getJSON: async (url) => { const view = await getJSON(url); drawAlwaysOn(view); return view; },
    post: (name, body) => post(FILE_SHIELD + name, body),
    hosts: { list: "sec-perms", restart: "sec-perm-restart", rules: "sec-perm-rules", never: "sec-never", note: "sec-perm-note",
             scope: "sec-perm-scope" },
  });

  $("sec-mode-audit").addEventListener("click", () => save({ mode: "audit" }, "sec-mode-note"));
  $("sec-mode-block").addEventListener("click", () => save({ mode: "block" }, "sec-mode-note"));
  $("sec-block-severity").addEventListener("change", (event) => save({ block_severity: event.target.value }, "sec-mode-note"));
  $("sec-hook-limit").addEventListener("change", (event) => save({ hook_payload_limit_mb: Number(event.target.value) }, "sec-limits-note"));
  loadSettings();
  card.read();
})();
