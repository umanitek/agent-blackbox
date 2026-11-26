/*
 * The dashboard's Protection page (protection_routes): the tamper counts, the protection log's
 * check and the watch rules. Adding and blocking go to /api/protection/watch*; taking a rule off
 * or stopping a block is saved through /api/settings, so it waits for your confirmation
 * (approvals.js handles the 428). /protection?kind=host&value=…&note=… opens with the form filled
 * (a finding's "Watch this"). All text is set with textContent.
 */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const TAMPER = {
    "self-protection": ["Blackbox's own files and settings", "an agent's hook asked and Blackbox refused"],
    "self-protection-kernel": ["Refused by the system sandbox", "the operating system stopped the agent"],
    "startup-item": ["Programs set to start by themselves", "a login item, launch job or service an agent tried to add"],
  };
  const LOG = {
    ok: "Whole: every entry is there, in order, unchanged.",
    empty: "Nothing refused yet.",
    broken: "Damaged: an entry was changed, removed or put in between, or the log can not be read.",
    rewound: "Put back to an older copy: entries written since are missing.",
    drift: "Replaced with a different log of the same length.",
  };

  async function token() {
    try { return (await (await fetch("/api/session")).json()).token || ""; } catch (_) { return ""; }
  }

  async function post(path, body) {
    return fetch(path, { method: "POST", headers: { "Content-Type": "application/json", "X-Blackbox-Token": await token() },
                         body: JSON.stringify(body || {}) });
  }

  function when(seconds) {
    return seconds ? new Date(seconds * 1000).toLocaleString() : "";
  }

  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
  }

  function drawTamper(tamper) {
    const root = $("pr-tamper");
    root.replaceChildren();
    Object.keys(TAMPER).forEach((key) => {
      const row = tamper[key] || { count: 0, last_at: 0, last_agent: "" };
      const tile = el("div", undefined, "pr-tile");
      tile.appendChild(el("b", String(row.count)));
      tile.appendChild(el("span", TAMPER[key][0]));
      tile.appendChild(el("small", row.count ? ` · last ${when(row.last_at)} by ${row.last_agent}` : ` · ${TAMPER[key][1]}`));
      root.appendChild(tile);
    });
  }

  function drawLog(log) {
    const line = $("pr-log");
    line.dataset.state = log.state;
    line.classList.remove("pr-muted");
    const bad = log.state === "broken" && log.first_bad ? ` First bad entry: ${log.first_bad}.` : "";
    line.textContent = `${LOG[log.state] || log.state}${bad} ${log.seq} ${log.seq === 1 ? "entry" : "entries"}.`;
  }

  // The person's own rules as the watch_rules section, with *change* applied to the one named.
  function sectionWith(rules, ruleId, change) {
    const mine = rules.filter((rule) => rule.origin === "person");
    const kept = mine.map((rule) => (rule.rule_id === ruleId ? change(rule) : rule)).filter(Boolean);
    return { rules: kept.map((rule) => ({ kind: rule.kind, value: rule.value, state: rule.state, ...(rule.note ? { note: rule.note } : {}) })) };
  }

  async function saveSection(section) {
    const response = await post("/api/settings", { watch_rules: section });
    if (!response.ok) {
      const answer = await response.json().catch(() => ({}));
      $("pr-add-result").textContent = (answer.errors || [answer.error || "Not saved."]).join(" ");
    }
    load();
  }

  function button(label, action) {
    const node = el("button", label, "pr");
    node.type = "button";
    node.addEventListener("click", action);
    return node;
  }

  function drawRules(rules) {
    const list = $("pr-rules");
    list.replaceChildren();
    if (!rules.length) {
      list.appendChild(el("li", "No watch rules yet. Add a website or package above, or use \"Watch this\" on a finding.", "pr-muted"));
      return;
    }
    rules.forEach((rule) => {
      const item = el("li", undefined, "pr-rule");
      item.dataset.state = rule.state;
      const what = el("div", undefined, "pr-what");
      what.appendChild(el("b", rule.value));
      const seen = rule.hits ? `${rule.hits} ${rule.hits === 1 ? "call" : "calls"}, last ${when(rule.last_at)} by ${rule.last_agent}` : "not reached yet";
      const by = rule.origin === "organisation" ? "your organisation's rule · " : "";
      what.appendChild(el("small", `${by}${rule.state === "enforce" ? "blocking" : "watching"} · ${seen}${rule.note ? " · " + rule.note : ""}`));
      item.appendChild(what);
      if (rule.origin === "person") {
        if (rule.state === "watch") {
          item.appendChild(button("Block", async () => { await post("/api/protection/watch/promote", { rule_id: rule.rule_id }); load(); }));
        } else {
          item.appendChild(button("Only watch", () => saveSection(sectionWith(rules, rule.rule_id, (r) => ({ ...r, state: "watch" })))));
        }
        item.appendChild(button("Remove", () => saveSection(sectionWith(rules, rule.rule_id, () => null))));
      }
      list.appendChild(item);
    });
  }

  async function load() {
    try {
      const answer = await (await fetch("/api/protection")).json();
      drawTamper(answer.tamper || {});
      drawLog(answer.log || { state: "broken", seq: 0 });
      drawRules(answer.rules || []);
    } catch (_) {
      $("pr-log").textContent = "The dashboard did not answer.";
    }
  }

  $("pr-add").addEventListener("submit", async (event) => {
    event.preventDefault();
    const result = $("pr-add-result");
    result.textContent = "Saving…";
    const response = await post("/api/protection/watch", { kind: $("pr-kind").value, value: $("pr-value").value.trim(), note: $("pr-note").value.trim() });
    const answer = await response.json().catch(() => ({}));
    result.textContent = response.ok ? "Watching." : (answer.errors || ["Not saved."]).join(" ");
    if (response.ok) { $("pr-value").value = ""; $("pr-note").value = ""; }
    load();
  });

  const asked = new URLSearchParams(window.location.search);
  if (asked.get("value")) {
    $("pr-kind").value = asked.get("kind") === "package" ? "package" : "host";
    $("pr-value").value = asked.get("value");
    $("pr-note").value = (asked.get("note") || "").slice(0, 200);
  }
  load();
})();
