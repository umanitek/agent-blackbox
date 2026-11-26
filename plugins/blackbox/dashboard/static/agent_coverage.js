/*
 * Every agent protected, now and later (2026-11-19) — the line above Connected agents and the
 * "New agent protected" note.
 *
 * Reads GET /api/agent-coverage ({auto_attach: true | false | null while unread, unprotected, recent}) every few seconds:
 *  - #agent-coverage-root shows ONE slim line while any agent on this machine is unprotected
 *    (an agent the operator switched off is never listed — that was a choice): who, a "Protect"
 *    for each, and "Protect every agent, now and later" (POST /api/agent-coverage/protect-all,
 *    the same yes the installer asks for). Empty when every agent is protected.
 *  - each agent the sweep protects by itself after the page opened gets the dashboard's corner
 *    note (#toast): "New agent protected: Hermes · coder".
 * POSTs carry the session token (X-Blackbox-Token from /api/session). Text is set with textContent.
 */
(function () {
  "use strict";
  var POLL_MS = 5000;
  var root = null, lastSeq = null, working = false, error = "", drawn = "";

  var CSS =
    ".ac-bar{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:center;margin:0 0 12px;padding:10px 14px;" +
    "border:1px solid color-mix(in srgb,var(--caution,#E3B341) 60%,transparent);border-radius:var(--radius,4px);" +
    "background:var(--panel,var(--bg));color:var(--text);font-size:13.5px}" +
    ".ac-bar .ac-text{flex:1 1 300px;min-width:0;line-height:1.5}.ac-bar b{font-weight:700}" +
    ".ac-names{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px}" +
    ".ac-name{display:inline-flex;gap:6px;align-items:center;border:1px solid var(--border);border-radius:999px;padding:2px 4px 2px 10px;" +
    "font:600 12px var(--mono,ui-monospace,monospace)}" +
    ".ac-bar button{border:1px solid var(--border-strong,var(--border));background:transparent;color:var(--text);" +
    "border-radius:var(--radius,4px);padding:6px 12px;font:700 12.5px var(--body-font,inherit);cursor:pointer}" +
    ".ac-name button{padding:2px 8px;border-radius:999px;font-size:11.5px}" +
    ".ac-bar button.ac-main{background:var(--text);color:var(--bg);border-color:var(--text)}" +
    ".ac-bar button:disabled{opacity:.55;cursor:wait}.ac-error{color:var(--signal);font-weight:600;flex-basis:100%}";

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }

  function post(path, body) {
    return fetch("/api/session", { cache: "no-store" }).then(function (r) {
      if (!r.ok) throw new Error("Open the dashboard on the machine itself to change protection.");
      return r.json();
    }).then(function (session) {
      return fetch(path, { method: "POST", cache: "no-store",
        headers: { "Content-Type": "application/json", "Accept": "application/json",
                   "X-Blackbox-Token": (session && session.token) || "" },
        body: JSON.stringify(body || {}) });
    }).then(function (r) { return r.json().then(function (j) { return { ok: r.ok && (!j || j.ok !== false), body: j || {} }; }); });
  }

  function toast(text) {
    var note = document.getElementById("toast");
    if (!note) return;
    note.textContent = text;
    note.className = "toast ok show";
    window.setTimeout(function () { note.className = "toast ok"; }, 5000);
  }

  // The agents list redraws from its own poll; ask it now so a change shows at once.
  function refreshAgents() {
    var button = document.getElementById("agents-refresh");
    if (button) button.click();
  }

  function act(request) {
    working = true; error = ""; drawn = ""; draw(last);
    request.then(function (res) {
      if (!res.ok) error = res.body.error || "That did not work.";
      else refreshAgents();
    }, function (err) { error = (err && err.message) || "That did not work."; })
      .then(function () { working = false; drawn = ""; return load(); });
  }

  function protectOne(agent) {
    act(post("/api/agents/protection", { targets: [{ kind: agent.kind, target: agent.target, enabled: true }] }));
  }

  var last = null;
  function draw(data) {
    if (!root || !data) return;
    var missing = data.unprotected || [];
    var sig = JSON.stringify([missing.map(function (a) { return a.kind + ":" + a.target; }), data.auto_attach, working, error]);
    if (sig === drawn) return;
    drawn = sig;
    root.innerHTML = "";
    root.hidden = !missing.length && !error;
    if (root.hidden) return;
    var bar = el("div", "ac-bar");
    bar.setAttribute("role", "status");
    var text = el("div", "ac-text");
    var lead = el("span");
    lead.appendChild(el("b", "", missing.length === 1 ? "1 agent on this machine is not protected." :
      missing.length + " agents on this machine are not protected."));
    lead.appendChild(document.createTextNode(data.auto_attach === true ? " Protecting it now…" :
      " Blackbox does not see what they do until you protect them."));
    text.appendChild(lead);
    var names = el("div", "ac-names");
    missing.forEach(function (agent) {
      var chip = el("span", "ac-name", agent.label);
      chip.title = agent.target;
      var b = el("button", "", "Protect");
      b.type = "button"; b.disabled = working;
      b.addEventListener("click", function () { protectOne(agent); });
      chip.appendChild(b);
      names.appendChild(chip);
    });
    text.appendChild(names);
    bar.appendChild(text);
    if (data.auto_attach === false) {   // null: the setting is not read yet — offer nothing on a guess
      var all = el("button", "ac-main", working ? "Protecting…" : "Protect every agent, now and later");
      all.type = "button"; all.disabled = working;
      all.title = "Protects these agents and every Hermes profile or OpenClaw workspace added later (Settings → Agents)";
      all.addEventListener("click", function () { act(post("/api/agent-coverage/protect-all")); });
      bar.appendChild(all);
    }
    if (error) bar.appendChild(el("div", "ac-error", error));
    root.appendChild(bar);
  }

  // Each agent the sweep protected by itself since the page opened: one corner note (the first
  // read only sets the mark, so opening the page never replays old ones).
  function announce(data) {
    var recent = (data && data.recent) || [];
    var newest = recent.reduce(function (max, item) { return Math.max(max, Number(item.seq) || 0); }, 0);
    if (lastSeq === null) { lastSeq = newest; return; }
    var fresh = recent.filter(function (item) { return Number(item.seq) > lastSeq; });
    if (fresh.length) {
      toast(fresh.length === 1 ? "New agent protected: " + fresh[0].label
        : fresh.length + " new agents protected: " + fresh.map(function (a) { return a.label; }).join(", "));
      refreshAgents();
    }
    lastSeq = Math.max(lastSeq, newest);
  }

  function load() {
    return fetch("/api/agent-coverage", { cache: "no-store" }).then(function (r) { return r.json(); }).then(function (data) {
      last = data || {};
      announce(last);
      draw(last);
    }).catch(function () { /* the dashboard's own banner reports a down service */ });
  }

  function start() {
    root = document.getElementById("agent-coverage-root");
    var style = el("style"); style.textContent = CSS; document.head.appendChild(style);
    load();
    window.setInterval(function () { if (!working && !document.hidden) load(); }, POLL_MS);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
