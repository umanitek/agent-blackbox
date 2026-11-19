/*
 * "Connect your agent to an AI model" (2026-11-19) — drawn into #model-connect-root while the
 * protected agent has no model (GET /api/agent-model says "missing"), gone once it has one.
 *
 * WHY: Blackbox checks each prompt as the agent sends it to its model; with no model nothing is
 * sent, so a fresh install's first test "does nothing". The panel offers the two ways Hermes
 * itself supports — a free Nous account (Hermes' own device sign-in: a link and a code) and an
 * API key (handed to Hermes, stored in the agent's own settings, never kept by Blackbox).
 *
 * Other parts of the page read the same answer: window.blackboxAgentModel.state() and
 * .onChange(fn) (the first-detection card and the assistant chat).
 * Every POST carries the session token (X-Blackbox-Token from /api/session). All text is set
 * with textContent; the sign-in link is an https Nous address checked by the server.
 */
(function () {
  "use strict";
  var FAST_MS = 4000, SLOW_MS = 60000;
  var root = null, timer = null, last = null, busy = false, error = "", justConnected = false, drawn = "";
  var listeners = [];

  var CSS = ".mc-panel{border:1px solid var(--signal,#FF4F00);border-radius:12px;padding:20px 22px;margin:0 0 22px;" +
    "background:var(--signal-soft,rgba(255,79,0,.08));color:var(--text)}" +
    ".mc-panel h2{margin:0 0 6px;font-size:20px}.mc-panel p{margin:6px 0;line-height:1.5;max-width:75ch}" +
    ".mc-eyebrow{font:700 11px var(--mono,ui-monospace,monospace);letter-spacing:.12em;text-transform:uppercase;color:var(--signal)}" +
    ".mc-ways{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px;margin-top:14px}" +
    ".mc-way{border:1px solid var(--border);border-radius:10px;padding:14px 16px;background:var(--bg)}" +
    ".mc-way h3{margin:0 0 4px;font-size:15px}.mc-hint{font-size:12.5px;color:var(--muted)}" +
    ".mc-panel button{border:1px solid var(--text);background:var(--text);color:var(--bg);border-radius:8px;padding:8px 14px;" +
    "font-weight:600;cursor:pointer;margin-top:8px}.mc-panel button.mc-quiet{background:transparent;color:var(--text)}" +
    ".mc-panel button:disabled{opacity:.55;cursor:wait}" +
    ".mc-row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:8px}" +
    ".mc-panel select,.mc-panel input{border:1px solid var(--border);border-radius:8px;padding:8px 10px;background:var(--bg);" +
    "color:var(--text);font:inherit;min-width:0;flex:1 1 180px}" +
    ".mc-code{font:700 22px var(--mono,ui-monospace,monospace);letter-spacing:.12em}" +
    ".mc-error{color:var(--signal);font-weight:600}.mc-ok{border-color:var(--secure,#3FB950);background:transparent}" +
    ".mc-panel a{color:var(--signal);font-weight:600;overflow-wrap:anywhere}";

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }

  function token() {
    return fetch("/api/session", { cache: "no-store" }).then(function (r) {
      if (!r.ok) throw new Error("Open the dashboard on the machine itself to connect a model.");
      return r.json();
    }).then(function (j) { return (j && j.token) || ""; });
  }

  function post(path, body) {
    return token().then(function (tok) {
      return fetch(path, { method: "POST", cache: "no-store",
        headers: { "Content-Type": "application/json", "Accept": "application/json", "X-Blackbox-Token": tok },
        body: JSON.stringify(body || {}) });
    }).then(function (r) { return r.json().then(function (j) { return { ok: r.ok, body: j || {} }; }); });
  }

  function notify() {
    listeners.forEach(function (fn) { try { fn(last); } catch (_) { /* a listener never breaks the panel */ } });
  }

  function signingIn(data) {
    var status = data && data.nous && data.nous.status;
    return status === "starting" || status === "waiting";
  }

  function schedule() {
    if (timer) window.clearTimeout(timer);
    var fast = last && (last.state === "missing" || signingIn(last));
    timer = window.setTimeout(refresh, fast ? FAST_MS : SLOW_MS);
  }

  function refresh() {
    return fetch("/api/agent-model", { cache: "no-store" }).then(function (r) { return r.json(); }).then(function (data) {
      var wasMissing = last && last.state === "missing";
      last = data || {};
      if (wasMissing && last.state === "ready") justConnected = true;
      draw();
      notify();
    }).catch(function () { /* the dashboard's own banner reports a down service */ }).then(schedule);
  }

  function drawNous(box) {
    var nous = (last && last.nous) || {};
    box.appendChild(el("h3", "", "Free Nous account"));
    box.appendChild(el("p", "mc-hint", "No card and no API key. You approve the sign-in on Nous's own site; Hermes stores it in your agent's settings."));
    if (nous.status === "waiting" && nous.link && nous.code) {
      var step = el("p", "");
      step.appendChild(document.createTextNode("1. Open "));
      var a = el("a", "", "the Nous sign-in page");
      a.href = nous.link; a.target = "_blank"; a.rel = "noopener noreferrer";
      step.appendChild(a);
      box.appendChild(step);
      box.appendChild(el("p", "", "2. Enter this code if asked:"));
      box.appendChild(el("div", "mc-code", nous.code));
      box.appendChild(el("p", "mc-hint", "3. Approve. This panel finishes by itself."));
      var cancel = el("button", "mc-quiet", "Cancel sign-in");
      cancel.type = "button";
      cancel.addEventListener("click", function () { act(post("/api/agent-model/nous/cancel")); });
      box.appendChild(cancel);
      return;
    }
    if (nous.status === "starting") { box.appendChild(el("p", "", "Asking Nous for a sign-in code…")); return; }
    if (nous.status === "failed" && nous.reason) box.appendChild(el("p", "mc-error", nous.reason));
    var start = el("button", "", "Sign in with Nous (free)");
    start.type = "button"; start.disabled = busy;
    start.addEventListener("click", function () { act(post("/api/agent-model/nous")); });
    box.appendChild(start);
  }

  function drawKey(box) {
    box.appendChild(el("h3", "", "Use an API key"));
    box.appendChild(el("p", "mc-hint", "The key goes straight to Hermes and is stored in your agent's settings on this machine. Blackbox never keeps, logs or shares it."));
    var row = el("div", "mc-row");
    var select = el("select");
    select.setAttribute("aria-label", "Provider");
    ((last && last.providers) || []).forEach(function (p) {
      var opt = el("option", "", p.name); opt.value = p.id; select.appendChild(opt);
    });
    var input = el("input");
    input.type = "password"; input.autocomplete = "off"; input.spellcheck = false;
    input.placeholder = "Paste your API key"; input.setAttribute("aria-label", "API key");
    row.appendChild(select); row.appendChild(input);
    box.appendChild(row);
    var save = el("button", "", busy ? "Saving…" : "Save key");
    save.type = "button"; save.disabled = busy;
    save.addEventListener("click", function () {
      var key = input.value; input.value = "";
      act(post("/api/agent-model/key", { provider: select.value, key: key }));
    });
    box.appendChild(save);
  }

  function act(request) {
    busy = true; error = ""; draw();
    request.then(function (res) {
      if (!res.ok || res.body.ok === false) error = res.body.error || res.body.reason || "That did not work.";
    }, function (err) { error = (err && err.message) || "That did not work."; })
      .then(function () { busy = false; return refresh(); });
  }

  // WHY a signature: the panel polls every few seconds while it is shown; rebuilding it each time
  // would wipe a key someone is typing. It redraws only when something it shows has changed.
  function signature() {
    var nous = (last && last.nous) || {};
    return JSON.stringify([last && last.state, nous.status, nous.link, nous.code, nous.reason, error, busy, justConnected]);
  }

  function draw() {
    if (!root) return;
    var sig = signature();
    if (sig === drawn) return;
    drawn = sig;
    root.innerHTML = "";
    var missing = last && (last.state === "missing" || signingIn(last));
    if (!missing && !justConnected) { root.hidden = true; return; }
    root.hidden = false;
    var panel = el("section", "mc-panel" + (missing ? "" : " mc-ok"));
    panel.setAttribute("aria-label", "Connect your agent to an AI model");
    if (!missing) {
      panel.appendChild(el("h2", "", "Your agent is connected to an AI model."));
      panel.appendChild(el("p", "", "Open a chat with your agent (run hermes in a terminal) and try the test prompt below — Blackbox should flag it."));
      var done = el("button", "mc-quiet", "Got it");
      done.type = "button";
      done.addEventListener("click", function () { justConnected = false; draw(); });
      panel.appendChild(done);
      root.appendChild(panel);
      return;
    }
    panel.appendChild(el("div", "mc-eyebrow", "One step left"));
    panel.appendChild(el("h2", "", "Connect your agent to an AI model"));
    panel.appendChild(el("p", "", "Blackbox checks every prompt your agent sends to its AI model. Your agent has no model connected yet, " +
      "so it cannot chat — and nothing reaches Blackbox to check. Threat-graph sync, local rules and this dashboard keep working meanwhile."));
    if (error) panel.appendChild(el("p", "mc-error", error));
    var ways = el("div", "mc-ways");
    var nous = el("div", "mc-way"); drawNous(nous); ways.appendChild(nous);
    var key = el("div", "mc-way"); drawKey(key); ways.appendChild(key);
    panel.appendChild(ways);
    panel.appendChild(el("p", "mc-hint", "Prefer a terminal? Run: " + ((last && last.fix) || "hermes setup") + "  (or hermes setup for any provider)."));
    root.appendChild(panel);
  }

  window.blackboxAgentModel = {
    state: function () { return last ? last.state : "unknown"; },
    fix: function () { return (last && last.fix) || "hermes setup"; },
    refresh: refresh,
    onChange: function (fn) { listeners.push(fn); if (last) fn(last); },
    open: function () { if (root) root.scrollIntoView({ behavior: "smooth", block: "start" }); }
  };

  function start() {
    root = document.getElementById("model-connect-root");
    var style = el("style"); style.textContent = CSS; document.head.appendChild(style);
    refresh();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
