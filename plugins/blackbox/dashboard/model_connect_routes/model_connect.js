/*
 * "Connect your agent to an AI model" (2026-11-19) — drawn into #model-connect-root while the
 * protected agent has no model (GET /api/agent-model says "missing"); once it has one, the panel
 * becomes the one-line "Your agent's AI model" card (provider · model · account, Hermes' own
 * "exhausted" mark) whose Manage opens the recommended model, another model and signing out.
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
  var expanded = false, confirmingSignOut = false;
  var listeners = [];

  var CSS = ".mc-panel{border:1px solid color-mix(in srgb,var(--signal,#FF4F00) 55%,transparent);border-radius:var(--radius,4px);padding:20px 22px;margin-top:28px;" +
    "background:var(--panel,var(--bg));color:var(--text)}" +
    ".mc-panel h2{margin:0 0 6px;font-size:20px}.mc-panel p{margin:6px 0;line-height:1.5;max-width:75ch}" +
    ".mc-eyebrow{font:700 11px var(--mono,ui-monospace,monospace);letter-spacing:.12em;text-transform:uppercase;color:var(--signal)}" +
    ".mc-ways{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px;margin-top:14px}" +
    ".mc-way{border:1px solid var(--border);border-radius:var(--radius,4px);padding:14px 16px;background:var(--bg)}" +
    ".mc-way h3{margin:0 0 4px;font-size:15px}.mc-hint{font-size:12.5px;color:var(--muted)}" +
    ".mc-panel button{border:1px solid var(--text);background:var(--text);color:var(--bg);border-radius:var(--radius,4px);padding:9px 15px;" +
    "font:700 13.5px var(--body-font,inherit);cursor:pointer;margin-top:8px}.mc-panel button.mc-quiet{background:transparent;color:var(--text)}" +
    ".mc-panel button:disabled{opacity:.55;cursor:wait}" +
    ".mc-row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:8px}" +
    ".mc-panel select,.mc-panel input{border:1px solid var(--border);border-radius:var(--radius,4px);padding:8px 10px;background:var(--bg);" +
    "color:var(--text);font:inherit;min-width:0;flex:1 1 180px}" +
    ".mc-code{font:700 22px var(--mono,ui-monospace,monospace);letter-spacing:.12em}" +
    ".mc-error{color:var(--signal);font-weight:600}.mc-ok{border-color:var(--secure,#3FB950);background:transparent}" +
    ".mc-panel a{color:var(--signal);font-weight:600;overflow-wrap:anywhere}" +
    ".mc-card{border:1px solid var(--border);border-radius:var(--radius,4px);padding:14px 20px;margin-top:28px;background:var(--panel,var(--bg));color:var(--text)}" +
    ".mc-card.mc-warn{border-color:var(--caution,#E3B341)}.mc-line{display:flex;flex-wrap:wrap;gap:8px 14px;align-items:center}" +
    ".mc-line strong{font-size:14px}.mc-what{color:var(--muted);font-size:13px;overflow-wrap:anywhere;min-width:0}" +
    ".mc-badge{font:700 11px var(--mono,ui-monospace,monospace);letter-spacing:.08em;text-transform:uppercase;padding:3px 8px;border-radius:999px}" +
    ".mc-badge.ok{color:var(--secure,#3FB950);background:var(--secure-soft,rgba(63,185,80,.12))}" +
    ".mc-badge.warn{color:var(--caution,#E3B341);background:var(--caution-soft,rgba(227,179,65,.14))}" +
    ".mc-badge.unknown{color:var(--muted);border:1px solid var(--border)}" +
    ".mc-card button{border:1px solid var(--border-strong,var(--border));background:transparent;color:var(--text);border-radius:var(--radius,4px);padding:7px 13px;font:700 13px var(--body-font,inherit);cursor:pointer}" +
    ".mc-card button.mc-main{background:var(--text);color:var(--bg);border-color:var(--text)}.mc-card button:disabled{opacity:.55;cursor:wait}" +
    ".mc-card .mc-manage{margin-left:auto}.mc-actions{display:grid;gap:12px;margin-top:12px;border-top:1px solid var(--border);padding-top:12px}" +
    ".mc-card input{border:1px solid var(--border);border-radius:var(--radius,4px);padding:6px 10px;background:var(--bg);color:var(--text);font:inherit;flex:1 1 220px;min-width:0}" +
    ".mc-card p{margin:4px 0;line-height:1.5;max-width:80ch}";

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
    // "unknown" is the first answer while Hermes is still being asked: ask again soon, so the panel
    // settles right after load instead of appearing (and moving the page) a minute later.
    var fast = !last || last.state === "missing" || last.state === "unknown" || signingIn(last);
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
    var c = (last && last.connection) || {};
    return JSON.stringify([last && last.state, nous.status, nous.link, nous.code, nous.reason, error, busy, justConnected,
      c.provider, c.model, c.account, c.status, expanded, confirmingSignOut]);
  }

  function providerName(id) {
    if (id === "nous") return "Nous Portal";
    var match = ((last && last.providers) || []).filter(function (p) { return p.id === id; })[0];
    return match ? match.name : id;
  }

  function button(label, cls, onClick) {
    var b = el("button", cls || "", label);
    b.type = "button"; b.disabled = busy;
    b.addEventListener("click", onClick);
    return b;
  }

  // The agent HAS a model: one line always (provider · model · account, Hermes' own status), and
  // Manage opens what can change — the recommended model, another model, signing out to switch.
  function drawCard() {
    var c = (last && last.connection) || {};
    var exhausted = c.status === "exhausted";
    var card = el("section", "mc-card" + (exhausted ? " mc-warn" : ""));
    card.setAttribute("aria-label", "Your agent's AI model");
    var line = el("div", "mc-line");
    line.appendChild(el("strong", "", "Your agent's AI model"));
    var what = [providerName(c.provider || ""), c.model || "Hermes' default model", c.account].filter(Boolean).join(" · ");
    line.appendChild(el("span", "mc-what", what));
    var badge = exhausted ? ["warn", "Refused recently"] : c.status === "working" ? ["ok", "Connected"] : ["unknown", "Status unknown"];
    line.appendChild(el("span", "mc-badge " + badge[0], badge[1]));
    line.appendChild(button(expanded ? "Close" : "Manage", "mc-manage", function () {
      expanded = !expanded; confirmingSignOut = false; draw();
    }));
    card.appendChild(line);
    if (justConnected) card.appendChild(el("p", "", "Connected. Open a chat with your agent (run hermes in a terminal) and try the test prompt below — Blackbox should flag it."));
    // Hermes' "exhausted" mark is a pause of up to an hour after a provider refused a request — it
    // can outlive the cause (seen 2026-11-19: still set while the free model answered), so the card
    // names it as recent and offers the step that both fixes the usual cause and clears the pause.
    if (exhausted) card.appendChild(el("p", "", "The provider refused this account recently, so Hermes paused it for up to an hour " +
      "(usually: no credits for the model it asked for). A free account can use a free model: \u201cUse the recommended model\u201d " +
      "also clears the pause. Or add credits with the provider, or switch to an API key."));
    if (error) card.appendChild(el("p", "mc-error", error));
    if (expanded || exhausted) card.appendChild(drawActions(c));
    return card;
  }

  function drawActions(c) {
    var box = el("div", "mc-actions");
    var rec = el("div");
    rec.appendChild(el("p", "", c.provider === "nous"
      ? "Use the model Nous recommends for your account (a free account gets a free model)."
      : "Use the model Hermes recommends for " + providerName(c.provider || "") + "."));
    rec.appendChild(button(busy ? "Working…" : "Use the recommended model", "mc-main", function () {
      act(post("/api/agent-model/recommended"));
    }));
    box.appendChild(rec);
    var pick = el("div", "mc-line");
    var input = el("input");
    input.placeholder = "Another model, e.g. vendor/model:free"; input.setAttribute("aria-label", "Model name");
    input.spellcheck = false; input.autocomplete = "off";
    pick.appendChild(input);
    pick.appendChild(button("Use this model", "", function () { act(post("/api/agent-model/model", { model: input.value })); }));
    box.appendChild(pick);
    var out = el("div");
    if (confirmingSignOut) {
      out.appendChild(el("p", "", "Sign your agent out of " + providerName(c.provider || "") + "? It cannot chat until you connect again — " +
        "a different Nous account, the free tier or an API key."));
      out.appendChild(button("Sign out", "mc-main", function () { confirmingSignOut = false; expanded = false; act(post("/api/agent-model/disconnect")); }));
      out.appendChild(button("Keep it", "", function () { confirmingSignOut = false; draw(); }));
    } else {
      out.appendChild(button("Switch account or sign out", "", function () { confirmingSignOut = true; draw(); }));
    }
    box.appendChild(out);
    return box;
  }

  function draw() {
    if (!root) return;
    var sig = signature();
    if (sig === drawn) return;
    drawn = sig;
    root.innerHTML = "";
    var missing = last && (last.state === "missing" || signingIn(last));
    if (!missing && !(last && last.state === "ready")) { root.hidden = true; return; }   // unknown: say nothing
    root.hidden = false;
    if (!missing) { root.appendChild(drawCard()); return; }
    var panel = el("section", "mc-panel");
    panel.setAttribute("aria-label", "Connect your agent to an AI model");
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
    open: function (manage) {
      if (manage) { expanded = true; draw(); }
      if (root) root.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  };

  function start() {
    root = document.getElementById("model-connect-root");
    var style = el("style"); style.textContent = CSS; document.head.appendChild(style);
    refresh();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
