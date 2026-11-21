/*
 * The agent's AI model, at a glance (2026-11-19) — a status dot in the top bar and one menu.
 *
 * WHY: Blackbox checks each prompt as the agent sends it to its model; with no model nothing is
 * sent, so a fresh install's first test "does nothing". The two ways Hermes itself supports are
 * offered here: a free Nous account (Hermes' own device sign-in: a link and a code) and an API key
 * (handed to Hermes, stored in the agent's own settings, never kept by Blackbox).
 *
 * Shape (Amos, 2026-11-19: the full-width panel was ugly and took a ton of space):
 *  - #model-status, a dot in the top bar: green = connected, amber = the provider refused recently
 *    (Hermes' "exhausted" pause), red = no model, grey = still asking Hermes. Its tooltip says
 *    which; clicking it opens the menu.
 *  - #model-popover, the menu: when there is no model, the free Nous sign-in (with a spinner while
 *    waiting for the approval and while connecting) and the API key; when there is one, the
 *    account and model, "Use the recommended model", another model, "Switch account or sign out".
 *  - #model-connect-root holds ONE slim line only while there is no model ("…no AI model
 *    connected … Connect"), so the gap is never missed; it is empty once connected, and the
 *    dashboard's own corner note (#toast) says when the agent connects.
 *
 * Other parts of the page read the same answer: window.blackboxAgentModel.state(), .onChange(fn)
 * and .open() (the first-detection card and the assistant chat).
 * Every POST carries the session token (X-Blackbox-Token from /api/session). All text is set
 * with textContent; the sign-in link is an https Nous address checked by the server.
 */
(function () {
  "use strict";
  var FAST_MS = 4000, SLOW_MS = 60000;
  var root = null, dot = null, menu = null, timer = null, last = null, working = false, error = "", notice = "";
  var menuOpen = false, confirmingSignOut = false, drawnBar = "", drawnMenu = "";
  var listeners = [];

  var CSS =
    ".mc-dot-btn{position:relative}.mc-dot{display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--muted)}" +
    ".mc-dot.ok{background:var(--secure,#3FB950)}.mc-dot.warn{background:var(--caution,#E3B341)}" +
    ".mc-dot.bad{background:var(--signal,#FF4F00);animation:mc-pulse 1.6s ease-in-out infinite}" +
    "@keyframes mc-pulse{50%{box-shadow:0 0 0 5px color-mix(in srgb,var(--signal,#FF4F00) 25%,transparent)}}" +
    "@media (prefers-reduced-motion:reduce){.mc-dot.bad{animation:none}}" +
    ".mc-bar{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:center;margin-top:28px;padding:10px 14px;" +
    "border:1px solid color-mix(in srgb,var(--signal,#FF4F00) 55%,transparent);border-radius:var(--radius,4px);" +
    "background:var(--panel,var(--bg));color:var(--text);font-size:13.5px}" +
    ".mc-bar .mc-text{flex:1 1 280px;min-width:0}" +
    ".mc-pop{position:fixed;z-index:1100;width:min(420px,calc(100vw - 32px));max-height:min(80vh,640px);overflow:auto;" +
    "background:var(--panel,var(--bg));color:var(--text);border:1px solid var(--border-strong,var(--border));" +
    "border-radius:var(--radius,4px);box-shadow:0 12px 36px rgba(0,0,0,.28);padding:16px 18px}" +
    ".mc-pop h3{margin:0 0 4px;font-size:15px}.mc-pop p{margin:6px 0;line-height:1.5}" +
    ".mc-sec{border-top:1px solid var(--border);margin-top:12px;padding-top:12px}" +
    ".mc-hint{font-size:12.5px;color:var(--muted)}.mc-error{color:var(--signal);font-weight:600}" +
    ".mc-what{font:600 13px var(--mono,ui-monospace,monospace);overflow-wrap:anywhere}" +
    ".mc-badge{font:700 11px var(--mono,ui-monospace,monospace);letter-spacing:.08em;text-transform:uppercase;padding:3px 8px;border-radius:999px}" +
    ".mc-badge.ok{color:var(--secure,#3FB950);background:var(--secure-soft,rgba(63,185,80,.12))}" +
    ".mc-badge.warn{color:var(--caution,#E3B341);background:var(--caution-soft,rgba(227,179,65,.14))}" +
    ".mc-badge.bad{color:var(--signal,#FF4F00);background:var(--signal-soft,rgba(255,79,0,.1))}" +
    ".mc-badge.unknown{color:var(--muted);border:1px solid var(--border)}" +
    ".mc-pop button,.mc-bar button{border:1px solid var(--border-strong,var(--border));background:transparent;color:var(--text);" +
    "border-radius:var(--radius,4px);padding:7px 13px;font:700 13px var(--body-font,inherit);cursor:pointer}" +
    ".mc-pop button.mc-main,.mc-bar button.mc-main{background:var(--text);color:var(--bg);border-color:var(--text)}" +
    ".mc-pop button:disabled{opacity:.55;cursor:wait}" +
    ".mc-row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:8px}" +
    ".mc-pop select,.mc-pop input{border:1px solid var(--border);border-radius:var(--radius,4px);padding:7px 10px;background:var(--bg);" +
    "color:var(--text);font:inherit;min-width:0;flex:1 1 160px}" +
    ".mc-code{font:700 22px var(--mono,ui-monospace,monospace);letter-spacing:.12em}" +
    ".mc-pop a{color:var(--signal);font-weight:600;overflow-wrap:anywhere}" +
    ".mc-busy{display:flex;gap:8px;align-items:center}.mc-spin{flex:none;width:12px;height:12px;border:2px solid currentColor;" +
    "border-right-color:transparent;border-radius:50%;animation:mc-spin .7s linear infinite}@keyframes mc-spin{to{transform:rotate(360deg)}}" +
    "@media (prefers-reduced-motion:reduce){.mc-spin{animation-duration:2.4s}}";

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
    listeners.forEach(function (fn) { try { fn(last); } catch (_) { /* a listener never breaks the dot */ } });
  }

  function signingIn(data) {
    var status = data && data.nous && data.nous.status;
    return status === "starting" || status === "waiting" || status === "finishing";
  }

  function missing() { return !!last && (last.state === "missing" || signingIn(last)); }
  function connection() { return (last && last.connection) || {}; }

  function schedule() {
    if (timer) window.clearTimeout(timer);
    // "unknown" is the first answer while Hermes is still being asked: ask again soon, so the dot
    // settles right after load; likewise while signing in and while the details load.
    var fast = !last || last.state === "missing" || last.state === "unknown" || signingIn(last) ||
      (last.state === "ready" && !connection().provider);
    timer = window.setTimeout(refresh, fast ? FAST_MS : SLOW_MS);
  }

  function refresh() {
    return fetch("/api/agent-model", { cache: "no-store" }).then(function (r) { return r.json(); }).then(function (data) {
      var wasMissing = missing();
      last = data || {};
      if (wasMissing && last.state === "ready") {
        toast("Your agent is connected to an AI model.");
        notice = "Connected. Open a chat with your agent (run hermes in a terminal) and try the test prompt — Blackbox should flag it.";
      }
      draw();
      notify();
    }).catch(function () { /* the dashboard's own banner reports a down service */ }).then(schedule);
  }

  // A line with a small spinner: work is going on (2026-11-19: the sign-in looked frozen while the
  // person approved on Nous's page and while Hermes finished).
  function spinnerLine(text) {
    var line = el("p", "mc-busy");
    line.appendChild(el("span", "mc-spin"));
    line.appendChild(el("span", "", text));
    line.setAttribute("role", "status");
    return line;
  }

  // The dashboard's own corner note (#toast), not a banner.
  function toast(text) {
    var note = document.getElementById("toast");
    if (!note) return;
    note.textContent = text;
    note.className = "toast ok show";
    window.setTimeout(function () { note.className = "toast ok"; }, 4500);
  }

  function providerName(id) {
    if (id === "nous") return "Nous Portal";
    var match = ((last && last.providers) || []).filter(function (p) { return p.id === id; })[0];
    return match ? match.name : id;
  }

  function button(label, cls, onClick) {
    var b = el("button", cls || "", label);
    b.type = "button"; b.disabled = working;
    b.addEventListener("click", onClick);
    return b;
  }

  // *done* (optional) turns a successful answer into the line the menu shows next, so every change
  // says what it did ("Use the recommended model" on the model already in use read as broken).
  function act(request, done) {
    working = true; error = ""; notice = ""; draw();
    request.then(function (res) {
      if (!res.ok || res.body.ok === false) error = res.body.error || res.body.reason || "That did not work.";
      else if (done) notice = done(res.body);
    }, function (err) { error = (err && err.message) || "That did not work."; })
      .then(function () { working = false; return refresh(); });
  }

  // ---------------------------------------------------------------- the dot and its tooltip
  function status() {
    if (!last || last.state === "unknown") return ["unknown", "AI model: checking with Hermes…"];
    if (missing()) return ["bad", "No AI model connected — your agent cannot chat, so Blackbox has nothing to check. Click to connect."];
    var c = connection();
    if (!c.provider) return ["unknown", "AI model: checking with Hermes…"];
    var what = providerName(c.provider) + " · " + (c.model || "Hermes' default model");
    if (c.status === "exhausted") return ["warn", "AI model: " + what + " — refused recently. Click to fix."];
    return ["ok", "AI model: " + what + " — connected. Click to manage."];
  }

  function drawDot() {
    if (!dot) return;
    var s = status();
    dot.querySelector(".mc-dot").className = "mc-dot " + s[0];
    dot.title = s[1];
    dot.setAttribute("aria-label", s[1]);
  }

  // ---------------------------------------------------------------- the slim line (no model only)
  function drawBar() {
    if (!root) return;
    var sig = JSON.stringify([missing(), last && last.nous && last.nous.status]);
    if (sig === drawnBar) return;
    drawnBar = sig;
    root.innerHTML = "";
    root.hidden = !missing();
    if (!missing()) return;
    var bar = el("div", "mc-bar");
    bar.setAttribute("role", "status");
    bar.appendChild(el("span", "mc-dot bad"));
    var text = signingIn(last) ? "Connecting your agent to an AI model…" :
      "Your agent has no AI model connected — it cannot chat, so Blackbox has nothing to check yet.";
    bar.appendChild(el("span", "mc-text", text));
    bar.appendChild(button(signingIn(last) ? "Show" : "Connect", "mc-main", function (e) { e.stopPropagation(); openMenu(true); }));
    root.appendChild(bar);
  }

  // ---------------------------------------------------------------- the menu
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
      box.appendChild(el("p", "", "3. Approve. This finishes by itself."));
      box.appendChild(spinnerLine("Waiting for you to approve on Nous's page…"));
      box.appendChild(button("Cancel sign-in", "", function () { act(post("/api/agent-model/nous/cancel")); }));
      return;
    }
    if (nous.status === "starting") { box.appendChild(spinnerLine("Asking Nous for a sign-in code…")); return; }
    if (nous.status === "finishing") { box.appendChild(spinnerLine("Approved. Connecting your Nous account to your agent…")); return; }
    if (nous.status === "failed" && nous.reason) box.appendChild(el("p", "mc-error", nous.reason));
    box.appendChild(button("Sign in with Nous (free)", "mc-main", function () { act(post("/api/agent-model/nous")); }));
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
    var save = button(working ? "Saving…" : "Save key", "", function () {
      var key = input.value; input.value = "";
      act(post("/api/agent-model/key", { provider: select.value, key: key }));
    });
    save.style.marginTop = "8px";
    box.appendChild(save);
  }

  function drawConnected(box) {
    var c = connection();
    var head = el("div", "mc-row");
    head.appendChild(el("h3", "", "Your agent's AI model"));
    var s = status();
    var badge = { ok: ["ok", "Connected"], warn: ["warn", "Refused recently"], unknown: ["unknown", "Checking"] }[s[0]] || ["unknown", ""];
    head.appendChild(el("span", "mc-badge " + badge[0], badge[1]));
    box.appendChild(head);
    if (!c.provider) { box.appendChild(spinnerLine("Checking with Hermes…")); return; }
    box.appendChild(el("p", "mc-what", [providerName(c.provider), c.model || "Hermes' default model", c.account].filter(Boolean).join(" · ")));
    // Hermes' "exhausted" mark is a pause of up to an hour after a provider refused a request — it
    // can outlive the cause, so it is named as recent with the step that fixes the usual cause.
    if (c.status === "exhausted") box.appendChild(el("p", "", "The provider refused this account recently, so Hermes paused it for up to an hour " +
      "(usually: no credits for the model it asked for). “Use the recommended model” picks one your account can use and clears the pause."));
    // A free model is small: said here, so a weak answer is not read as a broken product.
    if (/:free$/.test(c.model || "")) box.appendChild(el("p", "mc-hint", "A free model: fine for chatting and everyday work, but the " +
      "Blackbox assistant may misread broad questions. For sharper answers, connect an API key or a paid model."));
    var rec = el("div", "mc-sec");
    rec.appendChild(button(working ? "Working…" : "Use the recommended model", "mc-main", function () {
      act(post("/api/agent-model/recommended"), function (body) {
        return "Now using " + (body.model || "the recommended model") + " — the model recommended for this account.";
      });
    }));
    rec.appendChild(el("p", "mc-hint", c.provider === "nous" ? "The model Nous recommends for your account (a free account gets a free model)."
      : "The model Hermes recommends for " + providerName(c.provider) + "."));
    var pick = el("div", "mc-row");
    var input = el("input");
    input.placeholder = "Another model, e.g. vendor/model:free"; input.setAttribute("aria-label", "Model name");
    input.spellcheck = false; input.autocomplete = "off";
    pick.appendChild(input);
    pick.appendChild(button("Use this model", "", function () {
      var chosen = input.value.trim();
      act(post("/api/agent-model/model", { model: chosen }), function () { return "Now using " + chosen + "."; });
    }));
    rec.appendChild(pick);
    box.appendChild(rec);
    var out = el("div", "mc-sec");
    if (confirmingSignOut) {
      out.appendChild(el("p", "", "Sign your agent out of " + providerName(c.provider) + "? It cannot chat until you connect again — " +
        "a different Nous account, the free tier or an API key."));
      var row = el("div", "mc-row");
      row.appendChild(button("Sign out", "mc-main", function () { confirmingSignOut = false; act(post("/api/agent-model/disconnect")); }));
      row.appendChild(button("Keep it", "", function () { confirmingSignOut = false; draw(); }));
      out.appendChild(row);
    } else {
      out.appendChild(button("Switch account or sign out", "", function () { confirmingSignOut = true; draw(); }));
    }
    box.appendChild(out);
  }

  function placeMenu() {
    if (!menu || !dot) return;
    var r = dot.getBoundingClientRect();
    var width = menu.offsetWidth || 420;
    menu.style.top = Math.round(r.bottom + 8) + "px";
    menu.style.left = Math.round(Math.max(16, Math.min(window.innerWidth - width - 16, r.right - width))) + "px";
  }

  // WHY a signature: the menu polls while open; rebuilding it each time would wipe a key or a model
  // name someone is typing. It redraws only when something it shows has changed.
  function drawMenu() {
    if (!menu) return;
    menu.hidden = !menuOpen;
    if (!menuOpen) { drawnMenu = ""; return; }
    var nous = (last && last.nous) || {};
    var c = connection();
    var sig = JSON.stringify([last && last.state, nous.status, nous.link, nous.code, nous.reason, error, notice, working,
      c.provider, c.model, c.account, c.status, confirmingSignOut]);
    if (sig === drawnMenu) { placeMenu(); return; }
    drawnMenu = sig;
    menu.innerHTML = "";
    if (notice) menu.appendChild(el("p", "", notice));
    if (error) menu.appendChild(el("p", "mc-error", error));
    if (missing()) {
      menu.appendChild(el("p", "", "Blackbox checks every prompt your agent sends to its AI model. Connect one so your agent can chat:"));
      var nousBox = el("div", "mc-sec"); drawNous(nousBox); menu.appendChild(nousBox);
      var keyBox = el("div", "mc-sec"); drawKey(keyBox); menu.appendChild(keyBox);
      menu.appendChild(el("p", "mc-hint", "Prefer a terminal? Run: " + ((last && last.fix) || "hermes setup") + "  (or hermes setup for any provider)."));
    } else {
      drawConnected(menu);
    }
    placeMenu();
  }

  function draw() {
    drawDot();
    drawBar();
    drawMenu();
  }

  function openMenu(force) {
    menuOpen = force === undefined ? !menuOpen : !!force;
    if (menuOpen) refresh();
    else { confirmingSignOut = false; notice = ""; error = ""; }
    if (dot) dot.setAttribute("aria-expanded", menuOpen ? "true" : "false");
    draw();
  }

  window.blackboxAgentModel = {
    state: function () { return last ? last.state : "unknown"; },
    fix: function () { return (last && last.fix) || "hermes setup"; },
    refresh: refresh,
    onChange: function (fn) { listeners.push(fn); if (last) fn(last); },
    // Deferred: the click that asked (a link elsewhere on the page) must not reach the page's
    // close-on-outside-click handler after the menu opened.
    open: function () { window.setTimeout(function () { openMenu(true); }, 0); }
  };

  function start() {
    root = document.getElementById("model-connect-root");
    var style = el("style"); style.textContent = CSS; document.head.appendChild(style);
    var actions = document.getElementById("header-action-menu");
    if (actions) {
      dot = el("button", "gear-btn mc-dot-btn");
      dot.type = "button"; dot.id = "model-status";
      dot.setAttribute("aria-haspopup", "dialog"); dot.setAttribute("aria-expanded", "false");
      dot.appendChild(el("span", "mc-dot"));
      dot.appendChild(el("span", "header-action-label", "AI model"));
      dot.addEventListener("click", function (e) { e.stopPropagation(); openMenu(); });
      actions.insertBefore(dot, actions.firstChild);
    }
    menu = el("div", "mc-pop");
    menu.id = "model-popover"; menu.hidden = true;
    menu.setAttribute("role", "dialog"); menu.setAttribute("aria-label", "Your agent's AI model");
    menu.addEventListener("click", function (e) { e.stopPropagation(); });
    document.body.appendChild(menu);
    document.addEventListener("click", function () { if (menuOpen) openMenu(false); });
    document.addEventListener("keydown", function (e) { if (e.key === "Escape" && menuOpen) openMenu(false); });
    window.addEventListener("resize", placeMenu);
    window.addEventListener("scroll", placeMenu, { passive: true });
    draw();
    refresh();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
