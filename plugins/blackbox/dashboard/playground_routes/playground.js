/* The Playground — sandbox mode's panel (2026-10-21).
 *
 * Reads GET /api/playground. In sandbox mode it marks the page (<html data-sandbox="on">,
 * which index.html turns violet), shows a fixed SANDBOX badge and draws the panel into
 * #playground-root: four test buttons (a listed threat of each kind, sent through the real
 * check), this node's own tests, and the graph's sandbox lane (what every member shared).
 * Out of sandbox mode it removes all of that, so the page is the ordinary one again.
 *
 * In sandbox mode the Community tab of the threat graph also draws the verified graph's
 * SANDBOX lane (window.__bbSandbox switches index.html's graph and detail requests to
 * /api/playground/graph and /api/playground/threat) under a striped SANDBOX ribbon, and is
 * redrawn when the mode flips or a new sandbox entry arrives. Display only: protection keeps
 * reading the real reports lane.
 *
 * Below the threat tests it draws WALLET TESTS (GET /api/playground/wallets): every wallet the
 * shields find on this machine plus a generated seed phrase and key, each runnable through the
 * real check (POST /api/playground/wallets/run) — local only, never shared, nothing executed —
 * with its result beside it (blocked / flagged / let through and why), and "Run all".
 *
 * Kept short on purpose (2026-11-02): wallet tests fold into one row per wallet (opens to its
 * tests, with its own Run), this node's tests fold repeats of one check into "×N", the lane is
 * filtered by who sent it, and each list shows its newest LIST_CAP with "Show all". The panel is
 * redrawn every POLL_MS, so what is open or chosen lives in `ui`, never in the DOM.
 *
 * Every POST carries the dashboard's session token (X-Blackbox-Token from /api/session),
 * like index.html's own postJSON. Text from the node is written with textContent only.
 */
(function () {
  "use strict";
  var POLL_MS = 5000;
  var MIN_SPIN_MS = 600;   // how long a single wallet test's spinner stays up at least
  var KIND_LABELS = { "package": "Malware package", "domain": "Malicious domain", "ip": "C2 server address", "url": "Payload link" };
  var root = null, badge = null, ribbon = null, timer = null, busy = "", firstSeen = {}, lastResult = null, lastError = "";
  var lastMode = null, lastLaneSignature = "";
  var walletTests = [], walletResults = {}, walletBusy = "", walletError = "";
  var LIST_CAP = 8;        // rows a list shows before "Show all"
  // What the viewer opened or chose; survives the redraw every POLL_MS.
  var ui = { laneFrom: "all", showAll: {}, openWallets: {} };
  var DECISIONS = { blocked: ["BLOCKED", "pg-w-blocked"], flagged: ["FLAGGED", "pg-w-flagged"], allowed: ["LET THROUGH", "pg-w-allowed"] };
  var WALLET_CSS = ".pg-wallets{margin-top:22px}.pg-wallets .pg-w-head{display:flex;flex-wrap:wrap;align-items:center;gap:10px;margin-bottom:8px}" +
    ".pg-w-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:6px 12px;align-items:center;padding:8px 10px;border-bottom:1px solid var(--border)}" +
    ".pg-w-row:last-child{border-bottom:0}.pg-w-title{color:var(--text)}.pg-w-cmd{font-family:var(--mono,ui-monospace,monospace);font-size:11px;color:var(--muted);overflow-wrap:anywhere}" +
    ".pg-w-side{display:flex;align-items:center;gap:8px;justify-self:end}.pg-w-out{font:700 11px/1 var(--mono,ui-monospace,monospace);letter-spacing:.08em;padding:4px 8px;border-radius:999px}" +
    ".pg-w-blocked{color:var(--secure);background:var(--secure-soft)}.pg-w-flagged{color:var(--caution);background:var(--caution-soft)}" +
    ".pg-w-allowed{color:var(--signal);background:var(--signal-soft)}.pg-w-note{grid-column:1/-1;font-size:12px;color:var(--muted)}" +
    ".pg-wallets button{border:1px solid var(--sandbox,#8B5CF6);background:transparent;color:var(--text);border-radius:8px;padding:5px 10px;cursor:pointer}" +
    ".pg-wallets button:disabled{opacity:.55;cursor:progress}.pg-w-box{border:1px solid var(--border);border-radius:8px}" +
    "@media (max-width:560px){.pg-w-row{grid-template-columns:1fr}.pg-w-side{justify-self:start}}" +
    ".pg-spin{display:inline-block;width:11px;height:11px;margin-right:6px;vertical-align:-1px;border:2px solid currentColor;" +
    "border-right-color:transparent;border-radius:50%;animation:pg-spin .7s linear infinite}@keyframes pg-spin{to{transform:rotate(360deg)}}" +
    "@media (prefers-reduced-motion:reduce){.pg-spin{animation-duration:2.4s}}" +
    ".pg-chips{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 8px}.pg-panel button.pg-chip{border:1px solid var(--border);background:transparent;" +
    "color:var(--muted);border-radius:999px;padding:3px 10px;font:600 11px var(--mono,ui-monospace,monospace);cursor:pointer}" +
    ".pg-panel button.pg-chip[aria-pressed=true]{border-color:var(--sandbox,#8B5CF6);color:var(--text);background:var(--sandbox-soft,rgba(139,92,246,.12))}" +
    ".pg-panel button.pg-more{border:0;background:none;padding:6px 0 0;color:var(--sandbox,#8B5CF6);font-size:12px;cursor:pointer}" +
    ".pg-times{margin-left:6px;font:700 11px var(--mono,ui-monospace,monospace);color:var(--sandbox,#8B5CF6)}" +
    ".pg-w-wallet{border-bottom:1px solid var(--border)}.pg-w-wallet:last-child{border-bottom:0}" +
    ".pg-w-ghead{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px 12px;align-items:center;padding:8px 10px}" +
    ".pg-wallets button.pg-w-toggle{border:0;background:none;padding:0;text-align:left;color:var(--text);display:flex;gap:8px;align-items:baseline;flex-wrap:wrap;min-width:0}" +
    ".pg-w-caret{display:inline-block;width:10px;color:var(--muted);transition:transform .15s}.pg-w-toggle[aria-expanded=true] .pg-w-caret{transform:rotate(90deg)}" +
    ".pg-w-name{font-weight:600}.pg-w-sum{font-size:12px;color:var(--muted)}.pg-w-tests{border-top:1px solid var(--border);padding-left:18px}" +
    "@media (max-width:560px){.pg-w-ghead{grid-template-columns:1fr}}";

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = String(text);
    return node;
  }

  function token() {
    return fetch("/api/session", { cache: "no-store" }).then(function (r) {
      if (!r.ok) throw new Error("This dashboard is opened read-only here; open it on the machine itself to run tests.");
      return r.json();
    }).then(function (j) { return (j && j.token) || ""; });
  }

  function communityTabActive() {
    var tab = document.getElementById("tab-community");
    return !!tab && tab.getAttribute("aria-selected") === "true";
  }

  function showRibbon() {
    var stage = document.getElementById("graph-stage");
    if (!stage) return;
    if (!ribbon) {
      ribbon = el("div", "pg-ribbon");
      ribbon.setAttribute("role", "note");
      ribbon.appendChild(el("div", "pg-ribbon-mark", "S"));
      var text = el("div");
      text.appendChild(el("b", "", "SANDBOX COMMUNITY"));
      text.appendChild(el("span", "", "The verified graph's sandbox lane: tests only, never a flag or a rule."));
      ribbon.appendChild(text);
      stage.appendChild(ribbon);
    }
    ribbon.hidden = !(window.__bbSandbox === true && communityTabActive());
  }

  // Redraw the Community tab from the right lane when the mode flips or the sandbox lane changes.
  function syncCommunityGraph(state) {
    var mode = !!state.sandbox;
    var signature = mode ? ((state.lane && state.lane.entries) || []).map(function (e) { return e.identifier + "|" + e.reporter; }).sort().join(",") : "";
    window.__bbSandbox = mode;
    // What the Community card counts in sandbox mode: the lane's distinct threats and agents heard.
    var entries = (state.lane && state.lane.entries) || [];
    var distinct = {};
    entries.forEach(function (e) { distinct[e.identifier] = true; });
    window.__bbSandboxLane = mode && state.lane && state.lane.readable
      ? { threats: Object.keys(distinct).length, agents: state.lane.agents || 0 } : null;
    if (typeof window.blackboxRenderCommunityCard === "function") window.blackboxRenderCommunityCard();
    var flipped = lastMode !== null && lastMode !== mode;
    var startedInSandbox = lastMode === null && mode;
    var arrived = mode && lastMode === mode && signature !== lastLaneSignature;
    lastMode = mode;
    lastLaneSignature = signature;
    if ((flipped || startedInSandbox || arrived) && typeof window.blackboxCommunityReset === "function") {
      window.blackboxCommunityReset();
    }
    showRibbon();
  }

  function setSandboxLook(on) {
    var html = document.documentElement;
    if (on) html.setAttribute("data-sandbox", "on"); else html.removeAttribute("data-sandbox");
    if (on && !badge) {
      badge = el("div", "pg-badge", "SANDBOX MODE");
      badge.setAttribute("role", "status");
      badge.title = "Shares go to the sandbox lane only. Switch off in Settings → Community sharing.";
      document.body.appendChild(badge);
    } else if (!on && badge) {
      badge.remove();
      badge = null;
    }
  }

  function listOrEmpty(items, empty, render) {
    var list = el("ul", "pg-list");
    if (!items.length) { list.appendChild(el("li", "pg-meta", empty)); return list; }
    items.forEach(function (item) { list.appendChild(render(item)); });
    return list;
  }

  // A list that shows its newest LIST_CAP rows and a "Show all N" / "Show fewer" switch under it.
  function cappedList(key, items, empty, render) {
    var box = el("div");
    var open = !!ui.showAll[key];
    box.appendChild(listOrEmpty(open ? items : items.slice(0, LIST_CAP), empty, render));
    if (items.length > LIST_CAP) {
      var more = el("button", "pg-more", open ? "Show fewer" : "Show all " + items.length);
      more.type = "button";
      more.addEventListener("click", function () { ui.showAll[key] = !open; refresh(); });
      box.appendChild(more);
    }
    return box;
  }

  function testWhen(row) {
    var when = row.iso || (row.ts ? new Date(row.ts * 1000).toISOString() : "");
    return when.replace("T", " ").replace("Z", " UTC");
  }

  // One check can record several findings at once (a profile backup names every wallet inside):
  // rows with the same identifier in the same second fold into one row counted "×N".
  function foldTests(rows) {
    var folded = [], byKey = {};
    rows.forEach(function (row) {
      var f = row.finding || row || {};
      var identifier = f.identifier || row.identifier || "—";
      var key = identifier + "|" + testWhen(row).slice(0, 19);
      if (byKey[key]) { byKey[key].times += 1; return; }
      byKey[key] = { identifier: identifier, severity: f.severity || "", when: testWhen(row), times: 1 };
      folded.push(byKey[key]);
    });
    return folded;
  }

  function testRow(test) {
    var li = el("li");
    var id = el("div", "pg-id", test.identifier);
    if (test.times > 1) id.appendChild(el("span", "pg-times", "×" + test.times));
    li.appendChild(id);
    li.appendChild(el("div", "pg-meta", [test.severity, test.when].filter(Boolean).join(" · ")));
    return li;
  }

  function laneRow(entry) {
    var key = entry.identifier + "|" + entry.reporter;
    if (!firstSeen[key]) firstSeen[key] = new Date();
    var li = el("li");
    li.appendChild(el("div", "pg-id", entry.identifier));
    var meta = el("div", "pg-meta");
    meta.appendChild(el("span", entry.mine ? "pg-mine" : "", entry.mine ? "this node" : "member " + entry.reporter.slice(0, 10) + "…"));
    meta.appendChild(document.createTextNode(" · " + entry.severity + " · seen here " + firstSeen[key].toLocaleTimeString()));
    li.appendChild(meta);
    return li;
  }

  function laneSender(entry) { return entry.mine ? "mine" : entry.reporter; }

  // Filter chips over the lane: everyone, this node, then each member, each with its count.
  function laneChips(entries) {
    var counts = {}, order = [];
    entries.forEach(function (entry) {
      var who = laneSender(entry);
      if (!(who in counts)) { counts[who] = 0; order.push(who); }
      counts[who] += 1;
    });
    if (ui.laneFrom !== "all" && !(ui.laneFrom in counts)) ui.laneFrom = "all";
    order.sort(function (a, b) { return a === "mine" ? -1 : b === "mine" ? 1 : counts[b] - counts[a]; });
    var chips = el("div", "pg-chips");
    chips.setAttribute("role", "group");
    chips.setAttribute("aria-label", "Show the lane from");
    [["all", "All " + entries.length]].concat(order.map(function (who) {
      return [who, (who === "mine" ? "This node " : who.slice(0, 10) + "… ") + counts[who]];
    })).forEach(function (chip) {
      var button = el("button", "pg-chip", chip[1]);
      button.type = "button";
      button.setAttribute("aria-pressed", String(ui.laneFrom === chip[0]));
      if (chip[0] !== "all" && chip[0] !== "mine") button.title = "member " + chip[0];
      button.addEventListener("click", function () { ui.laneFrom = chip[0]; ui.showAll.lane = false; refresh(); });
      chips.appendChild(button);
    });
    return chips;
  }

  function drawLane(view) {
    var box = el("div");
    if (view.readable === false) { box.appendChild(el("p", "pg-meta", "The local node did not answer; trying again.")); return box; }
    var entries = view.entries || [];
    if (entries.length) box.appendChild(laneChips(entries));
    var shown = ui.laneFrom === "all" ? entries : entries.filter(function (e) { return laneSender(e) === ui.laneFrom; });
    box.appendChild(cappedList("lane", shown, "Nothing in the sandbox lane yet.", laneRow));
    return box;
  }

  // A button's label, with a spinner in front while its test runs (so the wait is visible).
  function setLabel(button, text, spinning) {
    button.textContent = "";
    if (spinning) {
      var spin = el("span", "pg-spin");
      spin.setAttribute("aria-hidden", "true");
      button.appendChild(spin);
      button.setAttribute("aria-busy", "true");
    }
    button.appendChild(document.createTextNode(text));
  }

  function ensureWalletStyle() {
    if (document.getElementById("pg-wallet-style")) return;
    var style = el("style");
    style.id = "pg-wallet-style";
    style.textContent = WALLET_CSS;
    document.head.appendChild(style);
  }

  function resultNote(test, result) {
    if (!result) return test.note || "";
    var parts = [];
    if (result.note) parts.push(result.note);
    if (result.decision === "flagged" && test.expect === "blocked" && !result.blocking) parts.push("Blackbox is in Audit mode: in Block mode this is blocked.");
    if (result.identifiers && result.identifiers.length) parts.push(result.identifiers.join(", ") + " · " + (result.check_ms / 1000).toFixed(2) + " s");
    return parts.join(" ");
  }

  function walletRow(test) {
    var row = el("div", "pg-w-row");
    var text = el("div");
    text.appendChild(el("div", "pg-w-title", test.title));
    text.appendChild(el("div", "pg-w-cmd", test.shown));
    row.appendChild(text);
    var side = el("div", "pg-w-side");
    var result = walletResults[test.id];
    var mark = result ? DECISIONS[result.decision] : null;
    if (mark) side.appendChild(el("span", "pg-w-out " + mark[1], mark[0]));
    else side.appendChild(el("span", "pg-meta", "should be " + test.expect));
    var button = el("button");
    setLabel(button, walletBusy === test.id ? "Checking…" : (result ? "Run again" : "Run"), walletBusy === test.id);
    button.type = "button";
    button.disabled = !!walletBusy;
    button.addEventListener("click", function () {
      setLabel(button, "Checking…", true);   // at once, before the round trip
      button.disabled = true;
      runWallets([test.id]);
    });
    side.appendChild(button);
    row.appendChild(side);
    var note = resultNote(test, result);
    if (note) row.appendChild(el("div", "pg-w-note", note));
    return row;
  }

  // The wallet tests in first-seen order of their group (one wallet, browser profiles, secrets).
  function walletGroups() {
    var groups = [], byId = {};
    walletTests.forEach(function (test) {
      if (!byId[test.group]) { byId[test.group] = { id: test.group, name: test.group_name || test.group, tests: [] }; groups.push(byId[test.group]); }
      byId[test.group].tests.push(test);
    });
    return groups;
  }

  // "3 tests · 2 blocked, 1 flagged" — what has been run so far in one group.
  function groupSummary(tests) {
    var done = {}, ran = 0;
    tests.forEach(function (test) {
      var result = walletResults[test.id];
      if (!result) return;
      ran += 1;
      done[result.decision] = (done[result.decision] || 0) + 1;
    });
    var text = tests.length + (tests.length === 1 ? " test" : " tests");
    if (!ran) return text;
    return text + " · " + ["blocked", "flagged", "allowed"].filter(function (d) { return done[d]; })
      .map(function (d) { return done[d] + " " + (d === "allowed" ? "let through" : d); }).join(", ");
  }

  function walletGroup(group) {
    var section = el("div", "pg-w-wallet");
    var head = el("div", "pg-w-ghead");
    var open = !!ui.openWallets[group.id];
    var toggle = el("button", "pg-w-toggle");
    toggle.type = "button";
    toggle.setAttribute("aria-expanded", String(open));
    toggle.appendChild(el("span", "pg-w-caret", "▸"));
    toggle.appendChild(el("span", "pg-w-name", group.name));
    toggle.appendChild(el("span", "pg-w-sum", groupSummary(group.tests)));
    toggle.addEventListener("click", function () { ui.openWallets[group.id] = !open; refresh(); });
    head.appendChild(toggle);
    var side = el("div", "pg-w-side");
    var running = group.tests.some(function (test) { return test.id === walletBusy; });
    var run = el("button");
    run.type = "button";
    setLabel(run, running ? "Checking…" : "Run " + group.tests.length, running);
    run.disabled = !!walletBusy;
    run.addEventListener("click", function () {
      setLabel(run, "Checking…", true);
      run.disabled = true;
      runWallets(group.tests.map(function (test) { return test.id; }));
    });
    side.appendChild(run);
    head.appendChild(side);
    section.appendChild(head);
    if (open) {
      var tests = el("div", "pg-w-tests");
      group.tests.forEach(function (test) { tests.appendChild(walletRow(test)); });
      section.appendChild(tests);
    }
    return section;
  }

  function drawWallets(panel) {
    ensureWalletStyle();
    var box = el("div", "pg-wallets");
    var head = el("div", "pg-w-head");
    head.appendChild(el("h3", "", "Wallet tests · local only"));
    var all = el("button");
    setLabel(all, walletBusy ? "Running…" : "Run all " + walletTests.length, !!walletBusy);
    all.type = "button";
    all.disabled = !!walletBusy || !walletTests.length;
    all.addEventListener("click", function () {
      setLabel(all, "Running…", true);
      all.disabled = true;
      runWallets(walletTests.map(function (t) { return t.id; }));
    });
    head.appendChild(all);
    box.appendChild(head);
    box.appendChild(el("p", "", "Every wallet Blackbox finds on this machine, plus a seed phrase and a key made for the test, " +
      "handed to the real check the way an agent's tool would hand it. Nothing is opened, run or sent; results stay in this " +
      "machine's sandbox log and are never shared."));
    if (walletError) box.appendChild(el("p", "pg-error", walletError));
    if (!walletTests.length) box.appendChild(el("p", "pg-meta", "No wallet found on this machine yet."));
    if (walletTests.length) {
      var list = el("div", "pg-w-box");
      walletGroups().forEach(function (group) { list.appendChild(walletGroup(group)); });
      box.appendChild(list);
    }
    panel.appendChild(box);
  }

  function runWallets(ids) {
    walletError = "";
    var queue = ids.slice();
    token().then(function (tok) {
      function next() {
        var id = queue.shift();
        if (!id) return Promise.resolve();
        walletBusy = id;
        refresh();
        // A check takes milliseconds: a single test keeps its spinner up briefly so the run is seen.
        var shown = new Promise(function (resolve) { window.setTimeout(resolve, ids.length === 1 ? MIN_SPIN_MS : 0); });
        return Promise.all([fetch("/api/playground/wallets/run", {
          method: "POST", cache: "no-store",
          headers: { "Content-Type": "application/json", "Accept": "application/json", "X-Blackbox-Token": tok },
          body: JSON.stringify({ id: id })
        }).then(function (r) { return r.json(); }), shown]).then(function (both) {
          var body = both[0];
          if (body && body.ok) walletResults[id] = body.result; else walletError = (body && body.error) || "The test did not run.";
        }).then(next);
      }
      return next();
    }).catch(function (err) { walletError = err && err.message ? err.message : "The test did not run."; })
      .then(function () { walletBusy = ""; return refresh(); });
  }

  function draw(state) {
    root.innerHTML = "";
    var panel = el("section", "pg-panel");
    panel.setAttribute("aria-label", "Sandbox Playground");
    panel.appendChild(el("h2", "", "Playground · sandbox mode"));
    panel.appendChild(el("p", "", "Send a threat already listed in this node's verified rules through the real check. " +
      "The finding and its share stay in the sandbox: the share goes to the graph's sandbox lane, which no rule or flag on any " +
      "machine reads, and nothing lands in your real findings. Members who joined the same graph see it below within seconds."));
    if (!state.sharing) panel.appendChild(el("p", "pg-error", "Community sharing is off. Turn it on in Settings to run tests (they stay in the sandbox lane)."));
    var kinds = el("div", "pg-kinds");
    (state.kinds || []).forEach(function (kind) {
      var button = el("button");
      setLabel(button, busy === kind ? "Asking Blackbox… (up to 90 s)" : "Send: " + (KIND_LABELS[kind] || kind), busy === kind);
      button.type = "button";
      button.disabled = !!busy || !state.sharing;
      button.addEventListener("click", function () {
        setLabel(button, "Asking Blackbox… (up to 90 s)", true);
        button.disabled = true;
        run(kind);
      });
      kinds.appendChild(button);
    });
    panel.appendChild(kinds);
    if (lastError) panel.appendChild(el("p", "pg-error", lastError));
    if (lastResult) {
      panel.appendChild(el("p", "", "Last test: " + lastResult.decision.toUpperCase() + " " + lastResult.identifier +
        " in " + (lastResult.check_ms / 1000).toFixed(1) + " s · share " + (lastResult.shared || "not sent")));
    }
    var cols = el("div", "pg-cols");
    var mine = el("div");
    mine.appendChild(el("h3", "", "This node's tests"));
    mine.appendChild(cappedList("tests", foldTests(state.tests || []), "No tests yet.", testRow));
    var lane = el("div");
    var view = state.lane || {};
    lane.appendChild(el("h3", "", "Sandbox lane · " + (view.agents || 0) + " agent(s) heard"));
    lane.appendChild(drawLane(view));
    cols.appendChild(mine);
    cols.appendChild(lane);
    panel.appendChild(cols);
    drawWallets(panel);
    root.appendChild(panel);
  }

  function refresh() {
    if (!root) return Promise.resolve();
    return fetch("/api/playground", { cache: "no-store" }).then(function (r) { return r.json(); }).then(function (state) {
      setSandboxLook(!!state.sandbox);
      syncCommunityGraph(state);
      root.hidden = !state.sandbox;
      if (!state.sandbox) { root.innerHTML = ""; return; }
      return fetch("/api/playground/wallets", { cache: "no-store" }).then(function (r) { return r.json(); })
        .then(function (body) { walletTests = (body && body.tests) || []; }, function () { /* keep the last list */ })
        .then(function () { draw(state); });
    }).catch(function () { /* the dashboard's own banner reports a down service */ });
  }

  function run(kind) {
    busy = kind; lastError = "";
    refresh();
    token().then(function (tok) {
      return fetch("/api/playground/run", {
        method: "POST", cache: "no-store",
        headers: { "Content-Type": "application/json", "Accept": "application/json", "X-Blackbox-Token": tok },
        body: JSON.stringify({ kind: kind })
      });
    }).then(function (r) { return r.json(); }).then(function (body) {
      if (body && body.ok) lastResult = body.result; else lastError = (body && body.error) || "The test did not run.";
    }).catch(function (err) { lastError = err && err.message ? err.message : "The test did not run."; })
      .then(function () { busy = ""; return refresh(); });
  }

  function start() {
    root = document.getElementById("playground-root");
    if (!root) return;
    ["tab-community", "tab-public", "tab-local"].forEach(function (id) {
      var tab = document.getElementById(id);
      if (tab) tab.addEventListener("click", function () { window.setTimeout(showRibbon, 0); });
    });
    refresh();
    timer = window.setInterval(function () { if (!document.hidden && !busy && !walletBusy) refresh(); }, POLL_MS);
  }

  window.blackboxPlayground = { refresh: refresh };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
