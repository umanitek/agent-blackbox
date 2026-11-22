/*
 * Running now — every live instance of every coding agent, drawn under Connected agents.
 *
 * Reads GET /api/agent-instances/live as a long-poll (?cursor=N&wait=25): the server holds the
 * answer until something changed, so the list is current within about a second while costing
 * one request per change (never faster than MIN_POLL_MS) or per WAIT_SECONDS when idle. The
 * poll pauses while the tab is hidden.
 *
 * The list is plain: grouped by project folder, then product, then session, with the session's
 * sub-agents indented under it. Each row says its status (live / waiting / ended / unprotected),
 * its protection in the server's words ("sandboxed (kernel-enforced)" / "hooks only — …"), its
 * counts (checked / refused / too late), its last action, its model and how it was launched,
 * and links to its detail page (agent_pages.js). Agent processes with no hook are listed last.
 * A companion app may draw richer views over the same API; the core's are deliberately plain.
 *
 * Text is set with textContent only. Also exposes the shared row helpers agent_pages.js uses:
 *
 *   BlackboxAgentViews.instanceRow(row, depth)   // one instance as a list row (a sub-agent: depth 1)
 *   BlackboxAgentViews.el(tag, cls, text), .getJSON(path), .when(ts), .chip(status), .href(page, params)
 */
(function (global) {
  "use strict";

  var WAIT_SECONDS = 25, MIN_POLL_MS = 1000, RETRY_MS = 5000;
  var NO_PROJECT = "No project folder";
  var VERDICT_WORDS = { allow: "allowed", flag: "flagged", block: "refused", "too-late": "too late — it ran" };

  function str(value) { return value == null ? "" : String(value); }
  function list(value) { return Array.isArray(value) ? value : []; }
  function obj(value) { return value && typeof value === "object" && !Array.isArray(value) ? value : {}; }
  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null && text !== "") node.textContent = text;
    return node;
  }
  function add(parent) {
    for (var i = 1; i < arguments.length; i++) if (arguments[i]) parent.appendChild(arguments[i]);
    return parent;
  }
  function getJSON(path) {
    return fetch(path, { cache: "no-store", headers: { Accept: "application/json" } }).then(function (answer) {
      if (!answer.ok) throw new Error("HTTP " + answer.status);
      return answer.json();
    });
  }
  function when(ts) {
    var seconds = Number(ts) || 0;
    if (!seconds) return "";
    try { return new Date(seconds * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "numeric", minute: "2-digit", second: "2-digit" }); }
    catch (_) { return ""; }
  }
  function ago(ts) {
    var seconds = Math.max(0, Date.now() / 1000 - (Number(ts) || 0));
    if (!Number(ts)) return "";
    if (seconds < 60) return "just now";
    if (seconds < 3600) return Math.floor(seconds / 60) + " min ago";
    if (seconds < 86400) return Math.floor(seconds / 3600) + " h ago";
    return when(ts);
  }
  // "#agents/<page>?<params>": the pages agent_pages.js draws, linkable and kept in the history.
  function href(page, params) {
    var query = new URLSearchParams();
    Object.keys(obj(params)).forEach(function (key) { if (str(params[key])) query.set(key, str(params[key])); });
    var text = query.toString();
    return "#agents/" + page + (text ? "?" + text : "");
  }
  function chip(status) { return el("span", "ai-chip ai-" + (str(status) || "live"), str(status) || "live"); }
  function link(target, text, cls) {
    var node = el("a", cls || "ts-link", text);
    node.href = target;
    return node;
  }

  function lastAction(row) {
    var action = obj(row.last_action);
    if (!action.ts) return "";
    var what = [str(action.tool), str(action.what)].filter(Boolean).join(": ") || str(action.kind);
    var verdict = VERDICT_WORDS[str(action.verdict)];
    return what + (verdict ? " · " + verdict : "") + " · " + ago(action.ts);
  }
  function counts(row) {
    return (Number(row.checked) || 0) + " checked · " + (Number(row.refused) || 0) + " refused · " + (Number(row.too_late) || 0) + " too late";
  }
  function title(row) {
    if (row.kind === "sub-agent") return "Sub-agent" + (row.type ? " · " + row.type : "") + (row.task ? " — " + row.task : "");
    return "Session started " + when(row.started);
  }

  /* One instance as a row: title and status, then its facts in one muted line. */
  function instanceRow(raw, depth) {
    var row = obj(raw);
    var node = el("div", "ai-row" + (depth ? " ai-sub" : "") + (Number(row.too_late) ? " ai-had-late" : ""));
    var head = add(el("div", "ai-row-head"), chip(row.status),
                   link(href("instance", { key: row.key }), title(row), "ai-title"));
    var facts = [str(row.protection_label) || "hooks only", counts(row)];   // the server always says it; never claim more
    if (row.status === "waiting" && row.waiting_for) facts.unshift("waiting for " + row.waiting_for);
    if (row.model) facts.push("model " + row.model);
    if (row.launch) facts.push("launch mode " + row.launch);
    add(node, head, el("div", "ai-facts", facts.join(" · ")));
    var last = lastAction(row);
    if (last) add(node, el("div", "ai-last", "Last: " + last));
    if (row.root_note) add(node, el("div", "ai-warn", row.root_note));
    return node;
  }

  /* The live tree regrouped as project → product → sessions (each with its sub-agents). */
  function byProject(tree) {
    var projects = {}, order = [];
    list(obj(tree).products).forEach(function (product) {
      product = obj(product);
      list(product.profiles).forEach(function (profile) {
        list(obj(profile).instances).forEach(function (instance) {
          var name = str(obj(instance).folder) || NO_PROJECT;
          if (!projects[name]) { projects[name] = {}; order.push(name); }
          var products = projects[name], label = str(product.name) || str(product.id);
          (products[label] = products[label] || []).push(instance);
        });
      });
    });
    return order.sort(function (a, b) { return a === NO_PROJECT ? 1 : b === NO_PROJECT ? -1 : a.localeCompare(b); })
      .map(function (name) { return { project: name, products: projects[name] }; });
  }

  function unprotectedRow(raw) {
    var proc = obj(raw);
    return add(el("div", "ai-row"), add(el("div", "ai-row-head"), chip("unprotected"), el("span", "ai-title", str(proc.name) || str(proc.agent))),
               el("div", "ai-facts", ["no hook — Blackbox does not see this agent's actions", proc.launch ? "launch mode " + proc.launch : "",
                                      proc.started ? "started " + when(proc.started) : ""].filter(Boolean).join(" · ")),
               el("div", "ai-last", str(proc.reason)));
  }

  function render(root, tree) {
    var groups = byProject(tree), stray = list(obj(tree).unprotected), live = obj(obj(tree).counts);
    var body = el("div", "ai-body");
    groups.forEach(function (group) {
      var section = add(el("div", "ai-project"), el("div", "ai-project-name", group.project));
      Object.keys(group.products).sort().forEach(function (product) {
        add(section, el("div", "ai-product", product));
        group.products[product].forEach(function (session) {
          add(section, instanceRow(session, 0));
          list(obj(session).sub_agents).forEach(function (sub) { add(section, instanceRow(sub, 1)); });
        });
      });
      add(body, section);
    });
    if (stray.length) {
      var section = add(el("div", "ai-project"), el("div", "ai-project-name", "Not protected"));
      stray.forEach(function (proc) { add(section, unprotectedRow(proc)); });
      add(body, section);
    }
    if (!groups.length && !stray.length) add(body, el("div", "ai-empty", "No coding agent is running right now."));
    var summary = (Number(live.live) || 0) + " live session" + (Number(live.live) === 1 ? "" : "s") + " · " +
      (Number(live.sub_agents) || 0) + " sub-agent" + (Number(live.sub_agents) === 1 ? "" : "s") + (stray.length ? " · " + stray.length + " unprotected" : "");
    var head = add(el("div", "ai-head"), add(el("div", "ai-head-text"), el("div", "ai-head-title", "Running now"), el("div", "ai-head-note", summary)),
                   add(el("div", "ai-links"), link(href("history", {}), "History"), link(href("profiles", {}), "Profiles"),
                       link("/docs#agents", "What Blackbox protects")));
    root.replaceChildren(head, body);
    root.hidden = false;
  }

  function mount() {
    var root = document.getElementById("agent-instances-root");
    if (!root) return;
    var cursor = "", lastPoll = 0;
    function next(delay) { setTimeout(poll, Math.max(delay, MIN_POLL_MS - (Date.now() - lastPoll))); }
    function poll() {
      if (document.hidden) { document.addEventListener("visibilitychange", function resume() {
        if (document.hidden) return;
        document.removeEventListener("visibilitychange", resume);
        poll();
      }); return; }
      lastPoll = Date.now();
      getJSON("/api/agent-instances/live" + (cursor ? "?cursor=" + encodeURIComponent(cursor) + "&wait=" + WAIT_SECONDS : ""))
        .then(function (tree) { cursor = str(obj(tree).cursor); render(root, tree); next(0); })
        .catch(function () { cursor = ""; next(RETRY_MS); });
    }
    poll();
  }

  global.BlackboxAgentViews = { str: str, list: list, obj: obj, el: el, add: add, link: link, getJSON: getJSON, when: when, ago: ago,
                                href: href, chip: chip, instanceRow: instanceRow, VERDICT_WORDS: VERDICT_WORDS };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", mount);
  else mount();
})(window);
