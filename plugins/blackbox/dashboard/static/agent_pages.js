/*
 * The agent pages: one instance, the history, and (agent_profiles.js) the profiles — drawn in a
 * full-screen window over the dashboard, the same window style the shields' events use.
 *
 * Each page is an address, so it can be linked, reloaded and gone back to:
 *
 *   #agents/instance?key=<instance key>      GET /api/agent-instances/detail?key=&offset=&limit=
 *   #agents/history?agent=&project=&kind=&from=YYYY-MM-DD&to=YYYY-MM-DD&outcome=
 *                                            GET /api/agent-instances/history (filters + paging)
 *   #agents/profiles, #agents/profile?agent=&home=&project=   (agent_profiles.js)
 *
 * Pattern: a small Router (hash → page function). A page is registered as
 * ``BlackboxAgentViews.pages[name] = function (params, body, setTitle) {…}`` and draws into
 * *body*; agent_profiles.js adds its two that way. Views only: every fact is the server's.
 * Prompt text is never shown here (the GET detail never carries it). Text uses textContent.
 */
(function (global) {
  "use strict";

  var V = global.BlackboxAgentViews;
  if (!V) return;
  var el = V.el, add = V.add, str = V.str, list = V.list, obj = V.obj, link = V.link, when = V.when;
  var TIMELINE_PAGE = 100, HISTORY_PAGE = 50, DAY_SECONDS = 86400;
  var OUTCOMES = [["", "Any outcome"], ["stopped", "Had refusals or too-late"], ["refused", "Had refusals"], ["too-late", "Had too-late actions"]];
  var pages = V.pages = V.pages || {};
  var overlay = null, titleNode = null, body = null;

  function fact(grid, label, value, mono) {
    if (value == null || value === "") return;
    add(grid, el("div", "k", label), typeof value === "object" ? add(el("div"), value) : el("div", mono ? "mono" : "", str(value)));
  }
  function section(heading) { return add(el("section", "wev-sec"), el("h4", "", heading)); }
  function failed(target, error) { target.replaceChildren(el("div", "ai-empty", "Could not read this from Blackbox (" + str(error && error.message) + ").")); }
  function table(headings) {
    var node = el("table", "ai-table"), row = el("tr"), rows = el("tbody");
    headings.forEach(function (heading) { add(row, el("th", "", heading)); });
    add(node, add(el("thead"), row), rows);
    return [node, rows];   // [the table, the tbody its rows go in]
  }
  V.fact = fact; V.section = section; V.failed = failed; V.table = table;

  // ---------- one instance: facts, parent, sub-agents, timeline ----------
  function actionRow(action) {
    action = obj(action);
    var verdict = str(action.verdict), late = verdict === "too-late";
    var row = el("tr", late ? "ai-late" : "");
    [when(action.ts), str(action.kind), str(action.tool), str(action.what)].forEach(function (text) { add(row, el("td", "", text)); });
    add(row, el("td", late ? "ai-late-mark" : "", (V.VERDICT_WORDS[verdict] || verdict) + (action.late ? " (arrived after the end)" : "")));
    add(row, el("td", "", str(action.reason)));
    return row;
  }
  function timeline(key, target) {
    var parts = table(["Time", "Kind", "Tool", "What", "Verdict", "Reason"]), more = el("button", "ai-more", "Show more");
    more.type = "button";
    var offset = 0;
    function load() {
      more.disabled = true;
      V.getJSON("/api/agent-instances/detail?key=" + encodeURIComponent(key) + "&offset=" + offset + "&limit=" + TIMELINE_PAGE).then(function (page) {
        var actions = list(obj(page).actions);
        actions.forEach(function (action) { add(parts[1], actionRow(action)); });
        offset += actions.length;
        more.hidden = actions.length < TIMELINE_PAGE;
        more.disabled = false;
        if (!offset) parts[0].replaceWith(el("div", "ai-empty", "Nothing recorded for this instance yet."));
      }).catch(function (error) { failed(target, error); });
    }
    more.addEventListener("click", load);
    add(target, add(el("div", "table-scroll"), parts[0]), more);
    load();
  }
  pages.instance = function (params, target, setTitle) {
    V.getJSON("/api/agent-instances/detail?key=" + encodeURIComponent(str(params.get("key"))) + "&limit=1").then(function (found) {
      var row = obj(obj(found).instance), grid = el("div", "wev-facts");
      setTitle(row.kind === "sub-agent" ? "Sub-agent" : "Session", str(row.agent));
      fact(grid, "Status", [str(row.status), row.waiting_for ? "waiting for " + row.waiting_for : "", row.end_reason ? "ended: " + row.end_reason : ""].filter(Boolean).join(" · "));
      fact(grid, "Protection", str(row.protection_label));
      fact(grid, "Counts", [["checked", "checked"], ["refused", "refused"], ["flagged", "flagged"], ["too_late", "too late"], ["prompts", "prompts"]]
        .map(function (pair) { return (Number(row[pair[0]]) || 0) + " " + pair[1]; }).join(" · "));
      fact(grid, "Project", [str(row.folder), str(row.cwd)].filter(Boolean).join(" — "), true);
      fact(grid, "Model", str(row.model));
      fact(grid, "Launched", str(row.launch));
      fact(grid, "Type", [str(row.type), str(row.task)].filter(Boolean).join(" — "));
      fact(grid, "Started", when(row.started));
      fact(grid, "Ended", when(row.ended));
      fact(grid, "Profile", link(V.href("profile", { agent: row.agent, home: row.profile, project: row.cwd }), str(row.profile) || "the default config home"));
      fact(grid, "Root", str(row.root_note));
      add(target, add(section("This instance"), grid));
      if (row.parent) add(target, add(section("Started by"), link(V.href("instance", { key: row.parent }), "Its session")));
      var subs = list(row.sub_agents);
      if (subs.length) {
        var holder = section("Sub-agents (" + subs.length + ")");
        subs.forEach(function (sub) { add(holder, V.instanceRow(sub, 0)); });
        add(target, holder);
      }
      var steps = section("Timeline — oldest first");
      add(steps, el("div", "ai-head-note", "A too-late row is an action Blackbox decided to stop whose answer came after the agent's time limit: it ran."));
      add(target, steps);
      timeline(str(row.key), steps);
    }).catch(function (error) { failed(target, error); });
  };

  // ---------- the history: filters on the server, paged with next_before ----------
  function day(text, end) {
    var parsed = text ? new Date(text + "T00:00:00") : null;
    return parsed && !isNaN(parsed) ? Math.floor(parsed.getTime() / 1000) + (end ? DAY_SECONDS - 1 : 0) : 0;
  }
  function select(name, options, current) {
    var node = el("select", "ai-select");
    node.name = name;
    options.forEach(function (option) {
      var item = el("option", "", option[1]);
      item.value = option[0];
      item.selected = option[0] === current;
      add(node, item);
    });
    return node;
  }
  function historyForm(params, facets) {
    var form = el("form", "ai-filters");
    var agents = [["", "Every agent"]].concat(list(facets.agents).map(function (agent) { return [str(obj(agent).id), str(obj(agent).name)]; }));
    var projects = [["", "Every project"]].concat(list(facets.projects).map(function (name) { return [str(name), str(name)]; }));
    add(form, select("agent", agents, str(params.get("agent"))), select("project", projects, str(params.get("project"))),
        select("kind", [["session", "Sessions"], ["sub-agent", "Sub-agents"]], str(params.get("kind")) || "session"),
        select("outcome", OUTCOMES, str(params.get("outcome"))));
    ["from", "to"].forEach(function (name) {
      var input = el("input", "ai-select");
      input.type = "date"; input.name = name; input.value = str(params.get(name)); input.setAttribute("aria-label", name === "from" ? "Ended on or after" : "Ended on or before");
      add(form, input);
    });
    form.addEventListener("change", function () {
      var chosen = {};
      Array.prototype.forEach.call(form.elements, function (field) { chosen[field.name] = field.value; });
      location.hash = V.href("history", chosen);
    });
    form.addEventListener("submit", function (event) { event.preventDefault(); });
    return form;
  }
  pages.history = function (params, target, setTitle) {
    setTitle("History", "Agents");
    var query = new URLSearchParams();
    ["agent", "project", "kind", "outcome"].forEach(function (name) { if (params.get(name)) query.set(name, params.get(name)); });
    if (day(params.get("from"), false)) query.set("since", String(day(params.get("from"), false)));
    if (day(params.get("to"), true)) query.set("until", String(day(params.get("to"), true)));
    query.set("limit", String(HISTORY_PAGE));
    var rows = el("div", "ai-body"), more = el("button", "ai-more", "Show older");
    more.type = "button"; more.hidden = true;
    var before = "", drawn = false;
    function load() {
      more.disabled = true;
      V.getJSON("/api/agent-instances/history?" + query.toString() + (before ? "&before=" + encodeURIComponent(before) : "")).then(function (page) {
        page = obj(page);
        if (!drawn) { drawn = true; target.replaceChildren(historyForm(params, obj(page.facets)), rows, more); }
        list(page.instances).forEach(function (row) {
          add(rows, add(V.instanceRow(row, 0), el("div", "ai-last", "Ended " + when(obj(row).ended) + (obj(row).folder ? " · " + obj(row).folder : ""))));
        });
        if (!rows.childNodes.length) add(rows, el("div", "ai-empty", "No ended instance matches these filters."));
        before = page.more ? str(page.next_before) : "";
        more.hidden = !page.more;
        more.disabled = false;
      }).catch(function (error) { failed(target, error); });
    }
    more.addEventListener("click", load);
    load();
  };

  // ---------- the window and the router ----------
  function build() {
    overlay = el("div", "wev-overlay ai-view");
    overlay.hidden = true;
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.setAttribute("aria-labelledby", "agent-page-title");
    var kicker = el("div", "wev-kicker", "Agents");
    titleNode = el("h2", "", "Agents");
    titleNode.id = "agent-page-title";
    var close = el("button", "wev-close", "✕");
    close.type = "button";
    close.setAttribute("aria-label", "Close");
    close.addEventListener("click", function () { history.replaceState(null, "", location.pathname + location.search); route(); });
    var nav = add(el("nav", "ai-links"), link(V.href("history", {}), "History"), link(V.href("profiles", {}), "Profiles"),
                  link("/docs#agents", "What Blackbox protects"));
    add(overlay, add(el("div", "wev-head"), add(el("div"), kicker, titleNode, nav), close));
    body = el("div", "ai-page");
    add(overlay, body);
    overlay.kicker = kicker;
    document.body.appendChild(overlay);
    document.addEventListener("keydown", function (event) { if (event.key === "Escape" && !overlay.hidden) close.click(); });
  }
  function route() {
    var match = /^#agents\/([a-z-]+)(?:\?(.*))?$/.exec(location.hash || "");
    var page = match && pages[match[1]];
    if (!page) {
      if (overlay && !overlay.hidden) { overlay.hidden = true; document.body.style.overflow = ""; }
      return;
    }
    if (!overlay) build();
    body.replaceChildren(el("div", "ai-empty", "Loading…"));
    var target = el("div");
    page(new URLSearchParams(match[2] || ""), target, function (heading, kicker) {
      titleNode.textContent = heading;
      overlay.kicker.textContent = kicker || "Agents";
    });
    body.replaceChildren(target);
    overlay.hidden = false;
    overlay.scrollTop = 0;
    document.body.style.overflow = "hidden";
  }
  V.route = route;
  global.addEventListener("hashchange", route);
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", route);
  else route();
})(window);
