/* Docs: "What Blackbox protects" — one card per coding agent, drawn from GET /api/docs/agents
   (the platform map and test registry, agent_registry.json). Text only reaches the page through
   textContent, so nothing in the data is ever read as HTML. */
(function () {
  "use strict";
  var WORDS = { "tested": "Tested", "covered-untested": "Built, not yet run in the product", "not-covered": "Not covered" };
  var LAYER_NAMES = { hooks: "Hooks", sandbox: "Sandbox", os: "OS-level" };
  var ORDER = ["tested", "covered-untested", "not-covered"];

  function el(tag, text, className) {
    var node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }

  function table(headers, rows) {
    var wrap = el("div", null, "table-wrap");
    var grid = el("table");
    var head = el("tr");
    headers.forEach(function (header) { head.appendChild(el("th", header)); });
    grid.appendChild(head);
    rows.forEach(function (cells) {
      var row = el("tr");
      cells.forEach(function (cell) { row.appendChild(el("td", cell)); });
      grid.appendChild(row);
    });
    wrap.appendChild(grid);
    return wrap;
  }

  function best(agent, layer) {
    var found = agent.coverage.filter(function (row) { return row.layer === layer; }).map(function (row) { return row.status; });
    found.sort(function (a, b) { return ORDER.indexOf(a) - ORDER.indexOf(b); });
    return found[0] || "not-covered";
  }

  function detail(row) {
    if (row.status !== "tested") return row.why || "";
    return row.date + ", Blackbox " + row.blackbox + (row.agent_version ? ", agent " + row.agent_version : ", agent version not recorded") +
      ": " + row.how + " — " + row.result;
  }

  function card(agent) {
    var box = el("details", null, "group");
    var summary = el("summary");
    summary.appendChild(el("b", agent.name));
    summary.appendChild(el("span", ["hooks", "sandbox", "os"].map(function (layer) {
      return LAYER_NAMES[layer] + ": " + WORDS[best(agent, layer)];
    }).join(" · "), "muted"));
    box.appendChild(summary);
    var body = el("div", null, "group-body");
    if (agent.installed) body.appendChild(el("p", "Installed here: " + (agent.installed.version || "version unknown") + " (" + agent.installed.path + ")"));
    if (agent.version_notice) body.appendChild(el("p", agent.version_notice, "notice"));
    body.appendChild(el("p", agent.processes));
    body.appendChild(el("h4", "Where it keeps its settings, and where Blackbox's hooks are"));
    body.appendChild(table(["Scope", "Where", "Blackbox's hooks there", "Note"], agent.scopes.map(function (row) {
      return [row.scope, row.where, row.hooked ? "yes" : "no", row.note || ""];
    })));
    body.appendChild(el("h4", "Ways it can be started"));
    body.appendChild(table(["Launch mode", "How", "Hooks run", "Note"], agent.launch_modes.map(function (row) {
      return [row.mode, row.how, row.hooks_run ? "yes" : "no", row.note || ""];
    })));
    body.appendChild(el("h4", "Sub-agents"));
    body.appendChild(el("p", agent.sub_agents));
    body.appendChild(el("h4", "What was tested"));
    body.appendChild(table(["OS", "Launch mode", "Layer", "Status", "Detail"], agent.coverage.map(function (row) {
      return [row.os, row.launch, LAYER_NAMES[row.layer], WORDS[row.status], detail(row)];
    })));
    body.appendChild(el("h4", "Not covered yet"));
    var list = el("ul");
    agent.not_covered.forEach(function (item) { list.appendChild(el("li", item)); });
    body.appendChild(list);
    box.appendChild(body);
    return box;
  }

  function draw(registry) {
    var root = document.getElementById("agent-cards");
    if (!root || !registry || !registry.agents) return;
    root.textContent = "";
    var layers = el("ul");
    ["hooks", "sandbox", "os"].forEach(function (layer) { layers.appendChild(el("li", registry.layers[layer])); });
    root.appendChild(layers);
    // What Blackbox keeps of a prompt: nothing but its length, unless the person turned recording on.
    if (registry.prompt_text) root.appendChild(el("p", registry.prompt_text + " Blackbox checks every prompt on this Mac; it keeps a prompt's text only if you turn that on in Settings."));
    registry.agents.forEach(function (agent) { root.appendChild(card(agent)); });
    root.appendChild(el("p", "Last updated " + registry.updated + " for Blackbox " + registry.blackbox + ".", "muted"));
  }

  fetch("/api/docs/agents", { cache: "no-store" }).then(function (answer) { return answer.json(); }).then(draw).catch(function () {
    var root = document.getElementById("agent-cards");
    if (root) root.textContent = "The agent list could not be read. Reload the page.";
  });
})();
