/*
 * The agent profiles pages, drawn by agent_pages.js's window:
 *
 *   #agents/profiles                          GET /api/agent-instances/profiles
 *       every config home of every agent: hooked or not, and what keeps the hooks from running
 *   #agents/profile?agent=&home=&project=     GET /api/agent-instances/profile (+ the profiles row)
 *       what that profile operates under, read by the core from the real files: the program and
 *       its signer, the instruction files in effect with their text AS SERVED (redacted by the
 *       core), the settings per scope (permission mode, allow / deny, model, environment names),
 *       the hooks, the MCP servers, definitions, risk notes, and the hooks-off / hook-invalid
 *       problems. An empty *home* means the agent's default config home.
 *
 * Views only: nothing here derives a fact. Text is set with textContent (an instruction file's
 * text is shown inside <pre>, never as markup).
 */
(function (global) {
  "use strict";

  var V = global.BlackboxAgentViews;
  if (!V || !V.pages) return;
  var el = V.el, add = V.add, str = V.str, list = V.list, obj = V.obj, link = V.link, when = V.when;
  var PROBLEM_WORDS = { "hooks-off": "Hooks switched off", "managed-only": "Only managed hooks run", "hooks-missing": "Blackbox's hooks are missing",
                        "hook-invalid": "A hook the agent will not run", unreadable: "A config file Blackbox could not read" };

  function yes(value) { return value ? "yes" : "no"; }
  function names(values) { return list(values).map(str).join(", "); }
  function problemList(problems) {
    var holder = el("div", "ai-body");
    list(problems).forEach(function (problem) {
      problem = obj(problem);
      add(holder, add(el("div", "ai-row"), add(el("div", "ai-row-head"), el("span", "ai-chip ai-unprotected", PROBLEM_WORDS[problem.kind] || str(problem.kind))),
                      el("div", "ai-facts", str(problem.file)), el("div", "ai-last", str(problem.detail))));
    });
    return holder;
  }
  function profileHref(row) { return V.href("profile", { agent: row.agent, home: row.home }); }

  V.pages.profiles = function (_params, target, setTitle) {
    setTitle("Profiles", "Agents");
    V.getJSON("/api/agent-instances/profiles").then(function (answer) {
      var rows = list(obj(answer).profiles).map(obj), parts = V.table(["Agent", "Config home", "Hooks", "Problems", ""]);
      rows.forEach(function (row) {
        var problems = list(row.problems).map(function (problem) { return PROBLEM_WORDS[obj(problem).kind] || str(obj(problem).kind); });
        var line = el("tr", problems.length ? "ai-late" : "");
        add(line, el("td", "", str(row.agent)), el("td", "", str(row.home) + (row["default"] ? " (default)" : "")),
            el("td", "", row.hooked ? "Blackbox's hooks in" : "not hooked"), el("td", "", problems.join(", ") || "none"),
            add(el("td"), link(profileHref(row), "Open")));
        add(parts[1], line);
      });
      target.replaceChildren(rows.length ? add(el("div", "table-scroll"), parts[0]) : el("div", "ai-empty", "No coding agent's config home was found on this machine."));
    }).catch(function (error) { V.failed(target, error); });
  };

  function settingsSection(scopes) {
    var holder = V.section("Settings, by scope");
    list(scopes).forEach(function (scope) {
      scope = obj(scope);
      var grid = el("div", "wev-facts");
      V.fact(grid, "Scope", str(scope.scope));
      V.fact(grid, "File", str(scope.path), true);
      V.fact(grid, "Permission mode", str(scope.permission_mode) || "the agent's default");
      V.fact(grid, "Allowed", names(scope.allowed), true);
      V.fact(grid, "Denied", names(scope.denied), true);
      V.fact(grid, "Model", str(scope.model));
      V.fact(grid, "Environment names", names(scope.env_names), true);
      V.fact(grid, "Skips permission prompts", names(scope.skips_prompts));
      add(holder, grid);
    });
    if (!list(scopes).length) add(holder, el("div", "ai-empty", "No settings file in effect."));
    return holder;
  }
  function hooksSection(scopes, problems) {
    var holder = V.section("Hooks"), parts = V.table(["Scope", "File", "Blackbox's hooks", "Other hooks", "Hooks off", "Will not run"]);
    list(scopes).forEach(function (scope) {
      scope = obj(scope);
      add(parts[1], add(el("tr", scope.hooks_off || list(scope.unloadable).length ? "ai-late" : ""), el("td", "", str(scope.scope)), el("td", "", str(scope.path)),
                        el("td", "", String(Number(scope.blackbox_hooks) || 0)), el("td", "", String(Number(scope.other_hooks) || 0)),
                        el("td", "", yes(scope.hooks_off)), el("td", "", list(scope.unloadable).map(str).join("; "))));
    });
    add(holder, add(el("div", "table-scroll"), parts[0]));
    if (list(problems).length) add(holder, el("h4", "ai-subhead", "Problems"), problemList(problems));
    return holder;
  }
  function instructionsSection(files) {
    var holder = V.section("Instruction files in effect");
    list(files).forEach(function (file) {
      file = obj(file);
      var details = el("details", "ai-file");
      add(details, el("summary", "", str(file.path) + " · " + str(file.scope) + " · " + (Number(file.size) || 0) + " bytes · changed " + when(file.modified)));
      add(details, file.text ? el("pre", "ai-pre", str(file.text)) : el("div", "ai-empty", "Too large or unreadable — not shown."));
      if (file.truncated) add(details, el("div", "ai-head-note", "Shown up to the size the core serves; the rest is cut."));
      add(holder, details);
    });
    if (!list(files).length) add(holder, el("div", "ai-empty", "No instruction file is in effect."));
    return holder;
  }
  function programGrid(detail, problemsRow) {
    var grid = el("div", "wev-facts"), signer = obj(detail.signer);
    V.fact(grid, "Agent", str(detail.name) || str(detail.agent));
    V.fact(grid, "Config home", str(detail.home), true);
    V.fact(grid, "Project", str(detail.project), true);
    V.fact(grid, "Hooks", problemsRow ? (problemsRow.hooked ? "Blackbox's hooks in" : "not hooked") : "");
    V.fact(grid, "Program", [str(detail.program), str(detail.version)].filter(Boolean).join(" — "), true);
    V.fact(grid, "Signer", str(detail.signature));
    if (signer.kind) V.fact(grid, "Signature", [str(signer.kind), str(signer.signer), str(signer.team) ? "team " + signer.team : "",
                                                 signer.verified === true ? "verified" : signer.verified === false ? "does not verify" : "not checked",
                                                 signer.notarised ? "notarised" : ""].filter(Boolean).join(" · "));
    V.fact(grid, "Sessions kept in", str(detail.sessions_path) + (detail.sessions_path && !detail.sessions_exist ? " (none yet)" : ""), true);
    V.fact(grid, "Running with", names(detail.running_flags));
    return grid;
  }

  var SIGNATURE_RECHECK_MS = 4000;
  V.pages.profile = function (params, target, setTitle) {
    var agent = str(params.get("agent")), home = str(params.get("home")), project = str(params.get("project"));
    V.getJSON("/api/agent-instances/profiles").then(function (answer) {
      var rows = list(obj(answer).profiles).map(obj);
      // An empty home is the agent's default config home (an instance records "" for it).
      var row = rows.filter(function (item) { return item.agent === agent && (home ? item.home === home : item["default"]); })[0] || null;
      var query = "agent=" + encodeURIComponent(agent) + "&home=" + encodeURIComponent(row ? row.home : home) + (project ? "&project=" + encodeURIComponent(project) : "");
      return V.getJSON("/api/agent-instances/profile?" + query).then(function (detail) {
        detail = obj(detail);
        setTitle("Profile", str(detail.name) || agent);
        var risks = V.section("Risk notes");
        list(detail.risks).forEach(function (risk) { add(risks, el("div", "ai-warn", str(risk))); });
        if (!list(detail.risks).length) add(risks, el("div", "ai-empty", "None found in this profile's files."));
        var mcp = V.section("MCP servers"), parts = V.table(["Name", "Configured in", "Starts"]);
        list(detail.mcp_servers).forEach(function (server) {
          server = obj(server);
          add(parts[1], add(el("tr"), el("td", "", str(server.name)), el("td", "", str(server.source)), el("td", "", str(server.launch))));
        });
        add(mcp, list(detail.mcp_servers).length ? add(el("div", "table-scroll"), parts[0]) : el("div", "ai-empty", "No MCP server configured."));
        var defs = V.section("Definitions (agents, commands, skills)");
        add(defs, list(detail.definitions).length ? el("div", "ai-facts", names(detail.definitions)) : el("div", "ai-empty", "None."));
        target.replaceChildren(add(V.section("This profile"), programGrid(detail, row)), risks, hooksSection(detail.settings, row && row.problems),
                               settingsSection(detail.settings), instructionsSection(detail.instructions), mcp, defs);
        // KI-584: the signature is checked in the background; read the page again once it is known.
        if (detail.signature_pending && !params.get("rechecked")) {
          setTimeout(function () {
            var again = new URLSearchParams(params.toString());
            again.set("rechecked", "1");
            V.pages.profile(again, target, setTitle);
          }, SIGNATURE_RECHECK_MS);
        }
      });
    }).catch(function (error) { V.failed(target, error); });
  };
})(window);
