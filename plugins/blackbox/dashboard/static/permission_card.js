/*
 * The sandbox permissions card — ONE drawing of File Shield's `permissions` read, used by File
 * Shield's page and by the Security page (served at /permission-card.js).
 *
 * Every permission is explained right where it is set: what the agent may do when it is allowed
 * (`unlocks`), what it meets while blocked (`when_blocked`), what can go wrong if you relax it
 * (`cost`), the strict default, and when a change applies. A change goes through File Shield's
 * own endpoints, so a loosening waits for the person (the approval gate's 428; approvals.js asks
 * and sends it again once confirmed — still held, the card says it waits for your approval).
 *
 * Usage:
 *   var card = BlackboxPermissionCard.mount({
 *     api: "../../api/shields/file-shield/api/",          // File Shield's endpoints
 *     getJSON: function (url) { ... },                      // -> Promise of the answer
 *     post: function (name, body) { ... },                  // -> Promise of the Response
 *     hosts: { list, restart, rules, never, note, scope },  // element ids; scope is optional
 *   });
 *   card.read();
 * With a `scope` host the person picks one agent and/or one project; each control then sets the
 * rule for that scope, and "Use the wider setting" removes it. All text is set with textContent.
 */
(function (root) {
  "use strict";
  var MODE_WORDS = { block: "Block", ask: "Ask", allow: "Allow" };
  var HELD = 428;

  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }

  function mount(options) {
    var hosts = options.hosts;
    var scope = { agent: "", project: "" };
    function $(name) { return hosts[name] ? document.getElementById(hosts[name]) : null; }
    function say(text) { var note = $("note"); if (note) note.textContent = text; }
    function scoped(body) {
      var out = {}; Object.keys(body).forEach(function (key) { out[key] = body[key]; });
      if (scope.agent) out.agent = scope.agent;
      if (scope.project) out.project = scope.project;
      return out;
    }
    function query() {
      var parts = [];
      if (scope.agent) parts.push("agent=" + encodeURIComponent(scope.agent));
      if (scope.project) parts.push("project=" + encodeURIComponent(scope.project));
      return parts.length ? "?" + parts.join("&") : "";
    }
    function read() {
      return options.getJSON(options.api + "permissions" + query()).then(draw)
        .catch(function () { say("The permissions could not be read for this agent or folder."); });
    }
    function change(name, body) {
      say("Saving…");
      return options.post(name, body).then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (answer) {
          if (r.ok) { say("Saved."); return scope.agent || scope.project ? read() : draw(answer); }
          if (r.status === HELD) {
            say("Waiting for your approval: " + ((answer.approval && answer.approval.reasons) || answer.errors || []).join(" ") +
                " Nothing changes until you confirm.");
            return null;
          }
          say(String((answer && (answer.error || answer.detail || (answer.errors || []).join(" "))) || "Not changed."));
          return null;
        });
      }).catch(function () { say("Not changed."); });
    }
    function scopeWords(row) { return (row.agent || "every agent") + (row.project ? " in " + row.project : ""); }

    function explained(permission) {
      var box = el("div", "permission-why");
      [["While blocked", permission.when_blocked], ["If you relax it", permission.cost],
       ["Strict default", MODE_WORDS[permission.default] || permission.default], ["When it applies", permission.applies_line]]
        .forEach(function (pair) {
          if (!pair[1]) return;
          var line = el("div", "muted"); line.appendChild(el("b", null, pair[0] + ": ")); line.appendChild(document.createTextNode(String(pair[1])));
          box.appendChild(line);
        });
      return box;
    }

    function drawOne(host, permission, view) {
      var line = el("div", "row permission"), left = el("div");
      left.appendChild(el("div", "item", String(permission.name)));
      left.appendChild(el("div", "muted", String(permission.unlocks)));
      left.appendChild(explained(permission));
      line.appendChild(left);
      if (!permission.controllable) {
        line.appendChild(el("span", "tag", "not controllable yet"));
        if (permission.note) left.appendChild(el("div", "muted", String(permission.note)));
        host.appendChild(line); return;
      }
      var controls = el("div", "modes");
      (permission.modes || []).forEach(function (mode) {
        var button = el("button", mode === permission.mode ? "primary" : null, MODE_WORDS[mode] || mode);
        button.setAttribute("aria-pressed", mode === permission.mode ? "true" : "false");
        button.addEventListener("click", function () { change("permission-set", scoped({ permission: permission.id, mode: mode })); });
        controls.appendChild(button);
      });
      if (permission.set_here && (scope.agent || scope.project)) {
        var wider = el("button", null, "Use the wider setting");
        wider.addEventListener("click", function () { change("permission-clear", scoped({ permission: permission.id })); });
        controls.appendChild(wider);
      }
      controls.appendChild(el("span", "tag", permission.applies === "now" ? "now" : "after restart"));
      line.appendChild(controls);
      host.appendChild(line);
    }

    function drawRules(view) {
      var rules = $("rules"); if (!rules) return;
      rules.textContent = "";
      var names = {}; (view.permissions || []).forEach(function (p) { names[p.id] = p.name; });
      (view.rules || []).filter(function (row) { return row.agent || row.project; }).forEach(function (row) {
        var line = el("div", "row");
        line.appendChild(el("span", null, (names[row.permission] || row.permission) + " · " + (MODE_WORDS[row.mode] || row.mode) + " · " + scopeWords(row)));
        var remove = el("button", null, "Remove");
        remove.addEventListener("click", function () { change("permission-clear", { permission: row.permission, agent: row.agent || "", project: row.project || "" }); });
        line.appendChild(remove); rules.appendChild(line);
      });
      (view.folders || []).forEach(function (row) {
        var line = el("div", "row");
        line.appendChild(el("span", null, row.path + " · " + (row.access === "read" ? "read only" : "kept out") + " · " + scopeWords(row)));
        var remove = el("button", null, "Remove");
        remove.addEventListener("click", function () { change("folder-clear", { path: row.path, agent: row.agent || "", project: row.project || "" }); });
        line.appendChild(remove); rules.appendChild(line);
      });
      rules.className = rules.children.length ? "" : "muted";
      if (!rules.children.length) rules.textContent = "No exceptions: every agent follows the list above.";
    }

    function drawRestart(view) {
      var restart = $("restart"); if (!restart) return;
      restart.textContent = "";
      (view.restart_needed || []).forEach(function (run) {
        var line = el("div", "row");
        line.appendChild(el("span", "tag", "restart needed"));
        line.appendChild(el("span", null, String(run.name) + " " + String(run.note)));
        var stop = el("button", null, "Stop it");
        stop.addEventListener("click", function () { change("stop-agent", { instance: run.instance }); });
        line.appendChild(stop); restart.appendChild(line);
      });
    }

    function drawNever(view) {
      var never = $("never"); if (!never) return;
      never.textContent = "";
      (view.never || []).concat(view.not_controllable || []).forEach(function (row) {
        var li = el("li"); li.appendChild(el("b", null, String(row.name))); li.appendChild(document.createTextNode(" — " + String(row.why))); never.appendChild(li);
      });
    }

    function drawScope(view) {
      var host = $("scope"); if (!host || host.children.length) return;
      var who = el("select", "scope-agent"); who.setAttribute("aria-label", "Which agent");
      var everyone = el("option", null, "Every agent"); everyone.value = ""; who.appendChild(everyone);
      (view.scope_agents || []).forEach(function (agent) {
        var option = el("option", null, agent.name + (agent.sandboxed ? " (in the sandbox)" : "")); option.value = agent.id; who.appendChild(option);
      });
      var where = el("input", "scope-project"); where.setAttribute("aria-label", "Project folder (optional)");
      where.setAttribute("placeholder", "every folder, or ~/work/shop"); where.setAttribute("autocomplete", "off");
      var show = el("button", null, "Show");
      function pick() { scope = { agent: who.value || "", project: String(where.value || "").trim() }; read(); }
      who.addEventListener("change", pick); show.addEventListener("click", pick);
      host.appendChild(who); host.appendChild(where); host.appendChild(show);
    }

    function draw(view) {
      if (!view) return null;
      drawScope(view);
      var host = $("list"); host.textContent = ""; host.className = "";
      if (view.scope && view.scope.words && (scope.agent || scope.project)) host.appendChild(el("p", "muted", "Showing what " + view.scope.words + " may do."));
      if (view.sandbox_unavailable) host.appendChild(el("p", "muted", String(view.sandbox_unavailable)));
      (view.permissions || []).forEach(function (permission) { drawOne(host, permission, view); });
      if (view.loosening_note) host.appendChild(el("p", "muted", String(view.loosening_note)));
      drawRules(view); drawRestart(view); drawNever(view);
      return view;
    }

    return { read: read, draw: draw };
  }

  root.BlackboxPermissionCard = { mount: mount, MODE_WORDS: MODE_WORDS };
})(typeof window !== "undefined" ? window : this);
