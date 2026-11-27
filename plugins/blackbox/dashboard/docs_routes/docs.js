/* Blackbox Docs — draws the page's diagrams and fills every product fact from GET /api/docs.
 *
 * Everything that comes from the product is written as text (textContent, never parsed as markup) and every
 * link is checked to be https, so a pack file can never inject markup into the dashboard.
 */
(function () {
  "use strict";

  var SVG_NS = "http://www.w3.org/2000/svg";
  var REDUCED_MOTION = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var STORE_ORDER = ["Chrome Web Store", "Firefox Add-ons", "Edge Add-ons", "Safari"];
  var STATE_TEXT = {
    "protected": "protected",
    "not-covered": "exists, not covered yet",
    "not-offered": "publisher does not offer it",
    "not-found": "no official listing found"
  };
  var STATE_MARK = { "protected": "✓", "not-covered": "!", "not-offered": "–", "not-found": "·" };
  var KIND_TEXT = { "browser-extension": "Browser extension", "desktop-app": "Desktop app", "cli-key-file": "Command-line key file" };
  var EMPTY_RETRY_MS = 1500;
  var EMPTY_RETRIES = 6;

  // ---- small DOM helpers -------------------------------------------------------------------
  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    setAttrs(node, attrs);
    append(node, children);
    return node;
  }
  function svg(tag, attrs, children) {
    var node = document.createElementNS(SVG_NS, tag);
    setAttrs(node, attrs);
    append(node, children);
    return node;
  }
  function setAttrs(node, attrs) {
    Object.keys(attrs || {}).forEach(function (key) {
      if (key === "text") node.textContent = attrs[key];
      else if (attrs[key] !== undefined && attrs[key] !== null) node.setAttribute(key, attrs[key]);
    });
  }
  function append(node, children) {
    (children || []).forEach(function (child) {
      if (child === null || child === undefined) return;
      node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
    });
  }
  function safeLink(url, label) {
    if (typeof url !== "string" || url.indexOf("https://") !== 0) return document.createTextNode(label || url || "");
    return el("a", { href: url, target: "_blank", rel: "noopener noreferrer", text: label || url });
  }
  function listText(names) {
    if (names.length < 2) return names.join("");
    return names.slice(0, -1).join(", ") + " and " + names[names.length - 1];
  }

  // ---- 1. The check pipeline ---------------------------------------------------------------
  var STEPS = [
    { title: "Action", text: "The agent decides to do something: run a shell command, read or write a file, install a package, fetch a web page or send a request to a model." },
    { title: "Intercept", text: "Blackbox's hook receives the action before the host runs it. Nothing has happened yet; the action can still be stopped." },
    { title: "Name", text: "The action is given a precise, deterministic name: a package becomes dep:npm:name@version, a command is broken into what it does and which files it touches." },
    { title: "Match", text: "That name is looked up in the threat rules from your own DKG node, and every shield you switched on checks it too. Lookups are dictionary-fast and need no network." },
    { title: "Decide", text: "Your mode, the finding's severity and its trust tier decide the outcome: blocked, flagged for you, or allowed. Only verified threats and your own shields can block." },
    { title: "Record", text: "The finding is written to Blackbox's redacted local log and shown on the dashboard. Secrets are removed before anything is written." }
  ];
  var PIPE = { left: 70, right: 910, y: 85, width: 112, height: 50 };

  function drawPipeline() {
    var root = document.getElementById("pipeline");
    var detail = document.getElementById("step-detail");
    if (!root) return;
    var gap = (PIPE.right - PIPE.left) / (STEPS.length - 1);
    var nodes = STEPS.map(function (step, index) {
      var x = PIPE.left + gap * index;
      var group = svg("g", { "class": "node", tabindex: "0", role: "button", "aria-label": step.title }, [
        svg("rect", { x: x - PIPE.width / 2, y: PIPE.y - PIPE.height / 2, width: PIPE.width, height: PIPE.height, rx: 3 }),
        svg("text", { "class": "num", x: x, y: PIPE.y - 6, text: "0" + (index + 1) }),
        svg("text", { x: x, y: PIPE.y + 12, text: step.title })
      ]);
      function select() { selectStep(index); }
      group.addEventListener("click", select);
      group.addEventListener("keydown", function (event) {
        if (event.key === "Enter" || event.key === " ") { event.preventDefault(); select(); }
      });
      root.appendChild(group);
      return { x: x, group: group };
    });
    var outcomes = [["blocked", "var(--signal)"], ["flagged", "var(--caution)"], ["allowed", "var(--secure)"]];
    var outcomeLabel = svg("text", { "class": "outcome-label", x: PIPE.right, y: PIPE.y + 52, "text-anchor": "middle" });
    root.appendChild(outcomeLabel);
    var packet = root.querySelector(".packet");
    root.appendChild(packet);   // keep the packet drawn above the boxes

    function selectStep(index) {
      nodes.forEach(function (node, i) { node.group.classList.toggle("selected", i === index); });
      detail.textContent = "";
      append(detail, [el("h3", { text: "0" + (index + 1) + " · " + STEPS[index].title }), el("p", { text: STEPS[index].text })]);
      detail.classList.remove("fade-in"); void detail.offsetWidth; detail.classList.add("fade-in");
    }
    selectStep(0);

    if (REDUCED_MOTION) { packet.setAttribute("cx", PIPE.right); outcomeLabel.textContent = "BLOCKED · FLAGGED · ALLOWED"; outcomeLabel.setAttribute("fill", "var(--muted)"); return; }
    var trip = 0;
    var duration = 4200;
    var start = null;
    function frame(now) {
      if (start === null) start = now;
      var progress = Math.min((now - start) / duration, 1);
      var x = PIPE.left + (PIPE.right - PIPE.left) * progress;
      packet.setAttribute("cx", x.toFixed(1));
      nodes.forEach(function (node) { node.group.classList.toggle("lit", Math.abs(node.x - x) < PIPE.width / 2); });
      var outcome = outcomes[trip % outcomes.length];
      if (progress > 0.82) {
        outcomeLabel.textContent = outcome[0].toUpperCase();
        outcomeLabel.setAttribute("fill", outcome[1]);
        packet.style.fill = outcome[1];
      } else {
        outcomeLabel.textContent = "";
        packet.style.fill = "";
      }
      if (progress >= 1 && now - start > duration + 900) { start = null; trip += 1; }
      window.requestAnimationFrame(frame);
    }
    window.requestAnimationFrame(frame);
  }

  // ---- 2. The four flows -------------------------------------------------------------------
  // Each flow: boxes {id, x, y, label, small} and wires [from, to]; positions in a 640×220 box.
  var FLOWS = {
    sync: {
      title: "Sync down — staying informed",
      text: "Your DKG node keeps a copy of Umanitek's verified threat graph current. Blackbox then reads it into fast lookup tables, so every check after that is local and offline.",
      steps: ["The node receives new verified threats from the network.", "blackbox sync pages them out of the node.", "They are compiled into lookup tables on disk."],
      boxes: [
        { id: "net", x: 90, y: 60, label: "DKG network", small: "verified graph" },
        { id: "node", x: 320, y: 60, label: "Your DKG node", small: "127.0.0.1:9320" },
        { id: "rules", x: 550, y: 60, label: "Threat rules", small: "on this machine" },
        { id: "check", x: 550, y: 165, label: "Every check", small: "reads the rules" }
      ],
      wires: [["net", "node"], ["node", "rules"], ["rules", "check"]]
    },
    check: {
      title: "Check — protecting you in the moment",
      text: "Every tool call and model request passes through Blackbox before it runs. It is named, matched against the rules and your shields, and blocked, flagged or allowed.",
      steps: ["The agent's action is intercepted.", "Detectors name it and match it.", "The decision goes back to the host before anything runs."],
      boxes: [
        { id: "agent", x: 90, y: 60, label: "Your agent", small: "about to act" },
        { id: "guard", x: 320, y: 60, label: "Blackbox guard", small: "pre-execution" },
        { id: "rules", x: 320, y: 165, label: "Rules + shields", small: "local, offline" },
        { id: "host", x: 550, y: 60, label: "Host", small: "runs it, or not" }
      ],
      wires: [["agent", "guard"], ["guard", "rules"], ["rules", "guard"], ["guard", "host"]]
    },
    record: {
      title: "Record — remembering what happened",
      text: "Each finding is written to a redacted, size-capped log under ~/.hermes/blackbox/ and shown on this dashboard. Secrets are removed before the write.",
      steps: ["A finding is produced.", "Secrets are redacted.", "It lands in the local log and on the dashboard."],
      boxes: [
        { id: "finding", x: 90, y: 110, label: "Finding", small: "what, how serious" },
        { id: "redact", x: 320, y: 110, label: "Redaction", small: "secrets removed" },
        { id: "log", x: 550, y: 60, label: "Local log", small: "~/.hermes/blackbox" },
        { id: "dash", x: 550, y: 165, label: "Dashboard", small: "127.0.0.1:9700" }
      ],
      wires: [["finding", "redact"], ["redact", "log"], ["redact", "dash"]]
    },
    report: {
      title: "Report up — only if you choose",
      text: "With sharing turned on, Blackbox can tell the community graph which threat it saw and how severe it was — never your commands, prompts or shield findings. It is off until you switch it on.",
      steps: ["A shareable finding (a known threat, not a secret).", "The sharing gate checks your consent, limits and what may leave.", "A privacy-safe report goes to the community graph."],
      boxes: [
        { id: "finding", x: 90, y: 110, label: "Finding", small: "known threat only" },
        { id: "gate", x: 320, y: 110, label: "Sharing gate", small: "your consent" },
        { id: "community", x: 550, y: 110, label: "Community graph", small: "flag-only reports" }
      ],
      wires: [["finding", "gate"], ["gate", "community"]]
    }
  };
  var BOX = { width: 150, height: 52 };

  function wirePath(from, to) {
    if (from.y === to.y) {
      var dir = to.x > from.x ? 1 : -1;
      return "M" + (from.x + dir * BOX.width / 2) + " " + from.y + " H" + (to.x - dir * BOX.width / 2);
    }
    if (from.x === to.x) {
      var down = to.y > from.y ? 1 : -1;
      var offset = from.id + to.id < to.id + from.id ? -16 : 16;   // two wires between one pair sit side by side
      return "M" + (from.x + offset) + " " + (from.y + down * BOX.height / 2) + " V" + (to.y - down * BOX.height / 2);
    }
    var startX = from.x + BOX.width / 2;
    var endX = to.x - BOX.width / 2;
    var midX = (startX + endX) / 2;
    return "M" + startX + " " + from.y + " C" + midX + " " + from.y + " " + midX + " " + to.y + " " + endX + " " + to.y;
  }

  function drawFlow(name) {
    var flow = FLOWS[name];
    var root = document.getElementById("flow-diagram");
    var text = document.getElementById("flow-text");
    root.textContent = "";
    var byId = {};
    flow.boxes.forEach(function (box) { byId[box.id] = box; });
    flow.wires.forEach(function (wire, index) {
      var path = wirePath(byId[wire[0]], byId[wire[1]]);
      root.appendChild(svg("path", { "class": "wire live", d: path, id: "wire-" + name + "-" + index }));
      if (!REDUCED_MOTION) {
        var dot = svg("circle", { "class": "dotmove", r: 4 });
        dot.appendChild(svg("animateMotion", { dur: "1.8s", repeatCount: "indefinite", begin: (index * 0.6) + "s", path: path }));
        root.appendChild(dot);
      }
    });
    flow.boxes.forEach(function (box, index) {
      root.appendChild(svg("g", { "class": "box" + (index === 0 ? " hot" : "") }, [
        svg("rect", { x: box.x - BOX.width / 2, y: box.y - BOX.height / 2, width: BOX.width, height: BOX.height, rx: 3 }),
        svg("text", { x: box.x, y: box.y - 3, text: box.label }),
        svg("text", { "class": "small", x: box.x, y: box.y + 14, text: box.small })
      ]));
    });
    text.textContent = "";
    append(text, [el("h3", { text: flow.title }), el("p", { text: flow.text }),
                  el("ol", {}, flow.steps.map(function (step) { return el("li", { text: step }); }))]);
    text.classList.remove("fade-in"); void text.offsetWidth; text.classList.add("fade-in");
  }

  function wireFlowTabs() {
    var tabs = Array.prototype.slice.call(document.querySelectorAll(".flow-tabs [role=tab]"));
    tabs.forEach(function (tab) {
      tab.addEventListener("click", function () {
        tabs.forEach(function (other) { other.setAttribute("aria-selected", other === tab ? "true" : "false"); });
        drawFlow(tab.getAttribute("data-flow"));
      });
    });
    drawFlow("sync");
  }

  // ---- 3. Product facts from /api/docs ------------------------------------------------------
  function countUp(node, target) {
    if (REDUCED_MOTION || target < 2) { node.textContent = String(target); return; }
    var start = null;
    function frame(now) {
      if (start === null) start = now;
      var progress = Math.min((now - start) / 900, 1);
      node.textContent = String(Math.round(target * (1 - Math.pow(1 - progress, 3))));
      if (progress < 1) window.requestAnimationFrame(frame);
    }
    window.requestAnimationFrame(frame);
  }

  function supportedPacks(shield) { return shield.packs.filter(function (pack) { return pack.status === "supported"; }); }

  function renderStats(payload) {
    var packs = 0, attacks = 0, browsers = 0;
    payload.shields.forEach(function (shield) {
      packs += supportedPacks(shield).length;
      attacks += (shield.attacks.rows || []).length;
      browsers += shield.browsers.length;
    });
    countUp(document.getElementById("stat-shields"), payload.shields.length);
    document.getElementById("stat-shields-label").textContent = payload.shields.length === 1 ? "shield" : "shields";
    countUp(document.getElementById("stat-wallets"), packs);
    countUp(document.getElementById("stat-attacks"), attacks);
    countUp(document.getElementById("stat-browsers"), browsers);
    document.getElementById("version").textContent = "version " + payload.version;
  }

  // The layers diagram: your agent, Blackbox's built-in protection around it, and every
  // registered shield as an arc of the outer ring (plus one dashed arc: room for the next).
  function drawLayers(shields) {
    var root = document.getElementById("layers");
    if (!root) return;
    root.textContent = "";
    var cx = 150, cy = 150;
    root.appendChild(svg("circle", { "class": "ring-outer", cx: cx, cy: cy, r: 128 }));
    var arcs = shields.length + 1;
    var span = 360 / arcs;
    for (var index = 0; index < arcs; index += 1) {
      var start = index * span - 90 + 4, end = (index + 1) * span - 90 - 4;
      var placeholder = index === shields.length;
      root.appendChild(svg("path", { "class": placeholder ? "arc arc-next" : "arc", d: arcPath(cx, cy, 128, start, end) }));
    }
    root.appendChild(svg("circle", { "class": "ring-core", cx: cx, cy: cy, r: 88 }));
    root.appendChild(svg("circle", { "class": "ring-agent", cx: cx, cy: cy, r: 44 }));
    root.appendChild(svg("text", { "class": "ring-label", x: cx, y: cy + 4, text: "Your agent" }));
    root.appendChild(svg("text", { "class": "ring-label small", x: cx, y: cy - 58, text: "BLACKBOX" }));
    root.appendChild(svg("text", { "class": "ring-label small", x: cx, y: cy - 44, text: "built-in protection" }));
    var legendY = 70;
    shields.forEach(function (shield) {
      root.appendChild(svg("rect", { "class": "legend-swatch", x: 310, y: legendY - 10, width: 14, height: 14, rx: 2 }));
      root.appendChild(svg("text", { "class": "legend-text", x: 332, y: legendY + 2, text: shield.name }));
      legendY += 28;
    });
    root.appendChild(svg("rect", { "class": "legend-swatch next", x: 310, y: legendY - 10, width: 14, height: 14, rx: 2 }));
    root.appendChild(svg("text", { "class": "legend-text muted", x: 332, y: legendY + 2, text: "room for more shields" }));
  }

  function arcPath(cx, cy, radius, startDeg, endDeg) {
    function point(deg) {
      var rad = deg * Math.PI / 180;
      return (cx + radius * Math.cos(rad)).toFixed(1) + " " + (cy + radius * Math.sin(rad)).toFixed(1);
    }
    return "M" + point(startDeg) + " A" + radius + " " + radius + " 0 " + (endDeg - startDeg > 180 ? 1 : 0) + " 1 " + point(endDeg);
  }

  function shieldIcon() {
    return svg("svg", { "class": "shield-ok", viewBox: "0 0 24 24", "aria-hidden": "true" }, [
      svg("path", { d: "M12 2l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V5z", fill: "currentColor", opacity: "0.18" }),
      svg("path", { d: "M8 12l3 3 5-6", fill: "none", stroke: "currentColor", "stroke-width": "2", "stroke-linecap": "round", "stroke-linejoin": "round" })
    ]);
  }

  function packLogo(pack, size) {
    return pack.logo ? el("img", { src: pack.logo, alt: "", width: String(size), height: String(size), loading: "lazy" })
                     : el("span", { "class": "mono-logo", "aria-hidden": "true", text: pack.name.charAt(0) });
  }

  function packCard(pack) {
    var body = el("div", { "class": "wallet-body", hidden: "" });
    Object.keys(pack.stores).forEach(function (engine) {
      body.appendChild(el("div", {}, [engine === "firefox" ? "Firefox id: " : "Chromium store ids: "].concat(
        pack.stores[engine].map(function (id) { return el("code", { text: id }); }))));
    });
    if (pack.places.length) {
      body.appendChild(el("div", {}, ["Folders guarded: "].concat(pack.places.map(function (place) { return el("code", { text: place }); }))));
    }
    body.appendChild(el("div", { text: "Checked " + pack.verified + " · " + pack.source }));
    var chips = pack.availability.length ? el("div", { "class": "chips" }, pack.availability
      .filter(function (entry) { return entry.state === "protected"; })
      .map(function (entry) { return el("span", { "class": "chip protected", text: entry.store }); })) : null;
    var card = el("button", { "class": "wallet", type: "button", "aria-expanded": "false" }, [
      el("div", { "class": "wallet-head" }, [packLogo(pack, 32), el("div", {}, [
        el("div", { "class": "wallet-name", text: pack.name }),
        el("div", { "class": "wallet-kind", text: pack.label || KIND_TEXT[pack.kind] || pack.kind })
      ]), shieldIcon()]),
      chips, body
    ]);
    card.addEventListener("click", function () {
      var open = card.getAttribute("aria-expanded") === "true";
      card.setAttribute("aria-expanded", open ? "false" : "true");
      body.hidden = open;
    });
    return card;
  }

  function availabilityByStore(pack) {
    var byStore = {};
    pack.availability.forEach(function (entry) { byStore[entry.store] = entry; });
    return byStore;
  }

  function matrixTable(packs) {
    var head = el("thead", {}, [el("tr", {}, [el("th", { scope: "col", text: "Name" })].concat(STORE_ORDER.map(function (store) {
      return el("th", { scope: "col", text: store });
    })))]);
    var body = el("tbody", {}, packs.map(function (pack) {
      var byStore = availabilityByStore(pack);
      return el("tr", {}, [el("th", { scope: "row" }, [el("span", { "class": "row-name" }, [packLogo(pack, 20), pack.name])])].concat(STORE_ORDER.map(function (store) {
        var entry = byStore[store];
        if (!entry) return el("td", { text: "" });
        var label = STATE_TEXT[entry.state] || entry.state;
        var hint = store + ": " + label + (entry.note ? " — " + entry.note : "") +
                   (entry.state === "protected" && entry.browsers ? " (" + entry.browsers.join(", ") + ")" : "");
        return el("td", {}, [el("span", { "class": "cell " + entry.state, title: hint, "aria-label": hint, text: STATE_MARK[entry.state] || "?" })]);
      })));
    }));
    return el("table", { "class": "matrix" }, [el("caption", { "class": "sr", text: "Support by store" }), head, body]);
  }

  function unsupportedItems(packs, shield) {
    var items = [];
    STORE_ORDER.forEach(function (store) {
      var byState = {};
      packs.forEach(function (pack) {
        var entry = availabilityByStore(pack)[store];
        if (entry && entry.state !== "protected") (byState[entry.state] = byState[entry.state] || []).push(pack.name);
      });
      var states = Object.keys(byState);
      if (!states.length) return;
      var parts = states.map(function (state) { return listText(byState[state]) + ": " + STATE_TEXT[state]; });
      items.push(el("li", {}, [el("b", { text: store + " — " }), parts.join("; ") + "."]));
    });
    var notCovered = [];
    packs.forEach(function (pack) {
      pack.availability.forEach(function (entry) {
        if (entry.state === "not-covered") notCovered.push(pack.name + " from " + entry.store + (entry.note ? " (" + entry.note + ")" : ""));
      });
    });
    if (notCovered.length) {
      items.push(el("li", {}, [el("b", { text: "Exists but not covered yet — " }),
        listText(notCovered) + ". Install it from the Chrome Web Store instead and it is protected."]));
    }
    shield.content.cannot.forEach(function (pair) { items.push(el("li", {}, [el("b", { text: pair[0] + " — " }), pair[1] + "."])); });
    items.push(el("li", {}, [el("b", { text: "Anything not listed — " }),
      "has no " + shield.name + " protection of its own. Blackbox's built-in protection still applies."]));
    return items;
  }

  function sourceItems(packs) {
    return packs.map(function (pack) {
      var links = [];
      var seen = {};
      pack.availability.forEach(function (entry) {
        if (entry.url) links.push(safeLink(entry.url, entry.store + " listing"));
        if (entry.source && entry.source.indexOf("https://") === 0) links.push(safeLink(entry.source, "publisher's download page"));
      });
      var item = el("li", {}, [el("b", { text: pack.name + ": " }), pack.source + (pack.verified ? " (checked " + pack.verified + ")" : "")]);
      links.forEach(function (link) {
        var key = link.textContent + (link.href || "");
        if (seen[key]) return;
        seen[key] = true;
        item.appendChild(document.createTextNode(" · "));
        item.appendChild(link);
      });
      return item;
    });
  }

  function outcomeBar(rows) {
    var counts = { blocked: 0, flagged: 0, allowed: 0 };
    rows.forEach(function (row) { if (counts[row.outcome] !== undefined) counts[row.outcome] += 1; });
    var total = rows.length || 1;
    return el("span", { "class": "bar", "aria-hidden": "true" }, [["blocked", "b"], ["flagged", "f"], ["allowed", "a"]].map(function (pair) {
      return el("i", { "class": pair[1], style: "width:" + (100 * counts[pair[0]] / total).toFixed(1) + "%" });
    }));
  }

  // The tested attack table of one shield, grouped and filterable by evidence level.
  function attackBlock(shield, packNames) {
    var table = shield.attacks;
    var activeEvidence = null;
    var groupsRoot = el("div", { "class": "attack-groups" });
    var legend = el("div", { "class": "evidence-legend" });
    Object.keys(table.evidence_levels || {}).forEach(function (level) {
      var button = el("button", { type: "button", "aria-pressed": "false", title: table.evidence_levels[level], text: level });
      button.addEventListener("click", function () {
        activeEvidence = activeEvidence === level ? null : level;
        Array.prototype.slice.call(legend.children).forEach(function (other) {
          other.setAttribute("aria-pressed", other === button && activeEvidence ? "true" : "false");
        });
        drawGroups();
      });
      legend.appendChild(button);
    });

    function drawGroups() {
      var wasOpen = {};
      Array.prototype.slice.call(groupsRoot.querySelectorAll("details")).forEach(function (node) { wasOpen[node.getAttribute("data-group")] = node.open; });
      groupsRoot.textContent = "";
      table.groups.forEach(function (group, index) {
        var rows = table.rows.filter(function (row) {
          return row.group === group.id && (!activeEvidence || (row.evidence || []).indexOf(activeEvidence) !== -1);
        });
        if (!rows.length) return;
        var details = el("details", { "class": "group", "data-group": group.id }, [
          el("summary", {}, [el("span", { "class": "group-title", text: group.title }), outcomeBar(rows),
            el("span", { "class": "group-count", text: rows.length + (rows.length === 1 ? " attack" : " attacks") })]),
          group.intro ? el("p", { "class": "group-intro", text: group.intro }) : null,
          el("div", { "class": "table-wrap" }, [el("table", {}, [
            el("thead", {}, [el("tr", {}, ["Attack", "Targets", "Outcome", "Evidence"].map(function (name) { return el("th", { scope: "col", text: name }); }))]),
            el("tbody", {}, rows.map(function (row) {
              return el("tr", {}, [
                el("td", {}, [el("strong", { text: row.title }), el("span", { "class": "row-how", text: row.how || "" })]),
                el("td", { text: (row.targets || []).map(function (id) { return packNames[id] || id; }).join(", ") || "—" }),
                el("td", {}, [el("span", { "class": "outcome " + row.outcome, text: row.outcome })]),
                el("td", {}, (row.evidence || []).map(function (level) { return el("span", { "class": "ev " + level, text: level }); }))
              ]);
            }))
          ])])
        ]);
        details.open = group.id in wasOpen ? wasOpen[group.id] : index === 0;
        groupsRoot.appendChild(details);
      });
    }
    drawGroups();
    return [table.tested_with ? el("p", { "class": "note", text: "Tested with: " + table.tested_with + "." }) : null, legend, groupsRoot];
  }

  function runCards(runs) {
    return runs.map(function (run) {
      return el("article", { "class": "run" }, [
        el("h4", { "class": "run-title", text: run.title || "" }),
        el("div", { "class": "meta", text: [run.date, run.machine].filter(Boolean).join(" · ") }),
        el("h5", { text: "Set up" }), el("ul", {}, (run.setup || []).map(function (line) { return el("li", { text: line }); })),
        el("h5", { text: "Results" }), el("ul", { "class": "results" }, (run.results || []).map(function (line) { return el("li", { text: line }); })),
        (run.open || []).length ? el("h5", { text: "Still open" }) : null,
        (run.open || []).length ? el("ul", { "class": "open" }, run.open.map(function (line) { return el("li", { text: line }); })) : null
      ]);
    });
  }

  // One sub-part of a shield's section: an anchor the contents list links to, a heading, content.
  function part(shieldId, slug, title, children) {
    return el("div", { "class": "shield-part", id: shieldId + "-" + slug, "data-title": title },
              [el("h3", { "class": "part-title", text: title })].concat(children));
  }

  function shieldSection(shield) {
    var packs = supportedPacks(shield);
    var packNames = {};
    packs.forEach(function (pack) { packNames[pack.id] = pack.name; });
    var withStores = packs.filter(function (pack) { return pack.availability.length; });
    var logos = el("div", { "class": "logo-strip", "aria-hidden": "true" }, packs.map(function (pack) {
      return el("span", { "class": "logo-chip", title: pack.name }, [packLogo(pack, 28)]);
    }));
    var parts = [
      part(shield.id, "adds", "What it adds", [
        el("div", { "class": "adds-grid" }, shield.content.can.map(function (pair) {
          return el("article", { "class": "card" }, [el("h4", { text: pair[0] }), el("p", { text: pair[1] })]);
        })),
        shield.capabilities.length ? el("div", { "class": "chips caps" }, shield.capabilities.map(function (cap) {
          return el("span", { "class": "chip", title: cap.note, text: cap.name });
        })) : null
      ]),
      part(shield.id, "protects", "What it protects", [el("div", { "class": "wallet-grid" }, packs.map(packCard))])
    ];
    if (withStores.length) {
      parts.push(part(shield.id, "where", "Where it works", [
        el("p", { text: "A browser extension is protected wherever its official version can be installed. Chrome, Brave, Edge, Opera, Vivaldi and Arc all install from the Chrome Web Store, so an extension from there is protected in every one of them. Firefox and Edge also have stores of their own." }),
        el("div", { "class": "legend", "aria-hidden": "true" }, Object.keys(STATE_TEXT).map(function (state) {
          return el("span", { "class": "chip " + state, text: STATE_TEXT[state] });
        })),
        el("div", { "class": "table-wrap" }, [matrixTable(withStores)])
      ]));
    }
    parts.push(part(shield.id, "not-supported", "Not supported", [
      el("p", { text: "Said plainly, so nobody assumes protection that is not there:" }),
      el("ul", { "class": "plain-list" }, unsupportedItems(withStores, shield)),
      shield.content.coming.length ? el("p", { "class": "note", text: "Coming next: " + listText(shield.content.coming) + "." }) : null
    ]));
    parts.push(part(shield.id, "tested", "What was tested", attackBlock(shield, packNames)));
    if (shield.field_tests.length) {
      parts.push(part(shield.id, "field", "Real-machine runs", [
        el("p", { text: "Fresh machines set up the way a person would: real software from the official sources, Blackbox from the one-line installer." }),
        el("div", { "class": "timeline" }, runCards(shield.field_tests))
      ]));
    }
    parts.push(part(shield.id, "sources", "Sources", [
      el("p", { text: "Where every claim in this section comes from: the publisher's own download page or the store's own listing. Search results were never used as evidence." }),
      el("ul", { "class": "source-list" }, sourceItems(packs))
    ]));
    return el("section", { id: "shield-" + shield.id, "class": "doc shield-doc",
                            "data-keywords": "shield " + shield.name + " " + packs.map(function (pack) { return pack.name; }).join(" ") }, [
      el("h2", {}, [shield.name, shield.beta ? el("span", { "class": "tag", text: "beta" }) : null]),
      el("p", { "class": "shield-tagline", text: shield.tagline }),
      logos,
      el("p", {}, [el("a", { "class": "shield-open", href: shield.page, text: "Open " + shield.name + " →" })])
    ].concat(parts));
  }

  function tocEntries(shield, section) {
    var items = [el("li", {}, [el("a", { href: "#shield-" + shield.id, text: shield.name })])];
    Array.prototype.slice.call(section.querySelectorAll(".shield-part")).forEach(function (node) {
      items.push(el("li", { "class": "sub" }, [el("a", { href: "#" + node.id, text: node.getAttribute("data-title") })]));
    });
    return items;
  }

  function renderShieldSections(payload) {
    var root = document.getElementById("shield-sections");
    var toc = document.getElementById("toc-shields");
    root.textContent = "";
    Array.prototype.slice.call(toc.querySelectorAll("li:not(:first-child)")).forEach(function (item) { item.remove(); });
    payload.shields.forEach(function (shield) {
      var section = shieldSection(shield);
      root.appendChild(section);
      tocEntries(shield, section).forEach(function (item) { toc.appendChild(item); });
    });
  }

  // ---- The security settings, from the one catalogue the guard and the Security page use -----
  var MODE_WORDS = { block: "blocked", ask: "asks you", allow: "allowed" };
  function renderSettings(settings) {
    if (!settings) return;
    var table = document.getElementById("settings-permissions");
    table.textContent = "";
    table.appendChild(el("tr", {}, [el("th", { text: "Setting" }), el("th", { text: "Starts" }), el("th", { text: "When allowed" }),
                                    el("th", { text: "While blocked" }), el("th", { text: "If you relax it" })]));
    (settings.permissions || []).forEach(function (row) {
      table.appendChild(el("tr", {}, [el("th", { scope: "row", text: row.name }), el("td", { text: MODE_WORDS[row.default] || row.default }),
                                      el("td", { text: row.unlocks }), el("td", { text: row.when_blocked }), el("td", { text: row.cost })]));
    });
    [["settings-always-blocked", settings.always_blocked], ["settings-always-on", settings.always_on]].forEach(function (pair) {
      var list = document.getElementById(pair[0]);
      list.textContent = "";
      (pair[1] || []).forEach(function (rule) {
        var tail = rule.permission ? " (an agent outside the sandbox can be let through with a setting)" : "";
        list.appendChild(el("li", {}, [el("b", { text: rule.name }), " — " + rule.why + tail]));
      });
    });
  }

  function render(payload) {
    renderStats(payload);
    renderSettings(payload.settings);
    drawLayers(payload.shields);
    renderShieldSections(payload);
    numberSections();
    observeSections();
  }

  // The dashboard's cache answers its very first request with an empty payload while it builds
  // the real one, so an empty answer is retried a few times before the page settles for it.
  function load(attempt) {
    fetch("/api/docs", { headers: { accept: "application/json" } })
      .then(function (response) { return response.json(); })
      .then(function (payload) {
        if (!payload || !Array.isArray(payload.shields)) throw new Error("unexpected answer");
        if (!payload.shields.length && attempt < EMPTY_RETRIES) { window.setTimeout(function () { load(attempt + 1); }, EMPTY_RETRY_MS); return; }
        render(payload);
      })
      .catch(function () {
        if (attempt < EMPTY_RETRIES) window.setTimeout(function () { load(attempt + 1); }, EMPTY_RETRY_MS);
      });
  }

  // ---- 4. Navigation: numbering, scroll-spy, search, phone contents ------------------------
  function numberSections() {
    var index = 0;
    Array.prototype.slice.call(document.querySelectorAll("section.doc h2")).forEach(function (heading) {
      index += 1;
      heading.setAttribute("data-index", (index < 10 ? "0" : "") + index);
    });
  }

  // Scroll-spy: the contents link of whatever section (or shield part) is at the top is lit.
  // Sections drawn later (each shield's) are observed when they are drawn.
  var spy = null;
  function observeSections() {
    if (!("IntersectionObserver" in window)) return;
    var links = {};
    Array.prototype.slice.call(document.querySelectorAll(".toc a")).forEach(function (link) { links[link.getAttribute("href").slice(1)] = link; });
    if (spy) spy.disconnect();
    spy = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting || !links[entry.target.id]) return;
        Object.keys(links).forEach(function (id) { links[id].classList.toggle("active", id === entry.target.id); });
      });
    }, { rootMargin: "-80px 0px -65% 0px" });
    Array.prototype.slice.call(document.querySelectorAll("section.doc, .shield-part")).forEach(function (node) { spy.observe(node); });
  }

  function wireSearch() {
    var input = document.getElementById("search");
    var none = document.getElementById("no-results");
    input.addEventListener("input", function () {
      var query = input.value.trim().toLowerCase();
      var shown = 0;
      Array.prototype.slice.call(document.querySelectorAll("section.doc")).forEach(function (section) {
        var haystack = (section.textContent + " " + (section.getAttribute("data-keywords") || "")).toLowerCase();
        var match = !query || haystack.indexOf(query) !== -1;
        section.hidden = !match;
        if (match) shown += 1;
      });
      none.hidden = shown > 0;
    });
  }

  function wirePhoneContents() {
    var toggle = document.getElementById("toc-toggle");
    var toc = document.getElementById("toc");
    toggle.addEventListener("click", function () {
      var open = toc.classList.toggle("open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
    toc.addEventListener("click", function (event) {
      if (event.target.tagName === "A") { toc.classList.remove("open"); toggle.setAttribute("aria-expanded", "false"); }
    });
  }

  numberSections();
  drawPipeline();
  wireFlowTabs();
  drawLayers([]);
  observeSections();
  wireSearch();
  wirePhoneContents();
  load(0);
})();
