/**
 * Shields on the dashboard: every registered shield drawn from the API alone.
 *
 * The page names no shield. Everything here is read from the server's records and drawn as given:
 *
 *   GET /api/shields                -> [{shield_id, name, tagline, beta, page, claims, mode, blocking, sections}]
 *   GET /api/shields/{id}/events    -> [ShieldEvent: ts, identifier, title, outcome, logo, story,
 *                                       what_to_do, facts, session, timeline, ...]
 *   GET/POST /api/settings          -> settings.shields = {id: {mode, fields}}; a save posts shields.<id>
 *
 * Per shield: one "New: <name>" banner (while the shield is off, for a week from first sight,
 * dismissible), one card (its status sections, plus its recent events), one Settings group (one
 * row per field: toggle, multi-pick or lines), and one shared events window. Every field is
 * optional with a default: a missing field renders empty and never throws (a payload from an
 * older or newer server still draws).
 *
 * Design: a Facade. index.html mounts it once, handing in its own helpers (dependency
 * injection, so there is one esc() and one fetch path), and talks to it through the object
 * mount() answers. Markup is created here into three hosts index.html provides
 * (#shield-banners, #shield-cards, #set-shields) and one overlay appended to <body>; every
 * element is created hidden and shown only by a render.
 *
 *   var shieldsUI = BlackboxShields.mount({ esc, getJSON, postJSON, toast, shortWhen, openSettings,
 *                                           lockScroll, unlockScroll, onSettingsChange });
 *   shieldsUI.refresh();                    // re-read the cards (and each engaged shield's events)
 *   shieldsUI.onFindings(fresh);            // new findings arrived: refresh when a shield claims one
 *   shieldsUI.findingMark(finding, "big");  // a claimed finding's logo or glyph; "" when unclaimed
 *   shieldsUI.findingRows(finding, rows);   // [label, value] detail rows for a claimed finding
 *   shieldsUI.settings.load(view); .render(); .payload(); .pathRows();
 */
(function (global) {
  "use strict";

  var REFRESH_MS = 30000;
  var FIRST_TRIES = 6, FIRST_RETRY_MS = 1000;
  var BANNER_DAYS = 7;
  var RECENT_EVENTS = 20;
  var SAME_EVENT_SECONDS = 2;   // a finding and its event are the same moment, logged twice
  // The first shield's banner shipped with its own storage keys; a renamed key would show
  // every existing dashboard the banner again, so those keys are kept for that shield.
  var KEPT_BANNER_KEYS = { trader: { first: "blackbox.trader-shield.first-seen.v1", dismissed: "blackbox.trader-shield.dismissed.v1" } };
  var STATES = { ok: 1, watch: 1, none: 1, warn: 1 };
  var OUTCOMES = { blocked: 1, flagged: 1 };
  var STEP_KIND = { api: "model", tool: "tool", file: "file", dependency: "install", threat: "threat", session: "session" };
  var GLYPH = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
    '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>';

  // ---------- defaults: every field the page reads is optional ----------
  function str(value) { return value == null ? "" : String(value); }
  function list(value) { return Array.isArray(value) ? value : []; }
  function obj(value) { return value && typeof value === "object" && !Array.isArray(value) ? value : {}; }
  function seconds(value) {
    if (typeof value === "number") return value < 1e12 ? value : value / 1000;
    var parsed = Date.parse(str(value));
    return isNaN(parsed) ? 0 : parsed / 1000;
  }
  function asCard(raw) {
    raw = obj(raw);
    var id = str(raw.shield_id);
    return { id: id, name: str(raw.name) || id, tagline: str(raw.tagline), beta: raw.beta === true,
             page: str(raw.page), claims: list(raw.claims).map(str).filter(Boolean),
             enabled: obj(raw.mode).enabled === true, blocking: raw.blocking === true,
             sections: list(raw.sections).map(function (section) {
               section = obj(section);
               return { title: str(section.title), help: str(section.help), rows: list(section.rows).map(obj) };
             }) };
  }
  // "*:crypto-wallet" -> /^.*:crypto\-wallet$/ (the server's own fnmatch patterns).
  function patternRegex(pattern) {
    return new RegExp("^" + pattern.split("*").map(function (part) {
      return part.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
    }).join(".*") + "$");
  }
  // A story is HTML-safe text with <b> and <q> spans: keep those four tags, neutralise any other.
  function safeStory(text) {
    return str(text).split(/(<\/?[bq]>)/).map(function (part) {
      return /^<\/?[bq]>$/.test(part) ? part : part.replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }).join("");
  }

  function mount(deps) {
    var esc = deps.esc;
    var state = { cards: [], events: {}, failed: false, drafts: {}, view: {} };
    var win = { shield: "", events: [], selected: 0, lastFocus: null };

    function byId(id) { return document.getElementById(id); }
    function cardOf(id) { return state.cards.filter(function (card) { return card.id === id; })[0] || null; }
    function claimant(finding) {
      var identifier = str(obj(finding).identifier);
      return state.cards.filter(function (card) {
        if (!card.regex) card.regex = card.claims.map(patternRegex);
        return card.regex.some(function (regex) { return regex.test(identifier); });
      })[0] || null;
    }
    function logoHTML(url, label, cls) {
      // A local path only: the server serves logos as images from its own registry.
      return /^\/[A-Za-z0-9_\/.-]+$/.test(url) && url.indexOf("..") < 0
        ? '<img class="wl ' + esc(cls || "") + '" src="' + esc(url) + '" alt="' + esc(label) + '" title="' + esc(label) + '" />'
        : '<span class="wl wl-mark ' + esc(cls || "") + '" aria-hidden="true">' + GLYPH + "</span>";
    }
    function help(text) {
      return text ? ' <span class="m-help" tabindex="0" role="note" aria-label="' + esc(text) + '" data-help="' + esc(text) + '">i</span>' : "";
    }

    // ---------- banners ----------
    function bannerDue(id) {
      var kept = KEPT_BANNER_KEYS[id];
      try {
        var stored = kept ? { first: Number(localStorage.getItem(kept.first) || 0), dismissed: localStorage.getItem(kept.dismissed) }
                          : obj(JSON.parse(localStorage.getItem("blackbox.shield." + id + ".banner") || "{}"));
        if (stored.dismissed) return false;
        var first = Number(stored.first || 0);
        if (!first) { first = Date.now(); saveBanner(id, { first: first }); }
        return Date.now() - first < BANNER_DAYS * 86400000;
      } catch (_) { return true; }
    }
    function saveBanner(id, change) {
      var kept = KEPT_BANNER_KEYS[id];
      try {
        if (kept) {
          if (change.first) localStorage.setItem(kept.first, String(change.first));
          if (change.dismissed) localStorage.setItem(kept.dismissed, String(change.dismissed));
          return;
        }
        var key = "blackbox.shield." + id + ".banner";
        var stored = obj(JSON.parse(localStorage.getItem(key) || "{}"));
        localStorage.setItem(key, JSON.stringify({ first: change.first || stored.first || Date.now(), dismissed: change.dismissed || stored.dismissed || 0 }));
      } catch (_) { /* a per-browser convenience only */ }
    }
    function bannerHTML(card) {
      return '<div class="ts-banner" data-shield-banner="' + esc(card.id) + '" hidden role="region" aria-label="' + esc("New: " + card.name) + '">' +
        '<div class="ts-glow" aria-hidden="true"></div><div class="ts-copy"><span class="ts-new">New' + (card.beta ? " · Beta" : "") + "</span>" +
        '<div class="ts-title">' + esc(card.name) + '</div><div class="ts-sub">' + esc(card.tagline) + "</div></div>" +
        '<div class="ts-actions"><button type="button" class="ts-btn primary" data-shield-engage="' + esc(card.id) + '">' + esc("Engage " + card.name) + "</button>" +
        (card.page ? '<a class="ts-btn" href="' + esc(card.page) + '">Learn more →</a>' : "") + "</div>" +
        '<button type="button" class="ts-close" data-shield-dismiss="' + esc(card.id) + '" aria-label="' + esc("Dismiss the " + card.name + " announcement") + '">&#10005;</button></div>';
    }
    function engage(id, button) {
      var card = cardOf(id), name = card ? card.name : id;
      button.disabled = true; button.textContent = "Engaging…";
      var body = { shields: {} };
      body.shields[id] = { enabled: true };   // only the switch: an earlier choice is kept
      deps.postJSON("/api/settings", body).then(function (res) {
        var view = obj(obj(obj(obj(res && res.body).settings).shields)[id]);
        var ok = !!(res && res.ok && obj(res.body).ok && obj(view.mode).enabled === true);
        button.disabled = false;
        button.textContent = ok ? "Engaged ✓" : "Engage " + name;
        deps.toast(ok ? name + " is engaged." : "Couldn't engage " + name + ".", ok ? "ok" : "err");
        refresh();
        var section = document.querySelector('[data-shield-card="' + id + '"]');
        if (ok && section && section.scrollIntoView) setTimeout(function () { section.scrollIntoView({ behavior: "smooth", block: "start" }); }, 400);
      }).catch(function (err) {   // a refused or failed request must never leave the button stuck on "Engaging…"
        button.disabled = false;
        button.textContent = "Engage " + name;
        deps.toast(err && err.readOnly ? err.message : "Couldn't engage " + name + ".", "err");
      });
    }

    // ---------- cards ----------
    function cardShellHTML(card) {
      return '<section class="section" data-shield-card="' + esc(card.id) + '" aria-label="' + esc(card.name) + '" hidden>' +
        '<div class="section-head"><div class="section-htext"><h2>' + esc(card.name) + (card.beta ? ' <span class="ts-beta">Beta</span>' : "") + "</h2>" +
        '<div class="section-note">What Blackbox found on this machine, and how it keeps your agent away from it.' +
        (card.page ? ' <a href="' + esc(card.page) + '" class="ts-link">Learn more</a>' : "") + "</div></div>" +
        '<div class="head-right"><span class="wp-mode" data-shield-mode>…</span>' +
        '<button type="button" class="ts-btn" data-shield-edit="' + esc(card.id) + '">Edit settings</button></div></div>' +
        '<div class="panel"><div class="wp-grid" data-shield-body><div class="empty" style="padding:24px 20px;">Checking this machine&hellip;</div></div></div></section>';
    }
    function rowHTML(row) {
      var cls = STATES[str(row.state)] ? str(row.state) : "none";
      return '<div class="wp-row"><span class="wp-ic ' + cls + '">' + esc(str(row.icon) || "–") + "</span><div>" +
        (row.logo ? logoHTML(str(row.logo), str(row.text)) : "") + "<b>" + esc(row.text) + "</b>" +
        (row.sub ? '<div class="wp-sub">' + esc(row.sub) + "</div>" : "") + "</div></div>";
    }
    function eventsColumnHTML(card) {
      var events = state.events[card.id];
      var rows = list(events).slice(0, RECENT_EVENTS).map(function (e) {
        var outcome = OUTCOMES[str(e.outcome)] ? str(e.outcome) : "flagged";
        return '<button type="button" class="wp-ev" data-shield-events="' + esc(card.id) + '" data-event-id="' + esc(e.identifier) +
          '" data-event-ts="' + esc(str(e.ts)) + '" title="Open the full report"><span class="o ' + outcome + '">' + esc(outcome) + "</span><span>" +
          logoHTML(str(e.logo), str(e.title)) + esc(str(e.title) || str(e.identifier)) +
          (e.sandbox ? ' <span class="sb-tag">SANDBOX</span>' : "") + '</span><span class="wp-sub">' + esc(deps.shortWhen(e.ts)) +
          '</span><span class="wp-sub">' + esc(e.tool ? "via " + e.tool : "") + "</span></button>";
      });
      var body = events === undefined ? '<div class="wp-sub">Loading…</div>'
        : events === null ? '<div class="wp-sub">Recent events are unavailable right now.</div>'
        : rows.length ? '<div class="wp-evlist" tabindex="0" aria-label="Recent events (scrolls)">' + rows.join("") + "</div>"
        : '<div class="wp-sub">Nothing yet — no agent has reached for anything ' + esc(card.name) + " protects.</div>";
      return '<div class="wp-col"><div class="wp-h">Recent events' + help("The latest times your agent reached for something this shield protects, and what Blackbox did. Click one for the full story.") +
        (rows.length ? '<button type="button" class="wev-all" data-shield-events="' + esc(card.id) + '" data-event-id="">View all →</button>' : "") + "</div>" + body + "</div>";
    }
    var LEGEND = '<div class="wp-legend" aria-label="What the marks mean"><span><span class="wp-ic ok">✓</span>secured — blocked</span>' +
      '<span><span class="wp-ic watch">~</span>watched — flagged only (audit mode)</span><span><span class="wp-ic none">–</span>not protected</span>' +
      '<span><span class="wp-ic warn">!</span>needs attention</span></div>';
    function renderCard(card) {
      var section = document.querySelector('[data-shield-card="' + card.id + '"]');
      if (!section) return;
      section.hidden = !card.enabled;   // only while the shield is on (Settings)
      var mode = section.querySelector("[data-shield-mode]"), body = section.querySelector("[data-shield-body]");
      mode.className = "wp-mode " + (card.blocking ? "block" : "audit");
      mode.textContent = card.blocking ? "● Blocking" : "Watching only · audit mode";
      mode.title = card.blocking ? "Threats are stopped before the action runs." : "Threats are recorded and shown, but not stopped. Turn on Block in Settings to stop them.";
      body.style.setProperty("--wp-cols", String(card.sections.length + 1));   // + the events column
      body.innerHTML = card.sections.map(function (part) {
        return '<div class="wp-col"><div class="wp-h">' + esc(part.title) + help(part.help) + "</div>" + part.rows.map(rowHTML).join("") + "</div>";
      }).join("") + eventsColumnHTML(card) + LEGEND;
    }
    function renderAll() {
      var banners = byId("shield-banners"), cards = byId("shield-cards");
      if (!banners || !cards) return;
      state.cards.forEach(function (card) {
        if (!banners.querySelector('[data-shield-banner="' + card.id + '"]')) banners.insertAdjacentHTML("beforeend", bannerHTML(card));
        if (!cards.querySelector('[data-shield-card="' + card.id + '"]')) cards.insertAdjacentHTML("beforeend", cardShellHTML(card));
        banners.querySelector('[data-shield-banner="' + card.id + '"]').hidden = card.enabled || !bannerDue(card.id);
        renderCard(card);
      });
    }
    function refresh() {
      return deps.getJSON("/api/shields").then(function (payload) {
        state.cards = list(payload).map(asCard).filter(function (card) { return card.id; });
        state.failed = false;
        renderAll();
        state.cards.forEach(function (card) { if (card.enabled) loadEvents(card.id); });
      }).catch(function () {
        state.failed = true;
        Array.prototype.forEach.call(document.querySelectorAll("[data-shield-body]"), function (body) {
          body.innerHTML = '<div class="empty" style="padding:24px 20px;">Shield status is unavailable right now.</div>';
        });
      });
    }
    function loadEvents(id) {
      return deps.getJSON("/api/shields/" + encodeURIComponent(id) + "/events").then(function (events) {
        state.events[id] = list(events).map(obj);
      }).catch(function () { state.events[id] = null; }).then(function () {
        var card = cardOf(id);
        if (card) renderCard(card);
        return state.events[id];
      });
    }

    // ---------- the events window ----------
    var overlay = document.createElement("div");
    overlay.className = "wev-overlay";
    overlay.hidden = true;
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.setAttribute("aria-labelledby", "shield-events-title");
    overlay.innerHTML = '<div class="wev-head"><div><div class="wev-kicker" data-window-kicker></div><h2 id="shield-events-title">Events</h2>' +
      '<div class="wev-note">Every time your agent reached for something this shield protects — what it was doing, and what Blackbox did.</div></div>' +
      '<button type="button" class="wev-close" data-window-close aria-label="Close the events">✕</button></div>' +
      '<div class="wev-private" role="note"><span aria-hidden="true">🔒</span><span><b>Private to this machine.</b> This report is read from Blackbox\'s own logs on this computer. ' +
      "These events are never shared with the community graph — not even a summary — and secrets in commands or messages were removed before they were written down.</span></div>" +
      '<div class="wev-body"><nav class="wev-list" data-window-list aria-label="Events"></nav><article class="wev-detail" data-window-detail aria-live="polite"></article></div>';
    document.body.appendChild(overlay);
    var winList = overlay.querySelector("[data-window-list]"), winDetail = overlay.querySelector("[data-window-detail]");

    function when(ts) {
      try { return new Date(seconds(ts) * 1000).toLocaleString([], { weekday: "short", month: "short", day: "numeric", hour: "numeric", minute: "2-digit", second: "2-digit" }); }
      catch (_) { return ""; }
    }
    function offset(ts, start) {
      var s = Math.max(0, seconds(ts) - seconds(start));
      return s < 60 ? "+" + s.toFixed(1) + "s" : "+" + Math.floor(s / 60) + "m " + Math.round(s % 60) + "s";
    }
    function factsHTML(e) {
      return '<div class="wev-facts">' + list(e.facts).map(obj).map(function (fact) {
        return '<div class="k">' + esc(fact.label) + "</div><div" + (fact.mono ? ' class="mono"' : "") + ">" + esc(fact.value) + "</div>";
      }).join("") + "</div>";
    }
    function timelineHTML(e) {
      var session = obj(e.session), steps = list(e.timeline).map(obj).slice();
      var start = session.start || (steps[0] && steps[0].ts) || 0;
      if (session.start) steps.unshift({ type: "session", ts: session.start, label: "Session started" });
      if (session.end && session.status && session.status !== "active") steps.push({ type: "session", ts: session.end, label: "Session ended (" + session.status + ")" });
      return '<ol class="wev-steps">' + steps.map(function (step) {
        var flags = list(step.threats).filter(function (t) { return t !== step.result; });
        var label = step.type === "tool" ? (step.tool ? esc(step.tool) + ": " : "") + "<code>" + esc(step.label) + "</code>" : esc(step.label);
        if (step.type === "threat" && list(step.threat_titles).length) label += ": <b>" + esc(step.threat_titles.join("; ")) + "</b>";
        return '<li class="wev-step' + (step.this ? " this" : "") + '"><span class="off">' + esc(offset(step.ts, start)) + '</span><span class="what"><span class="kind">' +
          esc(STEP_KIND[step.type] || step.type) + "</span>" + label + esc(step.result ? " → " + step.result : "") + esc(flags.length ? " · " + flags.join(", ") : "") +
          (step.this ? '<span class="here">← this event</span>' : "") + "</span></li>";
      }).join("") + "</ol>";
    }
    function renderDetail() {
      var e = win.events[win.selected];
      if (!e) { winDetail.innerHTML = '<div class="wev-empty">No events yet.</div>'; return; }
      var outcome = OUTCOMES[str(e.outcome)] ? str(e.outcome) : "flagged";
      winDetail.innerHTML = logoHTML(str(e.logo), str(e.title), "huge") + '<div><span class="wev-chip ' + outcome + '">' + outcome + "</span></div><h3>" +
        esc(str(e.title) || str(e.identifier)) + '</h3><div class="wev-when">' + esc(when(e.ts)) + (e.tool ? " · via " + esc(e.tool) : "") + "</div>" +
        '<p class="wev-story">' + safeStory(e.story) + "</p>" +
        '<div class="wev-sec"><h4>What to do</h4><ul class="wev-todo">' + list(e.what_to_do).map(function (t) { return "<li>" + esc(t) + "</li>"; }).join("") + "</ul></div>" +
        '<div class="wev-sec"><h4>The details</h4>' + factsHTML(e) + "</div>" +
        '<div class="wev-sec"><h4>What happened in that session</h4>' + timelineHTML(e) + "</div>";
      winDetail.scrollTop = 0;
    }
    function renderList() {
      winList.innerHTML = win.events.map(function (e, i) {
        var outcome = OUTCOMES[str(e.outcome)] ? str(e.outcome) : "flagged", session = obj(e.session);
        return '<button type="button" class="wev-item' + (e.isNew ? " fresh" : "") + '" data-event-index="' + i + '"' + (i === win.selected ? ' aria-current="true"' : "") + ">" +
          '<span class="wev-chip ' + outcome + '">' + outcome + "</span>" + (e.isNew ? '<span class="wev-new">New</span>' : "") +
          '<span class="t">' + logoHTML(str(e.logo), str(e.title)) + esc(str(e.title) || str(e.identifier)) + "</span>" +
          '<span class="m">' + esc(deps.shortWhen(e.ts)) + (session.model ? " · " + esc(session.model) : "") + "</span>" +
          (e.command ? "<code>" + esc(e.command) + "</code>" : "") + "</button>";
      }).join("");
    }
    function select(i) { win.selected = Math.max(0, Math.min(i, win.events.length - 1)); renderList(); renderDetail(); }
    function pick(identifier, ts) {   // the event a row was clicked for: same rule, nearest time
      var best = 0, gap = Infinity;
      win.events.forEach(function (e, i) {
        var g = Math.abs(seconds(e.ts) - ts);
        if ((!identifier || e.identifier === identifier) && g < gap) { best = i; gap = g; }
      });
      return identifier ? best : 0;
    }
    function openWindow(id, identifier, ts) {
      var card = cardOf(id);
      win.shield = id; win.lastFocus = document.activeElement;
      overlay.querySelector("[data-window-kicker]").textContent = card ? card.name + (card.beta ? " · Beta" : "") : "";
      overlay.hidden = false;
      deps.lockScroll();
      winDetail.innerHTML = '<div class="wev-empty">Loading…</div>';
      overlay.querySelector("[data-window-close]").focus();
      loadEvents(id).then(function (events) {
        if (events === null) { winDetail.innerHTML = '<div class="wev-empty">The events could not be read right now.</div>'; return; }
        win.events = list(events);
        select(pick(identifier, Number(ts) || 0));
      });
    }
    function closeWindow() {
      if (overlay.hidden) return;
      overlay.hidden = true;
      deps.unlockScroll();
      if (win.lastFocus && win.lastFocus.focus) win.lastFocus.focus();
    }
    function onFindings(fresh) {
      var claimed = list(fresh).map(claimant).filter(Boolean);
      if (!claimed.length) return;
      refresh();
      if (overlay.hidden) return;
      var current = win.events[win.selected], newestBefore = win.events.length ? seconds(win.events[0].ts) : 0;
      loadEvents(win.shield).then(function (events) {
        if (!events) return;   // the next poll tries again
        win.events = events;
        win.events.forEach(function (e) { e.isNew = seconds(e.ts) > newestBefore; });
        win.selected = current ? pick(current.identifier, seconds(current.ts)) : 0;
        renderList();
        if (!current) renderDetail();
      });
    }

    document.addEventListener("click", function (event) {
      var target = event.target && event.target.closest ? event.target : null;
      if (!target) return;
      var hit = target.closest("[data-shield-events]");
      if (hit) { openWindow(hit.getAttribute("data-shield-events"), hit.getAttribute("data-event-id"), seconds(Number(hit.getAttribute("data-event-ts")) || 0)); return; }
      hit = target.closest("[data-event-index]");
      if (hit) { select(Number(hit.getAttribute("data-event-index"))); return; }
      if (target.closest("[data-window-close]")) { closeWindow(); return; }
      hit = target.closest("[data-shield-engage]");
      if (hit) { engage(hit.getAttribute("data-shield-engage"), hit); return; }
      hit = target.closest("[data-shield-dismiss]");
      if (hit) {
        var id = hit.getAttribute("data-shield-dismiss");
        saveBanner(id, { dismissed: Date.now() });
        hit.closest("[data-shield-banner]").hidden = true;
        return;
      }
      hit = target.closest("[data-shield-edit]");
      if (hit) {
        deps.openSettings();
        var group = document.querySelector('[data-shield-settings="' + hit.getAttribute("data-shield-edit") + '"]');
        if (group && group.scrollIntoView) setTimeout(function () { group.scrollIntoView({ block: "start" }); }, 60);
      }
    });
    document.addEventListener("keydown", function (event) { if (event.key === "Escape") closeWindow(); });

    // ---------- findings elsewhere on the page ----------
    function matchingEvent(card, finding) {
      var ts = seconds(finding.ts != null ? finding.ts : finding.time);
      return list(state.events[card.id]).filter(function (e) {
        return e.identifier === finding.identifier && Math.abs(seconds(e.ts) - ts) <= SAME_EVENT_SECONDS;
      })[0] || null;
    }
    function findingMark(finding, cls) {
      var card = claimant(finding);
      if (!card) return "";
      var event = matchingEvent(card, obj(finding));
      return logoHTML(event ? str(event.logo) : "", card.name, cls);
    }
    function findingRows(finding, shown) {
      var card = claimant(finding);
      if (!card) return [];
      var labels = list(shown).map(function (row) { return row[0]; });
      var event = matchingEvent(card, obj(finding));
      return [["Protected by", card.name]].concat(list(event && event.facts).map(obj).filter(function (fact) {
        return fact.label && labels.indexOf(fact.label) < 0;
      }).map(function (fact) { return [str(fact.label), str(fact.value), !!fact.mono]; }));
    }

    // ---------- Settings: one group per shield, from its fields ----------
    function fieldsOf(id) { return list(obj(state.view[id]).fields).map(obj).filter(function (f) { return f.key; }); }
    function loadSettings(view) {
      state.view = obj(view);
      state.drafts = {};
      Object.keys(state.view).forEach(function (id) {
        var mode = obj(obj(state.view[id]).mode), draft = {};
        fieldsOf(id).forEach(function (field) {
          draft[field.key] = field.kind === "toggle" ? mode[field.key] === true : list(mode[field.key]).map(str);
        });
        state.drafts[id] = draft;
      });
    }
    function linesOf(id, field) {   // [kept, left out]: a line the field's pattern refuses is never sent
      var regex = field.pattern ? new RegExp(field.pattern) : null, kept = [], refused = 0;
      list(state.drafts[id][field.key]).forEach(function (line) {
        line = str(line).trim();
        if (!line) return;
        if (regex && !regex.test(line)) refused += 1;
        else if (kept.indexOf(line) < 0) kept.push(line);
      });
      return [kept, refused];
    }
    function fieldHTML(id, card, field, on, first) {
      var draft = state.drafts[id], attrs = ' data-shield-id="' + esc(id) + '" data-field="' + esc(field.key) + '"';
      var label = '<div class="set-rt">' + esc(field.label) + "</div>";
      var helpText = '<div class="set-rh">' + (first && card.page ? '<a href="' + esc(card.page) + '" class="ts-link">' + esc("What is " + card.name + "?") + "</a> " : "") + esc(field.help) + "</div>";
      if (field.kind === "toggle") {
        return '<div class="set-row"><div class="set-rl">' + label + helpText + '</div><div class="set-rc"><label class="set-toggle"><input type="checkbox"' + attrs +
          (draft[field.key] ? " checked" : "") + ' /><span class="set-track"></span></label></div></div>';
      }
      if (field.kind === "multi-pick") {
        var picks = list(field.options).map(obj).map(function (option) {
          if (option.status !== "supported") return '<label class="wallet-pick soon"><input type="checkbox" disabled /> ' + esc(option.name) + " <span>coming soon</span></label>";
          return '<label class="wallet-pick"><input type="checkbox"' + attrs + ' data-option="' + esc(option.id) + '"' +
            (draft[field.key].indexOf(str(option.id)) >= 0 ? " checked" : "") + (on ? "" : " disabled") + " /> " + esc(option.name) + "</label>";
        });
        return '<div class="set-row"><div class="set-rl">' + label + helpText + '<div class="wallet-picks">' + picks.join("") + "</div></div></div>";
      }
      if (field.kind === "lines") {
        return '<div class="set-row"><div class="set-rl">' + label + helpText + '<textarea class="set-addresses" rows="3" spellcheck="false" autocomplete="off"' + attrs +
          (on ? "" : " disabled") + ">" + esc(draft[field.key].join("\n")) + '</textarea><div class="set-addresses-note" data-lines-note="' + esc(field.key) + '"></div></div></div>';
      }
      return "";
    }
    function renderLinesNote(group, id, field) {
      var note = group.querySelector('[data-lines-note="' + field.key + '"]');
      if (!note) return;
      var counted = linesOf(id, field);
      note.className = "set-addresses-note" + (counted[1] ? " bad" : "");
      note.textContent = counted[1] ? counted[1] + " line" + (counted[1] === 1 ? " is" : "s are") + " not accepted and left out — never saved or sent."
        : counted[0].length ? counted[0].length + " listed." : "";
    }
    function renderSettings() {
      var host = byId("set-shields");
      if (!host) return;
      host.innerHTML = Object.keys(state.drafts).map(function (id) {
        var card = cardOf(id) || asCard({ shield_id: id }), on = state.drafts[id].enabled === true;
        return '<div class="set-group" data-shield-settings="' + esc(id) + '"><div class="set-glabel">' + esc(card.name) + (card.beta ? " · Beta" : "") + "</div>" +
          fieldsOf(id).map(function (field, i) { return fieldHTML(id, card, field, on, i === 0); }).join("") + "</div>";
      }).join("");
      Object.keys(state.drafts).forEach(function (id) {
        var group = host.querySelector('[data-shield-settings="' + id + '"]');
        fieldsOf(id).forEach(function (field) { if (field.kind === "lines") renderLinesNote(group, id, field); });
      });
    }
    function onSettingsInput(event) {
      var input = event.target, id = input && input.getAttribute && input.getAttribute("data-shield-id"), key = id && input.getAttribute("data-field");
      if (!id || !key || !state.drafts[id]) return;
      var field = fieldsOf(id).filter(function (f) { return f.key === key; })[0] || {};
      if (field.kind === "toggle") { state.drafts[id][key] = input.checked; renderSettings(); }
      else if (field.kind === "multi-pick") {
        var option = input.getAttribute("data-option"), chosen = state.drafts[id][key].filter(function (v) { return v !== option; });
        if (input.checked) chosen.push(option);
        state.drafts[id][key] = chosen;
      } else if (field.kind === "lines") {
        state.drafts[id][key] = input.value.split(/[\s,]+/);
        renderLinesNote(input.closest("[data-shield-settings]"), id, field);
      }
      deps.onSettingsChange();
    }
    function settingsPayload() {
      var out = {};
      Object.keys(state.drafts).forEach(function (id) {
        var section = {};
        fieldsOf(id).forEach(function (field) {
          var value = state.drafts[id][field.key];
          section[field.key] = field.kind === "toggle" ? value === true
            : field.kind === "lines" ? linesOf(id, field)[0] : list(value).slice(0, list(field.options).length);
        });
        out[id] = section;
      });
      return out;
    }
    // What an engaged shield guards beyond the file patterns, read-only under Protected files.
    function pathRows() {
      return Object.keys(state.drafts).map(function (id) {
        var card = cardOf(id) || asCard({ shield_id: id });
        if (state.drafts[id].enabled !== true) return "";
        var rows = [];
        fieldsOf(id).filter(function (field) { return field.kind === "multi-pick"; }).forEach(function (field) {
          list(field.options).map(obj).forEach(function (option) {
            if (option.status === "supported" && state.drafts[id][field.key].indexOf(str(option.id)) >= 0) {
              rows.push('<div class="path-row shield" title="' + esc("Protected by " + card.name + ". Untick it or turn " + card.name + " off to stop.") + '"><code>' +
                esc(option.name + " · everywhere it keeps its keys") + '</code><span class="path-shield">' + esc(card.name) + "</span></div>");
            }
          });
        });
        return rows.length ? '<div class="paths-shield-note">' + esc("Also protected while " + card.name + " is on — every profile, and inside archives and copies:") + "</div>" + rows.join("") : "";
      }).join("");
    }
    // Delegated from the document: the Settings markup may come after the script that mounts this.
    document.addEventListener("change", onSettingsInput);
    document.addEventListener("input", function (event) { if (event.target && event.target.tagName === "TEXTAREA") onSettingsInput(event); });

    // The server caches /api/shields and its very first answer is the cache's empty default:
    // ask again shortly until the cards arrive, so they are drawn at load, not 30 s later.
    (function firstLoad(triesLeft, delay) {
      setTimeout(function () {
        refresh().then(function () {
          if (!state.cards.length && !state.failed && triesLeft > 1) firstLoad(triesLeft - 1, FIRST_RETRY_MS);
        });
      }, delay);
    })(FIRST_TRIES, 300);
    setInterval(refresh, REFRESH_MS);
    return { refresh: refresh, onFindings: onFindings, findingMark: findingMark, findingRows: findingRows,
             settings: { load: loadSettings, render: renderSettings, payload: settingsPayload, pathRows: pathRows } };
  }

  global.BlackboxShields = { mount: mount };
})(window);
