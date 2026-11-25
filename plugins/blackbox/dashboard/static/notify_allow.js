/*
 * "Allow Blackbox to notify you" (KI-PENDING-411cdb) — the card on the dashboard while the
 * system's notifications for Blackbox are not asked yet or switched off.
 *
 * macOS asks "may Blackbox notify you?" only ONCE, and only a person at the desktop: an installer
 * run over SSH is answered "denied" with no question, and a question nobody answers is recorded as
 * Off for good. So the question waits for the person, here:
 *  - permission not asked yet (notifier.can_ask): "Allow Blackbox to notify you" →
 *    POST /api/notifications/allow, which opens Blackbox's notifier through LaunchServices in the
 *    person's own session; macOS then asks once.
 *  - permission off, or not askable from here: notifier.settings_label →
 *    POST /api/notifications/settings (System Settings at Blackbox's notifications).
 * Either way the card says that security notices still reach the person through macOS's script
 * notifier meanwhile. Reads GET /api/notifications/policy; hidden when notifications are allowed.
 * POSTs carry the session token. Text is set with textContent.
 */
(function () {
  "use strict";
  var POLL_MS = 15000;
  var root = null, note = "";

  var CSS =
    ".na-bar{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:center;margin:0 0 12px;padding:10px 14px;" +
    "border:1px solid color-mix(in srgb,var(--caution,#E3B341) 60%,transparent);border-radius:var(--radius,4px);" +
    "background:var(--panel,var(--bg));color:var(--text);font-size:13.5px}" +
    ".na-bar .na-text{flex:1 1 300px;min-width:0;line-height:1.5}.na-bar b{font-weight:700}" +
    ".na-bar button{border:1px solid var(--text);background:var(--text);color:var(--bg);border-radius:var(--radius,4px);" +
    "padding:6px 12px;font:700 12.5px var(--body-font,inherit);cursor:pointer}";

  async function token() {
    try { return (await (await fetch("/api/session")).json()).token || ""; } catch (_) { return ""; }
  }

  async function post(path) {
    var response = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json", "X-Blackbox-Token": await token() }, body: "{}" });
    return response.json();
  }

  function draw(notifier) {
    var ask = !!notifier.can_ask;
    var off = notifier.permission === "denied" || (notifier.permission === "not-determined" && !ask);
    if (!ask && !(off && notifier.settings)) { root.hidden = true; root.replaceChildren(); return; }
    var bar = document.createElement("div");
    bar.className = "na-bar";
    var text = document.createElement("div");
    text.className = "na-text";
    var title = document.createElement("b");
    title.textContent = ask ? "Allow Blackbox to notify you" : "Blackbox's notifications are off";
    var body = document.createElement("div");
    body.textContent = note || notifier.detail || "";
    text.append(title, body);
    var button = document.createElement("button");
    button.type = "button";
    button.textContent = ask ? "Allow notifications" : (notifier.settings_label || "Open Notification settings");
    button.addEventListener("click", async function () {
      button.disabled = true;
      try {
        if (ask) {
          var answer = await post("/api/notifications/allow");
          note = ((answer || {}).notifier || {}).detail || "";
        } else {
          var opened = await post("/api/notifications/settings");
          note = (opened || {}).opened ? "System Settings is open at Blackbox's notifications: switch on Allow notifications."
                                         : "Open System Settings → Notifications → Blackbox on this Mac and switch on Allow notifications.";
        }
      } catch (_) {
        note = "The dashboard did not answer.";
      }
      refresh();
    });
    bar.append(text, button);
    root.replaceChildren(bar);
    root.hidden = false;
  }

  async function refresh() {
    try {
      var answer = await (await fetch("/api/notifications/policy")).json();
      draw((answer || {}).notifier || {});
    } catch (_) { /* the next poll tries again */ }
  }

  function start() {
    root = document.getElementById("notify-allow-root");
    if (!root) return;
    var style = document.createElement("style");
    style.textContent = CSS;
    document.head.appendChild(style);
    refresh();
    window.setInterval(function () { if (!document.hidden) refresh(); }, POLL_MS);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
