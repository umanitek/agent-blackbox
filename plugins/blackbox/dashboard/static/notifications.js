/*
 * The dashboard's Notifications page (notify_routes): what the plugin's notifier is, the policy
 * (saved through /api/settings, so a change that tells you less waits for your confirmation —
 * approvals.js handles the 428) and the history of the feed. All text is set with textContent.
 */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const BOXES = ["enabled", "security", "lifecycle", "digest", "watched", "details"];
  const DELIVERY = { delivered: "delivered to Notification Center", fallback: "shown through macOS's script notifier",
                     "not-shown": "macOS did not show it (notifications are off for Blackbox)" };
  const HELD = { "quiet-hours": "held: quiet hours", muted: "held: this agent is muted", rate: "counted into a summary" };

  async function token() {
    try { return (await (await fetch("/api/session")).json()).token || ""; } catch (_) { return ""; }
  }

  async function post(path, body) {
    return fetch(path, { method: "POST", headers: { "Content-Type": "application/json", "X-Blackbox-Token": await token() },
                         body: JSON.stringify(body || {}) });
  }

  async function loadPolicy() {
    const answer = await (await fetch("/api/notifications/policy")).json();
    const policy = answer.policy || {};
    BOXES.forEach((name) => { $("nt-" + name).checked = !!policy[name]; });
    $("nt-quiet").value = policy.quiet_hours || "";
    $("nt-rate").value = policy.per_minute || 6;
    $("nt-digest-minutes").value = policy.digest_minutes || 0;
    const who = answer.holder ? "A companion app is running and shows them. " : "";
    $("nt-notifier").textContent = who + ((answer.notifier || {}).detail || "");
    const settings = $("nt-settings");
    settings.hidden = !(answer.notifier || {}).settings;
    settings.textContent = (answer.notifier || {}).settings_label || "Open Notification settings";
  }

  async function loadHistory() {
    const list = $("nt-list");
    const answer = await (await fetch("/api/notifications/history?limit=100")).json();
    list.replaceChildren();
    const notices = answer.notices || [];
    if (!notices.length) {
      const empty = document.createElement("li");
      empty.className = "nt-muted";
      empty.textContent = "Nothing yet. A notice appears here the moment Blackbox raises one.";
      list.appendChild(empty);
      return;
    }
    notices.forEach((notice) => {
      const item = document.createElement("li");
      item.className = "nt-item";
      item.dataset.level = notice.level || "info";
      const title = document.createElement("b");
      title.textContent = notice.title || "";
      const body = document.createElement("div");
      body.textContent = notice.detail ? notice.body + " " + notice.detail : notice.body || "";
      const when = document.createElement("time");
      when.textContent = new Date((notice.ts || 0) * 1000).toLocaleString();
      item.append(title, body, when);
      const outcome = DELIVERY[notice.delivery];
      if (outcome) {
        const shown = document.createElement("span");
        shown.className = "nt-held";
        shown.textContent = " · " + outcome;
        item.appendChild(shown);
      }
      if (notice.held) {
        const held = document.createElement("span");
        held.className = "nt-held";
        held.textContent = " · " + (HELD[notice.held] || notice.held);
        item.appendChild(held);
      }
      list.appendChild(item);
    });
  }

  $("nt-save").addEventListener("click", async () => {
    const section = { quiet_hours: $("nt-quiet").value.trim(), per_minute: Number($("nt-rate").value) || 6,
                      digest_minutes: Number($("nt-digest-minutes").value) || 0 };
    BOXES.forEach((name) => { section[name] = $("nt-" + name).checked; });
    const result = $("nt-save-result");
    result.textContent = "Saving…";
    try {
      const response = await post("/api/settings", { notifications: section });
      const answer = await response.json().catch(() => ({}));
      result.textContent = response.ok ? "Saved." : (answer.errors || [answer.error || "Not saved."]).join(" ");
    } catch (_) {
      result.textContent = "Not saved: the dashboard did not answer.";
    }
    loadPolicy();
  });

  $("nt-settings").addEventListener("click", async () => {
    const result = $("nt-test-result");
    try {
      const answer = await (await post("/api/notifications/settings")).json();
      result.textContent = answer.opened ? "System Settings is open at Blackbox's notifications." : "Open System Settings → Notifications → Blackbox on this Mac.";
    } catch (_) {
      result.textContent = "The dashboard did not answer.";
    }
  });

  $("nt-test").addEventListener("click", async () => {
    const result = $("nt-test-result");
    result.textContent = "Sending…";
    try {
      const answer = await (await post("/api/notifications/test")).json();
      // The system's own answer: "Delivered to Notification Center." or why it did not show it — never "shown" when it was not.
      result.textContent = (answer.delivery || {}).detail || ((answer.notifier || {}).detail || "");
    } catch (_) {
      result.textContent = "The dashboard did not answer.";
    }
  });

  loadPolicy().catch(() => { $("nt-notifier").textContent = "The dashboard did not answer."; });
  loadHistory().catch(() => {});
  window.setInterval(() => { if (!document.hidden) loadHistory().catch(() => {}); }, 5000);
})();
