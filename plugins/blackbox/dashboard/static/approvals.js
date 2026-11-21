/*
 * Turning protection down needs your confirmation (approval_routes).
 *
 * The core answers a change that weakens protection with 428 and the held request. This script
 * wraps the page's fetch(): on a 428 it shows what would be turned down. "Confirm with your
 * password" asks the core to show the SYSTEM's password prompt. The page itself cannot
 * approve, because a page can be scripted. Once confirmed, the same request is sent again and
 * applied once. "Keep protection on" leaves everything as it was. With Blackbox Desktop open,
 * its native dialog asks too: either answer works.
 * All text is set with textContent.
 */
(function () {
  "use strict";
  if (window.__blackboxApprovals) return;
  window.__blackboxApprovals = true;
  const original = window.fetch.bind(window);

  async function token() {
    try { return (await (await original("/api/session")).json()).token || ""; } catch (_) { return ""; }
  }

  function ask(held) {
    return new Promise((resolve) => {
      const shade = document.createElement("div");
      shade.setAttribute("role", "dialog");
      shade.setAttribute("aria-modal", "true");
      shade.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center;z-index:99999;padding:16px";
      const card = document.createElement("div");
      card.style.cssText = "max-width:460px;width:100%;background:var(--panel,#16181d);color:var(--text,#eee);border:1px solid var(--border,#333);border-radius:12px;padding:20px;font:14px/1.45 system-ui,sans-serif";
      const title = document.createElement("h3");
      title.textContent = "Turn Blackbox's protection down?";
      title.style.margin = "0 0 8px";
      const list = document.createElement("ul");
      (held.reasons || []).forEach((reason) => { const li = document.createElement("li"); li.textContent = reason; list.appendChild(li); });
      const note = document.createElement("p");
      note.textContent = "Only allow this if you asked for it yourself. Your computer will ask for your password.";
      note.style.opacity = ".8";
      const status = document.createElement("p");
      status.setAttribute("aria-live", "polite");
      const row = document.createElement("div");
      row.style.cssText = "display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap";
      const keep = document.createElement("button");
      keep.textContent = "Keep protection on";
      const confirm = document.createElement("button");
      confirm.textContent = "Confirm with your password";
      const close = (value) => { shade.remove(); resolve(value); };
      keep.onclick = () => close(false);
      confirm.onclick = async () => {
        confirm.disabled = keep.disabled = true;
        status.textContent = "Waiting for your password…";
        try {
          const answer = await original("/api/approvals/confirm", {
            method: "POST", headers: { "Content-Type": "application/json", "X-Blackbox-Token": await token() },
            body: JSON.stringify({ id: held.id }),
          });
          if (answer.ok) return close(true);
          status.textContent = ((await answer.json().catch(() => ({}))).error) || "Not confirmed: protection stays on.";
        } catch (_) {
          status.textContent = "Could not ask for confirmation: protection stays on.";
        }
        keep.disabled = false;
      };
      row.append(keep, confirm);
      card.append(title, list, note, status, row);
      shade.appendChild(card);
      document.body.appendChild(shade);
      keep.focus();
    });
  }

  window.fetch = async function (input, init) {
    const response = await original(input, init);
    if (response.status !== 428) return response;
    const body = await response.clone().json().catch(() => null);
    if (!body || !body.approval) return response;
    return (await ask(body.approval)) ? original(input, init) : response;
  };
})();
