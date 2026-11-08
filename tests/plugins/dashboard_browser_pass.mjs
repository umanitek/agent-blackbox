/**
 * Real-browser pass of the Blackbox dashboard (LES-002, KI-199) — the browser half.
 *
 * Opens the dashboard at desktop (1440) and phone (390) widths, lands, switches
 * to the Community tab, then opens every shield's own page (each card's `page`
 * from /api/shields), and writes one JSON summary per viewport: console
 * errors, page errors, failed requests, horizontal overflow and the text of
 * the sections the Refine work added (`shield-pages`: the pages it opened). `tests/plugins/test_blackbox_dashboard_browser.py`
 * serves a fixture app, runs this script and asserts on the summary.
 *
 *   PW_EXEC=<chromium binary> node tests/plugins/dashboard_browser_pass.mjs <base url> <out dir>
 */
import { chromium } from "playwright";
import { writeFileSync } from "node:fs";

const base = process.argv[2];
const outDir = process.argv[3] || ".";
const viewports = [
  { name: "desktop", width: 1440, height: 900 },
  { name: "phone", width: 390, height: 844 },
];

const launch = process.env.PW_EXEC ? { executablePath: process.env.PW_EXEC } : {};
const browser = await chromium.launch(launch);
const summary = [];
for (const vp of viewports) {
  const context = await browser.newContext({ viewport: { width: vp.width, height: vp.height }, deviceScaleFactor: 1 });
  const page = await context.newPage();
  const consoleErrors = [];
  const pageErrors = [];
  const failedRequests = [];
  page.on("console", (msg) => { if (msg.type() === "error") consoleErrors.push(msg.text().slice(0, 300)); });
  page.on("pageerror", (err) => pageErrors.push(String(err.stack || err).slice(0, 600)));
  page.on("requestfailed", (req) => failedRequests.push(`${req.method()} ${req.url()} — ${req.failure()?.errorText}`));
  page.on("response", (res) => { if (res.status() >= 400) failedRequests.push(`${res.status()} ${res.url()}`); });

  await page.goto(base, { waitUntil: "domcontentloaded", timeout: 30000 });
  try { await page.waitForLoadState("networkidle", { timeout: 15000 }); } catch { /* the page polls */ }
  await page.waitForTimeout(3000);

  const overflow = async (label) => page.evaluate((label) => {
    const doc = document.documentElement;
    return { label, scrollWidth: doc.scrollWidth, clientWidth: doc.clientWidth,
             horizontalOverflow: doc.scrollWidth > doc.clientWidth };
  }, label);
  const sectionText = async (id) => page.evaluate((id) => {
    const el = document.getElementById(id);
    return el ? (el.innerText || "").replace(/\s+/g, " ").trim().slice(0, 400) : null;
  }, id);
  const cellSqueeze = async () => page.evaluate(() => {
    // In the phone card mode (rows laid out as a grid) a track collapsing under an
    // unbreakable token leaves a cell a few pixels wide: text spills over its
    // neighbour, or wraps one character per line (KI-200). In the two Refine
    // tables this pass certifies, flag any grid cell narrower than 25% of its
    // row, or spilling past its box.
    const squeezed = [];
    const tables = 'table[aria-label="Community statements"] tbody tr, table[aria-label="My reports"] tbody tr';
    for (const tr of document.querySelectorAll(tables)) {
      if (getComputedStyle(tr).display !== "grid") continue;
      const rowWidth = tr.getBoundingClientRect().width;
      for (const td of tr.querySelectorAll("td")) {
        if (!td.innerText.trim() || td.colSpan > 1) continue;
        const width = td.getBoundingClientRect().width;
        if (width < rowWidth * 0.25 || td.scrollWidth > td.clientWidth + 1) {
          squeezed.push(`${Math.round(width)}px of ${Math.round(rowWidth)}px: ${td.innerText.trim().slice(0, 40)}`);
        }
      }
    }
    return squeezed.slice(0, 8);
  });

  const checks = [await overflow("landing")];
  const sections = {};
  for (const id of ["health-strip", "tab-community", "stat-community-count", "stat-sharing-state",
                    "vs-pct", "vs-chip", "vs-val-downloaded", "vs-note", "vs-lookups"]) sections[id] = await sectionText(id);
  // The Community graph section and its details window were removed (Amos, 2026-10-10):
  // community threats live in the Threat graph's Community tab and the two summary tiles.
  sections["community-panel-present"] = (await page.locator("#community-panel").count()) > 0;
  const spillingCells = await cellSqueeze();
  // "Attach agent" opens its dialog from a click on anything inside the button (its icon or
  // label — the click target is then the child), and Escape closes it (2026-11-08 review).
  sections["attach-dialog"] = await page.evaluate(async () => {
    const button = document.getElementById("attach-open");
    const overlay = document.getElementById("attach-modal");
    if (!button || !overlay) return "missing";
    let child = button.querySelector("*");
    if (!child) { child = document.createElement("span"); child.textContent = "label"; button.appendChild(child); }
    child.click();
    await new Promise((resolve) => setTimeout(resolve, 200));
    const opened = overlay.classList.contains("open");
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    await new Promise((resolve) => setTimeout(resolve, 200));
    return `${opened ? "opened" : "stayed shut"}/${overlay.classList.contains("open") ? "stayed open" : "closed"}`;
  });
  const communityTab = page.locator("#tab-community");
  if (await communityTab.count()) {
    await communityTab.click();
    await page.waitForTimeout(2500);
    checks.push(await overflow("community-tab"));
  }
  // Every shield's own page, in the same tab: its errors, failed requests and overflow count too.
  // /api/shields is stale-while-revalidate, so a cold read can still be [] — ask until it fills.
  sections["shield-pages"] = [];
  let cards = [];
  for (let i = 0; i < 20 && !cards.length; i++) {
    cards = await page.evaluate(async () => (await fetch("/api/shields")).json());
    if (!Array.isArray(cards)) cards = [];
    if (!cards.length) await page.waitForTimeout(500);
  }
  for (const card of cards) {
    if (typeof card.page !== "string" || !card.page.startsWith("/")) continue;
    await page.goto(base + card.page, { waitUntil: "domcontentloaded", timeout: 30000 });
    try { await page.waitForLoadState("networkidle", { timeout: 15000 }); } catch { /* the page polls */ }
    await page.waitForTimeout(2000);
    checks.push(await overflow(`shield-page ${card.page}`));
    sections["shield-pages"].push(card.page);
  }
  // A freshly started dashboard answers /api/shields with [] while it reads the machine: the
  // Trader page must say it is still checking, never "Not engaged" (2026-11-08 review).
  await page.route("**/api/shields", (route) => route.fulfill({ status: 200, contentType: "application/json", body: "[]" }));
  await page.goto(base + "/shields/trader", { waitUntil: "domcontentloaded", timeout: 30000 });
  await page.waitForTimeout(1200);
  sections["trader-status-while-cold"] = (await page.locator("#status").innerText()).trim();
  await page.unroute("**/api/shields");
  summary.push({ viewport: vp, consoleErrors, pageErrors, failedRequests, checks, sections, spillingCells });
  await context.close();
}
await browser.close();
writeFileSync(`${outDir}/dashboard-browser-summary.json`, JSON.stringify(summary, null, 2));
