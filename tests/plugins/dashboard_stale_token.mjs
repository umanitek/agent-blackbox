/**
 * Real-browser check that an open dashboard page survives a dashboard restart (KI-498) — the
 * browser half. The session token is minted when the dashboard starts, and the page kept the one
 * it loaded for good: after a restart every Save answered "Could not save (HTTP 403)" until a
 * reload. Here the page's FIRST /api/session is answered with a token the server does not hold
 * (what a restart leaves the page with); later ones reach the real server. Save must succeed.
 * tests/plugins/test_blackbox_dashboard_browser.py serves the fixture app, runs this script and
 * asserts on the summary.
 *
 *   PW_EXEC=<chromium binary> node tests/plugins/dashboard_stale_token.mjs <base url> <out dir>
 */
import { chromium } from "playwright";
import { writeFileSync } from "node:fs";

const base = process.argv[2];
const outDir = process.argv[3] || ".";
const browser = await chromium.launch(process.env.PW_EXEC ? { executablePath: process.env.PW_EXEC } : {});
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
const pageErrors = [];
page.on("pageerror", (err) => pageErrors.push(String(err)));
let sessionReads = 0;
await page.route("**/api/session", (route) => {
  sessionReads += 1;
  if (sessionReads === 1) {
    return route.fulfill({ status: 200, contentType: "application/json",
      body: JSON.stringify({ token: "token-of-the-dashboard-before-the-restart" }) });
  }
  return route.continue();
});
const settingsPosts = [];
page.on("response", (response) => {
  if (response.request().method() === "POST" && response.url().endsWith("/api/settings")) settingsPosts.push(response.status());
});

await page.goto(base + "/", { waitUntil: "domcontentloaded" });
await page.click("#settings-open");
await page.waitForFunction(() => !document.getElementById("set-save")?.disabled, null, { timeout: 30000 });
await page.click("#set-save");
await page.waitForFunction(() => document.getElementById("set-save")?.textContent !== "Saving…", null, { timeout: 30000 });
await page.waitForTimeout(500);
const saveStatus = await page.locator("#set-status").innerText();

writeFileSync(`${outDir}/stale-token-summary.json`, JSON.stringify({ saveStatus, settingsPosts, sessionReads, pageErrors }, null, 1));
await browser.close();
