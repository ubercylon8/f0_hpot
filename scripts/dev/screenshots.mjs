/*
 * Copyright 2026 The f0_hpot Authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Capture console screenshots for the README and docs.
 *
 * Deliberately points at a LOCAL demo stack: screenshots of a production
 * console would republish the token domain and console hostname that the
 * repository history was rewritten to remove. Bring the stack up as
 * described in AGENTS.md ("Commands") / deploy/local-demo.env, seed it with
 * scripts/e2e/seed.mjs, then:
 *
 *   F0_CONSOLE=http://localhost:5173 F0_E2E_KEY=<console key> \
 *     node scripts/dev/screenshots.mjs
 *
 * Point F0_CONSOLE at whichever port vite actually bound. The console's dev
 * server proxies /api to 127.0.0.1:${F0_API_PORT:-8443}, so it must have
 * been started with the same F0_API_PORT as the API — otherwise every
 * request 404s and this script captures an empty console that still looks
 * plausible.
 */
import { chromium } from "playwright";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const BASE = process.env.F0_CONSOLE ?? "http://localhost:5173";
const KEY = process.env.F0_E2E_KEY;
if (!KEY) {
  console.error("F0_E2E_KEY is required (printed by scripts/e2e/seed.mjs)");
  process.exit(2);
}

// Written relative to the repo, not the cwd, so it can be run from anywhere.
const OUT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "docs", "img");

/** path, output file, a selector proving the page rendered real data. */
const PAGES = [
  ["", "console-dashboard.png", ".recharts-surface"],
  ["/incidents", "console-incidents.png", "span.font-mono.uppercase"],
  ["/tokens", "console-tokens.png", "table tbody tr"],
  ["/agents", "console-agents.png", "table tbody tr"],
];

mkdirSync(OUT, { recursive: true });
const browser = await chromium.launch(
  process.env.F0_SCREENSHOT_CHROMIUM
    ? { executablePath: process.env.F0_SCREENSHOT_CHROMIUM }
    : {},
);
const ctx = await browser.newContext({
  viewport: { width: 1440, height: 900 },
  deviceScaleFactor: 2,
});
const page = await ctx.newPage();

// The console reads its key from localStorage, which only exists once the
// origin has been loaded — so visit first, store the key, then navigate.
await page.goto(BASE);
await page.evaluate((k) => localStorage.setItem("f0_api_key", k), KEY);

let failed = 0;
for (const [path, file, ready] of PAGES) {
  await page.goto(`${BASE}${path}`, { waitUntil: "networkidle" });
  try {
    await page.waitForSelector(ready, { timeout: 15_000 });
  } catch {
    failed++;
    console.error(`! ${file}: "${ready}" never appeared — logged out or no data?`);
  }
  // Let charts finish their entry animation before the shutter.
  await page.waitForTimeout(1200);
  await page.screenshot({ path: join(OUT, file) });
  console.log(`wrote docs/img/${file}`);
}

await browser.close();
if (failed > 0) process.exit(1);
