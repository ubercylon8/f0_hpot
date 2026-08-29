/**
 * f0_hpot e2e: systematic UI test of the Settings section.
 *
 * Part A (demo API, authenticated): server status card, API-key list
 * (last-used), create key (show-once flow), revoke.
 *
 * Part B (fresh keyless API on :18444 + vite on :5174): open-mode warning
 * banner, create first key → open mode closes → login gate → log in with
 * the new key → banner gone.
 *
 *   F0_E2E_KEY=f0k_... node scripts/e2e/settings-ui.mjs
 */
import { spawn } from "node:child_process";
import { openSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  CONSOLE,
  apiJson,
  launchBrowser,
  loginPage,
  makeReporter,
  requireKey,
} from "./lib.mjs";

requireKey();
const { report, summarize } = makeReporter();
const RUN = Date.now().toString(36);

async function check(name, fn) {
  try {
    await fn();
    report(name, true);
  } catch (err) {
    report(name, false, err instanceof Error ? err.message : String(err));
  }
}

function card(page, title) {
  // Scope by the card's heading, not free text — the open-mode banner
  // also contains the words "API key".
  return page
    .locator("div.rounded-lg.border", {
      has: page.getByRole("heading", { name: title, exact: true }),
    })
    .first();
}

// ---------------------------------------------------------------- Part A
const browser = await launchBrowser();
const page = await loginPage(browser);
try {
  await page.goto(`${CONSOLE}/settings`);
  await page.waitForSelector("text=Access control and server configuration");

  await check("server status card shows geoip/enrollment/throttle state", async () => {
    const serverStatus = await apiJson("/api/v1/status");
    const status = card(page, "Server status");
    await status.locator("text=GeoIP enrichment").waitFor();
    // badge mirrors the live F0_GEOIP_DB state
    await status.locator(`text=${serverStatus.geoipEnabled ? "enabled" : "disabled"}`).first().waitFor();
    await status.locator("text=Agent enrollment").waitFor();
    await status.locator("text=configured").waitFor();
    await status.locator("text=Alert throttle").waitFor();
    await status.locator("text=/min per token+IP").waitFor();
  });

  await check("open-mode banner is hidden while auth is enforced", async () => {
    if ((await page.locator("text=open mode").count()) !== 0) {
      throw new Error("banner visible despite closed auth");
    }
  });

  await check("API key list shows the current key with a last-used time", async () => {
    const keys = card(page, "API keys");
    await keys.locator("text=demo-console").waitFor();
    // Scope to the demo-console row: any other never-used key in the list
    // (debris from an earlier run) would otherwise fail this assertion.
    const demoRow = keys.locator("div", { hasText: "demo-console" }).last();
    if ((await demoRow.locator("text=never").count()) !== 0) {
      throw new Error("demo key shows never-used despite driving the console");
    }
  });

  await check("create key: show-once box, copy button, done, row appears", async () => {
    const keys = card(page, "API keys");
    await keys.getByPlaceholder("key label (e.g. laptop, ci-runner)").fill(`e2e-${RUN}`);
    await keys.getByRole("button", { name: "create key" }).click();
    await page.waitForSelector("text=never be shown again");
    const code = keys.locator("code", { hasText: "f0k_" });
    await code.waitFor();
    await keys.getByTitle("copy new API key").waitFor();
    await keys.getByRole("button", { name: "done" }).click();
    await page.waitForTimeout(400);
    await keys.locator(`text=e2e-${RUN}`).waitFor();
  });

  await check("revoke removes the key from the list", async () => {
    const keys = card(page, "API keys");
    const row = keys.locator("div", { hasText: `e2e-${RUN}` }).last();
    // Two-step now: revoking the key you are using is a footgun.
    await row.getByRole("button", { name: "revoke", exact: true }).click();
    await row.getByRole("button", { name: "confirm revoke" }).click();
    await page.waitForSelector(`text=key "e2e-${RUN}" revoked`);
    await page.waitForTimeout(600);
    if ((await keys.locator(`text=e2e-${RUN}`).count()) !== 0) {
      throw new Error("key still listed after revoke");
    }
  });
} finally {
  await browser.close();
}

// ---------------------------------------------------------------- Part B
// Fresh keyless API (no env tokens => open mode) + a vite proxy for it.
const API_B_PORT = 18444;
const VITE_B_PORT = 5174;
const procs = [];

/** Long-running child with output to a log file (execFile pipe buffers
 *  fill up with vite's startup chatter and stall the child). Uses a
 *  shell because pnpm/npx are shims, not real executables. */
function spawnLogged(command, cwd, env, logPath) {
  const fd = openSync(logPath, "w");
  const p = spawn(command, {
    cwd,
    env: { ...process.env, ...env },
    stdio: ["ignore", fd, fd],
    shell: true,
  });
  procs.push(p);
  return p;
}

const repoRoot = fileURLToPath(new URL("../../", import.meta.url));
spawnLogged(
  "npx tsx src/server.ts",
  path.join(repoRoot, "apps/api"),
  {
    F0_DB_PATH: `/tmp/f0settings-${RUN}.db`,
    F0_API_PORT: String(API_B_PORT),
    F0_GATEWAY_ORIGIN: "http://localhost:18080",
  },
  `/tmp/f0settings-apib-${RUN}.log`,
);
spawnLogged(
  `pnpm dev --port ${VITE_B_PORT} --strictPort`,
  path.join(repoRoot, "apps/web"),
  { F0_API_PORT: String(API_B_PORT) },
  `/tmp/f0settings-viteb-${RUN}.log`,
);

async function waitForHttp(url, ms = 45_000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(url);
      if (r.ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`timeout waiting for ${url}`);
}

try {
  await waitForHttp(`http://localhost:${VITE_B_PORT}/`);

  const browserB = await launchBrowser();
  const pageB = await (await browserB.newContext()).newPage();
  pageB.setDefaultTimeout(15_000);
  try {
    await check("open mode: banner visible and console works without a key", async () => {
      await pageB.goto(`http://localhost:${VITE_B_PORT}/settings`);
      await pageB.waitForSelector("text=API is running in open mode");
      await card(pageB, "Server status").waitFor();
      await card(pageB, "API keys").locator("text=No persistent keys").waitFor();
    });

    await check("first key bootstrap: show-once box, no gate, banner clears, session persists", async () => {
      const keys = card(pageB, "API keys");
      await keys.getByPlaceholder("key label (e.g. laptop, ci-runner)").fill(`first-${RUN}`);
      await keys.getByRole("button", { name: "create key" }).click();
      await pageB.waitForSelector("text=never be shown again");
      const newKey = await keys.locator("code", { hasText: "f0k_" }).textContent();
      if (!newKey?.startsWith("f0k_")) throw new Error("no fresh key in the show-once box");
      // the bootstrap fix: the new key is adopted as the session key —
      // reloading must NOT bounce to the login gate
      await pageB.reload();
      await pageB.waitForSelector("text=Access control and server configuration");
      if ((await pageB.locator('input[type="password"]').count()) !== 0) {
        throw new Error("login gate appeared despite bootstrap key adoption");
      }
      if ((await pageB.locator("text=API is running in open mode").count()) !== 0) {
        throw new Error("banner still visible after first key");
      }
      // and the session is authenticated with it (list loads the new key)
      await card(pageB, "API keys").locator(`text=first-${RUN}`).waitFor();
    });
  } finally {
    await browserB.close();
  }
} finally {
  for (const p of procs) p.kill();
  rmSync(`/tmp/f0settings-${RUN}.db`, { force: true });
}

if (summarize("settings UI checks") > 0) process.exit(1);
