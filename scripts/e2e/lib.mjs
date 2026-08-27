/**
 * Shared helpers for the f0_hpot e2e suites (see tokens-ui.mjs,
 * incidents-ui.mjs). Run with the demo stack up and F0_E2E_KEY set.
 */
import { chromium } from "playwright";

export const CONSOLE = process.env.F0_E2E_CONSOLE ?? "http://localhost:5173";
export const API = process.env.F0_E2E_API ?? "http://127.0.0.1:18443";
export const GATEWAY = process.env.F0_E2E_GATEWAY ?? "http://localhost:18080";
export const KEY = process.env.F0_E2E_KEY;

export function requireKey() {
  if (!KEY) {
    console.error("F0_E2E_KEY (console API key) is required");
    process.exit(2);
  }
  return KEY;
}

export function makeReporter() {
  const results = [];
  return {
    report(name, ok, note = "") {
      results.push({ name, ok });
      console.log(`${ok ? "PASS" : "FAIL"}  ${name}${note ? ` — ${note}` : ""}`);
    },
    summarize(label) {
      const failed = results.filter((r) => !r.ok);
      console.log(`\n${results.length - failed.length}/${results.length} ${label} passed`);
      return failed.length;
    },
  };
}

export async function apiJson(path, init = {}) {
  const res = await fetch(`${API}${path}`, {
    ...init,
    headers: {
      ...(init.body ? { "content-type": "application/json" } : {}),
      authorization: `Bearer ${KEY}`,
    },
  });
  if (!res.ok) throw new Error(`${path}: ${res.status}`);
  return res.json();
}

export async function gwFetch(path, redirect = "manual") {
  return fetch(`${GATEWAY}${path}`, { redirect });
}

/** Incident appears within ~3s (gateway forwards asynchronously). */
export async function waitForIncident(tokenId) {
  for (let i = 0; i < 10; i++) {
    const rows = await apiJson(`/api/v1/tokens/${tokenId}/incidents`);
    if (rows.length > 0) return true;
    await new Promise((r) => setTimeout(r, 300));
  }
  return false;
}

export async function launchBrowser() {
  return chromium.launch({
    ...(process.env.F0_E2E_CHROMIUM !== "bundled"
      ? { executablePath: process.env.F0_E2E_CHROMIUM ?? "/usr/bin/chromium" }
      : {}),
  });
}

/** New context+page with the console key stored (logged-in console). */
export async function loginPage(browser) {
  const ctx = await browser.newContext({ acceptDownloads: true });
  const page = await ctx.newPage();
  page.setDefaultTimeout(10_000);
  await page.goto(CONSOLE);
  await page.evaluate((k) => localStorage.setItem("f0_api_key", k), KEY);
  return page;
}

/** Wait for radix dialogs/sheets to finish closing before continuing. */
export async function settle(page) {
  await page
    .waitForFunction(() => !document.querySelector('[data-state="open"]'), null, {
      timeout: 3000,
    })
    .catch(() => {});
}

/** Forward a gateway-style incident directly to the API (test seeding). */
export function forwardIncident(tokenId, event, severity) {
  return apiJson("/api/v1/incidents", {
    method: "POST",
    body: JSON.stringify({ tokenId, event, ...(severity ? { severity } : {}) }),
  }).then((r) => r.id);
}

export function httpEvent(tokenId, ip, ua) {
  return {
    kind: "http",
    tokenHint: tokenId,
    timestamp: new Date().toISOString(),
    sourceIp: ip,
    http: {
      method: "GET",
      host: `${tokenId}.tokens.example.com`,
      path: `/${tokenId}/pixel.gif`,
      userAgent: ua,
    },
  };
}

export function dnsEvent(tokenId, ip) {
  return {
    kind: "dns",
    tokenHint: tokenId,
    timestamp: new Date().toISOString(),
    sourceIp: ip,
    dns: { queryName: `${tokenId}.tokens.example.com`, queryType: "A" },
  };
}
