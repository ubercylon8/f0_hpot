/**
 * f0_hpot e2e: systematic UI test of the Agents section.
 *
 * Covers: fleet table rendering, add-agent one-liner dialog, agent drawer
 * (memo edit, sensor editor incl. enable/disable, retire with confirm),
 * release binaries download, and release-signing-key management
 * (generate, list, sign — with a cryptographic verification of the
 * resulting manifest).
 *
 * Needs the demo stack with F0_AGENT_RELEASE_DIR populated (make -C agent
 * release) and F0_ENROLLMENT_TOKEN set on the API.
 *
 *   F0_E2E_KEY=f0k_... node scripts/e2e/agents-ui.mjs
 */
import { createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
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
const HOST = `e2e-agent-${RUN}`;
const MEMO = `e2e memo ${RUN}`;
const KEY_LABEL = `e2e-${RUN}`;
const SIGN_VERSION = `v-e2e-${RUN}`;
const RELEASE_DIR = process.env.F0_E2E_RELEASE_DIR ?? "agent/bin";

const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

async function check(name, fn) {
  try {
    await fn();
    report(name, true);
  } catch (err) {
    report(name, false, err instanceof Error ? err.message : String(err));
  }
}

async function seed() {
  const res = await fetch(`${process.env.F0_E2E_API ?? "http://127.0.0.1:18443"}/api/v1/agent/enroll`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      enrollment_token: process.env.F0_E2E_ENROLL ?? "demo-enroll-token",
      hostname: HOST,
      platform: "linux/amd64",
      version: "1.4.2",
    }),
  });
  if (!res.ok) throw new Error(`enroll failed: ${res.status}`);
  return res.json();
}

function row(page, text) {
  return page.locator("tr", { hasText: text }).first();
}

const seeded = await seed();
const browser = await launchBrowser();
const page = await loginPage(browser);
try {
  await page.goto(`${CONSOLE}/agents`);
  await page.waitForSelector("text=Honeypot fleet, sensors, and releases");

  await check("fleet table renders agents with platform, sensors, status", async () => {
    await row(page, HOST).waitFor();
    const r = row(page, HOST);
    await r.locator("text=linux/amd64").waitFor();
    await r.locator("text=online").waitFor();
  });

  await check("add-agent dialog shows the install one-liner with enrollment token", async () => {
    await page.getByRole("button", { name: "Add agent" }).click();
    const dialog = page.getByRole("dialog");
    await dialog.waitFor();
    const enroll = process.env.F0_E2E_ENROLL ?? "demo-enroll-token";
    await dialog.locator(`code:has-text("${enroll}")`).waitFor();
    await dialog.locator(`code:has-text("--install")`).waitFor();
    await dialog.getByTitle("copy one-liner").waitFor();
    await page.keyboard.press("Escape");
  });

  await check("drawer: memo edit saves and shows in the fleet table", async () => {
    await row(page, HOST).click();
    await page.waitForSelector("text=Sensors");
    await page.getByPlaceholder("e.g. dmz honeypot, rack 3").fill(MEMO);
    await page.getByRole("button", { name: "save", exact: true }).click();
    await page.waitForSelector("text=memo saved");
    await page.keyboard.press("Escape");
    await row(page, MEMO).waitFor();
  });

  await check("drawer: sensor editor adds and disables sensors", async () => {
    await row(page, HOST).click();
    await page.waitForSelector("text=Sensors");
    await page.getByRole("button", { name: "edit sensors" }).click();
    await page.getByRole("button", { name: "+ add sensor" }).click();
    const editor = page.locator("div.rounded-md.border");
    await editor.locator('input[placeholder="port"]').last().fill("12222");
    await editor.locator('input[placeholder="token id"]').last().fill("whwmhnd54y5b");
    // disable the new row's switch, then deploy
    await editor.locator('button[role="switch"]').last().click();
    await page.getByRole("button", { name: "save & deploy" }).click();
    await page.waitForSelector("text=Sensor config deployed");
    await page.locator("span.font-mono", { hasText: "http_login" }).first().waitFor();
    await page.keyboard.press("Escape");
  });

  await check("releases card lists all 5 platform binaries", async () => {
    for (const f of ["linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64", "windows-amd64.exe"]) {
      await page.locator(`text=f0-deception-agent-${f}`).first().waitFor();
    }
    await page.locator("text=signed release manifest present").waitFor();
  });

  await check("release binary downloads with the right name and size", async () => {
    const row = page
      .locator("span.font-mono", { hasText: "f0-deception-agent-linux-amd64" })
      .locator("..");
    await row.getByRole("button", { name: "download" }).waitFor();
    const dlPromise = page.waitForEvent("download");
    await row.getByRole("button", { name: "download" }).click();
    const dl = await dlPromise;
    if (dl.suggestedFilename() !== "f0-deception-agent-linux-amd64") {
      throw new Error(`unexpected filename: ${dl.suggestedFilename()}`);
    }
    const { statSync } = await import("node:fs");
    const size = statSync(await dl.path()).size;
    if (size < 1_000_000) throw new Error(`suspiciously small binary: ${size}`);
  });

  await check("signing keys: generate, list, and sign the release dir", async () => {
    await page.getByPlaceholder("key label (e.g. prod-2026)").fill(KEY_LABEL);
    await page.getByRole("button", { name: "generate key" }).click();
    await page.waitForSelector("text=generated");
    await page.getByText(KEY_LABEL, { exact: true }).first().waitFor();
    // sign with the new key
    await page.locator("div.border-t").getByRole("combobox").click();
    await page.getByRole("option", { name: new RegExp(KEY_LABEL) }).click();
    await page.getByPlaceholder("version (default: dev-<date>)").fill(SIGN_VERSION);
    await page.getByRole("button", { name: "sign release dir" }).click();
    await page.waitForSelector(`text=signed manifest ${SIGN_VERSION} covering 5 file(s)`);
  });

  await check("signed manifest verifies cryptographically against the new key", async () => {
    const keys = await apiJson("/api/v1/release-keys");
    const k = keys.find((x) => x.label === KEY_LABEL);
    if (!k) throw new Error("generated key not listed by API");
    const manifest = JSON.parse(readFileSync(`${RELEASE_DIR}/release-manifest.json`, "utf8"));
    if (manifest.version !== SIGN_VERSION) {
      throw new Error(`manifest version ${manifest.version} != ${SIGN_VERSION}`);
    }
    const spki = Buffer.concat([SPKI_PREFIX, Buffer.from(k.publicKey, "base64")]);
    const pub = createPublicKey({ key: spki, format: "der", type: "spki" });
    const { canonicalManifestBytes } = await import(
      "../../apps/api/dist/release-signing.js"
    );
    const canonical = canonicalManifestBytes(manifest.version, manifest.files);
    const ok = verify(null, Buffer.from(canonical, "utf8"), pub, Buffer.from(manifest.signature, "base64"));
    if (!ok) throw new Error("signature invalid");
  });

  await check("retire removes the agent after the danger confirm", async () => {
    await row(page, HOST).click();
    await page.waitForSelector("text=Danger zone");
    await page.getByText("retire agent…").click();
    await page.getByRole("button", { name: "retire agent", exact: true }).click();
    await page.waitForSelector("text=agent retired");
    await page.waitForTimeout(800);
    if ((await row(page, HOST).count()) !== 0) throw new Error("agent still in table");
    // its key must be dead now
    const hb = await fetch(`${process.env.F0_E2E_API ?? "http://127.0.0.1:18443"}/api/v1/agent/heartbeat`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${seeded.agent_key}` },
      body: JSON.stringify({ agent_id: seeded.agent_id }),
    });
    if (hb.status !== 401) throw new Error(`heartbeat after retire: ${hb.status} != 401`);
  });
} finally {
  await browser.close();
}

if (summarize("agent UI checks") > 0) process.exit(1);
