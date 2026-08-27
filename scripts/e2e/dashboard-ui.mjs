/**
 * f0_hpot e2e: dashboard adjustments — attention card, new KPIs, and
 * click-through deep links into the incidents/tokens pages.
 *
 *   F0_E2E_KEY=f0k_... node scripts/e2e/dashboard-ui.mjs
 */
import {
  CONSOLE,
  apiJson,
  dnsEvent,
  forwardIncident,
  gwFetch,
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

const browser = await launchBrowser();
const page = await loginPage(browser);
try {
  // Seed our own attention state (other suites ack incidents and reset
  // failure counters, so leftovers are unreliable):
  // - one pending deployment (against an offline agent, stays pending)
  // - one high-severity unacked incident (dns)
  // - one failing channel (live dispatch failure against a dead port)
  const agents = await apiJson("/api/v1/agents");
  const target = agents.find((a) => a.hostname === "dmz-honeypot-01") ?? agents[0];
  const tok = await apiJson("/api/v1/tokens", {
    method: "POST",
    body: JSON.stringify({ type: "web_bug", memo: `e2e-dash-${RUN}` }),
  });
  await apiJson(`/api/v1/agents/${target.id}/deploy`, {
    method: "POST",
    body: JSON.stringify({ token_id: tok.id, target_dir: "/tmp/f0-dash" }),
  });
  const dnsTok = await apiJson("/api/v1/tokens", {
    method: "POST",
    body: JSON.stringify({ type: "dns", memo: `e2e-dash-dns-${RUN}` }),
  });
  await forwardIncident(dnsTok.id, dnsEvent(dnsTok.id, "198.51.100.99"));
  await apiJson("/api/v1/alert-channels", {
    method: "POST",
    body: JSON.stringify({ kind: "webhook", config: { url: "http://127.0.0.1:9/dead" } }),
  });
  await gwFetch(`/${tok.id}/pixel.gif`);

  await page.goto(CONSOLE);
  await page.waitForSelector("text=Posture across tokens, incidents, and fleet");

  await check("KPI row includes pending deploys and unacked-high subtext", async () => {
    await page.locator("text=Pending deploys").waitFor();
    await page.locator("text=high severity").first().waitFor();
  });

  await check("attention card lists failing channels, offline agents, pending deploys, unacked high", async () => {
    const card = page.locator("div.rounded-lg.border", { hasText: "needs attention" }).first();
    await card.locator("text=alert channel(s) failing").waitFor();
    await card.locator("text=agent(s) offline").waitFor();
    await card.locator("text=token deployment(s) pending").waitFor();
    await card.locator("text=high-severity incident(s) unacknowledged").waitFor();
  });

  await check("attention link deep-links to severity-filtered incidents", async () => {
    await page.getByText("high-severity incident(s) unacknowledged").click();
    await page.waitForSelector("text=Trigger events across tokens and sensors");
    if (!page.url().includes("/incidents?severity=high")) {
      throw new Error(`unexpected url: ${page.url()}`);
    }
    // the severity select shows "high" and unacked rows are visible
    const trigger = page.getByRole("combobox").first();
    if (!(await trigger.textContent())?.includes("high")) {
      throw new Error("severity filter not initialized from URL");
    }
  });

  await check("top source IP click-through applies the IP filter with a clearable chip", async () => {
    await page.goto(CONSOLE);
    await page.waitForSelector("text=Top source IPs");
    await page
      .locator("div.rounded-lg.border", { hasText: "Top source IPs" })
      .first()
      .getByRole("link")
      .first()
      .click();
    await page.waitForSelector("text=Trigger events across tokens and sensors");
    if (!page.url().includes("source_ip=")) throw new Error(`unexpected url: ${page.url()}`);
    await page.locator("text=/^ip: /").first().waitFor();
    // clearing the chip removes the filter
    await page.getByTitle("clear IP filter").click();
    await page.waitForTimeout(600);
    if ((await page.locator("text=/^ip: /").count()) !== 0) {
      throw new Error("IP chip did not clear");
    }
  });

  await check("token leaderboard click-through opens the token drawer", async () => {
    await page.goto(CONSOLE);
    await page.waitForSelector("text=Token leaderboard");
    const board = page.locator("div.rounded-lg.border", { hasText: "Token leaderboard" }).first();
    if ((await board.getByRole("link").count()) === 0) {
      throw new Error("leaderboard has no links (no hit tokens?)");
    }
    await board.getByRole("link").first().click();
    await page.waitForSelector("text=Artifacts");
    if (!page.url().includes("/tokens?id=")) throw new Error(`unexpected url: ${page.url()}`);
  });
} finally {
  await browser.close();
}

if (summarize("dashboard UI checks") > 0) process.exit(1);
