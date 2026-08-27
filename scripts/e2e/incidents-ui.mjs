/**
 * f0_hpot e2e: systematic UI test of the Incidents section.
 *
 * Seeds deterministic incidents via the API, then drives the real console:
 * list rendering, severity/type/ack-state/text filters, expand + raw event,
 * notes (save + preview), single ack, checkbox bulk-ack, select-all
 * bulk-ack, and the source-IP tooltip.
 *
 *   F0_E2E_KEY=f0k_... node scripts/e2e/incidents-ui.mjs
 */
import {
  CONSOLE,
  apiJson,
  dnsEvent,
  forwardIncident,
  httpEvent,
  launchBrowser,
  loginPage,
  makeReporter,
  requireKey,
} from "./lib.mjs";

requireKey();
const { report, summarize } = makeReporter();

// Run-unique anchors: repeated runs must not collide with leftover
// incidents from previous runs.
const RUN = Date.now().toString(36);
const MARK = `e2e-marker-${RUN}`;
const ACKED_UA = `e2e-acked-${RUN}`;
const IPO = 50 + Math.floor(Math.random() * 150);
const IPA = `203.0.113.${IPO}`;
const IPB = `203.0.113.${IPO + 1}`;
const NOTE = `e2e triage note ${RUN}`;

/** Incident row card containing `text` (rows are the only rounded-lg cards). */
function rowCard(page, text) {
  return page.locator("div.rounded-lg.border", { hasText: text }).first();
}

async function ackButtonCount(page, text) {
  return rowCard(page, text)
    .getByRole("button", { name: "ack", exact: true })
    .count();
}

async function selectOption(page, comboboxIndex, name) {
  await page.getByRole("combobox").nth(comboboxIndex).click();
  await page.getByRole("option", { name, exact: true }).click();
  await page.waitForTimeout(400); // filter refetch
}

/** Back to a clean slate after a failed step so failures don't cascade. */
async function resetFilters(page) {
  const search = page.getByPlaceholder("search raw event (path, UA, DNS name)…");
  if (await search.count()) await search.fill("");
  for (const [i, label] of [
    [0, "all severities"],
    [1, "all types"],
    [2, "all states"],
  ]) {
    try {
      await selectOption(page, i, label);
    } catch {}
  }
}

async function seed() {
  const web = await apiJson("/api/v1/tokens", {
    method: "POST",
    body: JSON.stringify({ type: "web_bug", memo: "e2e incidents webbug" }),
  });
  const dns = await apiJson("/api/v1/tokens", {
    method: "POST",
    body: JSON.stringify({ type: "dns", memo: "e2e incidents dns" }),
  });
  await forwardIncident(web.id, httpEvent(web.id, IPA, MARK));
  await forwardIncident(web.id, httpEvent(web.id, IPB, MARK));
  await forwardIncident(dns.id, dnsEvent(dns.id, "198.51.100.77"));
  const acked = await forwardIncident(web.id, httpEvent(web.id, `203.0.113.${IPO + 2}`, ACKED_UA));
  await apiJson(`/api/v1/incidents/${acked}/ack`, { method: "PATCH" });
  return { webId: web.id, dnsId: dns.id };
}

async function check(name, fn) {
  try {
    await fn();
    report(name, true);
  } catch (err) {
    report(name, false, err instanceof Error ? err.message : String(err));
    await resetFilters(page);
  }
}

const { webId, dnsId } = await seed();
const browser = await launchBrowser();
const page = await loginPage(browser);
try {
  await page.goto(`${CONSOLE}/incidents`);
  await page.waitForSelector("text=Trigger events across tokens and sensors");

  await check("list renders seeded incidents (marker UA, dns id, acked row)", async () => {
    await page.waitForSelector(`text=${MARK}`);
    await page.waitForSelector(`text=${dnsId}`);
    await page.waitForSelector(`text=${ACKED_UA}`);
  });

  await check("severity filter (high shows dns, hides medium web_bug rows)", async () => {
    await selectOption(page, 0, "high");
    await page.waitForSelector(`text=${dnsId}`);
    if ((await page.locator(`text=${MARK}`).count()) !== 0) {
      throw new Error("medium rows still visible under severity=high");
    }
    await selectOption(page, 0, "all severities");
  });

  await check("type filter (Web Bug shows marker rows, hides dns)", async () => {
    await selectOption(page, 1, "Web Bug");
    await page.waitForSelector(`text=${MARK}`);
    if ((await page.locator(`text=${dnsId}`).count()) !== 0) {
      throw new Error("dns row still visible under type=web_bug");
    }
    await selectOption(page, 1, "all types");
  });

  await check("ack-state filter (acknowledged vs unacknowledged)", async () => {
    await selectOption(page, 2, "acknowledged");
    await page.waitForSelector(`text=${ACKED_UA}`);
    if ((await page.locator(`text=${MARK}`).count()) !== 0) {
      throw new Error("unacked rows visible under acknowledged filter");
    }
    await selectOption(page, 2, "unacknowledged");
    await page.waitForSelector(`text=${MARK}`);
    if ((await page.locator(`text=${ACKED_UA}`).count()) !== 0) {
      throw new Error("acked row visible under unacknowledged filter");
    }
    await selectOption(page, 2, "all states");
  });

  await check("free-text search matches raw event and clears", async () => {
    await page.getByPlaceholder("search raw event (path, UA, DNS name)…").fill(MARK);
    await page.waitForTimeout(800); // debounce + refetch
    const rows = await page.locator(`text=${MARK}`).count();
    if (rows < 2) throw new Error(`expected >= 2 marker rows, got ${rows}`);
    if ((await page.locator(`text=${dnsId}`).count()) !== 0) {
      throw new Error("unrelated rows visible during search");
    }
    await page.getByPlaceholder("search raw event (path, UA, DNS name)…").fill("");
    await page.waitForTimeout(800);
    await page.waitForSelector(`text=${dnsId}`);
  });

  await check("expand shows raw event JSON and notes editor", async () => {
    await rowCard(page, IPA).click();
    await page.waitForSelector(`pre:has-text("${MARK}")`);
    await page.waitForSelector('textarea[placeholder="triage notes…"]');
  });

  await check("notes save shows toast and collapsed preview", async () => {
    await page.getByPlaceholder("triage notes…").fill(NOTE);
    await page.getByRole("button", { name: "save notes" }).click();
    await page.waitForSelector("text=Notes saved");
    await rowCard(page, IPA).click(); // collapse
    await page.waitForSelector(`text=📝 ${NOTE}`);
  });

  await check("single ack removes the ack button from that row", async () => {
    await rowCard(page, IPB).getByRole("button", { name: "ack", exact: true }).click();
    await page.waitForTimeout(1000);
    if ((await ackButtonCount(page, IPB)) !== 0) throw new Error("ack button still present");
  });

  await check("checkbox bulk-ack acknowledges the selected row", async () => {
    await rowCard(page, IPA).locator('input[type="checkbox"]').click();
    await page.getByRole("button", { name: /ack \d+ selected/ }).click();
    await page.waitForSelector("text=incident(s) acknowledged");
    await page.waitForTimeout(800);
    if ((await ackButtonCount(page, IPA)) !== 0) throw new Error("row still unacked");
  });

  await check("select-all + bulk ack clears every visible ack button", async () => {
    await page.locator('input[type="checkbox"]').first().click();
    await page.getByRole("button", { name: /ack \d+ selected/ }).click();
    await page.waitForSelector("text=incident(s) acknowledged");
    await page.waitForTimeout(1000);
    const left = await page.getByRole("button", { name: "ack", exact: true }).count();
    if (left !== 0) throw new Error(`${left} ack button(s) remain`);
  });

  await check("source-IP hover shows the geo tooltip", async () => {
    await rowCard(page, IPB).locator("span.font-mono").last().hover();
    await page.waitForSelector('[role="tooltip"]');
  });
} finally {
  await browser.close();
}

if (summarize("incident UI checks") > 0) process.exit(1);
