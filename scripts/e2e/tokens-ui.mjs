/**
 * f0_hpot e2e: systematic UI test of every token type.
 *
 * Drives the real console (Playwright) through creation, per-type
 * configuration, and artifact download — from BOTH the create dialog and
 * the detail drawer — then fires the attacker-facing gateway URL and
 * confirms an incident was recorded (for HTTP-triggerable types).
 *
 * Prerequisites: demo stack running (api + gateway + vite console) and a
 * console API key.
 *
 *   F0_E2E_KEY=f0k_... pnpm e2e
 *
 * Env overrides: F0_E2E_CONSOLE (http://localhost:5173),
 * F0_E2E_API (http://127.0.0.1:18443), F0_E2E_GATEWAY
 * (http://localhost:18080), F0_E2E_CHROMIUM (/usr/bin/chromium).
 */
import { createServer } from "node:http";
import {
  CONSOLE,
  apiJson,
  gwFetch,
  launchBrowser,
  loginPage,
  makeReporter,
  requireKey,
  settle,
  waitForIncident,
} from "./lib.mjs";

requireKey();
const { report, summarize } = makeReporter();

/** Chrome mutates suggested filenames: leading dots are stripped from
 *  dotfiles and ".txt" is appended to extension-less text/plain files. */
function nameMatches(expected, actual) {
  return (
    expected === actual ||
    actual === expected.replace(/^\./, "") ||
    actual === `${expected}.txt`
  );
}

function downloadNamesMatch(expected, actual) {
  return (
    expected.length === actual.length &&
    expected.every((e, i) => nameMatches(e, actual[i] ?? ""))
  );
}

/** Tiny static site used as the cloned_website target. */
function startCloneSite() {
  const srv = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/html" });
    res.end("<html><head><title>Corp SSO</title></head><body><h1>Sign in</h1></body></html>");
  });
  return new Promise((resolve) => {
    srv.listen(0, "127.0.0.1", () => resolve({ srv, port: srv.address().port }));
  });
}

const PNG_1PX = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
  "base64",
);

/** Per-type matrix. downloads = expected filenames in artifact order. */
const TYPES = [
  { id: "web_bug", label: "Web Bug", downloads: [], trigger: (id) => [`/${id}/pixel.gif`, 200] },
  { id: "custom_image", label: "Custom Image", downloads: [], upload: true, trigger: (id) => [`/${id}/image`, 200] },
  { id: "dns", label: "DNS Token", downloads: [] },
  { id: "email", label: "Unique Email", downloads: [] },
  { id: "qr_code", label: "QR Code", filename: "e2e-wifi-qr.png", downloads: ["e2e-wifi-qr.png"], trigger: (id) => [`/${id}/qr`, 200] },
  { id: "word_doc", label: "Word Document", filename: "e2e-board-pack.docx", downloads: ["e2e-board-pack.docx"], trigger: (id) => [`/${id}/pixel.gif`, 200] },
  { id: "excel_doc", label: "Excel Workbook", filename: "e2e-figures.xlsx", downloads: ["e2e-figures.xlsx"], trigger: (id) => [`/${id}/pixel.gif`, 200] },
  { id: "pdf_doc", label: "PDF Document", filename: "e2e-confidential.pdf", downloads: ["e2e-confidential.pdf"], trigger: (id) => [`/${id}/pixel.gif`, 200] },
  { id: "windows_folder", label: "Windows Folder", downloads: [] },
  { id: "cloned_website", label: "Cloned Website", clone: true, downloads: [], trigger: (id) => [`/${id}/site`, 200, "pixel.gif"] },
  { id: "sql_injection", label: "SQL Injection Canary", filename: "e2e-rules.conf", serverKind: "apache", decoyPath: "/e2e-search.php", downloads: ["e2e-rules.conf"], trigger: (id) => [`/${id}/sqli`, 200] },
  { id: "sensitive_cmd", label: "Sensitive Command", cmdName: "cat /etc/shadow", downloads: [], trigger: (id) => [`/${id}/cmd/cat_etc_shadow`, 200, "root:"] },
  { id: "fast_redirect", label: "Fast Redirect", targetUrl: "https://example.com/landing", downloads: [], trigger: (id) => [`/${id}/r`, 302] },
  { id: "aws_keys", label: "AWS Key Decoy", downloads: ["aws_decoy_readme.txt", "credentials"], trigger: (id) => [`/${id}/aws`, 200] },
  { id: "azure_config", label: "Azure SP Decoy", downloads: ["azure_decoy_readme.txt", ".env.azure"], trigger: (id) => [`/${id}/azure`, 200] },
  { id: "honeypot", label: "Honeypot Link", downloads: [] },
];

async function createViaUi(page, t, clonePort) {
  // Defensive: a previous iteration may have left a dialog/drawer open
  // (radix overlays can swallow the "New token" click mid-animation).
  if (await page.getByRole("dialog").count()) {
    await page.keyboard.press("Escape");
    await settle(page);
  }
  await page.getByRole("button", { name: "New token" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.waitFor();
  const typeSelect = dialog.getByRole("combobox").first();
  await typeSelect.click();
  await page.getByRole("option", { name: t.label, exact: true }).click();
  if (t.targetUrl) await dialog.getByPlaceholder("https://target.example.com/").fill(t.targetUrl);
  if (t.clone) await dialog.getByPlaceholder("https://target.example.com/").fill(`http://127.0.0.1:${clonePort}/`);
  if (t.decoyPath) await dialog.getByPlaceholder("/search.php").fill(t.decoyPath);
  if (t.serverKind) {
    await dialog.getByRole("combobox").nth(1).click();
    await page.getByRole("option", { name: t.serverKind, exact: true }).click();
  }
  if (t.cmdName) {
    await dialog.getByRole("combobox").nth(1).click();
    await page.getByRole("option", { name: t.cmdName, exact: true }).click();
  }
  if (t.filename) await dialog.getByPlaceholder("e.g. Q4-board-pack.docx").fill(t.filename);
  await dialog.getByPlaceholder("where this is planted").fill(`e2e ${t.id}`);
  await dialog.getByRole("button", { name: "Create token" }).click();
  await page.waitForSelector("text=ready", { timeout: 15_000 });
}

/** Download every file artifact visible in the current dialog/drawer. */
async function downloadAll(page, expected) {
  const got = [];
  for (let i = 0; i < expected.length; i++) {
    const dlPromise = page.waitForEvent("download", { timeout: 10_000 });
    await page.getByTitle("download").nth(i).click();
    const dl = await dlPromise;
    got.push(dl.suggestedFilename());
  }
  return got;
}

async function findTokenId(memo) {
  const rows = await apiJson("/api/v1/tokens");
  return rows.find((r) => r.memo === memo)?.id;
}

async function testType(page, t, clonePort) {
  const memo = `e2e ${t.id}`;
  try {
    await createViaUi(page, t, clonePort);
    // create dialog downloads
    const dialogNames = await downloadAll(page, t.downloads);
    if (!downloadNamesMatch(t.downloads, dialogNames)) {
      throw new Error(`dialog downloads ${JSON.stringify(dialogNames)} != expected ${JSON.stringify(t.downloads)}`);
    }
    await page.getByRole("button", { name: "done" }).click();
    await settle(page);

    // row in table + drawer downloads
    const tokenId = await findTokenId(memo);
    if (!tokenId) throw new Error("token not found in list after creation");
    await page.getByText(memo).first().click();
    await page.waitForSelector("text=Incident history", { timeout: 10_000 });
    const drawerNames = await downloadAll(page, t.downloads);
    if (!downloadNamesMatch(t.downloads, drawerNames)) {
      throw new Error(`drawer downloads ${JSON.stringify(drawerNames)} != expected`);
    }

    if (t.upload) {
      await page.locator('input[type="file"]').setInputFiles({
        name: "e2e-logo.png",
        mimeType: "image/png",
        buffer: PNG_1PX,
      });
      await page.waitForSelector("text=image uploaded", { timeout: 10_000 });
      await page.waitForSelector('img[alt="current bait"]', { timeout: 10_000 });
    }
    if (t.clone) {
      await page.waitForSelector("text=clone ok", { timeout: 10_000 });
    }
    await page.keyboard.press("Escape");
    await settle(page);

    if (t.trigger) {
      const [path, wantStatus, contains] = t.trigger(tokenId);
      // cloned pages take a moment to be cached/served; retry briefly.
      let res;
      for (let i = 0; i < 5; i++) {
        res = await gwFetch(path);
        if (res.status === wantStatus) break;
        await new Promise((r) => setTimeout(r, 300));
      }
      if (res.status !== wantStatus) throw new Error(`gateway ${path}: ${res.status} != ${wantStatus}`);
      if (contains) {
        const body = await res.text();
        if (!body.includes(contains)) throw new Error(`gateway ${path}: body missing ${contains}`);
      } else {
        await res.arrayBuffer().catch(() => {});
      }
      if (!(await waitForIncident(tokenId))) throw new Error("no incident recorded after trigger");
    }
    report(t.id, true);
  } catch (err) {
    report(t.id, false, err instanceof Error ? err.message : String(err));
    try {
      await page.screenshot({ path: `/tmp/e2e-fail-${t.id}.png`, fullPage: true });
      console.log(`  screenshot: /tmp/e2e-fail-${t.id}.png`);
    } catch {}
    try { await page.keyboard.press("Escape"); } catch {}
    await settle(page);
    await page.goto(`${CONSOLE}/tokens`);
    await page.waitForSelector("text=New token");
  }
}

const { srv: cloneSrv, port: clonePort } = await startCloneSite();
const browser = await launchBrowser();
try {
  const page = await loginPage(browser);
  await page.goto(`${CONSOLE}/tokens`);
  await page.waitForSelector("text=New token");

  for (const t of TYPES) {
    await testType(page, t, clonePort);
  }
} finally {
  await browser.close();
  cloneSrv.close();
}

if (summarize("token types") > 0) process.exit(1);
