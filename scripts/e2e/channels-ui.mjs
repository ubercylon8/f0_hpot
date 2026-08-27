/**
 * f0_hpot e2e: systematic UI test of the Alert Channels section.
 *
 * Stands up sink receivers (HTTP, UDP/syslog, minimal SMTP) and drives the
 * real console: add-channel forms per kind, test-delivery against the
 * sinks (proving each sender's wire format end-to-end), endpoint summaries,
 * secret masking, enable/disable with failure-counter reset, error toast
 * on unreachable endpoints, delete, and the empty state.
 *
 *   F0_E2E_KEY=f0k_... node scripts/e2e/channels-ui.mjs
 */
import { createServer as httpCreateServer } from "node:http";
import { createServer as netCreateServer } from "node:net";
import { createSocket } from "node:dgram";
import {
  CONSOLE,
  apiJson,
  gwFetch,
  launchBrowser,
  loginPage,
  makeReporter,
  requireKey,
} from "./lib.mjs";

requireKey();
const { report, summarize } = makeReporter();

async function check(name, fn) {
  try {
    await fn();
    report(name, true);
  } catch (err) {
    report(name, false, err instanceof Error ? err.message : String(err));
  }
}

function startHttpSink() {
  const requests = [];
  const srv = httpCreateServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      requests.push({ method: req.method, url: req.url, headers: req.headers, body });
      res.writeHead(200, { "content-type": "application/json" });
      res.end("{}");
    });
  });
  return new Promise((resolve) =>
    srv.listen(0, "127.0.0.1", () =>
      resolve({ srv, port: srv.address().port, requests }),
    ),
  );
}

function startUdpSink() {
  const messages = [];
  const sock = createSocket("udp4");
  sock.on("message", (msg) => messages.push(msg.toString()));
  return new Promise((resolve) =>
    sock.bind(0, "127.0.0.1", () =>
      resolve({ sock, port: sock.address().port, messages }),
    ),
  );
}

/** Minimal SMTP sink: EHLO/MAIL/RCPT/DATA, captures message bodies. */
function startSmtpSink() {
  const mails = [];
  const srv = netCreateServer((conn) => {
    let inData = false;
    let buf = "";
    let mail = "";
    conn.write("220 sink ESMTP ready\r\n");
    conn.on("data", (chunk) => {
      buf += chunk.toString();
      let idx;
      while ((idx = buf.indexOf("\r\n")) !== -1) {
        const line = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        if (inData) {
          if (line === ".") {
            inData = false;
            mails.push(mail);
            conn.write("250 queued\r\n");
          } else {
            mail += line + "\n";
          }
          continue;
        }
        const verb = line.split(" ")[0].toUpperCase();
        if (verb === "DATA") {
          conn.write("354 go ahead\r\n");
          inData = true;
          mail = "";
        } else if (verb === "QUIT") {
          conn.write("221 bye\r\n");
          conn.end();
        } else {
          conn.write("250 OK\r\n");
        }
      }
    });
  });
  return new Promise((resolve) =>
    srv.listen(0, "127.0.0.1", () =>
      resolve({ srv, port: srv.address().port, mails }),
    ),
  );
}

/** Wait until `fn()` returns a non-empty array (delivery is async). */
async function until(fn, what, ms = 4000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    const got = fn();
    if (got.length > 0) return got;
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`nothing received: ${what}`);
}

function card(page, text) {
  return page.locator("div.rounded-lg.border", { hasText: text }).first();
}

const http = await startHttpSink();
const udp = await startUdpSink();
const smtp = await startSmtpSink();
const browser = await launchBrowser();
const page = await loginPage(browser);

const SECRET = "e2e-secret-123";

async function addChannel(kindLabel, fill) {
  await page.getByRole("button", { name: "Add channel" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.waitFor();
  await dialog.getByRole("combobox").first().click();
  await page.getByRole("option", { name: kindLabel, exact: true }).click();
  await fill(dialog);
  await dialog.getByRole("button", { name: "Add channel", exact: true }).click();
  await page.waitForSelector("text=channel added");
}

try {
  await page.goto(`${CONSOLE}/channels`);
  await page.waitForSelector("text=Where incident alerts are delivered");

  await check("seeded channels render with endpoint summaries and states", async () => {
    await card(page, "https://hooks.slack.example.com").waitFor();
    await card(page, "siem.corp.local").waitFor();
    await card(page, "smtp.corp.local").waitFor();
    // seeded: syslog disabled, email has failure badge
    await card(page, "siem.corp.local").locator("text=disabled").waitFor();
    await card(page, "smtp.corp.local").locator("text=consecutive failures").waitFor();
  });

  await check("webhook: form, test delivery, signature header, secret masked", async () => {
    const url = `http://127.0.0.1:${http.port}/webhook`;
    await addChannel("Webhook", async (d) => {
      await d.locator("input").nth(0).fill(url);
      await d.locator("input").nth(1).fill(SECRET);
    });
    await card(page, url).waitFor();
    await card(page, url).getByRole("button", { name: "test" }).click();
    await page.waitForSelector("text=test alert delivered via webhook");
    const [req] = await until(
      () => http.requests.filter((r) => r.url === "/webhook"),
      "webhook request",
    );
    if (req.method !== "POST") throw new Error(`method ${req.method}`);
    if (req.headers["x-f0-signature"] !== SECRET) {
      throw new Error("x-f0-signature header missing/wrong");
    }
    if (!req.body.includes("test00000000")) throw new Error("payload missing test alert");
    // secret is masked server-side in the list endpoint
    const channels = await apiJson("/api/v1/alert-channels");
    const created = channels.find((c) => c.config.url === url);
    if (!created) throw new Error("channel not in list");
    if (created.config.secret !== "•••") {
      throw new Error(`secret not masked: ${JSON.stringify(created.config)}`);
    }
  });

  await check("elasticsearch: form + test delivery to <index>/_doc with basic auth", async () => {
    const url = `http://127.0.0.1:${http.port}/elastic`;
    await addChannel("Elasticsearch", async (d) => {
      await d.locator("input").nth(0).fill(url);
      await d.locator("input").nth(1).fill("e2e_idx");
      await d.locator("input").nth(2).fill("elastic");
      await d.locator("input").nth(3).fill("e2e-es-pass");
    });
    await card(page, url).getByRole("button", { name: "test" }).click();
    await page.waitForSelector("text=test alert delivered via elasticsearch");
    const [req] = await until(
      () => http.requests.filter((r) => r.url === "/elastic/e2e_idx/_doc"),
      "elastic doc",
    );
    if (!req.headers.authorization?.startsWith("Basic ")) throw new Error("basic auth missing");
    if (!req.body.includes("test00000000")) throw new Error("doc missing test alert");
  });

  await check("loki: form + test delivery to /loki/api/v1/push with tenant header", async () => {
    const url = `http://127.0.0.1:${http.port}/loki`;
    await addChannel("Grafana Loki", async (d) => {
      await d.locator("input").nth(0).fill(url);
      await d.locator("input").nth(1).fill("e2e-tenant");
    });
    await card(page, url).getByRole("button", { name: "test" }).click();
    await page.waitForSelector("text=test alert delivered via loki");
    const [req] = await until(
      () => http.requests.filter((r) => r.url === "/loki/loki/api/v1/push"),
      "loki push",
    );
    if (req.headers["x-scope-orgid"] !== "e2e-tenant") throw new Error("tenant header missing");
    if (!req.body.includes("canary_triggered")) throw new Error("loki line missing");
  });

  await check("syslog: form + UDP datagram with RFC5424 content", async () => {
    await addChannel("Syslog (UDP)", async (d) => {
      await d.locator("input").nth(0).fill("127.0.0.1");
      await d.locator("input").nth(1).fill(String(udp.port));
      await d.locator("input").nth(2).fill("e2e-syslog");
    });
    await card(page, `127.0.0.1:${udp.port}`).getByRole("button", { name: "test" }).click();
    await page.waitForSelector("text=test alert delivered via syslog");
    const msgs = await until(
      () => udp.messages.filter((m) => m.includes("test00000000")),
      "syslog datagram",
    );
    if (!msgs[0].startsWith("<")) throw new Error("missing PRI prefix");
    if (!msgs[0].includes("e2e-syslog")) throw new Error("app_name missing");
  });

  await check("email: form + SMTP delivery with subject prefix", async () => {
    await addChannel("Email (SMTP)", async (d) => {
      await d.locator("input").nth(0).fill("127.0.0.1");
      await d.locator("input").nth(1).fill(String(smtp.port));
      // smtp_user / smtp_pass intentionally left blank (optional)
      await d.locator("input").nth(4).fill("f0_hpot@e2e.local");
      await d.locator("input").nth(5).fill("soc@e2e.local");
      await d.locator("input").nth(6).fill("[e2e]");
    });
    await card(page, "f0_hpot@e2e.local").getByRole("button", { name: "test" }).click();
    await page.waitForSelector("text=test alert delivered via email");
    const got = await until(
      () => smtp.mails.filter((m) => m.includes("[e2e] canary triggered")),
      "email",
    );
    if (!got[0].includes("test00000000")) throw new Error("subject missing token id");
  });

  await check("error toast on unreachable endpoint", async () => {
    await card(page, "hooks.slack.example.com").getByRole("button", { name: "test" }).click();
    await page.waitForSelector("text=test delivery failed", { timeout: 15_000 });
  });

  await check("dispatch failure badge appears, disable resets it, enable restores", async () => {
    // a channel pointing at a dead port, then a REAL trigger through the
    // gateway so the dispatcher actually fails against it
    const dead = await apiJson("/api/v1/alert-channels", {
      method: "POST",
      body: JSON.stringify({
        kind: "webhook",
        config: { url: "http://127.0.0.1:9/dead-end" },
      }),
    });
    const tok = await apiJson("/api/v1/tokens", {
      method: "POST",
      body: JSON.stringify({ type: "web_bug", memo: "e2e channel failure" }),
    });
    await gwFetch(`/${tok.id}/pixel.gif`);
    const deadCard = card(page, "127.0.0.1:9/dead-end");
    await deadCard.locator("text=consecutive failures").waitFor({ timeout: 20_000 });
    await deadCard.locator('button[role="switch"]').click();
    await page.waitForSelector("text=channel disabled (failure counter reset)");
    await deadCard.locator("text=disabled").waitFor();
    if ((await deadCard.locator("text=consecutive failures").count()) !== 0) {
      throw new Error("failure badge still visible after reset");
    }
    await deadCard.locator('button[role="switch"]').click();
    await page.waitForSelector("text=channel enabled");
  });

  await check("delete removes channels; empty state shows; seeded channels restored", async () => {
    // delete every channel card
    for (;;) {
      const del = page.getByRole("button", { name: "delete", exact: true }).first();
      if ((await del.count()) === 0) break;
      await del.click();
      await page.waitForSelector("text=channel deleted");
      await page.waitForTimeout(300);
    }
    await page.waitForSelector("text=No channels yet");
    // restore the demo's seeded channels via the API
    await apiJson("/api/v1/alert-channels", {
      method: "POST",
      body: JSON.stringify({
        kind: "webhook",
        config: { url: "https://hooks.slack.example.com/services/T00/B00/xxx", secret: "shhh" },
      }),
    });
    await apiJson("/api/v1/alert-channels", {
      method: "POST",
      body: JSON.stringify({ kind: "syslog", config: { host: "siem.corp.local", port: 514 } }),
    });
    await apiJson("/api/v1/alert-channels", {
      method: "POST",
      body: JSON.stringify({
        kind: "email",
        config: { smtp_host: "smtp.corp.local", from: "f0_hpot@corp.local", to: "soc@corp.local", subject_prefix: "[f0_hpot]" },
      }),
    });
    const syslog = (await apiJson("/api/v1/alert-channels")).find((c) => c.kind === "syslog");
    await apiJson(`/api/v1/alert-channels/${syslog.id}`, {
      method: "PATCH",
      body: JSON.stringify({ enabled: false }),
    });
    await page.reload();
    await card(page, "hooks.slack.example.com").waitFor({ timeout: 15_000 });
  });
} finally {
  await browser.close();
  http.srv.close();
  udp.sock.close();
  smtp.srv.close();
}

if (summarize("channel UI checks") > 0) process.exit(1);
