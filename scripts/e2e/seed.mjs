/**
 * Seed a fresh demo stack into the state the e2e suites assume.
 *
 * The suites expect a populated console — a `demo-console` API key, an
 * enrolled agent, and three alert channels in specific states. Nothing in
 * the repo created that, so running the suite against a clean database
 * failed in ways that looked like product regressions but were missing
 * fixtures. Run this once after starting the stack.
 *
 *   F0_E2E_ADMIN=<admin token> node scripts/e2e/seed.mjs
 *
 * It prints the console key to use as F0_E2E_KEY.
 */
import { existsSync } from "node:fs";

const API = process.env.F0_E2E_API ?? "http://127.0.0.1:18443";
const ADMIN = process.env.F0_E2E_ADMIN;
const ENROLL = process.env.F0_E2E_ENROLL ?? "bootstrap-test-123";
const DB = process.env.F0_DB_PATH;

if (!ADMIN) {
  console.error("F0_E2E_ADMIN (the API's F0_ADMIN_TOKEN) is required");
  process.exit(2);
}

async function api(path, init = {}, key = ADMIN) {
  const res = await fetch(`${API}${path}`, {
    ...init,
    headers: {
      ...(init.body ? { "content-type": "application/json" } : {}),
      authorization: `Bearer ${key}`,
    },
  });
  if (!res.ok) throw new Error(`${path}: ${res.status} ${await res.text()}`);
  return res.status === 204 ? null : res.json();
}

const post = (path, body) => api(path, { method: "POST", body: JSON.stringify(body) });

// 1. The console key the suites authenticate with. It must be a real key
//    (not the admin env token) so the settings suite can assert it shows a
//    last-used time.
const existingKeys = await api("/api/v1/auth/keys");
let consoleKey = null;
if (!existingKeys.some((k) => k.label === "demo-console")) {
  consoleKey = (await post("/api/v1/auth/keys", { label: "demo-console" })).key;
}

// 2. An agent for the dashboard/deployment checks.
const agents = await api("/api/v1/agents");
if (!agents.some((a) => a.hostname === "dmz-honeypot-01")) {
  const res = await fetch(`${API}/api/v1/agent/enroll`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      enrollment_token: ENROLL,
      hostname: "dmz-honeypot-01",
      platform: "linux/amd64",
      version: "1.4.2",
    }),
  });
  if (!res.ok) throw new Error(`enroll: ${res.status} (check F0_E2E_ENROLL)`);
}

// 3. Three channels in the states the channels suite asserts: a healthy
//    webhook, a disabled syslog, and an email channel showing failures.
const channels = await api("/api/v1/alert-channels");
const has = (needle) => channels.some((c) => JSON.stringify(c.config).includes(needle));

if (!has("hooks.slack.example.com")) {
  await post("/api/v1/alert-channels", {
    kind: "webhook",
    config: { url: "https://hooks.slack.example.com/services/T0/B0/xxx" },
  });
}
if (!has("siem.corp.local")) {
  const { id } = await post("/api/v1/alert-channels", {
    kind: "syslog",
    config: { host: "siem.corp.local", port: 514 },
  });
  await api(`/api/v1/alert-channels/${id}`, {
    method: "PATCH",
    body: JSON.stringify({ enabled: false }),
  });
}
let mailId = null;
if (!has("smtp.corp.local")) {
  mailId = (
    await post("/api/v1/alert-channels", {
      kind: "email",
      config: { smtp_host: "smtp.corp.local", from: "f0@corp.local", to: "soc@corp.local" },
    })
  ).id;
}

// failure_count is server-managed (incremented only by real dispatch
// failures), so the "N consecutive failures" badge has to be set directly.
if (mailId) {
  if (DB && existsSync(DB)) {
    const { DatabaseSync } = await import("node:sqlite");
    const db = new DatabaseSync(DB);
    db.prepare("UPDATE alert_channels SET failure_count = 3 WHERE id = ?").run(mailId);
    db.close();
  } else {
    console.warn(
      "! F0_DB_PATH not set or missing: the email channel's failure badge was not seeded,\n" +
        "  so 'seeded channels render' will fail. Re-run with F0_DB_PATH pointing at the demo DB.",
    );
  }
}

console.log("seeded: demo-console key, dmz-honeypot-01 agent, 3 alert channels");
if (consoleKey) console.log(`\nexport F0_E2E_KEY=${consoleKey}`);
else console.log("\n(demo-console key already existed — reuse the F0_E2E_KEY you saved)");
