#!/usr/bin/env node
/**
 * f0_hpot — production installer (zero-dependency TUI).
 *
 * Node ≥ 20, no npm packages: raw ANSI spinners, progress bars, boxed
 * sections. Guides an internet deployment end to end: preflight →
 * questions → secrets → DNS records (verified) → binaries/GeoIP →
 * docker compose up → health checks → first-run card.
 *
 * Flags:
 *   --reconfigure   re-ask all questions (secrets are preserved)
 *   --dry-run       stop before `docker compose up` (writes .env + Caddyfile)
 */
import { execFileSync, execFile, spawn } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  copyFileSync,
  createWriteStream,
  chmodSync,
} from "node:fs";
import { createInterface } from "node:readline";
import { randomBytes } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const DEPLOY_DIR = fileURLToPath(new URL(".", import.meta.url));
const REPO_ROOT = path.resolve(DEPLOY_DIR, "..");
const ENV_PATH = path.join(DEPLOY_DIR, ".env");
const LOG_PATH = path.join(DEPLOY_DIR, "install.log");
const DRY_RUN = process.argv.includes("--dry-run");
const RECONFIGURE = process.argv.includes("--reconfigure");

// ---------------------------------------------------------------- TUI kit
const ESC = "";
const C = {
  reset: `${ESC}[0m`,
  bold: `${ESC}[1m`,
  dim: `${ESC}[2m`,
  green: `${ESC}[38;5;82m`,
  amber: `${ESC}[38;5;214m`,
  red: `${ESC}[38;5;196m`,
  cyan: `${ESC}[38;5;45m`,
  gray: `${ESC}[38;5;245m`,
};
const ok = (s) => `${C.green}✓${C.reset} ${s}`;
const bad = (s) => `${C.red}✗${C.reset} ${s}`;
const info = (s) => process.stdout.write(`${C.dim}${s}${C.reset}\n`);

function hideCursor() {
  process.stdout.write(`${ESC}[?25l`);
}
function showCursor() {
  process.stdout.write(`${ESC}[?25h`);
}
process.on("exit", showCursor);

function banner() {
  const rows = [
    "",
    `${C.green}  ███████╗ ██████╗         ${C.reset}${C.bold}f0_hpot${C.reset} ${C.dim}— deception platform installer${C.reset}`,
    `${C.green}  ██╔════╝██╔═████╗        ${C.reset}${C.dim}production · single host · docker compose${C.reset}`,
    `${C.green}  █████╗  ██║██╔██║${C.reset}`,
    `${C.green}  ██╔══╝  ████╔╝██║${C.reset}`,
    `${C.green}  ██║     ╚██████╔╝${C.reset}`,
    `${C.green}  ╚═╝      ╚═════╝ ${C.reset}`,
    "",
  ];
  process.stdout.write(rows.join("\n") + "\n");
}

function box(title, lines, color = C.green) {
  const width = Math.min(
    Math.max(...[title, ...lines].map((l) => stripAnsi(l).length)) + 4,
    100,
  );
  // Wrap lines that would overflow the border.
  const wrapped = [];
  for (const l of lines) {
    let rest = l;
    while (stripAnsi(rest).length > width - 4) {
      const cut = width - 4;
      wrapped.push(rest.slice(0, cut));
      rest = `  ${rest.slice(cut)}`;
    }
    wrapped.push(rest);
  }
  const bar = "─".repeat(width - 2);
  process.stdout.write(`\n${color}╭${bar}╮${C.reset}\n`);
  if (title) {
    process.stdout.write(
      `${color}│${C.reset} ${C.bold}${title}${C.reset}${" ".repeat(Math.max(0, width - 3 - stripAnsi(title).length))}${color}│${C.reset}\n`,
    );
  }
  for (const l of wrapped) {
    process.stdout.write(
      `${color}│${C.reset} ${l}${" ".repeat(Math.max(0, width - 3 - stripAnsi(l).length))}${color}│${C.reset}\n`,
    );
  }
  process.stdout.write(`${color}╰${bar}╯${C.reset}\n`);
}

function stripAnsi(s) {
  return s.replace(/\x1b\[[0-9;]*m/g, "");
}

function phase(n, title) {
  process.stdout.write(`\n${C.cyan}${C.bold}[${n}/7] ${title}${C.reset}\n${C.dim}${"─".repeat(48)}${C.reset}\n`);
}

function spinner(text) {
  const frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
  let i = 0;
  hideCursor();
  const timer = setInterval(() => {
    process.stdout.write(`\r${C.cyan}${frames[i++ % frames.length]}${C.reset} ${text}`);
  }, 80);
  return {
    succeed(msg = text) {
      clearInterval(timer);
      showCursor();
      process.stdout.write(`\r${ok(msg)}${" ".repeat(20)}\n`);
    },
    fail(msg = text) {
      clearInterval(timer);
      showCursor();
      process.stdout.write(`\r${bad(msg)}${" ".repeat(20)}\n`);
    },
  };
}

function progress(label, fraction, extra = "") {
  const width = 30;
  const filled = Math.round(width * Math.min(1, fraction));
  const bar = `${C.green}${"█".repeat(filled)}${C.gray}${"░".repeat(width - filled)}${C.reset}`;
  process.stdout.write(
    `\r${bar} ${String(Math.round(fraction * 100)).padStart(3)}% ${label} ${C.dim}${extra}${C.reset}    `,
  );
  if (fraction >= 1) process.stdout.write("\n");
}

const rl = createInterface({ input: process.stdin, output: process.stdout });

// Line queue: readline drops lines that arrive while no question is
// pending (e.g. piped stdin). Buffer every line; prompts consume in
// order, and a closed stdin rejects instead of hanging forever.
const lineQueue = [];
let rlClosed = false;
let lineWaiter = null;
rl.on("line", (l) => {
  lineQueue.push(l);
  lineWaiter?.();
});
rl.on("close", () => {
  rlClosed = true;
  lineWaiter?.();
});

function nextLine() {
  return new Promise((resolve, reject) => {
    const tryTake = () => {
      if (lineQueue.length > 0) {
        // Clear the waiter BEFORE resolving, or it keeps consuming
        // (and discarding) lines meant for the next prompt.
        lineWaiter = null;
        return resolve(lineQueue.shift());
      }
      if (rlClosed) {
        lineWaiter = null;
        return reject(new Error("stdin closed before all answers were given"));
      }
      lineWaiter = tryTake;
    };
    tryTake();
  });
}

function prompt(question, { def = "", validate = () => true, hint = "" } = {}) {
  const ask = async () => {
    const suffix = def ? ` ${C.dim}(${def})${C.reset}` : "";
    process.stdout.write(`${C.amber}?${C.reset} ${question}${suffix}: `);
    const answer = await nextLine();
    const value = answer.trim() || def;
    const err = validate(value);
    if (err === true) return value;
    process.stdout.write(`${C.red}  ${err || "invalid value"}${C.reset}\n`);
    return ask();
  };
  if (hint) process.stdout.write(`${C.dim}  ${hint}${C.reset}\n`);
  return ask();
}

async function confirm(question, defYes = true) {
  const a = await prompt(`${question} ${C.dim}${defYes ? "[Y/n]" : "[y/N]"}${C.reset}`, {
    def: defYes ? "y" : "n",
  });
  return a.toLowerCase().startsWith("y");
}

async function select(question, options) {
  process.stdout.write(`${C.amber}?${C.reset} ${question}\n`);
  options.forEach((o, i) => {
    process.stdout.write(
      `  ${C.green}${i + 1}${C.reset}) ${o.label}${o.hint ? ` ${C.dim}— ${o.hint}${C.reset}` : ""}\n`,
    );
  });
  const n = await prompt("choose", {
    def: "1",
    validate: (v) =>
      Number(v) >= 1 && Number(v) <= options.length ? true : `pick 1-${options.length}`,
  });
  return options[Number(n) - 1].value;
}

// ---------------------------------------------------------------- helpers
function run(cmd, args, opts = {}) {
  try {
    return execFileSync(cmd, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], ...opts }).trim();
  } catch (err) {
    if (opts.ignoreError) return "";
    throw err;
  }
}

function which(cmd) {
  return !!run("which", [cmd], { ignoreError: true });
}

function log(line) {
  writeFileSync(LOG_PATH, `${new Date().toISOString()} ${line}\n`, { flag: "a" });
}

const FQDN_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i;
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;

function detectPublicIp() {
  const out = run("ip", ["route", "get", "1.1.1.1"], { ignoreError: true });
  const src = out.match(/src (\d{1,3}(?:\.\d{1,3}){3})/);
  const dev = out.match(/dev (\S+)/);
  return { ip: src?.[1] ?? "", iface: dev?.[1] ?? "" };
}

function dig(query, type) {
  return run("dig", ["+short", query, type, "@8.8.8.8"], { ignoreError: true });
}

function downloadWithProgress(url, dest, label) {
  return new Promise((resolve, reject) => {
    let lastPrint = 0;
    fetch(url).then(async (res) => {
      if (!res.ok) return reject(new Error(`${url}: HTTP ${res.status}`));
      const total = Number(res.headers.get("content-length") ?? 0);
      const out = createWriteStream(dest);
      let got = 0;
      for await (const chunk of res.body) {
        got += chunk.length;
        out.write(chunk);
        // Print at most every 120ms (plus the final 100% line).
        const fraction = total > 0 ? got / total : 0;
        if (Date.now() - lastPrint > 120 || fraction >= 1) {
          lastPrint = Date.now();
          const extra = total > 0
            ? `${(got / 1e6).toFixed(1)}/${(total / 1e6).toFixed(1)} MB`
            : `${(got / 1e6).toFixed(1)} MB`;
          progress(label, fraction, extra);
        }
      }
      out.end();
      out.on("finish", () => {
        progress(label, 1, `${(got / 1e6).toFixed(1)} MB`);
        resolve();
      });
    }, reject);
  });
}

// ---------------------------------------------------------------- phases
const answers = {};

async function phasePreflight() {
  phase(1, "Preflight checks");
  const checks = [
    ["Node.js ≥ 20", () => Number(process.versions.node.split(".")[0]) >= 20 || "upgrade node"],
    ["docker engine", () => which("docker") || "install docker"],
    ["docker compose plugin", () => !!run("docker", ["compose", "version"], { ignoreError: true }) || "install the compose plugin"],
    ["openssl", () => which("openssl") || "install openssl"],
    ["curl", () => which("curl") || "install curl"],
    ["dig (dnsutils)", () => which("dig") || "install dnsutils/bind-utils"],
    ["go toolchain (optional, builds agent binaries)", () => which("go") || true],
  ];
  for (const [label, fn] of checks) {
    const sp = spinner(label);
    const r = fn();
    if (r === true) sp.succeed(label);
    else {
      sp.fail(`${label} — ${r}`);
      throw new Error(`preflight failed: ${label}`);
    }
  }

  // port conflicts (informational: systemd-resolved / MTA)
  const listeners = run("ss", ["-tlnup"], { ignoreError: true });
  if (/127\.0\.0\.53:53/.test(listeners)) {
    info("note: systemd-resolved listens on 127.0.0.53:53 — harmless: the gateway binds the PUBLIC ip, not loopback.");
  }
  if (/:25\b/.test(listeners)) {
    info("note: something already listens on :25 (host MTA?) — choose a custom SMTP port below or stop it.");
  }
}

async function phaseQuestions() {
  phase(2, "Deployment questions");
  const detected = detectPublicIp();
  answers.ip = await prompt("Public IP address the gateway + console listen on", {
    def: detected.ip,
    hint: `detected on interface ${detected.iface || "?"}`,
    validate: (v) => IPV4_RE.test(v) || "expected an IPv4 address",
  });
  answers.iface = detected.iface;

  answers.tokenDomain = await prompt("Token base domain (attacker-facing, e.g. canary.example.com)", {
    validate: (v) => FQDN_RE.test(v) || "expected a valid domain",
  });

  answers.consoleMode = await select("Console exposure", [
    { label: "private (recommended)", value: "private", hint: "loopback only; reach via ssh -L tunnel" },
    { label: "public", value: "public", hint: "internet-reachable with ACME TLS" },
  ]);
  if (answers.consoleMode === "public") {
    answers.consoleDomain = await prompt("Console FQDN (e.g. soc.example.com)", {
      validate: (v) => FQDN_RE.test(v) || "expected a valid domain",
    });
    answers.acmeEmail = await prompt("ACME contact email (for the console cert)", {
      validate: (v) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v) || "expected an email address",
    });
  } else {
    answers.consoleDomain = "localhost";
    answers.acmeEmail = "";
  }

  answers.mailDomain = await prompt("Email-token domain (MX target)", {
    def: answers.tokenDomain,
    validate: (v) => FQDN_RE.test(v) || "expected a valid domain",
  });

  answers.tlsMode = await select("Token-surface TLS mode", [
    { label: "http (default)", value: "http", hint: "reach-back content isn't secret; simplest" },
    { label: "import wildcard cert", value: "import", hint: "you provide cert+key for *.<token domain>" },
    { label: "on-demand TLS", value: "on_demand", hint: "per-hostname certs; rate-limit bound" },
  ]);
  if (answers.tlsMode === "import") {
    answers.certPath = await prompt("wildcard certificate file (full chain)", {
      validate: (v) => existsSync(v) || "file not found",
    });
    answers.keyPath = await prompt("wildcard private key file", {
      validate: (v) => existsSync(v) || "file not found",
    });
  }

  answers.smtpPort = await prompt("SMTP ingest port for email tokens", {
    def: "2525",
    hint: "use 25 only if no other MTA binds it",
    validate: (v) => (Number(v) > 0 && Number(v) < 65536 ? true : "expected a port number"),
  });

  answers.geoip = await confirm("Download the DB-IP city GeoLite database (~62MB) for GeoIP?", true);
  answers.buildBinaries = which("go")
    ? await confirm("Build agent release binaries for all 5 platforms with Go?", true)
    : false;
}

function readExistingSecrets() {
  const secrets = {};
  if (existsSync(ENV_PATH) && !RECONFIGURE) {
    const env = readFileSync(ENV_PATH, "utf8");
    for (const key of ["F0_ADMIN_TOKEN", "F0_INTERNAL_SECRET", "F0_ENROLLMENT_TOKEN"]) {
      const m = env.match(new RegExp(`^${key}=(.+)$`, "m"));
      if (m) secrets[key] = m[1].trim();
    }
  }
  for (const key of ["F0_ADMIN_TOKEN", "F0_INTERNAL_SECRET", "F0_ENROLLMENT_TOKEN"]) {
    if (!secrets[key]) secrets[key] = randomBytes(24).toString("base64");
  }
  return secrets;
}

function phaseSecrets() {
  phase(3, "Secrets & configuration");
  const sp = spinner("generating configuration");
  const secrets = readExistingSecrets();
  answers.secrets = secrets;

  const env = [
    "# f0_hpot production configuration — generated by install.mjs",
    `# ${new Date().toISOString()} · keep this file private (chmod 600)`,
    "",
    `F0_TOKEN_DOMAINS=${answers.tokenDomain}`,
    `F0_GATEWAY_ORIGIN=${answers.tlsMode === "http" ? "http" : "https"}://${answers.tokenDomain}`,
    `F0_GATEWAY_IP=${answers.ip}`,
    `GATEWAY_PUBLISH_IP=${answers.ip}`,
    `F0_MAIL_DOMAINS=${answers.mailDomain}`,
    `F0_SMTP_PORT=${answers.smtpPort}`,
    `CONSOLE_DOMAIN=${answers.consoleDomain}`,
    `CONSOLE_PUBLISH_IP=${answers.consoleMode === "public" ? answers.ip : "127.0.0.1"}`,
    `TOKEN_TLS_MODE=${answers.tlsMode}`,
    ...(answers.acmeEmail ? [`ACME_EMAIL=${answers.acmeEmail}`] : []),
    "",
    `F0_ADMIN_TOKEN=${secrets.F0_ADMIN_TOKEN}`,
    `F0_INTERNAL_SECRET=${secrets.F0_INTERNAL_SECRET}`,
    `F0_ENROLLMENT_TOKEN=${secrets.F0_ENROLLMENT_TOKEN}`,
    "F0_MAX_ALERTS_PER_MINUTE=1",
    ...(answers.geoip ? ["F0_GEOIP_DB=/geoip/dbip-city-lite.mmdb"] : []),
    "",
  ].join("\n");
  writeFileSync(ENV_PATH, env, { mode: 0o600 });
  chmodSync(ENV_PATH, 0o600);
  sp.succeed(`.env written (${ENV_PATH}, mode 600)`);

  renderCaddyfile();
}

function renderCaddyfile() {
  const sp = spinner("rendering Caddyfile");
  const globalOpts =
    answers.acmeEmail ? `{\n\temail {$ACME_EMAIL}\n}\n\n` : "";
  const consoleBlock =
    answers.consoleMode === "public"
      ? `{$CONSOLE_DOMAIN} {\n\tencode gzip\n\thandle /api/* {\n\t\treverse_proxy {$API_ORIGIN}\n\t}\n\thandle {\n\t\troot * /srv/www\n\t\ttry_files {path} /index.html\n\t\tfile_server\n\t}\n}`
      : `:8080 {\n\tencode gzip\n\thandle /api/* {\n\t\treverse_proxy {$API_ORIGIN}\n\t}\n\thandle {\n\t\troot * /srv/www\n\t\ttry_files {path} /index.html\n\t\tfile_server\n\t}\n}`;

  let tokenBlock = "";
  if (answers.tlsMode === "import") {
    mkdirSync(path.join(DEPLOY_DIR, "certs"), { recursive: true });
    copyFileSync(answers.certPath, path.join(DEPLOY_DIR, "certs", "wildcard.crt"));
    copyFileSync(answers.keyPath, path.join(DEPLOY_DIR, "certs", "wildcard.key"));
    tokenBlock = `{$TOKEN_DOMAIN}, *.{$TOKEN_DOMAIN} {\n\ttls /certs/wildcard.crt /certs/wildcard.key\n\treverse_proxy {$GATEWAY_ORIGIN}\n}`;
  } else if (answers.tlsMode === "on_demand") {
    tokenBlock = `{$TOKEN_DOMAIN}, *.{$TOKEN_DOMAIN} {\n\ttls {\n\t\ton_demand\n\t}\n\treverse_proxy {$GATEWAY_ORIGIN}\n}`;
  }

  const template = readFileSync(path.join(DEPLOY_DIR, "Caddyfile.template"), "utf8");
  writeFileSync(
    path.join(DEPLOY_DIR, "Caddyfile"),
    globalOpts +
      template
        .replaceAll("{{CONSOLE_BLOCK}}", consoleBlock)
        .replaceAll("{{TOKEN_BLOCK}}", tokenBlock),
  );
  sp.succeed(`Caddyfile rendered (console: ${answers.consoleMode}, tokens: ${answers.tlsMode})`);
}

async function phaseDns() {
  phase(4, "DNS records");
  const records = [
    ["A", `ns1.${answers.tokenDomain}`, answers.ip, "gateway nameserver identity"],
    ["NS", answers.tokenDomain, `ns1.${answers.tokenDomain}`, "delegates the token zone to the gateway"],
    ["A", `*.${answers.tokenDomain}`, answers.ip, "wildcard → host (HTTP token URLs)"],
    ["MX", answers.mailDomain, `ns1.${answers.tokenDomain}`, "email tokens (priority 10)"],
  ];
  if (answers.consoleMode === "public") {
    records.push(["A", answers.consoleDomain, answers.ip, "console (ACME + access)"]);
  }
  box(
    "Create these DNS records at your provider",
    [
      ...records.map(([t, name, value, why]) => `${C.bold}${t.padEnd(4)}${C.reset}${name} ${C.dim}→${C.reset} ${value} ${C.dim}# ${why}${C.reset}`),
      "",
      `${C.dim}TTL 60–300s. Propagation may take a few minutes.${C.reset}`,
    ],
    C.cyan,
  );
  await prompt("press ENTER when the records are in place", { def: "" });

  for (;;) {
    const checks = [
      [`A ns1.${answers.tokenDomain} → ${answers.ip}`, dig(`ns1.${answers.tokenDomain}`, "A").includes(answers.ip)],
      [`NS ${answers.tokenDomain} → ns1`, dig(answers.tokenDomain, "NS").includes(`ns1.${answers.tokenDomain}`)],
      [`MX ${answers.mailDomain} → ns1`, dig(answers.mailDomain, "MX").includes(`ns1.${answers.tokenDomain}`)],
    ];
    if (answers.consoleMode === "public") {
      checks.push([`A ${answers.consoleDomain} → ${answers.ip}`, dig(answers.consoleDomain, "A").includes(answers.ip)]);
    }
    let allOk = true;
    for (const [label, pass] of checks) {
      process.stdout.write(`${pass ? ok(label) : bad(label)}\n`);
      if (!pass) allOk = false;
    }
    if (allOk) return;
    const action = await select("some records are not visible yet", [
      { label: "re-check", value: "retry", hint: "after waiting for propagation" },
      { label: "skip verification (not recommended)", value: "skip" },
      { label: "abort install", value: "abort" },
    ]);
    if (action === "retry") continue;
    if (action === "skip") return;
    throw new Error("aborted at DNS verification");
  }
}

async function phaseBuild() {
  phase(5, "Binaries & GeoIP");
  mkdirSync(path.join(DEPLOY_DIR, "release-bin"), { recursive: true });
  mkdirSync(path.join(DEPLOY_DIR, "data"), { recursive: true });

  if (answers.buildBinaries) {
    const sp = spinner("cross-compiling 5 agent platforms (go build)");
    try {
      run("make", ["-C", path.join(REPO_ROOT, "agent"), "release", `OUT=${path.join(DEPLOY_DIR, "release-bin")}`], {
        ignoreError: false,
      });
      sp.succeed("agent binaries built (linux/darwin/windows, amd64+arm64)");
    } catch {
      sp.fail("binary build failed — see install.log; place binaries into deploy/release-bin manually");
    }
  } else {
    info("skipping binary build — place release binaries into deploy/release-bin yourself (make -C agent release).");
  }

  if (answers.geoip && !existsSync(path.join(DEPLOY_DIR, "data", "dbip-city-lite.mmdb"))) {
    const url = "https://download.db-ip.com/free/dbip-city-lite-2026-08.mmdb.gz";
    await downloadWithProgress(url, path.join(DEPLOY_DIR, "data", "dbip-city-lite.mmdb.gz"), "geoip db");
    const sp = spinner("decompressing geoip db");
    run("gunzip", ["-f", path.join(DEPLOY_DIR, "data", "dbip-city-lite.mmdb.gz")]);
    sp.succeed("geoip database ready (DB-IP city-lite)");
  } else if (answers.geoip) {
    info("geoip database already present, keeping it.");
  }
}

function compose(args, label) {
  return new Promise((resolve, reject) => {
    const sp = spinner(label);
    const p = spawn(
      "docker",
      ["compose", "-f", path.join(DEPLOY_DIR, "docker-compose.yml"), "--env-file", ENV_PATH, ...args],
      { cwd: DEPLOY_DIR },
    );
    p.stdout.on("data", (d) => log(d.toString().trim()));
    p.stderr.on("data", (d) => log(d.toString().trim()));
    p.on("close", (code) => {
      if (code === 0) {
        sp.succeed(label);
        resolve();
      } else {
        sp.fail(`${label} (exit ${code}) — see ${LOG_PATH}`);
        reject(new Error(`docker compose ${args.join(" ")} failed`));
      }
    });
  });
}

async function phaseDeploy() {
  phase(6, "Launch & health checks");
  if (DRY_RUN) {
    info("--dry-run: skipping docker compose up. .env and Caddyfile are ready.");
    return;
  }
  await compose(["up", "-d", "--build"], "docker compose up -d --build");

  // API through the console proxy (private mode serves :8080 locally).
  {
    const sp = spinner("health: API /status via console proxy");
    const base = answers.consoleMode === "public" ? `https://${answers.consoleDomain}` : "http://127.0.0.1:8080";
    const out = run("curl", [
      "-sfk", "--max-time", "20", "--retry", "5", "--retry-delay", "2", "--retry-all-errors",
      "-H", `authorization: Bearer ${answers.secrets.F0_ADMIN_TOKEN}`,
      `${base}/api/v1/status`,
    ], { ignoreError: true });
    if (out.includes("authOpenMode")) sp.succeed("health: API answering");
    else {
      sp.fail("health: API did not answer");
      throw new Error("health check failed: api");
    }
  }
  // Gateway HTTP on the public IP.
  {
    const sp = spinner("health: gateway HTTP");
    const code = run("curl", [
      "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "10",
      "-H", `Host: probe.${answers.tokenDomain}`, `http://${answers.ip}/`,
    ], { ignoreError: true });
    if (["200", "404", "421"].includes(code)) sp.succeed(`health: gateway HTTP serving (${code})`);
    else {
      sp.fail(`health: gateway HTTP (${code || "no answer"})`);
      throw new Error("health check failed: gateway http");
    }
  }
  // Gateway DNS answers with the public IP.
  {
    const sp = spinner("health: gateway DNS");
    const got = run("dig", ["+short", "A", `probe.${answers.tokenDomain}`, `@${answers.ip}`], { ignoreError: true });
    if (got.includes(answers.ip)) sp.succeed("health: gateway DNS authoritative");
    else {
      sp.fail(`health: gateway DNS (got "${got}")`);
      throw new Error("health check failed: gateway dns");
    }
  }
}

function phaseFinish() {
  phase(7, "Done");
  const consoleUrl =
    answers.consoleMode === "public" ? `https://${answers.consoleDomain}` : "http://localhost:8080";
  const tunnelHint =
    answers.consoleMode === "public"
      ? ""
      : `${C.dim}reach it via: ssh -L 8080:127.0.0.1:8080 <user>@${answers.ip}${C.reset}`;
  const agentUrl =
    answers.tlsMode === "http" ? `http://${answers.tokenDomain}` : `https://${answers.tokenDomain}`;
  box(
    "f0_hpot is live",
    [
      `${C.bold}console${C.reset}      ${consoleUrl}`,
      ...(tunnelHint ? [tunnelHint] : []),
      `${C.bold}admin token${C.reset}  ${C.green}${answers.secrets.F0_ADMIN_TOKEN}${C.reset}`,
      `${C.dim}(shown once — store it; manage more keys in Settings)${C.reset}`,
      "",
      `${C.bold}install your first agent${C.reset} (on the honeypot host):`,
      `curl -LO ${consoleUrl}/api/v1/agent-releases/f0-deception-agent-linux-amd64 && \\`,
      `  chmod +x f0-deception-agent-linux-amd64 && \\`,
      `  sudo ./f0-deception-agent-linux-amd64 --server ${consoleUrl} \\`,
      `  --enroll ${answers.secrets.F0_ENROLLMENT_TOKEN} --install`,
      "",
      `${C.bold}token surface${C.reset}   ${agentUrl} (${answers.tlsMode}) — plant tokens from the console`,
      `${C.bold}backups${C.reset}        docker run --rm -v f0-deception_api-data:/data -v $(pwd):/backup alpine tar czf /backup/api-data.tar.gz -C /data .`,
      `${C.bold}logs${C.reset}           docker compose -f deploy/docker-compose.yml logs -f · install log: ${LOG_PATH}`,
    ],
    C.green,
  );
}

// ---------------------------------------------------------------- main
async function main() {
  banner();
  try {
    await phasePreflight();
    await phaseQuestions();
    phaseSecrets();
    await phaseDns();
    await phaseBuild();
    await phaseDeploy();
    phaseFinish();
  } catch (err) {
    box("installation failed", [`${C.red}${err.message}${C.reset}`, `details: ${LOG_PATH}`], C.red);
    rl.close();
    process.exit(1);
  }
  rl.close();
}

await main();
