import { describe, it, expect, afterEach } from "vitest";
import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { FastifyInstance } from "fastify";
import { buildServer } from "./server.js";

const ENV_VARS = ["F0_ADMIN_TOKEN", "F0_INTERNAL_SECRET", "F0_AGENT_RELEASE_DIR"] as const;

function savedEnv() {
  const saved: Record<string, string | undefined> = {};
  for (const v of ENV_VARS) saved[v] = process.env[v];
  return saved;
}

function restoreEnv(saved: Record<string, string | undefined>) {
  for (const v of ENV_VARS) {
    if (saved[v] === undefined) delete process.env[v];
    else process.env[v] = saved[v];
  }
}

async function makeServer(): Promise<FastifyInstance> {
  delete process.env.F0_ADMIN_TOKEN;
  delete process.env.F0_INTERNAL_SECRET;
  const { app } = buildServer({ dbPath: ":memory:" });
  await app.ready();
  return app;
}

function rcodesignPath(): string {
  try {
    const out = execFileSync("which", ["rcodesign"], { encoding: "utf8" }).trim();
    if (out) return out;
  } catch {
    /* fall through */
  }
  return `${process.env.HOME}/.cargo/bin/rcodesign`;
}

function hasRcodesign(): boolean {
  return existsSync(rcodesignPath());
}

async function generateCert(app: FastifyInstance, label = "test-cert") {
  const res = await app.inject({
    method: "POST",
    url: "/api/v1/codesign-certs",
    payload: {
      label,
      generate: true,
      commonName: "f0_hpot Test Signing",
      passphrase: "test-pass",
    },
  });
  expect(res.statusCode).toBe(201);
  return res.json() as { id: string; subject: string };
}

describe("code signing (Authenticode)", () => {
  const saved = savedEnv();
  afterEach(() => restoreEnv(saved));

  it("generate, list (no private material), delete", async () => {
    const app = await makeServer();
    try {
      const cert = await generateCert(app);
      expect(cert.subject).toContain("f0_hpot Test Signing");

      const list = (
        await app.inject({ method: "GET", url: "/api/v1/codesign-certs" })
      ).json() as Record<string, unknown>[];
      expect(list.length).toBe(1);
      // Private material must never leave the API.
      expect(list[0]).not.toHaveProperty("pfx");
      expect(list[0]).not.toHaveProperty("passphrase");
      expect(list[0]?.["notAfter"]).toBeTruthy();

      const del = await app.inject({
        method: "DELETE",
        url: `/api/v1/codesign-certs/${cert.id}`,
      });
      expect(del.statusCode).toBe(200);
      const after = (
        await app.inject({ method: "GET", url: "/api/v1/codesign-certs" })
      ).json() as unknown[];
      expect(after.length).toBe(0);
    } finally {
      await app.close();
    }
  });

  it("upload flow: wrong passphrase rejected, correct one stored", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "f0-upload-test-"));
    const app = await makeServer();
    try {
      // Build a .p12 out-of-band (simulating an operator's local cert).
      execFileSync("openssl", [
        "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", `${dir}/k.pem`, "-out", `${dir}/c.pem`,
        "-days", "365", "-nodes", "-subj", "/CN=Org Local Codesign",
      ]);
      execFileSync("openssl", [
        "pkcs12", "-export", "-out", `${dir}/c.p12`,
        "-inkey", `${dir}/k.pem`, "-in", `${dir}/c.pem`,
        "-passout", "pass:right-pass",
      ]);
      const { readFileSync } = await import("node:fs");
      const pfx = readFileSync(`${dir}/c.p12`).toString("base64");

      let res = await app.inject({
        method: "POST",
        url: "/api/v1/codesign-certs",
        payload: { label: "org-cert", pfx, passphrase: "wrong-pass" },
      });
      expect(res.statusCode).toBe(400);

      res = await app.inject({
        method: "POST",
        url: "/api/v1/codesign-certs",
        payload: { label: "org-cert", pfx, passphrase: "right-pass" },
      });
      expect(res.statusCode).toBe(201);
      expect((res.json() as { subject: string }).subject).toContain("Org Local Codesign");
    } finally {
      rmSync(dir, { recursive: true, force: true });
      await app.close();
    }
  });

  it("codesign endpoint rejects unknown cert and missing release dir", async () => {
    delete process.env.F0_AGENT_RELEASE_DIR;
    const app = await makeServer();
    try {
      const cert = await generateCert(app);
      let res = await app.inject({
        method: "POST",
        url: "/api/v1/agent-releases/codesign",
        payload: { certId: cert.id },
      });
      expect(res.statusCode).toBe(400); // no F0_AGENT_RELEASE_DIR

      process.env.F0_AGENT_RELEASE_DIR = mkdtempSync(path.join(tmpdir(), "f0-rel-empty-"));
      res = await app.inject({
        method: "POST",
        url: "/api/v1/agent-releases/codesign",
        payload: { certId: cert.id },
      });
      expect(res.statusCode).toBe(400); // dir has no .exe

      res = await app.inject({
        method: "POST",
        url: "/api/v1/agent-releases/codesign",
        payload: { certId: "cert_missing" },
      });
      expect(res.statusCode).toBe(400); // unknown certId
      rmSync(process.env.F0_AGENT_RELEASE_DIR, { recursive: true, force: true });
    } finally {
      await app.close();
    }
  });

  const repoExe = path.resolve("../../agent/bin/f0-deception-agent-windows-amd64.exe");
  it.runIf(existsSync(repoExe))(
    "signs the real Windows binary and osslsigncode verifies it",
    async () => {
      // Build the cert out-of-band (operator's local cert) so the test can
      // verify with it as the CA — self-signed is not system-trusted.
      const certDir = mkdtempSync(path.join(tmpdir(), "f0-cert-"));
      execFileSync("openssl", [
        "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", `${certDir}/k.pem`, "-out", `${certDir}/c.pem`,
        "-days", "365", "-nodes", "-subj", "/CN=f0_hpot Test Signing",
      ]);
      execFileSync("openssl", [
        "pkcs12", "-export", "-out", `${certDir}/c.p12`,
        "-inkey", `${certDir}/k.pem`, "-in", `${certDir}/c.pem`,
        "-passout", "pass:test-pass",
      ]);
      // Sign temp COPIES — never mutate the repo binaries.
      const dir = mkdtempSync(path.join(tmpdir(), "f0-sign-test-"));
      const exe = path.join(dir, "f0-deception-agent-windows-amd64.exe");
      copyFileSync(repoExe, exe);
      const repoBin = path.resolve("../../agent/bin");
      for (const extra of [
        "f0-deception-agent-darwin-amd64",
        "f0-deception-agent-linux-amd64",
      ]) {
        if (existsSync(path.join(repoBin, extra))) {
          copyFileSync(path.join(repoBin, extra), path.join(dir, extra));
        }
      }
      process.env.F0_AGENT_RELEASE_DIR = dir;
      const app = await makeServer();
      try {
        const { readFileSync } = await import("node:fs");
        const up = await app.inject({
          method: "POST",
          url: "/api/v1/codesign-certs",
          payload: {
            label: "t",
            pfx: readFileSync(`${certDir}/c.p12`).toString("base64"),
            passphrase: "test-pass",
          },
        });
        expect(up.statusCode).toBe(201);
        const certId = (up.json() as { id: string }).id;
        const res = await app.inject({
          method: "POST",
          url: "/api/v1/agent-releases/codesign",
          payload: { certId },
        });
        expect(res.statusCode).toBe(200);
        const report = res.json() as { signed: string[]; skipped: string[] };
        expect(report.signed).toContain("f0-deception-agent-windows-amd64.exe");
        // Linux has no OS-level signing — it must be skipped, not touched.
        expect(report.skipped).toContain("f0-deception-agent-linux-amd64");
        // Signed whether or not the input was already signed (re-sign
        // replaces the signature, so size is not a reliable signal).
        execFileSync("osslsigncode", [
          "extract-signature", "-in", exe, "-out", `${dir}/sig.der`,
        ]);
        expect(statSync(`${dir}/sig.der`).size).toBeGreaterThan(100);
        const out = execFileSync("osslsigncode", [
          "verify", "-CAfile", `${certDir}/c.pem`, exe,
        ]).toString();
        expect(out.toLowerCase()).toContain("signature verification: ok");

        // Mach-O got rcodesign-signed with the same cert (when rcodesign
        // is available on this host).
        if (hasRcodesign()) {
          const darwin = path.join(dir, "f0-deception-agent-darwin-amd64");
          expect(report.signed).toContain("f0-deception-agent-darwin-amd64");
          execFileSync(rcodesignPath(), ["verify", darwin]);
        }
      } finally {
        rmSync(dir, { recursive: true, force: true });
        rmSync(certDir, { recursive: true, force: true });
        await app.close();
      }
    },
    60_000,
  );
});
