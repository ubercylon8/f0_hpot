import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import {
  copyFileSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir, homedir } from "node:os";
import path from "node:path";
import { X509Certificate } from "node:crypto";
import { eq } from "drizzle-orm";
import type { Db } from "./db/index.js";
import { codeSigningCerts } from "./db/schema.js";
import { newId } from "./ids.js";

/**
 * Resolve a signing tool binary: env override, then PATH, then the
 * user's cargo bin (where `cargo install apple-codesign` lands).
 */
function resolveTool(name: string): string {
  const envOverride = process.env[`F0_${name.toUpperCase()}`];
  const candidates = [
    ...(envOverride ? [envOverride] : []),
    name,
    path.join(homedir(), ".cargo", "bin", name),
  ];
  for (const c of candidates) {
    if (c.includes("/") && existsSync(c)) return c;
    if (!c.includes("/")) {
      // PATH lookup via the shell's which (cheap, startup-time only).
      try {
        const out = execFileSync("which", [c], { encoding: "utf8" }).trim();
        if (out) return out;
      } catch {
        /* not on PATH */
      }
    }
  }
  throw new Error(
    `${name} not found — install it (rcodesign: cargo install apple-codesign) or set F0_${name.toUpperCase()}`,
  );
}

/**
 * Authenticode code signing of agent binaries.
 *
 * Distinct from release-manifest signing (release-signing.ts, Ed25519):
 * that layer protects the agent's self-update channel. THIS layer signs
 * the Windows binary itself so endpoints where the org's certificate is
 * already trusted (GPO/MDM Trusted Root + Publishers) don't raise
 * SmartScreen / ASR publisher blocks. Certificates are org-local
 * (self-signed or uploaded) — no public CA required in that model.
 *
 * Tooling is shelled out (openssl for cert handling, osslsigncode for
 * signing) via execFile with argument arrays — never a shell — and all
 * path inputs are either validated by regex or taken from the DB/env.
 */

const execFileAsync = promisify(execFile);

interface RunOpts {
  env?: NodeJS.ProcessEnv;
  timeoutMs?: number;
}

async function run(cmd: string, args: string[], opts: RunOpts = {}): Promise<string> {
  try {
    const { stdout } = await execFileAsync(cmd, args, {
      maxBuffer: 16 * 1024 * 1024,
      ...(opts.env ? { env: opts.env } : {}),
      ...(opts.timeoutMs ? { timeout: opts.timeoutMs } : {}),
    });
    return stdout;
  } catch (err) {
    const stderr = (err as { stderr?: string }).stderr?.trim();
    throw new Error(stderr ? `${cmd}: ${stderr.split("\n").pop()}` : String(err));
  }
}

/** Shell-out wrapper shared with release-build (execFile, arg arrays). */
export { run as runTool };

/** mkdtemp + guaranteed cleanup for sensitive intermediate files. */
async function withTempDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = mkdtempSync(path.join(tmpdir(), "f0-codesign-"));
  try {
    return await fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

export interface CertView {
  id: string;
  label: string;
  subject: string;
  issuer: string;
  notAfter: string;
  createdAt: string;
}

function toView(row: typeof codeSigningCerts.$inferSelect): CertView {
  const { id, label, subject, issuer, notAfter, createdAt } = row;
  return { id, label, subject, issuer, notAfter, createdAt };
}

export function listCodeSignCerts(db: Db): CertView[] {
  return db.select().from(codeSigningCerts).all().map(toView);
}

export function deleteCodeSignCert(db: Db, id: string): boolean {
  return db.delete(codeSigningCerts).where(eq(codeSigningCerts.id, id)).run()
    .changes > 0;
}

function insertCert(
  db: Db,
  input: { label: string; subject: string; issuer: string; notAfter: string; pfx: Buffer; passphrase: string },
): CertView {
  const id = newId("cert");
  db.insert(codeSigningCerts)
    .values({ id, createdAt: new Date().toISOString(), ...input, pfx: input.pfx.toString("base64") })
    .run();
  return toView(db.select().from(codeSigningCerts).where(eq(codeSigningCerts.id, id)).get()!);
}

/** Generate an org-local self-signed code-signing certificate (RSA-2048). */
export async function generateCodeSignCert(
  db: Db,
  opts: { label: string; commonName: string; passphrase: string },
): Promise<CertView> {
  return withTempDir(async (dir) => {
    const keyPem = path.join(dir, "key.pem");
    const certPem = path.join(dir, "cert.pem");
    const p12 = path.join(dir, "cert.p12");
    await run("openssl", [
      "req", "-x509", "-newkey", "rsa:2048",
      "-keyout", keyPem, "-out", certPem,
      "-days", "1825", "-nodes",
      "-subj", `/CN=${opts.commonName}`,
    ]);
    await run("openssl", [
      "pkcs12", "-export",
      "-out", p12, "-inkey", keyPem, "-in", certPem,
      "-passout", `pass:${opts.passphrase}`,
    ]);
    const x509 = new X509Certificate(readFileSync(certPem, "utf8"));
    return insertCert(db, {
      label: opts.label,
      subject: x509.subject.replaceAll("\n", ", "),
      issuer: x509.issuer.replaceAll("\n", ", "),
      notAfter: x509.validTo,
      pfx: readFileSync(p12),
      passphrase: opts.passphrase,
    });
  });
}

/** Store an operator-supplied .p12/.pfx (validated + metadata extracted). */
export async function storeUploadedCodeSignCert(
  db: Db,
  opts: { label: string; pfx: Buffer; passphrase: string },
): Promise<CertView> {
  return withTempDir(async (dir) => {
    const p12 = path.join(dir, "upload.p12");
    writeFileSync(p12, opts.pfx, { mode: 0o600 });
    // Extracts the client cert; fails cleanly on a bad passphrase/bundle.
    const pem = await run("openssl", [
      "pkcs12", "-in", p12, "-clcerts", "-nokeys",
      "-passin", `pass:${opts.passphrase}`,
    ]);
    const x509 = new X509Certificate(pem);
    return insertCert(db, {
      label: opts.label,
      subject: x509.subject.replaceAll("\n", ", "),
      issuer: x509.issuer.replaceAll("\n", ", "),
      notAfter: x509.validTo,
      pfx: opts.pfx,
      passphrase: opts.passphrase,
    });
  });
}

export const WINDOWS_EXE_RE = /^f0-deception-agent-[a-z0-9.-]+\.exe$/;
export const MACHO_RE = /^f0-deception-agent-darwin-(amd64|arm64)$/;

async function signWindowsExe(
  cert: typeof codeSigningCerts.$inferSelect,
  releaseDir: string,
  target: string,
): Promise<void> {
  const exePath = path.join(releaseDir, target);
  await withTempDir(async (dir) => {
    const p12 = path.join(dir, "cert.p12");
    writeFileSync(p12, Buffer.from(cert.pfx, "base64"), { mode: 0o600 });
    // osslsigncode verify chains against the system trust store; an
    // org-local (self-signed) cert must be passed as its own CA.
    const certPem = await run("openssl", [
      "pkcs12", "-in", p12, "-clcerts", "-nokeys",
      "-passin", `pass:${cert.passphrase}`,
    ]);
    const caPath = path.join(dir, "ca.pem");
    writeFileSync(caPath, certPem, { mode: 0o600 });
    const signedPath = path.join(dir, target);
    copyFileSync(exePath, signedPath);
    await run("osslsigncode", [
      "sign",
      "-pkcs12", p12,
      "-pass", cert.passphrase,
      "-n", "f0_hpot Agent",
      "-i", "https://github.com/f0rt1ka/f0_deception",
      "-in", signedPath,
      "-out", `${signedPath}.signed`,
    ]);
    await run("osslsigncode", ["verify", "-CAfile", caPath, `${signedPath}.signed`]);
    // copyFileSync, not rename: the release dir may be on another fs (EXDEV).
    copyFileSync(`${signedPath}.signed`, exePath);
  });
}

async function signMachO(
  cert: typeof codeSigningCerts.$inferSelect,
  releaseDir: string,
  target: string,
  rcodesign: string,
): Promise<void> {
  const binPath = path.join(releaseDir, target);
  await withTempDir(async (dir) => {
    const p12 = path.join(dir, "cert.p12");
    writeFileSync(p12, Buffer.from(cert.pfx, "base64"), { mode: 0o600 });
    // rcodesign wants PEM cert chain + key (not a p12 bundle).
    const certPem = await run("openssl", [
      "pkcs12", "-in", p12, "-clcerts", "-nokeys",
      "-passin", `pass:${cert.passphrase}`,
    ]);
    const keyPem = await run("openssl", [
      "pkcs12", "-in", p12, "-nocerts", "-nodes",
      "-passin", `pass:${cert.passphrase}`,
    ]);
    const certPath = path.join(dir, "cert.pem");
    const keyPath = path.join(dir, "key.pem");
    writeFileSync(certPath, certPem, { mode: 0o600 });
    writeFileSync(keyPath, keyPem, { mode: 0o600 });
    const signedPath = path.join(dir, target);
    copyFileSync(binPath, signedPath);
    await run(rcodesign, [
      "sign",
      "--pem-file", keyPath,
      "--pem-file", certPath,
      signedPath,
      `${signedPath}.signed`,
    ]);
    await run(rcodesign, ["verify", `${signedPath}.signed`]);
    copyFileSync(`${signedPath}.signed`, binPath);
  });
}

export interface SignReport {
  signed: string[];
  skipped: string[];
}

/**
 * Sign every signable release binary in-place with a stored cert:
 * Windows .exe via osslsigncode (Authenticode), darwin Mach-O via
 * rcodesign. Linux binaries are skipped (no OS-level signing — the
 * Ed25519 release manifest covers them).
 */
export async function signReleaseBinaries(
  db: Db,
  certId: string,
  releaseDir: string,
): Promise<SignReport> {
  const cert = db
    .select()
    .from(codeSigningCerts)
    .where(eq(codeSigningCerts.id, certId))
    .get();
  if (!cert) throw new Error("unknown certId");

  const report: SignReport = { signed: [], skipped: [] };
  // rcodesign is optional: without it, darwin binaries skip (not fail).
  let rcodesign: string | null = null;
  try {
    rcodesign = resolveTool("rcodesign");
  } catch {
    rcodesign = null;
  }
  for (const name of readdirSync(releaseDir).sort()) {
    if (WINDOWS_EXE_RE.test(name)) {
      await signWindowsExe(cert, releaseDir, name);
      report.signed.push(name);
    } else if (MACHO_RE.test(name)) {
      if (rcodesign) {
        await signMachO(cert, releaseDir, name, rcodesign);
        report.signed.push(name);
      } else {
        report.skipped.push(name);
      }
    } else if (name.startsWith("f0-deception-agent-")) {
      report.skipped.push(name);
    }
  }
  if (report.signed.length === 0 && report.skipped.length === 0) {
    throw new Error("no release binaries found in the release dir");
  }
  return report;
}
