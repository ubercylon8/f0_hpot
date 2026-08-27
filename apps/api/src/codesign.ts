import { execFile } from "node:child_process";
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
import { tmpdir } from "node:os";
import path from "node:path";
import { X509Certificate } from "node:crypto";
import { eq } from "drizzle-orm";
import type { Db } from "./db/index.js";
import { codeSigningCerts } from "./db/schema.js";
import { newId } from "./ids.js";

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

async function run(cmd: string, args: string[]): Promise<string> {
  try {
    const { stdout } = await execFileAsync(cmd, args, { maxBuffer: 16 * 1024 * 1024 });
    return stdout;
  } catch (err) {
    const stderr = (err as { stderr?: string }).stderr?.trim();
    throw new Error(stderr ? `${cmd}: ${stderr.split("\n").pop()}` : String(err));
  }
}

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

/**
 * Authenticode-sign a Windows release binary in-place with a stored cert
 * (signed copy is verified before replacing the original).
 */
export async function signReleaseExe(
  db: Db,
  certId: string,
  releaseDir: string,
  filename?: string,
): Promise<{ file: string }> {
  const cert = db
    .select()
    .from(codeSigningCerts)
    .where(eq(codeSigningCerts.id, certId))
    .get();
  if (!cert) throw new Error("unknown certId");

  const target =
    filename ??
    (() => {
      const exes = readdirSync(releaseDir).filter((f) => WINDOWS_EXE_RE.test(f));
      if (exes.length !== 1) {
        throw new Error(
          exes.length === 0
            ? "no Windows .exe in the release dir"
            : "multiple .exe files — specify which one to sign",
        );
      }
      return exes[0]!;
    })();
  if (!WINDOWS_EXE_RE.test(target)) {
    throw new Error("only f0-deception-agent-*.exe binaries can be signed");
  }
  const exePath = path.join(releaseDir, target);
  if (!existsSync(exePath)) throw new Error(`${target} not found in the release dir`);

  return withTempDir(async (dir) => {
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
    // Verify the signature is structurally valid before trusting it.
    await run("osslsigncode", ["verify", "-CAfile", caPath, `${signedPath}.signed`]);
    // copyFileSync, not rename: the release dir may be on another fs (EXDEV).
    copyFileSync(`${signedPath}.signed`, exePath);
    return { file: target };
  });
}
