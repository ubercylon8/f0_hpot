import {
  createHash,
  createPrivateKey,
  generateKeyPairSync,
  sign as edSign,
} from "node:crypto";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { eq } from "drizzle-orm";
import type { Db } from "./db/index.js";
import { releaseKeys } from "./db/schema.js";
import { newId } from "./ids.js";

/**
 * Server-side signing of agent release manifests (Ed25519).
 *
 * The agent's verifier (agent/internal/update/update.go) re-canonicalizes
 * the manifest with Go's encoding/json before verifying: struct fields in
 * declaration order (version, files, signature), map keys sorted, compact
 * separators, HTML chars escaped, and the signature field present but
 * EMPTY. canonicalManifestBytes reproduces that byte string exactly — it is
 * locked by a golden test on both sides (Go + TS).
 */

export interface ManifestFileEntry {
  sha256: string;
  size: number;
}

export interface ReleaseManifest {
  version: string;
  files: Record<string, ManifestFileEntry>;
  signature: string;
}

/** Escape exactly what Go's json.Marshal escapes inside strings. */
function goJsonString(s: string): string {
  return JSON.stringify(s)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

/** Exact bytes the agent verifies (signature field present but empty). */
export function canonicalManifestBytes(
  version: string,
  files: Record<string, ManifestFileEntry>,
): string {
  const names = Object.keys(files).sort();
  const inner = names
    .map((n) => {
      const f = files[n]!;
      return `${goJsonString(n)}:{"sha256":${goJsonString(f.sha256)},"size":${f.size}}`;
    })
    .join(",");
  return `{"version":${goJsonString(version)},"files":{${inner}},"signature":""}`;
}

export interface GeneratedKey {
  id: string;
  label: string;
  /** Raw 32-byte Ed25519 public key, base64 — embed via
   *  -ldflags '-X update.UpdatePublicKey=<this>'. */
  publicKey: string;
}

export function generateReleaseKey(db: Db, label: string): GeneratedKey {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" });
  const pkcs8 = privateKey.export({ format: "der", type: "pkcs8" });
  const id = newId("rkey");
  db.insert(releaseKeys)
    .values({
      id,
      label,
      publicKey: Buffer.from(spki).toString("base64"),
      privateKey: Buffer.from(pkcs8).toString("base64"),
      createdAt: new Date().toISOString(),
    })
    .run();
  // Raw key = last 32 bytes of the SPKI DER wrapper.
  return {
    id,
    label,
    publicKey: Buffer.from(spki.subarray(spki.length - 32)).toString("base64"),
  };
}

export function listReleaseKeys(db: Db) {
  return db
    .select({
      id: releaseKeys.id,
      label: releaseKeys.label,
      publicKey: releaseKeys.publicKey,
      createdAt: releaseKeys.createdAt,
    })
    .from(releaseKeys)
    .all()
    .map((k) => ({
      ...k,
      // Expose the raw embeddable form, not the SPKI wrapper.
      publicKey: Buffer.from(
        Buffer.from(k.publicKey, "base64").subarray(
          Buffer.from(k.publicKey, "base64").length - 32,
        ),
      ).toString("base64"),
    }));
}

export function signManifestWithStoredKey(
  db: Db,
  keyId: string,
  version: string,
  files: Record<string, ManifestFileEntry>,
): ReleaseManifest | null {
  const row = db
    .select()
    .from(releaseKeys)
    .where(eq(releaseKeys.id, keyId))
    .get();
  if (!row) return null;
  const key = createPrivateKey({
    key: Buffer.from(row.privateKey, "base64"),
    format: "der",
    type: "pkcs8",
  });
  const canonical = canonicalManifestBytes(version, files);
  const signature = edSign(null, Buffer.from(canonical, "utf8"), key);
  return { version, files, signature: signature.toString("base64") };
}

export const RELEASE_FILE_RE = /^f0-deception-agent-[a-z0-9.-]+$/;

/**
 * Hash every agent binary in `dir`, sign with the stored key, and write
 * release-manifest.json (pretty-printed; the agent re-canonicalizes before
 * verifying, so file formatting is cosmetic).
 */
export function signReleaseDir(
  db: Db,
  keyId: string,
  dir: string,
  version: string,
): ReleaseManifest | null {
  const files: Record<string, ManifestFileEntry> = {};
  for (const name of readdirSync(dir).sort()) {
    if (!RELEASE_FILE_RE.test(name)) continue;
    const data = readFileSync(path.join(dir, name));
    files[name] = {
      sha256: createHash("sha256").update(data).digest("hex"),
      size: data.length,
    };
  }
  if (Object.keys(files).length === 0) return null;
  const manifest = signManifestWithStoredKey(db, keyId, version, files);
  if (!manifest) return null;
  const pretty = `${JSON.stringify(
    { files: manifest.files, version: manifest.version, signature: manifest.signature },
    null,
    2,
  )}\n`;
  writeFileSync(path.join(dir, "release-manifest.json"), pretty);
  return manifest;
}
