import { randomBytes } from "node:crypto";
import { eq } from "drizzle-orm";
import type { Db } from "./db/index.js";
import { enrollmentTokens } from "./db/schema.js";
import { hashAgentKey } from "./auth.js";
import { newId } from "./ids.js";

/**
 * Managed, per-installation enrollment tokens (f0et_…). An alternative
 * to the single static F0_ENROLLMENT_TOKEN: labeled, revocable, tracked
 * (uses + last used), optionally expiring. The raw value is shown once
 * at creation; only the sha256 hash is stored.
 */

export function newEnrollmentToken(): string {
  return `f0et_${randomBytes(30).toString("base64url")}`;
}

export function createEnrollmentToken(
  db: Db,
  label: string,
  expiresInHours?: number,
): { id: string; label: string; token: string; expiresAt: string | null } {
  const token = newEnrollmentToken();
  const id = newId("etok");
  const expiresAt = expiresInHours
    ? new Date(Date.now() + expiresInHours * 3600e3).toISOString()
    : null;
  db.insert(enrollmentTokens)
    .values({
      id,
      label,
      tokenHash: hashAgentKey(token),
      expiresAt,
      createdAt: new Date().toISOString(),
    })
    .run();
  return { id, label, token, expiresAt };
}

export function listEnrollmentTokens(db: Db) {
  return db
    .select({
      id: enrollmentTokens.id,
      label: enrollmentTokens.label,
      expiresAt: enrollmentTokens.expiresAt,
      lastUsedAt: enrollmentTokens.lastUsedAt,
      uses: enrollmentTokens.uses,
      createdAt: enrollmentTokens.createdAt,
    })
    .from(enrollmentTokens)
    .all();
}

export function deleteEnrollmentToken(db: Db, id: string): boolean {
  return db.delete(enrollmentTokens).where(eq(enrollmentTokens.id, id)).run()
    .changes > 0;
}

/**
 * Validate a presented token against the managed set: must exist, be
 * unexpired — then record the use (uses + 1, last_used_at).
 */
export function consumeEnrollmentToken(db: Db, presented: string): boolean {
  const row = db
    .select()
    .from(enrollmentTokens)
    .where(eq(enrollmentTokens.tokenHash, hashAgentKey(presented)))
    .get();
  if (!row) return false;
  if (row.expiresAt && row.expiresAt < new Date().toISOString()) return false;
  db.update(enrollmentTokens)
    .set({ uses: row.uses + 1, lastUsedAt: new Date().toISOString() })
    .where(eq(enrollmentTokens.id, row.id))
    .run();
  return true;
}
