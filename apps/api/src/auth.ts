import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { eq } from "drizzle-orm";
import type { FastifyReply, FastifyRequest } from "fastify";
import type { Db } from "./db/index.js";
import { agents, apiKeys } from "./db/schema.js";

/**
 * Console authentication.
 *
 * Three bearer credentials are recognised:
 *  1. F0_ADMIN_TOKEN (env) — bootstrap master key; also used to create the
 *     first persistent API key.
 *  2. Persistent API keys (api_keys table, sha256-hashed) — created via
 *     POST /api/v1/auth/keys, used by the console and MCP (F0_API_TOKEN).
 *  3. F0_INTERNAL_SECRET (env) — gateway→API internal scope (incident
 *     forwarding, internal-config/page lookups). NOT valid for console
 *     routes.
 *
 * Agent routes keep their own credentials (enrollment token / agent key)
 * and are exempt from this hook.
 *
 * Back-compat escape hatch: if neither F0_ADMIN_TOKEN nor F0_INTERNAL_SECRET
 * is set AND the api_keys table is empty, console routes are open (local
 * dev). A loud warning is logged at startup; create a key to enforce auth.
 */

const OPEN_ROUTES: { method: string; path: RegExp }[] = [
  // Agent self-service (own credentials checked in the handler).
  { method: "POST", path: /^\/api\/v1\/agent\/(enroll|heartbeat)$/ },
  // Login probe — validates a presented key without side effects.
  { method: "POST", path: /^\/api\/v1\/auth\/login$/ },
];

const INTERNAL_ROUTES: { method: string; path: RegExp }[] = [
  // Gateway incident forwarding + artifact lookups.
  { method: "POST", path: /^\/api\/v1\/incidents$/ },
  { method: "GET", path: /^\/api\/v1\/tokens\/[^/]+\/internal-(config|page|image)$/ },
];

export function hashApiKey(key: string): string {
  return createHash("sha256").update(key).digest("hex");
}

export function newApiKey(): string {
  return `f0k_${randomBytes(30).toString("base64url")}`;
}

export function hashAgentKey(key: string): string {
  return createHash("sha256").update(key).digest("hex");
}

/** Timing-safe compare of a bearer key against a stored hash. */
export function verifyAgentKey(presented: string, storedHash: string): boolean {
  const presentedHash = Buffer.from(hashAgentKey(presented), "hex");
  const stored = Buffer.from(storedHash, "hex");
  return presentedHash.length === stored.length && presentedHash.equals(stored);
}

function isValidAgentCredential(
  db: Db,
  agentId: string,
  key: string,
): boolean {
  const agent = db
    .select({ agentKeyHash: agents.agentKeyHash })
    .from(agents)
    .where(eq(agents.id, agentId))
    .get();
  return !!agent && verifyAgentKey(key, agent.agentKeyHash);
}

function presentedKey(request: FastifyRequest): string | undefined {
  const auth = request.headers.authorization;
  if (auth?.startsWith("Bearer ")) return auth.slice(7).trim() || undefined;
  return undefined;
}

export function timingSafeMatch(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

export interface AuthContext {
  adminToken?: string;
  internalSecret?: string;
}

export function buildAuthContext(): AuthContext {
  return {
    adminToken: process.env.F0_ADMIN_TOKEN || undefined,
    internalSecret: process.env.F0_INTERNAL_SECRET || undefined,
  };
}

/**
 * Back-compat escape hatch, evaluated per-request: open only while no auth
 * material is configured AND no persistent keys exist. Creating the first
 * key (or setting an env token) closes open mode without a restart.
 */
export function isOpenMode(db: Db, ctx: AuthContext): boolean {
  if (ctx.adminToken || ctx.internalSecret) return false;
  return db.select({ id: apiKeys.id }).from(apiKeys).limit(1).all().length === 0;
}

export function isValidConsoleKey(db: Db, key: string): boolean {
  const hash = hashApiKey(key);
  const row = db.select().from(apiKeys).where(eq(apiKeys.keyHash, hash)).get();
  if (!row) return false;
  db.update(apiKeys)
    .set({ lastUsedAt: new Date().toISOString() })
    .where(eq(apiKeys.id, row.id))
    .run();
  return true;
}

/** Fastify onRequest hook enforcing the auth model above. */
export function makeAuthHook(db: Db, ctx: AuthContext) {
  return async function authHook(
    request: FastifyRequest,
    reply: FastifyReply,
  ): Promise<void> {
    const url = request.url.split("?")[0] ?? request.url;
    const method = request.method;

    if (OPEN_ROUTES.some((r) => r.method === method && r.path.test(url))) {
      return;
    }

    const key = presentedKey(request);
    const openMode = isOpenMode(db, ctx);

    if (INTERNAL_ROUTES.some((r) => r.method === method && r.path.test(url))) {
      // Internal routes accept the internal secret, the admin token, or a
      // console key (MCP/CLI tooling may reasonably forward incidents).
      if (key && ctx.internalSecret && timingSafeMatch(key, ctx.internalSecret)) {
        return;
      }
      if (key && ctx.adminToken && timingSafeMatch(key, ctx.adminToken)) return;
      if (key && isValidConsoleKey(db, key)) return;
      // Agents report incidents with their own key + x-agent-id.
      if (method === "POST" && key) {
        const agentId = request.headers["x-agent-id"];
        if (typeof agentId === "string" && isValidAgentCredential(db, agentId, key)) {
          return;
        }
      }
      if (openMode) return;
      return reply.unauthorized("invalid internal credentials");
    }

    // Everything else under /api/v1 is console scope.
    if (openMode) return;
    if (key && ctx.adminToken && timingSafeMatch(key, ctx.adminToken)) return;
    if (key && isValidConsoleKey(db, key)) return;
    return reply.unauthorized("authentication required");
  };
}
