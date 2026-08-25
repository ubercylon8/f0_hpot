import { eq } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { Db } from "../db/index.js";
import { apiKeys } from "../db/schema.js";
import { newId } from "../ids.js";
import {
  hashApiKey,
  isOpenMode,
  isValidConsoleKey,
  newApiKey,
  timingSafeMatch,
  type AuthContext,
} from "../auth.js";

/**
 * Console auth self-service.
 *
 * POST /auth/login is a side-effect-free probe the console uses to validate
 * a presented key before storing it. Key management routes are gated by the
 * global auth hook (console scope) — the first key can be created in open
 * mode, after which a valid key or the admin token is required.
 */
export function registerAuthRoutes(
  app: FastifyInstance,
  db: Db,
  ctx: AuthContext,
): void {
  app.post(
    "/api/v1/auth/login",
    { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } },
    async (request, reply) => {
      const parsed = z
        .object({ key: z.string().min(1).max(256) })
        .safeParse(request.body);
      if (!parsed.success) return reply.unauthorized("invalid key");
      const { key } = parsed.data;
      if (ctx.adminToken && timingSafeMatch(key, ctx.adminToken)) {
        return reply.code(204).send();
      }
      if (isValidConsoleKey(db, key)) return reply.code(204).send();
      if (isOpenMode(db, ctx)) return reply.code(204).send();
      return reply.unauthorized("invalid key");
    },
  );

  app.post("/api/v1/auth/keys", async (request, reply) => {
    const parsed = z
      .object({ label: z.string().min(1).max(128) })
      .safeParse(request.body);
    if (!parsed.success) {
      return reply.badRequest(parsed.error.issues.map((i) => i.message).join("; "));
    }
    const id = newId("key");
    const key = newApiKey();
    db.insert(apiKeys)
      .values({
        id,
        keyHash: hashApiKey(key),
        label: parsed.data.label,
        createdAt: new Date().toISOString(),
      })
      .run();
    // The raw key is returned exactly once; only its hash is stored.
    return reply.code(201).send({ id, key, label: parsed.data.label });
  });

  app.get("/api/v1/auth/keys", async () => {
    return db
      .select({
        id: apiKeys.id,
        label: apiKeys.label,
        createdAt: apiKeys.createdAt,
        lastUsedAt: apiKeys.lastUsedAt,
      })
      .from(apiKeys)
      .all();
  });

  app.delete("/api/v1/auth/keys/:id", async (request, reply) => {
    const { id } = request.params as { id: string };
    const result = db.delete(apiKeys).where(eq(apiKeys.id, id)).run();
    if (result.changes === 0) return reply.notFound("key not found");
    return reply.send({ ok: true });
  });
}
