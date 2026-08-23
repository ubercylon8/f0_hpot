import { eq, desc, sql } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import {
  tokenTypeSchema,
  tokenStatusSchema,
  incidentSeveritySchema,
} from "@f0/deception-shared";
import { getTokenType } from "@f0/deception-tokens-core";
import type { Db } from "../db/index.js";
import { tokens, incidents } from "../db/schema.js";
import { newTokenId } from "../ids.js";

export function registerTokenRoutes(app: FastifyInstance, db: Db): void {
  app.post("/api/v1/tokens", async (request, reply) => {
      const parsed = z
        .object({
          type: tokenTypeSchema,
          memo: z.string().max(500).optional(),
          config: z.record(z.string(), z.unknown()).optional(),
        })
        .safeParse(request.body);
      if (!parsed.success) {
        return reply.badRequest(parsed.error.issues.map((i) => i.message).join("; "));
      }

      const def = getTokenType(parsed.data.type);
      if (!def) return reply.notFound(`unknown token type: ${parsed.data.type}`);

      const configResult = def.configSchema.safeParse(parsed.data.config ?? {});
      if (!configResult.success) {
        return reply.badRequest(configResult.error.issues.map((i) => i.message).join("; "));
      }

      const id = newTokenId();
      const createdAt = new Date().toISOString();
      db.insert(tokens)
        .values({
          id,
          type: def.id,
          memo: parsed.data.memo ?? null,
          status: "active",
          config: configResult.data,
          createdAt,
        })
        .run();

      const ctx = generateContextFor(id, configResult.data);
      const artifacts = def.generate(ctx);

      return reply.code(201).send({
        id,
        type: def.id,
        memo: parsed.data.memo ?? null,
        status: "active",
        config: configResult.data,
        artifacts,
        createdAt,
        hitCount: 0,
      });
      });

  app.get("/api/v1/tokens", async () => {
    const rows = db.select().from(tokens).orderBy(desc(tokens.createdAt)).all();
    return rows.map((row) => ({
      ...row,
      hitCount: db
        .select({ count: sql<number>`count(*)` })
        .from(incidents)
        .where(eq(incidents.tokenId, row.id))
        .get()?.count ?? 0,
    }));
  });

  app.get("/api/v1/tokens/:id", async (request, reply) => {
    const { id } = request.params as { id: string };
    const row = db.select().from(tokens).where(eq(tokens.id, id)).get();
    if (!row) return reply.notFound("token not found");
    const hitCount =
      db
        .select({ count: sql<number>`count(*)` })
        .from(incidents)
        .where(eq(incidents.tokenId, id))
        .get()?.count ?? 0;
    return { ...row, hitCount };
  });

  app.delete("/api/v1/tokens/:id", async (request, reply) => {
    const { id } = request.params as { id: string };
    const result = db
      .update(tokens)
      .set({ status: "revoked" })
      .where(eq(tokens.id, id))
      .run();
    if (result.changes === 0) return reply.notFound("token not found");
    return reply.send({ ok: true });
  });

  app.patch("/api/v1/tokens/:id/status", async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = z
      .object({ status: tokenStatusSchema })
      .safeParse(request.body);
    if (!parsed.success) {
      return reply.badRequest(parsed.error.issues.map((i) => i.message).join("; "));
    }
    const result = db
      .update(tokens)
      .set({ status: parsed.data.status })
      .where(eq(tokens.id, id))
      .run();
    if (result.changes === 0) return reply.notFound("token not found");
    return reply.send({ ok: true });
  });

  app.get("/api/v1/tokens/:id/incidents", async (request, reply) => {
    const { id } = request.params as { id: string };
    const rows = db
      .select()
      .from(incidents)
      .where(eq(incidents.tokenId, id))
      .orderBy(desc(incidents.seenAt))
      .limit(200)
      .all();
    return rows;
  });

  app.post("/api/v1/incidents", async (request, reply) => {
      // Internal endpoint used by the gateway.
      const parsed = z
        .object({
          tokenId: z.string().min(1),
          severity: incidentSeveritySchema.default("medium"),
          event: z.record(z.string(), z.unknown()),
        })
        .safeParse(request.body);
      if (!parsed.success) {
        return reply.badRequest(parsed.error.issues.map((i) => i.message).join("; "));
      }
      const token = db
        .select()
        .from(tokens)
        .where(eq(tokens.id, parsed.data.tokenId))
        .get();
      if (!token || token.status !== "active") {
        return reply.notFound("no active token for this incident");
      }
      const incidentId = `inc_${Date.now().toString(36)}${Math.random()
        .toString(36)
        .slice(2, 8)}`;
      db.insert(incidents)
        .values({
          id: incidentId,
          tokenId: token.id,
          severity: parsed.data.severity,
          event: parsed.data.event,
          seenAt: new Date().toISOString(),
        })
        .run();
      return reply.code(201).send({ id: incidentId });
  });
}

function generateContextFor(tokenId: string, config: Record<string, unknown>) {
  const baseDomain = process.env.F0_TOKEN_DOMAINS?.split(",")[0]?.trim() ?? "tokens.example.com";
  const gatewayOrigin = process.env.F0_GATEWAY_ORIGIN ?? `https://${baseDomain}`;
  return {
    tokenId,
    baseDomain,
    gatewayOrigin,
    config,
  };
}
