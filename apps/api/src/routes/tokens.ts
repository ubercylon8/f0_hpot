import { eq, desc, sql, and } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import {
  tokenTypeSchema,
  tokenStatusSchema,
  incidentSeveritySchema,
} from "@f0/deception-shared";
import { getTokenType } from "@f0/deception-tokens-core";
import type { Db } from "../db/index.js";
import { tokens, incidents, tokenFiles } from "../db/schema.js";
import { newId, newTokenId } from "../ids.js";
import type { AlertDispatcher } from "../alerts/dispatcher.js";
import type { TriggerEvent } from "@f0/deception-shared";

export function registerTokenRoutes(
  app: FastifyInstance,
  db: Db,
  dispatcher: AlertDispatcher,
): void {
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

      // Persist generated files for download endpoints.
      let fileIdx = 0;
      for (const artifact of artifacts) {
        if (!artifact.file) continue;
        db.insert(tokenFiles)
          .values({
            id: newId("file"),
            tokenId: id,
            idx: fileIdx,
            filename: artifact.file.filename,
            contentType: artifact.file.contentType,
            data: artifact.file.bodyBase64,
            createdAt,
          })
          .run();
        fileIdx += 1;
      }

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

  app.get("/api/v1/tokens/:id/files/:idx", async (request, reply) => {
    const { id, idx } = request.params as { id: string; idx: string };
    const row = db
      .select()
      .from(tokenFiles)
      .where(and(eq(tokenFiles.tokenId, id), eq(tokenFiles.idx, Number(idx))))
      .get();
    if (!row) return reply.notFound("artifact not found");
    reply.header("content-type", row.contentType);
    reply.header("content-disposition", `attachment; filename="${row.filename}"`);
    return reply.send(Buffer.from(row.data, "base64"));
  });

  // Internal: gateway artifact rendering needs the token type + config.
  app.get("/api/v1/incidents", async (request) => {
    const query = request.query as { limit?: string; acknowledged?: string };
    const limit = Math.min(Number(query.limit ?? 200) || 200, 500);
    let stmt = db
      .select({
        id: incidents.id,
        tokenId: incidents.tokenId,
        tokenType: tokens.type,
        severity: incidents.severity,
        acknowledged: incidents.acknowledged,
        event: incidents.event,
        seenAt: incidents.seenAt,
      })
      .from(incidents)
      .innerJoin(tokens, eq(incidents.tokenId, tokens.id))
      .orderBy(desc(incidents.seenAt))
      .limit(limit)
      .$dynamic();
    if (query.acknowledged === "false") {
      stmt = stmt.where(eq(incidents.acknowledged, false));
    }
    return stmt.all();
  });

  app.patch("/api/v1/incidents/:id/ack", async (request, reply) => {
    const { id } = request.params as { id: string };
    const result = db
      .update(incidents)
      .set({ acknowledged: true })
      .where(eq(incidents.id, id))
      .run();
    if (result.changes === 0) return reply.notFound("incident not found");
    return reply.send({ ok: true });
  });

  app.get("/api/v1/tokens/:id/internal-config", async (request, reply) => {
    const { id } = request.params as { id: string };
    const row = db
      .select({ type: tokens.type, config: tokens.config, status: tokens.status })
      .from(tokens)
      .where(eq(tokens.id, id))
      .get();
    if (!row || row.status !== "active") return reply.notFound();
    return { type: row.type, config: row.config };
  });

  app.get("/api/v1/tokens/:id/incidents", async (request, reply) => {    const { id } = request.params as { id: string };
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

      // The gateway forwards candidate events; the token's own type rules
      // are authoritative for whether this event is really a hit.
      const def = getTokenType(token.type as Parameters<typeof getTokenType>[0]);
      const match = def?.matchTrigger(
        parsed.data.event as never,
        token.id,
      );
      if (!def || !match?.matched) {
        return reply.notFound("event does not match this token's triggers");
      }

      const incidentId = `inc_${Date.now().toString(36)}${Math.random()
        .toString(36)
        .slice(2, 8)}`;
      db.insert(incidents)
        .values({
          id: incidentId,
          tokenId: token.id,
          severity: match.severity,
          event: parsed.data.event,
          seenAt: new Date().toISOString(),
        })
        .run();

      // Fire-and-forget alerting; incident is already durably recorded.
      void dispatcher.dispatch({
        tokenId: token.id,
        tokenType: token.type,
        severity: match.severity,
        incidentId,
        seenAt: new Date().toISOString(),
        event: parsed.data.event as TriggerEvent,
      });

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
