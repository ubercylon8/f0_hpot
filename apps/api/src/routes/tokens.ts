import { eq, desc, sql, and, like, inArray, type SQL } from "drizzle-orm";
import QRCode from "qrcode";
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
import { extractSourceIp, type GeoLookup } from "../geoip.js";

// Whitelist for custom_image uploads (no svg: script-bearing markup).
const IMAGE_CONTENT_TYPES = new Set([
  "image/png",
  "image/jpeg",
  "image/gif",
  "image/webp",
  "image/avif",
  "image/bmp",
  "image/x-icon",
]);

export function registerTokenRoutes(
  app: FastifyInstance,
  db: Db,
  dispatcher: AlertDispatcher,
  geo: GeoLookup,
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

      // Persist generated files for download endpoints (filenames are
      // operator-configurable on several types — sanitize for the
      // content-disposition header either way).
      let fileIdx = 0;
      for (const artifact of artifacts) {
        if (!artifact.file) continue;
        db.insert(tokenFiles)
          .values({
            id: newId("file"),
            tokenId: id,
            idx: fileIdx,
            filename: artifact.file.filename.replace(/["\\/:]/g, "_"),
            contentType: artifact.file.contentType,
            data: artifact.file.bodyBase64,
            createdAt,
          })
          .run();
        fileIdx += 1;
      }

      // QR tokens: render the PNG at creation so it is downloadable from
      // token_files (the artifact value points at /files/0). Encoding the
      // trigger URL — scanning the QR visits it and fires the token.
      if (def.id === "qr_code") {
        const png = await QRCode.toBuffer(`${gatewayOriginFor(id)}/${id}/qr`, {
          width: 512,
          margin: 1,
          errorCorrectionLevel: "L",
        });
        db.insert(tokenFiles)
          .values({
            id: newId("file"),
            tokenId: id,
            idx: 0,
            filename: String(configResult.data["filename"] ?? "qr.png").replace(
              /["\\/:]/g,
              "_",
            ),
            contentType: "image/png",
            data: png.toString("base64"),
            createdAt,
          })
          .run();
      }

      // Cloned-site tokens: fetch the target page now, inject the beacon,
      // store it for the gateway to serve at /<tokenId>/site.
      if (def.id === "cloned_website") {
        await cloneWebsiteForToken(
          app,
          db,
          id,
          String(configResult.data["target_url"] ?? ""),
        );
      }

      return reply.code(201).send({
        id,
        type: def.id,
        memo: parsed.data.memo ?? null,
        status: "active",
        config: configResult.data,
        artifacts,
        // Persisted files so the console can name downloads correctly
        // right from the create dialog (mirrors GET /tokens/:id).
        files: db
          .select({
            idx: tokenFiles.idx,
            filename: tokenFiles.filename,
            contentType: tokenFiles.contentType,
          })
          .from(tokenFiles)
          .where(eq(tokenFiles.tokenId, id))
          .all(),
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
    // Artifacts are deterministic (type + config + id): regenerate for
    // display, stripping embedded file bodies (downloaded via /files/:idx).
    const def = getTokenType(row.type as Parameters<typeof getTokenType>[0]);
    const artifacts = def
      ? def
          .generate(generateContextFor(row.id, row.config as Record<string, unknown>))
          .map(({ kind, label, value }) => ({ kind, label, value }))
      : [];
    const files = db
      .select({
        idx: tokenFiles.idx,
        filename: tokenFiles.filename,
        contentType: tokenFiles.contentType,
      })
      .from(tokenFiles)
      .where(eq(tokenFiles.tokenId, id))
      .all();
    return { ...row, hitCount, artifacts, files };
  });

  // Bulk revoke/hard-delete for the console's selection toolbar.
  app.post("/api/v1/tokens/bulk", async (request, reply) => {
    const parsed = z
      .object({
        ids: z.array(z.string().min(1)).min(1).max(1000),
        action: z.enum(["revoke", "delete"]),
      })
      .safeParse(request.body);
    if (!parsed.success) {
      return reply.badRequest(parsed.error.issues.map((i) => i.message).join("; "));
    }
    const { ids, action } = parsed.data;
    if (action === "revoke") {
      const result = db
        .update(tokens)
        .set({ status: "revoked" })
        .where(inArray(tokens.id, ids))
        .run();
      return reply.send({ ok: true, updated: result.changes });
    }
    // Count rows that actually existed: reporting ids.length let the
    // console claim it deleted tokens that were already gone.
    const present = db
      .select({ id: tokens.id })
      .from(tokens)
      .where(inArray(tokens.id, ids))
      .all().length;
    db.transaction((tx) => {
      for (const id of ids) hardDeleteToken(tx as unknown as Db, id);
    });
    return reply.send({ ok: true, updated: present });
  });

  app.delete("/api/v1/tokens/:id", async (request, reply) => {
    const { id } = request.params as { id: string };
    // ?hard=true deletes the token, its files, and its incident history;
    // the default is a soft revoke (history preserved, triggering stops).
    const { hard } = request.query as { hard?: string };
    if (hard === "true") {
      if (!db.select({ id: tokens.id }).from(tokens).where(eq(tokens.id, id)).get()) {
        return reply.notFound("token not found");
      }
      db.transaction((tx) => hardDeleteToken(tx as unknown as Db, id));
      return reply.send({ ok: true, deleted: "hard" });
    }
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

  // Operator memo edit (status changes use the dedicated route above).
  app.patch("/api/v1/tokens/:id", async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = z
      .object({ memo: z.string().max(500).nullable() })
      .safeParse(request.body);
    if (!parsed.success) {
      return reply.badRequest(parsed.error.issues.map((i) => i.message).join("; "));
    }
    const result = db
      .update(tokens)
      .set({ memo: parsed.data.memo })
      .where(eq(tokens.id, id))
      .run();
    if (result.changes === 0) return reply.notFound("token not found");
    return reply.send({ ok: true });
  });

  // Re-run the clone for cloned_website tokens (first attempt failed, or
  // the target page changed). Outcome is stamped into the token config.
  app.post("/api/v1/tokens/:id/reclone", async (request, reply) => {
    const { id } = request.params as { id: string };
    const row = db.select().from(tokens).where(eq(tokens.id, id)).get();
    if (!row) return reply.notFound("token not found");
    if (row.type !== "cloned_website") {
      return reply.badRequest("token is not a cloned_website token");
    }
    const targetUrl = String((row.config as Record<string, unknown>)["target_url"] ?? "");
    if (!targetUrl) return reply.badRequest("token has no target_url configured");
    const result = await cloneWebsiteForToken(app, db, id, targetUrl);
    if (!result.ok) return reply.badRequest(`re-clone failed: ${result.error}`);
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

  app.post(
    "/api/v1/tokens/:id/image",
    // Roomy body cap: 4 MiB image + base64 overhead + envelope.
    { bodyLimit: 6 * 1024 * 1024 },
    async (request, reply) => {
      const { id } = request.params as { id: string };
      const parsed = z
        .object({
          data: z.string().min(1),
          contentType: z.string().min(3).max(100),
          filename: z.string().min(1).max(200).optional(),
        })
        .safeParse(request.body);
      if (!parsed.success) {
        return reply.badRequest(parsed.error.issues.map((i) => i.message).join("; "));
      }
      const token = db
        .select({ type: tokens.type })
        .from(tokens)
        .where(eq(tokens.id, id))
        .get();
      if (!token) return reply.notFound("token not found");
      if (token.type !== "custom_image") {
        return reply.badRequest("token is not a custom_image token");
      }
      // svg deliberately excluded: no script-bearing markup served inline.
      if (!IMAGE_CONTENT_TYPES.has(parsed.data.contentType)) {
        return reply.badRequest(
          `contentType must be one of: ${[...IMAGE_CONTENT_TYPES].join(", ")}`,
        );
      }
      const b64 = parsed.data.data.replace(/\s/g, "");
      if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) {
        return reply.badRequest("data must be base64");
      }
      const body = Buffer.from(b64, "base64");
      if (body.length === 0 || body.length > 4 * 1024 * 1024) {
        return reply.badRequest("image must decode to 1 byte - 4 MiB");
      }
      const filename = (parsed.data.filename ?? "image").replace(/["\\/:]/g, "_");
      db.delete(tokenFiles)
        .where(and(eq(tokenFiles.tokenId, id), eq(tokenFiles.idx, 0)))
        .run();
      db.insert(tokenFiles)
        .values({
          id: newId("file"),
          tokenId: id,
          idx: 0,
          filename,
          contentType: parsed.data.contentType,
          data: b64,
          createdAt: new Date().toISOString(),
        })
        .run();
      return reply.send({ ok: true, size: body.length });
    },
  );

  app.get("/api/v1/incidents", async (request, reply) => {
    const parsed = z
      .object({
        limit: z.coerce.number().int().min(1).max(500).default(200),
        acknowledged: z.enum(["true", "false"]).optional(),
        source_ip: z.string().max(100).optional(),
        severity: incidentSeveritySchema.optional(),
        type: z.string().max(64).optional(),
        token_id: z.string().max(64).optional(),
        // Substring match against the raw event JSON (path, UA, DNS name...).
        q: z.string().max(200).optional(),
      })
      .safeParse(request.query);
    if (!parsed.success) {
      return reply.badRequest(parsed.error.issues.map((i) => i.message).join("; "));
    }
    const query = parsed.data;
    const conditions: SQL[] = [];
    if (query.acknowledged === "false") {
      conditions.push(eq(incidents.acknowledged, false));
    }
    if (query.acknowledged === "true") {
      conditions.push(eq(incidents.acknowledged, true));
    }
    if (query.source_ip) conditions.push(eq(incidents.sourceIp, query.source_ip));
    if (query.severity) conditions.push(eq(incidents.severity, query.severity));
    if (query.type) conditions.push(eq(tokens.type, query.type));
    if (query.token_id) conditions.push(eq(incidents.tokenId, query.token_id));
    if (query.q) conditions.push(like(incidents.event, `%${query.q}%`));
    let stmt = db
      .select({
        id: incidents.id,
        tokenId: incidents.tokenId,
        tokenType: tokens.type,
        severity: incidents.severity,
        acknowledged: incidents.acknowledged,
        event: incidents.event,
        seenAt: incidents.seenAt,
        sourceIp: incidents.sourceIp,
        geo: incidents.geo,
        notes: incidents.notes,
      })
      .from(incidents)
      .innerJoin(tokens, eq(incidents.tokenId, tokens.id))
      .orderBy(desc(incidents.seenAt))
      .limit(query.limit)
      .$dynamic();
    if (conditions.length > 0) {
      stmt = stmt.where(and(...conditions));
    }
    return stmt.all();
  });

  app.get("/api/v1/incidents/:id", async (request, reply) => {
    const { id } = request.params as { id: string };
    const row = db
      .select({
        id: incidents.id,
        tokenId: incidents.tokenId,
        tokenType: tokens.type,
        severity: incidents.severity,
        acknowledged: incidents.acknowledged,
        event: incidents.event,
        seenAt: incidents.seenAt,
        sourceIp: incidents.sourceIp,
        geo: incidents.geo,
        notes: incidents.notes,
      })
      .from(incidents)
      .innerJoin(tokens, eq(incidents.tokenId, tokens.id))
      .where(eq(incidents.id, id))
      .get();
    if (!row) return reply.notFound("incident not found");
    return row;
  });

  // Operator triage notes (free text, replaces on each PATCH).
  app.patch("/api/v1/incidents/:id/notes", async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = z
      .object({ notes: z.string().max(4000).nullable() })
      .safeParse(request.body);
    if (!parsed.success) {
      return reply.badRequest(parsed.error.issues.map((i) => i.message).join("; "));
    }
    const result = db
      .update(incidents)
      .set({ notes: parsed.data.notes })
      .where(eq(incidents.id, id))
      .run();
    if (result.changes === 0) return reply.notFound("incident not found");
    return reply.send({ ok: true });
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

  // Bulk triage: acknowledge up to 500 incidents in one call.
  app.post("/api/v1/incidents/bulk-ack", async (request, reply) => {
    const parsed = z
      .object({ ids: z.array(z.string().min(1)).min(1).max(500) })
      .safeParse(request.body);
    if (!parsed.success) {
      return reply.badRequest(parsed.error.issues.map((i) => i.message).join("; "));
    }
    const result = db
      .update(incidents)
      .set({ acknowledged: true })
      .where(inArray(incidents.id, parsed.data.ids))
      .run();
    return reply.send({ ok: true, updated: result.changes });
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

  // Internal: gateway serves cloned pages from here.
  app.get("/api/v1/tokens/:id/internal-page", async (request, reply) => {
    const { id } = request.params as { id: string };
    const token = db
      .select({ type: tokens.type, status: tokens.status })
      .from(tokens)
      .where(eq(tokens.id, id))
      .get();
    if (!token || token.status !== "active" || token.type !== "cloned_website") {
      return reply.notFound();
    }
    const file = db
      .select()
      .from(tokenFiles)
      .where(and(eq(tokenFiles.tokenId, id), eq(tokenFiles.idx, 0)))
      .get();
    if (!file) return reply.notFound();
    reply.header("content-type", file.contentType);
    return reply.send(Buffer.from(file.data, "base64"));
  });

  // Internal: gateway serves custom_image uploads from here.
  app.get("/api/v1/tokens/:id/internal-image", async (request, reply) => {
    const { id } = request.params as { id: string };
    const token = db
      .select({ type: tokens.type, status: tokens.status })
      .from(tokens)
      .where(eq(tokens.id, id))
      .get();
    if (!token || token.status !== "active" || token.type !== "custom_image") {
      return reply.notFound();
    }
    const file = db
      .select()
      .from(tokenFiles)
      .where(and(eq(tokenFiles.tokenId, id), eq(tokenFiles.idx, 0)))
      .get();
    if (!file) return reply.notFound();
    reply.header("content-type", file.contentType);
    return reply.send(Buffer.from(file.data, "base64"));
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

      // Agent-reported detections carry their own sensor identity and
      // severity; gateway events must satisfy the token's type rules.
      const eventRecord = parsed.data.event as Record<string, unknown>;
      const detail = eventRecord["detail"] as Record<string, unknown> | undefined;
      const agentReported =
        typeof detail?.["sensor"] === "string" && detail["sensor"].length > 0;

      let severity: string;
      if (agentReported) {
        severity = parsed.data.severity;
      } else {
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
        severity = match.severity;
      }

      const incidentId = `inc_${Date.now().toString(36)}${Math.random()
        .toString(36)
        .slice(2, 8)}`;
      // Extract + enrich the source IP once at ingest; the event JSON stays
      // the authoritative full record.
      const sourceIp = extractSourceIp(eventRecord) ?? null;
      const geoInfo = sourceIp ? geo.lookup(sourceIp) : null;
      db.insert(incidents)
        .values({
          id: incidentId,
          tokenId: token.id,
          severity,
          event: parsed.data.event,
          seenAt: new Date().toISOString(),
          sourceIp,
          geo: geoInfo,
        })
        .run();

      // Fire-and-forget alerting; incident is already durably recorded.
      void dispatcher.dispatch({
        tokenId: token.id,
        tokenType: token.type,
        severity,
        incidentId,
        seenAt: new Date().toISOString(),
        event: parsed.data.event as TriggerEvent,
      });

      return reply.code(201).send({ id: incidentId });
  });
}

function gatewayOriginFor(_tokenId: string): string {
  const baseDomain = process.env.F0_TOKEN_DOMAINS?.split(",")[0]?.trim() ?? "tokens.example.com";
  return process.env.F0_GATEWAY_ORIGIN ?? `https://${baseDomain}`;
}

/** Hard delete: token + its files + its incident history. */
function hardDeleteToken(db: Db, id: string): void {
  db.delete(incidents).where(eq(incidents.tokenId, id)).run();
  db.delete(tokenFiles).where(eq(tokenFiles.tokenId, id)).run();
  db.delete(tokens).where(eq(tokens.id, id)).run();
}

export function generateContextFor(tokenId: string, config: Record<string, unknown>) {
  const baseDomain = process.env.F0_TOKEN_DOMAINS?.split(",")[0]?.trim() ?? "tokens.example.com";
  const gatewayOrigin = process.env.F0_GATEWAY_ORIGIN ?? `https://${baseDomain}`;
  return {
    tokenId,
    baseDomain,
    gatewayOrigin,
    config,
  };
}

/**
 * Fetch a clone target, inject the pixel beacon, store the page in
 * token_files idx 0, and record the outcome in the token's config
 * (clone_status / clone_error / cloned_at) so the console can show it.
 */
async function cloneWebsiteForToken(
  app: FastifyInstance,
  db: Db,
  tokenId: string,
  targetUrl: string,
): Promise<{ ok: boolean; error?: string }> {
  const stamp = (status: "ok" | "failed", error: string | null) => {
    const row = db
      .select({ config: tokens.config })
      .from(tokens)
      .where(eq(tokens.id, tokenId))
      .get();
    const config = {
      ...((row?.config ?? {}) as Record<string, unknown>),
      clone_status: status,
      clone_error: error,
      cloned_at: new Date().toISOString(),
    };
    db.update(tokens).set({ config }).where(eq(tokens.id, tokenId)).run();
  };

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10_000);
    const res = await fetch(targetUrl, {
      signal: controller.signal,
      redirect: "follow",
      headers: { "user-agent": "Mozilla/5.0 (compatible; f0_deception)" },
    });
    clearTimeout(timer);
    if (!res.ok) throw new Error(`target responded ${res.status}`);
    let html = await res.text();
    const beacon =
      `<img src="${gatewayOriginFor(tokenId)}/${tokenId}/pixel.gif" width="1" height="1" alt="" style="display:none">`;
    html = html.includes("</body>")
      ? html.replace(/<\/body>/i, `${beacon}</body>`)
      : html + beacon;
    db.delete(tokenFiles)
      .where(and(eq(tokenFiles.tokenId, tokenId), eq(tokenFiles.idx, 0)))
      .run();
    db.insert(tokenFiles)
      .values({
        id: newId("file"),
        tokenId,
        idx: 0,
        filename: "cloned_page.html",
        contentType: "text/html",
        data: Buffer.from(html).toString("base64"),
        createdAt: new Date().toISOString(),
      })
      .run();
    stamp("ok", null);
    return { ok: true };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    app.log.warn(`clone fetch failed for ${targetUrl}: ${msg}`);
    stamp("failed", msg);
    return { ok: false, error: msg };
  }
}
