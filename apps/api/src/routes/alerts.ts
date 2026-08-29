import { eq, desc } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { Db } from "../db/index.js";
import { alertChannels } from "../db/schema.js";
import { newId } from "../ids.js";
import type { AlertDispatcher } from "../alerts/dispatcher.js";
import { alertChannelKindSchema } from "@f0/deception-shared";

const channelConfigSchemas: Record<string, z.ZodType> = {
  webhook: z.object({
    url: z.string().url(),
    secret: z.string().optional(),
  }),
  email: z.object({
    smtp_host: z.string().min(1),
    smtp_port: z.number().int().min(1).max(65535).optional(),
    smtp_user: z.string().optional(),
    smtp_pass: z.string().optional(),
    from: z.string().min(3),
    to: z.string().min(3),
    subject_prefix: z.string().optional(),
  }),
  syslog: z.object({
    host: z.string().min(1),
    port: z.number().int().min(1).max(65535).optional(),
    app_name: z.string().optional(),
  }),
  elasticsearch: z.object({
    url: z.string().url(),
    index: z.string().optional(),
    username: z.string().optional(),
    password: z.string().optional(),
  }),
  loki: z.object({
    url: z.string().url(),
    labels: z.record(z.string(), z.string()).optional(),
    tenant_id: z.string().optional(),
  }),
};

const SECRET_KEY_RE = /pass|secret|token|key/i;

/** Sentinel returned in place of a stored secret; never a real value. */
export const SECRET_MASK = "•••";

function maskSecrets(config: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(config).map(([k, v]) => [
      k,
      SECRET_KEY_RE.test(k) && typeof v === "string" && v !== "" ? SECRET_MASK : v,
    ]),
  );
}

export function registerAlertRoutes(
  app: FastifyInstance,
  db: Db,
  dispatcher: AlertDispatcher,
): void {
  app.get("/api/v1/alert-channels", async () => {
    // Secrets are write-only: the console never needs them back.
    return db
      .select()
      .from(alertChannels)
      .orderBy(desc(alertChannels.createdAt))
      .all()
      .map((c) => ({ ...c, config: maskSecrets(c.config as Record<string, unknown>) }));
  });

  app.post("/api/v1/alert-channels", async (request, reply) => {
    const parsed = z
      .object({
        kind: alertChannelKindSchema,
        config: z.record(z.string(), z.unknown()),
      })
      .safeParse(request.body);
    if (!parsed.success) {
      return reply.badRequest(parsed.error.issues.map((i) => i.message).join("; "));
    }
    const schema = channelConfigSchemas[parsed.data.kind];
    if (!schema) return reply.badRequest(`unsupported kind: ${parsed.data.kind}`);
    const configResult = schema.safeParse(parsed.data.config);
    if (!configResult.success) {
      return reply.badRequest(configResult.error.issues.map((i) => i.message).join("; "));
    }
    const id = newId("chan");
    db.insert(alertChannels)
      .values({
        id,
        kind: parsed.data.kind,
        config: configResult.data,
        enabled: true,
        failureCount: 0,
        createdAt: new Date().toISOString(),
      })
      .run();
    return reply.code(201).send({ id });
  });

  app.delete("/api/v1/alert-channels/:id", async (request, reply) => {
    const { id } = request.params as { id: string };
    const result = db.delete(alertChannels).where(eq(alertChannels.id, id)).run();
    if (result.changes === 0) return reply.notFound("channel not found");
    return reply.send({ ok: true });
  });

  app.patch("/api/v1/alert-channels/:id", async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = z
      .object({
        enabled: z.boolean().optional(),
        config: z.record(z.string(), z.unknown()).optional(),
      })
      .refine((b) => b.enabled !== undefined || b.config !== undefined, {
        message: "nothing to update: provide enabled and/or config",
      })
      .safeParse(request.body);
    if (!parsed.success) {
      return reply.badRequest(parsed.error.issues.map((i) => i.message).join("; "));
    }

    const existing = db
      .select()
      .from(alertChannels)
      .where(eq(alertChannels.id, id))
      .get();
    if (!existing) return reply.notFound("channel not found");

    const patch: { enabled?: boolean; failureCount?: number; config?: unknown } = {};
    if (parsed.data.enabled !== undefined) {
      // Re-enabling clears the circuit breaker, as before.
      patch.enabled = parsed.data.enabled;
      patch.failureCount = 0;
    }

    if (parsed.data.config) {
      // Secrets are masked on read, so an edit form cannot echo them back.
      // A field left at the mask (or omitted) keeps the stored value; a new
      // value replaces it. Without this, saving an edited channel would
      // write the literal mask string as the credential.
      const stored = (existing.config ?? {}) as Record<string, unknown>;
      const incoming = parsed.data.config;
      const merged: Record<string, unknown> = { ...incoming };
      for (const [k, v] of Object.entries(incoming)) {
        if (SECRET_KEY_RE.test(k) && (v === SECRET_MASK || v === "" || v === undefined)) {
          if (stored[k] !== undefined) merged[k] = stored[k];
          else delete merged[k];
        }
      }
      const schema = channelConfigSchemas[existing.kind];
      if (!schema) return reply.badRequest(`unsupported kind: ${existing.kind}`);
      const result = schema.safeParse(merged);
      if (!result.success) {
        return reply.badRequest(result.error.issues.map((i) => i.message).join("; "));
      }
      patch.config = result.data;
      // A reconfigured channel deserves a fresh start on the breaker.
      patch.failureCount = 0;
    }

    db.update(alertChannels).set(patch).where(eq(alertChannels.id, id)).run();
    return reply.send({ ok: true });
  });

  app.post("/api/v1/alert-channels/:id/test", async (request, reply) => {
    const { id } = request.params as { id: string };
    try {
      await dispatcher.testChannel(id);
    } catch (err) {
      return reply.badRequest(
        `test delivery failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    return reply.send({ ok: true });
  });
}
