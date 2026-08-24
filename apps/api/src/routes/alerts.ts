import { eq, desc } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { Db } from "../db/index.js";
import { alertChannels } from "../db/schema.js";
import { newId } from "../ids.js";
import type { AlertDispatcher } from "../alerts/dispatcher.js";

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

export function registerAlertRoutes(
  app: FastifyInstance,
  db: Db,
  dispatcher: AlertDispatcher,
): void {
  app.get("/api/v1/alert-channels", async () => {
    return db.select().from(alertChannels).orderBy(desc(alertChannels.createdAt)).all();
  });

  app.post("/api/v1/alert-channels", async (request, reply) => {
    const parsed = z
      .object({
        kind: z.enum(["webhook", "email", "syslog", "elasticsearch", "loki"]),
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
      .object({ enabled: z.boolean() })
      .safeParse(request.body);
    if (!parsed.success) {
      return reply.badRequest(parsed.error.issues.map((i) => i.message).join("; "));
    }
    const result = db
      .update(alertChannels)
      .set({ enabled: parsed.data.enabled, failureCount: 0 })
      .where(eq(alertChannels.id, id))
      .run();
    if (result.changes === 0) return reply.notFound("channel not found");
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
