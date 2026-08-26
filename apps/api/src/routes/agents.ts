import { randomBytes } from "node:crypto";
import { eq } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { Db } from "../db/index.js";
import { agents, agentSensors } from "../db/schema.js";
import { newId } from "../ids.js";
import { hashAgentKey, verifyAgentKey } from "../auth.js";

const SENSOR_CONFIG_SCHEMA = z.array(
  z.object({
    kind: z.enum(["ssh", "http_login", "smb", "rdp", "planted_credential", "file_watch"]),
    enabled: z.boolean().default(true),
    config: z.record(z.string(), z.unknown()).default({}),
  }),
);

export function registerAgentRoutes(app: FastifyInstance, db: Db): void {
  app.post(
    "/api/v1/agent/enroll",
    { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } },
    async (request, reply) => {
    const parsed = z
      .object({
        enrollment_token: z.string().min(1),
        hostname: z.string().min(1).max(255),
        platform: z.string().min(1).max(64),
        version: z.string().max(32).default("0.0.0"),
      })
      .safeParse(request.body);
    if (!parsed.success) {
      return reply.badRequest(parsed.error.issues.map((i) => i.message).join("; "));
    }
    const expected = process.env.F0_ENROLLMENT_TOKEN;
    if (!expected || parsed.data.enrollment_token !== expected) {
      return reply.unauthorized("invalid enrollment token");
    }

    // Re-enrollment of the same host replaces its key.
    const existing = db
      .select()
      .from(agents)
      .where(eq(agents.hostname, parsed.data.hostname))
      .get();

    const rawKey = `fdk_${randomBytes(30).toString("base64url")}`;
    if (existing) {
      db.update(agents)
        .set({
          agentKeyHash: hashAgentKey(rawKey),
          status: "online",
          lastSeenAt: new Date().toISOString(),
        })
        .where(eq(agents.id, existing.id))
        .run();
      return reply.send({ agent_id: existing.id, agent_key: rawKey });
    }

    const id = `agt_${randomBytes(8).toString("hex")}`;
    db.insert(agents)
      .values({
        id,
        agentKeyHash: hashAgentKey(rawKey),
        hostname: parsed.data.hostname,
        platform: parsed.data.platform,
        version: parsed.data.version,
        status: "online",
        lastSeenAt: new Date().toISOString(),
        createdAt: new Date().toISOString(),
      })
      .run();
    return reply.code(201).send({ agent_id: id, agent_key: rawKey });
    },
  );

  app.post("/api/v1/agent/heartbeat", async (request, reply) => {
    const auth = request.headers.authorization;
    const key = auth?.startsWith("Bearer ") ? auth.slice(7) : undefined;
    const body = z
      .object({ agent_id: z.string().min(1) })
      .safeParse(request.body);
    if (!key || !body.success) return reply.unauthorized("missing credentials");

    const agent = db.select().from(agents).where(eq(agents.id, body.data.agent_id)).get();
    if (!agent || !verifyAgentKey(key, agent.agentKeyHash)) {
      return reply.unauthorized("unknown agent or bad key");
    }

    db.update(agents)
      .set({ status: "online", lastSeenAt: new Date().toISOString() })
      .where(eq(agents.id, agent.id))
      .run();

    // Sensor configuration is fleet-managed via the console (DB-backed).
    const sensors = db
      .select({
        kind: agentSensors.kind,
        enabled: agentSensors.enabled,
        config: agentSensors.config,
      })
      .from(agentSensors)
      .where(eq(agentSensors.agentId, agent.id))
      .all();

    return reply.send({
      poll_interval_seconds: Number(process.env.F0_AGENT_POLL_INTERVAL ?? 60),
      sensors,
    });
  });

  app.get("/api/v1/agents", async () => {
    const rows = db
      .select({
        id: agents.id,
        hostname: agents.hostname,
        platform: agents.platform,
        version: agents.version,
        memo: agents.memo,
        status: agents.status,
        lastSeenAt: agents.lastSeenAt,
      })
      .from(agents)
      .all();
    return rows.map((a) => ({
      ...a,
      sensors: db
        .select()
        .from(agentSensors)
        .where(eq(agentSensors.agentId, a.id))
        .all(),
    }));
  });

  // Update operator-facing metadata (memo/alias).
  app.patch("/api/v1/agents/:id", async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = z
      .object({ memo: z.string().max(500).nullable() })
      .safeParse(request.body);
    if (!parsed.success) {
      return reply.badRequest(parsed.error.issues.map((i) => i.message).join("; "));
    }
    const result = db
      .update(agents)
      .set({ memo: parsed.data.memo })
      .where(eq(agents.id, id))
      .run();
    if (result.changes === 0) return reply.notFound("agent not found");
    return reply.send({ ok: true });
  });

  // Retire an agent: its key dies with the row (heartbeats/reporting start
  // returning 401). Incident history lives against tokens, not agents.
  app.delete("/api/v1/agents/:id", async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!db.select({ id: agents.id }).from(agents).where(eq(agents.id, id)).get()) {
      return reply.notFound("agent not found");
    }
    db.transaction((tx) => {
      tx.delete(agentSensors).where(eq(agentSensors.agentId, id)).run();
      tx.delete(agents).where(eq(agents.id, id)).run();
    });
    return reply.send({ ok: true });
  });

  // Replace the sensor set for an agent.
  app.put("/api/v1/agents/:id/sensors", async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!db.select().from(agents).where(eq(agents.id, id)).get()) {
      return reply.notFound("agent not found");
    }
    const parsed = z
      .object({ sensors: SENSOR_CONFIG_SCHEMA })
      .safeParse(request.body);
    if (!parsed.success) {
      return reply.badRequest(parsed.error.issues.map((i) => i.message).join("; "));
    }
    db.transaction((tx) => {
      tx.delete(agentSensors).where(eq(agentSensors.agentId, id)).run();
      for (const s of parsed.data.sensors) {
        tx.insert(agentSensors)
          .values({
            id: newId("sns"),
            agentId: id,
            kind: s.kind,
            enabled: s.enabled,
            config: s.config,
            createdAt: new Date().toISOString(),
          })
          .run();
      }
    });
    return reply.send({ ok: true });
  });
}
