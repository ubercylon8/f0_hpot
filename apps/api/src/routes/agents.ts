import { createHash, randomBytes } from "node:crypto";
import { eq } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { Db } from "../db/index.js";
import { agents } from "../db/schema.js";

export function hashAgentKey(key: string): string {
  return createHash("sha256").update(key).digest("hex");
}

/** Timing-safe compare of a bearer key against a stored hash. */
export function verifyAgentKey(presented: string, storedHash: string): boolean {
  const presentedHash = Buffer.from(hashAgentKey(presented), "hex");
  const stored = Buffer.from(storedHash, "hex");
  return (
    presentedHash.length === stored.length &&
    createHash("sha256").update(presented).digest() !== undefined &&
    presentedHash.equals(stored)
  );
}

const SENSOR_CONFIG_SCHEMA = z.array(
  z.object({
    kind: z.enum(["ssh", "http_login", "planted_credential", "file_watch"]),
    enabled: z.boolean().default(true),
    config: z.record(z.string(), z.unknown()).default({}),
  }),
);

export function registerAgentRoutes(app: FastifyInstance, db: Db): void {
  app.post("/api/v1/agent/enroll", async (request, reply) => {
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
  });

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

    // v1: sensors are configured via env JSON (fleet UI comes in P4 proper).
    let sensorConfig: unknown = [];
    try {
      if (process.env.F0_AGENT_SENSORS) {
        sensorConfig = SENSOR_CONFIG_SCHEMA.parse(
          JSON.parse(process.env.F0_AGENT_SENSORS),
        );
      }
    } catch (err) {
      request.log.warn(`invalid F0_AGENT_SENSORS: ${String(err)}`);
    }

    return reply.send({
      poll_interval_seconds: Number(process.env.F0_AGENT_POLL_INTERVAL ?? 60),
      sensors: sensorConfig,
    });
  });

  app.get("/api/v1/agents", async () => {
    return db
      .select({
        id: agents.id,
        hostname: agents.hostname,
        platform: agents.platform,
        version: agents.version,
        status: agents.status,
        lastSeenAt: agents.lastSeenAt,
      })
      .from(agents)
      .all();
  });
}
