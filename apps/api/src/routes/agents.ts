import { randomBytes } from "node:crypto";
import { and, desc, eq } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { getTokenType } from "@f0/deception-tokens-core";
import type { Db } from "../db/index.js";
import { agentDeployments, agents, agentSensors, tokens, tokenFiles } from "../db/schema.js";
import { newId } from "../ids.js";
import { hashAgentKey, verifyAgentKey } from "../auth.js";
import { consumeEnrollmentToken } from "../enrollment.js";
import { agentStatus, pollIntervalSeconds } from "../agent-status.js";
import { generateContextFor } from "./tokens.js";

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
    const presented = parsed.data.enrollment_token;
    const valid =
      (expected !== undefined && expected !== "" && presented === expected) ||
      consumeEnrollmentToken(db, presented);
    if (!valid) {
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
      .object({
        agent_id: z.string().min(1),
        version: z.string().max(32).optional(),
        deployment_results: z
          .array(
            z.object({
              id: z.string().min(1),
              ok: z.boolean(),
              error: z.string().max(500).optional(),
            }),
          )
          .max(100)
          .optional(),
      })
      .safeParse(request.body);
    if (!key || !body.success) return reply.unauthorized("missing credentials");

    const agent = db.select().from(agents).where(eq(agents.id, body.data.agent_id)).get();
    // Distinguish "this agent was retired" from "these credentials are
    // wrong". A retired agent is told so definitively (410) so it can stop
    // its sensors instead of running honeypots nobody is listening to.
    // A bad key on an agent that still exists stays a 401: it may be an
    // orphaned process superseded by a re-enrollment, and it must keep
    // retrying rather than treat a transient problem as decommissioning.
    if (!agent) {
      return reply.code(410).send({
        statusCode: 410,
        error: "Gone",
        status: "revoked",
        message: "agent is no longer registered with this console",
      });
    }
    if (!verifyAgentKey(key, agent.agentKeyHash)) {
      return reply.unauthorized("unknown agent or bad key");
    }

    db.update(agents)
      .set({
        status: "online",
        lastSeenAt: new Date().toISOString(),
        // Refresh on every beat: recorded only at enrollment, it went stale
        // the moment an agent was upgraded, so the fleet list showed old
        // versions for hosts that were already patched.
        ...(body.data.version ? { version: body.data.version } : {}),
      })
      .where(eq(agents.id, agent.id))
      .run();

    // Token-deployment results from the agent's previous work (agent-scoped
    // update only — an agent can only complete its own pending deployments).
    for (const r of body.data.deployment_results ?? []) {
      db.update(agentDeployments)
        .set({
          status: r.ok ? "done" : "failed",
          error: r.ok ? null : (r.error ?? "agent reported failure"),
          completedAt: new Date().toISOString(),
        })
        .where(
          and(
            eq(agentDeployments.id, r.id),
            eq(agentDeployments.agentId, agent.id),
            eq(agentDeployments.status, "pending"),
          ),
        )
        .run();
    }

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

    // One-shot token deployments pending for this agent.
    const deployments = db
      .select({
        id: agentDeployments.id,
        kind: agentDeployments.kind,
        targetDir: agentDeployments.targetDir,
        filename: agentDeployments.filename,
        payload: agentDeployments.payload,
        url: agentDeployments.url,
      })
      .from(agentDeployments)
      .where(
        and(
          eq(agentDeployments.agentId, agent.id),
          eq(agentDeployments.status, "pending"),
        ),
      )
      .limit(20)
      .all();

    return reply.send({
      poll_interval_seconds: pollIntervalSeconds(),
      sensors,
      deployments,
    });
  });

  // Console-scope: what the "add agent" flow needs to render a one-liner.
  // The enrollment token is a bootstrap secret shared with console
  // operators — they can already mint agent keys by definition.
  app.get("/api/v1/agent-bootstrap", async () => {
    return { enrollmentToken: process.env.F0_ENROLLMENT_TOKEN ?? null };
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
      // Derived, not the stored column: see agent-status.ts.
      status: agentStatus(a.lastSeenAt),
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

  // Queue a token deployment to an agent (one-shot; executed on the next
  // heartbeat, result reported on the one after).
  app.post("/api/v1/agents/:id/deploy", async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = z
      .object({
        token_id: z.string().min(1),
        target_dir: z.string().min(1).max(200),
      })
      .safeParse(request.body);
    if (!parsed.success) {
      return reply.badRequest(parsed.error.issues.map((i) => i.message).join("; "));
    }
    if (!db.select({ id: agents.id }).from(agents).where(eq(agents.id, id)).get()) {
      return reply.notFound("agent not found");
    }
    const token = db.select().from(tokens).where(eq(tokens.id, parsed.data.token_id)).get();
    if (!token) return reply.notFound("token not found");
    if (token.status !== "active") return reply.badRequest("token is not active");
    // A honeypot token's artifact is the reference string "token_id=<id>",
    // meaningful only to a sensor config. Deploying it planted a nonsense
    // shortcut on the host instead of being rejected.
    if (token.type === "honeypot") {
      return reply.badRequest(
        "honeypot tokens are not deployable files — reference this token from a sensor's token_id instead",
      );
    }

    const deployment = buildDeployment(db, token.id, token.type);
    if (!deployment) {
      return reply.badRequest("token has no deployable artifact (no file, no URL)");
    }
    const depId = newId("dep");
    db.insert(agentDeployments)
      .values({
        id: depId,
        agentId: id,
        tokenId: token.id,
        ...deployment,
        targetDir: parsed.data.target_dir,
        createdAt: new Date().toISOString(),
      })
      .run();
    app.log.warn(
      `deployment ${depId} queued for agent ${id}: ${deployment.kind} ${deployment.filename} -> ${parsed.data.target_dir}`,
    );
    return reply.code(201).send({ id: depId, ...deployment, status: "pending" });
  });

  app.get("/api/v1/agents/:id/deployments", async (request, reply) => {
    const { id } = request.params as { id: string };
    return db
      .select({
        id: agentDeployments.id,
        tokenId: agentDeployments.tokenId,
        kind: agentDeployments.kind,
        targetDir: agentDeployments.targetDir,
        filename: agentDeployments.filename,
        url: agentDeployments.url,
        status: agentDeployments.status,
        error: agentDeployments.error,
        createdAt: agentDeployments.createdAt,
        completedAt: agentDeployments.completedAt,
      })
      .from(agentDeployments)
      .where(eq(agentDeployments.agentId, id))
      .orderBy(desc(agentDeployments.createdAt))
      .limit(50)
      .all();
  });
}

interface DeploymentSpec {
  kind: "file" | "shortcut";
  filename: string;
  payload: string | null;
  url: string | null;
}

/**
 * Build the deployment payload for a token:
 * - file-bearing tokens (word/excel/pdf/qr/custom_image/sql_injection/
 *   cloned page) deploy their token_files idx 0 bytes;
 * - everything else deploys a .url shortcut pointing at its trigger URL.
 */
function buildDeployment(db: Db, tokenId: string, tokenType: string): DeploymentSpec | null {
  const sanitize = (f: string) =>
    f.replaceAll("\\", "_").replaceAll("/", "_").replaceAll('"', "_").replaceAll("..", "_");

  const file = db
    .select()
    .from(tokenFiles)
    .where(and(eq(tokenFiles.tokenId, tokenId), eq(tokenFiles.idx, 0)))
    .get();
  if (file) {
    return { kind: "file", filename: sanitize(file.filename), payload: file.data, url: null };
  }

  const def = getTokenType(tokenType as Parameters<typeof getTokenType>[0]);
  if (!def) return null;
  const token = db.select().from(tokens).where(eq(tokens.id, tokenId)).get();
  const artifacts = def.generate(
    generateContextFor(tokenId, (token?.config ?? {}) as Record<string, unknown>),
  );
  const artifact = artifacts.find(
    (a) => (a.kind === "url" || a.kind === "hostname") && a.value,
  );
  if (!artifact) return null;
  return { kind: "shortcut", filename: `${sanitize(tokenId)}.url`, payload: null, url: artifact.value };
}
