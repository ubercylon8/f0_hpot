import { describe, it, expect, afterEach } from "vitest";
import { buildServer } from "./server.js";

const ENV = ["F0_ADMIN_TOKEN", "F0_INTERNAL_SECRET", "F0_ENROLLMENT_TOKEN"] as const;
const saved: Record<string, string | undefined> = {};
for (const v of ENV) saved[v] = process.env[v];

/**
 * Retiring an agent has to be distinguishable from an auth failure. The
 * agent stops its honeypots on a revocation and keeps retrying through
 * anything else, so a 401 where a 410 belongs leaves live sensors reporting
 * to nobody — and a 410 where a 401 belongs would shut down a healthy
 * fleet on a transient problem.
 */
describe("agent revocation signalling", () => {
  afterEach(() => {
    for (const v of ENV) {
      if (saved[v] === undefined) delete process.env[v];
      else process.env[v] = saved[v];
    }
  });

  async function enrolledServer() {
    process.env["F0_ENROLLMENT_TOKEN"] = "enroll-me";
    delete process.env["F0_ADMIN_TOKEN"];
    delete process.env["F0_INTERNAL_SECRET"];
    const { app } = buildServer({ dbPath: ":memory:" });
    await app.ready();
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/agent/enroll",
      payload: {
        enrollment_token: "enroll-me",
        hostname: "host-a",
        platform: "linux/amd64",
        version: "test",
      },
    });
    expect(res.statusCode).toBe(201);
    const { agent_id, agent_key } = res.json() as { agent_id: string; agent_key: string };
    return { app, agentId: agent_id, agentKey: agent_key };
  }

  const beat = (app: Awaited<ReturnType<typeof enrolledServer>>["app"], id: string, key: string) =>
    app.inject({
      method: "POST",
      url: "/api/v1/agent/heartbeat",
      headers: { authorization: `Bearer ${key}`, "x-agent-id": id },
      payload: { agent_id: id },
    });

  it("refreshes the reported version on every heartbeat", async () => {
    // Version was captured at enrollment only, so an upgraded fleet kept
    // showing the version it first enrolled with.
    const { app, agentId, agentKey } = await enrolledServer();
    try {
      await app.inject({
        method: "POST",
        url: "/api/v1/agent/heartbeat",
        headers: { authorization: `Bearer ${agentKey}`, "x-agent-id": agentId },
        payload: { agent_id: agentId, version: "9.9.9-upgraded" },
      });
      const list = await app.inject({ method: "GET", url: "/api/v1/agents" });
      const row = (list.json() as { id: string; version: string }[]).find((a) => a.id === agentId);
      expect(row?.version).toBe("9.9.9-upgraded");

      // An agent that reports no version keeps the one on record.
      await app.inject({
        method: "POST",
        url: "/api/v1/agent/heartbeat",
        headers: { authorization: `Bearer ${agentKey}`, "x-agent-id": agentId },
        payload: { agent_id: agentId },
      });
      const after = await app.inject({ method: "GET", url: "/api/v1/agents" });
      const row2 = (after.json() as { id: string; version: string }[]).find((a) => a.id === agentId);
      expect(row2?.version).toBe("9.9.9-upgraded");
    } finally {
      await app.close();
    }
  });

  it("answers a retired agent with 410 and a revoked marker", async () => {
    const { app, agentId, agentKey } = await enrolledServer();
    try {
      expect((await beat(app, agentId, agentKey)).statusCode).toBe(200);

      await app.inject({ method: "DELETE", url: `/api/v1/agents/${agentId}` });

      const res = await beat(app, agentId, agentKey);
      expect(res.statusCode).toBe(410);
      // The agent keys off this to stop its sensors.
      expect((res.json() as { status: string }).status).toBe("revoked");
    } finally {
      await app.close();
    }
  });

  it("keeps a wrong key on a live agent at 401, not 410", async () => {
    const { app, agentId } = await enrolledServer();
    try {
      // An orphaned process superseded by a re-enrollment must keep
      // retrying, not decommission itself.
      const res = await beat(app, agentId, "fdk_not-the-right-key");
      expect(res.statusCode).toBe(401);
    } finally {
      await app.close();
    }
  });

  it("does not report revocation for an unknown id with no credentials", async () => {
    const { app } = await enrolledServer();
    try {
      const res = await app.inject({
        method: "POST",
        url: "/api/v1/agent/heartbeat",
        payload: { agent_id: "agt_doesnotexist" },
      });
      // No bearer at all is a credentials problem, not a retirement.
      expect(res.statusCode).toBe(401);
    } finally {
      await app.close();
    }
  });
});
