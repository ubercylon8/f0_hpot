import { describe, it, expect, afterEach } from "vitest";
import { buildServer } from "./server.js";

const ENV_VARS = ["F0_ADMIN_TOKEN", "F0_INTERNAL_SECRET"] as const;

function savedEnv() {
  const saved: Record<string, string | undefined> = {};
  for (const v of ENV_VARS) saved[v] = process.env[v];
  return saved;
}

function restoreEnv(saved: Record<string, string | undefined>) {
  for (const v of ENV_VARS) {
    if (saved[v] === undefined) delete process.env[v];
    else process.env[v] = saved[v];
  }
}

describe("API auth", () => {
  const saved = savedEnv();
  afterEach(() => restoreEnv(saved));

  it("open mode: console routes are open while no keys/tokens exist, and close once a key is created", async () => {
    delete process.env.F0_ADMIN_TOKEN;
    delete process.env.F0_INTERNAL_SECRET;
    const { app } = buildServer({ dbPath: ":memory:" });
    await app.ready();

    // Open mode: no credentials needed.
    let res = await app.inject({ method: "GET", url: "/api/v1/tokens" });
    expect(res.statusCode).toBe(200);

    // Bootstrap the first persistent key in open mode.
    res = await app.inject({
      method: "POST",
      url: "/api/v1/auth/keys",
      payload: { label: "console" },
    });
    expect(res.statusCode).toBe(201);
    const { key } = res.json() as { key: string };
    expect(key.startsWith("f0k_")).toBe(true);

    // Open mode is closed now — unauthenticated requests are rejected.
    res = await app.inject({ method: "GET", url: "/api/v1/tokens" });
    expect(res.statusCode).toBe(401);

    // The new key works, including the login probe.
    res = await app.inject({
      method: "GET",
      url: "/api/v1/tokens",
      headers: { authorization: `Bearer ${key}` },
    });
    expect(res.statusCode).toBe(200);
    res = await app.inject({
      method: "POST",
      url: "/api/v1/auth/login",
      payload: { key },
    });
    expect(res.statusCode).toBe(204);

    // Key management: list + revoke.
    res = await app.inject({
      method: "GET",
      url: "/api/v1/auth/keys",
      headers: { authorization: `Bearer ${key}` },
    });
    expect(res.statusCode).toBe(200);
    const keys = res.json() as { id: string; label: string }[];
    expect(keys).toHaveLength(1);
    expect(keys[0]!.label).toBe("console");
    res = await app.inject({
      method: "DELETE",
      url: `/api/v1/auth/keys/${keys[0]!.id}`,
      headers: { authorization: `Bearer ${key}` },
    });
    expect(res.statusCode).toBe(200);
    // Revoking the LAST key re-opens the escape hatch (documented behavior:
    // open while no tokens configured and the table is empty).
    res = await app.inject({
      method: "GET",
      url: "/api/v1/tokens",
      headers: { authorization: `Bearer ${key}` },
    });
    expect(res.statusCode).toBe(200);

    await app.close();
  });

  it("admin token grants console scope; wrong keys are rejected", async () => {
    process.env.F0_ADMIN_TOKEN = "test-admin-token";
    delete process.env.F0_INTERNAL_SECRET;
    const { app } = buildServer({ dbPath: ":memory:" });
    await app.ready();

    let res = await app.inject({ method: "GET", url: "/api/v1/tokens" });
    expect(res.statusCode).toBe(401);
    res = await app.inject({
      method: "GET",
      url: "/api/v1/tokens",
      headers: { authorization: "Bearer wrong" },
    });
    expect(res.statusCode).toBe(401);
    res = await app.inject({
      method: "GET",
      url: "/api/v1/tokens",
      headers: { authorization: "Bearer test-admin-token" },
    });
    expect(res.statusCode).toBe(200);
    res = await app.inject({
      method: "POST",
      url: "/api/v1/auth/login",
      payload: { key: "test-admin-token" },
    });
    expect(res.statusCode).toBe(204);
    res = await app.inject({
      method: "POST",
      url: "/api/v1/auth/login",
      payload: { key: "nope" },
    });
    expect(res.statusCode).toBe(401);

    await app.close();
  });

  it("internal scope: gateway secret authorizes incident forwarding, console keys do not leak out", async () => {
    process.env.F0_ADMIN_TOKEN = "test-admin-token";
    process.env.F0_INTERNAL_SECRET = "test-internal-secret";
    const { app } = buildServer({ dbPath: ":memory:" });
    await app.ready();

    const incident = {
      tokenId: "nonexistent",
      severity: "low",
      event: { kind: "http" },
    };
    // No credentials: rejected.
    let res = await app.inject({
      method: "POST",
      url: "/api/v1/incidents",
      payload: incident,
    });
    expect(res.statusCode).toBe(401);
    // Internal secret: auth passes (404 = unknown token id, as designed).
    res = await app.inject({
      method: "POST",
      url: "/api/v1/incidents",
      headers: { authorization: "Bearer test-internal-secret" },
      payload: incident,
    });
    expect(res.statusCode).toBe(404);
    // The internal secret must NOT work for console routes.
    res = await app.inject({
      method: "GET",
      url: "/api/v1/tokens",
      headers: { authorization: "Bearer test-internal-secret" },
    });
    expect(res.statusCode).toBe(401);
    // internal-config also accepts the secret (404 = unknown token).
    res = await app.inject({
      method: "GET",
      url: "/api/v1/tokens/nonexistent/internal-config",
      headers: { authorization: "Bearer test-internal-secret" },
    });
    expect(res.statusCode).toBe(404);

    await app.close();
  });

  it("agent enroll/heartbeat stay exempt from console auth", async () => {
    process.env.F0_ADMIN_TOKEN = "test-admin-token";
    delete process.env.F0_INTERNAL_SECRET;
    process.env.F0_ENROLLMENT_TOKEN = "enroll-token";
    const { app } = buildServer({ dbPath: ":memory:" });
    await app.ready();
    try {
      const res = await app.inject({
        method: "POST",
        url: "/api/v1/agent/enroll",
        payload: {
          enrollment_token: "enroll-token",
          hostname: "testhost",
          platform: "linux/amd64",
        },
      });
      expect(res.statusCode).toBe(201);
      const { agent_id, agent_key } = res.json() as {
        agent_id: string;
        agent_key: string;
      };
      const hb = await app.inject({
        method: "POST",
        url: "/api/v1/agent/heartbeat",
        headers: { authorization: `Bearer ${agent_key}` },
        payload: { agent_id },
      });
      expect(hb.statusCode).toBe(200);

      // Agent key + x-agent-id authorizes incident reporting (internal route).
      const inc = await app.inject({
        method: "POST",
        url: "/api/v1/incidents",
        headers: {
          authorization: `Bearer ${agent_key}`,
          "x-agent-id": agent_id,
        },
        payload: {
          tokenId: "nonexistent",
          severity: "high",
          event: { kind: "agent", detail: { sensor: "ssh" } },
        },
      });
      expect(inc.statusCode).toBe(404); // unknown token, but auth passed
    } finally {
      delete process.env.F0_ENROLLMENT_TOKEN;
      await app.close();
    }
  });
});
