import { describe, it, expect, afterEach } from "vitest";
import type { FastifyInstance } from "fastify";
import { createServer as createHttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { dashboardStatsSchema } from "@f0/deception-shared";
import { buildServer } from "./server.js";

const ENV_VARS = ["F0_ADMIN_TOKEN", "F0_INTERNAL_SECRET", "F0_ENROLLMENT_TOKEN"] as const;

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

/** Open-mode server (no auth env): console routes are unauthenticated. */
async function makeServer(): Promise<FastifyInstance> {
  delete process.env.F0_ADMIN_TOKEN;
  delete process.env.F0_INTERNAL_SECRET;
  const { app } = buildServer({ dbPath: ":memory:" });
  await app.ready();
  return app;
}

async function createToken(app: FastifyInstance, type = "web_bug"): Promise<string> {
  const res = await app.inject({
    method: "POST",
    url: "/api/v1/tokens",
    payload: { type, memo: `test ${type}` },
  });
  expect(res.statusCode).toBe(201);
  return (res.json() as { id: string }).id;
}

/** Forward a gateway-style hit that satisfies the token's matchTrigger. */
async function forwardHit(
  app: FastifyInstance,
  tokenId: string,
  kind: "web_bug" | "dns" = "web_bug",
): Promise<string> {
  const event =
    kind === "dns"
      ? {
          kind: "dns",
          tokenHint: tokenId,
          timestamp: new Date().toISOString(),
          sourceIp: "198.51.100.23",
          dns: { queryName: `${tokenId}.tokens.example.com`, queryType: "A" },
        }
      : {
          kind: "http",
          tokenHint: tokenId,
          timestamp: new Date().toISOString(),
          sourceIp: "203.0.113.7",
          http: {
            method: "GET",
            host: `${tokenId}.tokens.example.com`,
            path: `/${tokenId}/pixel.gif`,
            userAgent: "curl/8 smoke",
          },
        };
  const res = await app.inject({
    method: "POST",
    url: "/api/v1/incidents",
    payload: { tokenId, event },
  });
  expect(res.statusCode).toBe(201);
  return (res.json() as { id: string }).id;
}

describe("fleet + dashboard API", () => {
  const saved = savedEnv();
  afterEach(() => restoreEnv(saved));

  it("agent memo patch + delete retires the agent and kills its key", async () => {
    process.env.F0_ENROLLMENT_TOKEN = "enroll-token";
    const app = await makeServer();
    try {
      const enroll = await app.inject({
        method: "POST",
        url: "/api/v1/agent/enroll",
        payload: {
          enrollment_token: "enroll-token",
          hostname: "fleet-test",
          platform: "linux/amd64",
        },
      });
      expect(enroll.statusCode).toBe(201);
      const { agent_id, agent_key } = enroll.json() as {
        agent_id: string;
        agent_key: string;
      };

      let res = await app.inject({
        method: "PATCH",
        url: `/api/v1/agents/${agent_id}`,
        payload: { memo: "dc rack 3" },
      });
      expect(res.statusCode).toBe(200);
      let list = (await app.inject({ method: "GET", url: "/api/v1/agents" })).json() as {
        id: string;
        memo: string | null;
      }[];
      expect(list.find((a) => a.id === agent_id)?.memo).toBe("dc rack 3");

      res = await app.inject({ method: "PATCH", url: "/api/v1/agents/agt_nope", payload: { memo: "x" } });
      expect(res.statusCode).toBe(404);

      res = await app.inject({ method: "DELETE", url: `/api/v1/agents/${agent_id}` });
      expect(res.statusCode).toBe(200);
      // The retired agent's key no longer authorizes heartbeats.
      const hb = await app.inject({
        method: "POST",
        url: "/api/v1/agent/heartbeat",
        headers: { authorization: `Bearer ${agent_key}` },
        payload: { agent_id },
      });
      expect(hb.statusCode).toBe(401);
      list = (await app.inject({ method: "GET", url: "/api/v1/agents" })).json() as [];
      expect(list.length).toBe(0);
      res = await app.inject({ method: "DELETE", url: `/api/v1/agents/${agent_id}` });
      expect(res.statusCode).toBe(404);
    } finally {
      await app.close();
    }
  });

  it("stats rollup reflects tokens, incidents, and fleet", async () => {
    const app = await makeServer();
    try {
      const tokenId = await createToken(app);
      await forwardHit(app, tokenId);
      const res = await app.inject({ method: "GET", url: "/api/v1/stats" });
      expect(res.statusCode).toBe(200);
      // Contract check: the response validates against the shared schema.
      const stats = dashboardStatsSchema.parse(res.json());
      expect(stats.tokens).toEqual({ total: 1, active: 1, paused: 0, revoked: 0 });
      expect(stats.incidents.total).toBe(1);
      expect(stats.incidents.unacked).toBe(1);
      expect(stats.incidents.last24h).toBe(1);
      expect(stats.bySeverity).toEqual({ low: 0, medium: 1, high: 0 });
      expect(stats.byType).toContainEqual({ type: "web_bug", count: 1 });
      expect(stats.timeline.length).toBe(30);
      expect(stats.timeline[29]?.count).toBe(1);
      expect(stats.topSourceIps).toContainEqual({ ip: "203.0.113.7", count: 1 });
      expect(stats.agents).toEqual({ total: 0, online: 0 });
    } finally {
      await app.close();
    }
  });

  it("incident filters: severity, type, token_id, q", async () => {
    const app = await makeServer();
    try {
      const webId = await createToken(app, "web_bug");
      await forwardHit(app, webId, "web_bug"); // medium
      const dnsId = await createToken(app, "dns");
      await forwardHit(app, dnsId, "dns"); // high

      const list = async (qs: string) =>
        (await app.inject({ method: "GET", url: `/api/v1/incidents?${qs}` })).json() as {
          id: string;
          tokenType: string;
        }[];

      expect((await list("severity=high")).map((i) => i.tokenType)).toEqual(["dns"]);
      expect((await list("type=web_bug")).length).toBe(1);
      expect((await list(`token_id=${dnsId}`)).length).toBe(1);
      expect((await list("q=curl")).length).toBe(1);
      expect((await list("q=no-such-string")).length).toBe(0);
      const bad = await app.inject({ method: "GET", url: "/api/v1/incidents?severity=bogus" });
      expect(bad.statusCode).toBe(400);
    } finally {
      await app.close();
    }
  });

  it("bulk-ack acknowledges many incidents at once", async () => {
    const app = await makeServer();
    try {
      const tokenId = await createToken(app);
      const a = await forwardHit(app, tokenId);
      const b = await forwardHit(app, tokenId);
      const res = await app.inject({
        method: "POST",
        url: "/api/v1/incidents/bulk-ack",
        payload: { ids: [a, b, "inc_missing"] },
      });
      expect(res.statusCode).toBe(200);
      expect((res.json() as { updated: number }).updated).toBe(2);
      const unacked = (
        await app.inject({ method: "GET", url: "/api/v1/incidents?acknowledged=false" })
      ).json() as unknown[];
      expect(unacked.length).toBe(0);
    } finally {
      await app.close();
    }
  });

  it("hard delete cascades; soft delete revokes but keeps history", async () => {
    const app = await makeServer();
    try {
      // Hard delete removes token + incidents (+ files).
      const a = await createToken(app);
      await forwardHit(app, a);
      let res = await app.inject({ method: "DELETE", url: `/api/v1/tokens/${a}?hard=true` });
      expect(res.statusCode).toBe(200);
      let tokens = (await app.inject({ method: "GET", url: "/api/v1/tokens" })).json() as {
        id: string;
        status: string;
      }[];
      expect(tokens.find((t) => t.id === a)).toBeUndefined();
      let incidents = (await app.inject({ method: "GET", url: "/api/v1/incidents" })).json() as [];
      expect(incidents.length).toBe(0);

      // Soft delete keeps the row (revoked) and the incident history.
      const b = await createToken(app);
      await forwardHit(app, b);
      res = await app.inject({ method: "DELETE", url: `/api/v1/tokens/${b}` });
      expect(res.statusCode).toBe(200);
      tokens = (await app.inject({ method: "GET", url: "/api/v1/tokens" })).json() as {
        id: string;
        status: string;
      }[];
      expect(tokens.find((t) => t.id === b)?.status).toBe("revoked");
      incidents = (await app.inject({ method: "GET", url: "/api/v1/incidents" })).json() as [];
      expect(incidents.length).toBe(1);

      res = await app.inject({ method: "DELETE", url: "/api/v1/tokens/tok_missing?hard=true" });
      expect(res.statusCode).toBe(404);
    } finally {
      await app.close();
    }
  });

  it("token detail regenerates artifacts (no file bodies) and lists files", async () => {
    const app = await makeServer();
    try {
      const id = await createToken(app, "word_doc");
      const res = await app.inject({ method: "GET", url: `/api/v1/tokens/${id}` });
      expect(res.statusCode).toBe(200);
      const detail = res.json() as {
        artifacts: { kind: string; label: string; value: string; file?: unknown }[];
        files: { idx: number; filename: string; contentType: string }[];
      };
      expect(detail.artifacts.length).toBeGreaterThan(0);
      // Embedded file bodies must not ship in the detail response.
      expect(detail.artifacts.every((a) => a.file === undefined)).toBe(true);
      const doc = detail.files.find((f) => f.filename === "quarterly_report.docx");
      expect(doc).toBeDefined();
      const dl = await app.inject({
        method: "GET",
        url: `/api/v1/tokens/${id}/files/${doc!.idx}`,
      });
      expect(dl.statusCode).toBe(200);
      expect(dl.headers["content-type"]).toContain("wordprocessingml");
    } finally {
      await app.close();
    }
  });

  it("agent-bootstrap exposes the enrollment token to console operators", async () => {
    process.env.F0_ENROLLMENT_TOKEN = "enroll-token";
    const app = await makeServer();
    try {
      const res = await app.inject({ method: "GET", url: "/api/v1/agent-bootstrap" });
      expect(res.statusCode).toBe(200);
      expect((res.json() as { enrollmentToken: string | null }).enrollmentToken).toBe(
        "enroll-token",
      );
    } finally {
      await app.close();
    }
    delete process.env.F0_ENROLLMENT_TOKEN;
    const app2 = await makeServer();
    try {
      const res = await app2.inject({ method: "GET", url: "/api/v1/agent-bootstrap" });
      expect((res.json() as { enrollmentToken: string | null }).enrollmentToken).toBeNull();
    } finally {
      await app2.close();
    }
  });

  it("qr_code tokens get a downloadable PNG at creation (files/0)", async () => {
    const app = await makeServer();
    try {
      const id = await createToken(app, "qr_code");
      const detail = (
        await app.inject({ method: "GET", url: `/api/v1/tokens/${id}` })
      ).json() as {
        artifacts: { kind: string; value: string }[];
        files: { idx: number; filename: string; contentType: string }[];
      };
      expect(detail.files).toContainEqual({ idx: 0, filename: "qr.png", contentType: "image/png" });
      const dlArtifact = detail.artifacts.find((a) => a.kind === "file_download");
      expect(dlArtifact?.value.endsWith("/files/0")).toBe(true);
      const dl = await app.inject({ method: "GET", url: `/api/v1/tokens/${id}/files/0` });
      expect(dl.statusCode).toBe(200);
      expect(dl.headers["content-type"]).toBe("image/png");
      // PNG magic bytes.
      expect(dl.rawPayload.subarray(0, 4).toString("hex")).toBe("89504e47");
    } finally {
      await app.close();
    }
  });

  it("token memo is editable via PATCH /tokens/:id", async () => {
    const app = await makeServer();
    try {
      const id = await createToken(app);
      let res = await app.inject({
        method: "PATCH",
        url: `/api/v1/tokens/${id}`,
        payload: { memo: "planted in the wiki footer" },
      });
      expect(res.statusCode).toBe(200);
      let detail = (
        await app.inject({ method: "GET", url: `/api/v1/tokens/${id}` })
      ).json() as { memo: string | null };
      expect(detail.memo).toBe("planted in the wiki footer");
      // null clears it again.
      res = await app.inject({
        method: "PATCH",
        url: `/api/v1/tokens/${id}`,
        payload: { memo: null },
      });
      expect(res.statusCode).toBe(200);
      detail = (
        await app.inject({ method: "GET", url: `/api/v1/tokens/${id}` })
      ).json() as { memo: string | null };
      expect(detail.memo).toBeNull();
      res = await app.inject({
        method: "PATCH",
        url: "/api/v1/tokens/tok_missing",
        payload: { memo: "x" },
      });
      expect(res.statusCode).toBe(404);
    } finally {
      await app.close();
    }
  });

  it("cloned_website: clone outcome is stamped in config; reclone works and failures surface", async () => {
    // Tiny static site to clone.
    const site = createHttpServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/html" });
      res.end("<html><body><h1>corp login</h1></body></html>");
    });
    await new Promise<void>((resolve) => site.listen(0, "127.0.0.1", resolve));
    const sitePort = (site.address() as AddressInfo).port;
    const app = await makeServer();
    try {
      const res = await app.inject({
        method: "POST",
        url: "/api/v1/tokens",
        payload: {
          type: "cloned_website",
          config: { target_url: `http://127.0.0.1:${sitePort}/` },
        },
      });
      expect(res.statusCode).toBe(201);
      const { id } = res.json() as { id: string };

      let detail = (
        await app.inject({ method: "GET", url: `/api/v1/tokens/${id}` })
      ).json() as { config: Record<string, unknown>; files: { filename: string }[] };
      expect(detail.config["clone_status"]).toBe("ok");
      expect(detail.files.some((f) => f.filename === "cloned_page.html")).toBe(true);

      // Re-clone succeeds against the live site.
      let rc = await app.inject({ method: "POST", url: `/api/v1/tokens/${id}/reclone` });
      expect(rc.statusCode).toBe(200);

      // With the target down, re-clone reports the failure and stamps config.
      await new Promise<void>((resolve) => site.close(() => resolve()));
      rc = await app.inject({ method: "POST", url: `/api/v1/tokens/${id}/reclone` });
      expect(rc.statusCode).toBe(400);
      detail = (
        await app.inject({ method: "GET", url: `/api/v1/tokens/${id}` })
      ).json() as { config: Record<string, unknown>; files: { filename: string }[] };
      expect(detail.config["clone_status"]).toBe("failed");
      expect(typeof detail.config["clone_error"]).toBe("string");

      // Re-clone is type-guarded.
      const other = await createToken(app);
      rc = await app.inject({ method: "POST", url: `/api/v1/tokens/${other}/reclone` });
      expect(rc.statusCode).toBe(400);
    } finally {
      site.close();
      await app.close();
    }
  });

  it("operator-chosen bait filenames are used and sanitized", async () => {
    const app = await makeServer();
    try {
      const filesOf = async (id: string) =>
        (
          (await app.inject({ method: "GET", url: `/api/v1/tokens/${id}` })).json() as {
            files: { filename: string }[];
          }
        ).files;

      // Custom filename flows into token_files (and is returned by create).
      let res = await app.inject({
        method: "POST",
        url: "/api/v1/tokens",
        payload: { type: "word_doc", config: { filename: "Q4-board-pack.docx" } },
      });
      expect(res.statusCode).toBe(201);
      expect((res.json() as { files: { filename: string }[] }).files[0]?.filename).toBe(
        "Q4-board-pack.docx",
      );
      expect((await filesOf((res.json() as { id: string }).id))[0]?.filename).toBe(
        "Q4-board-pack.docx",
      );

      // Path-ish characters are stripped (content-disposition safety).
      res = await app.inject({
        method: "POST",
        url: "/api/v1/tokens",
        payload: { type: "qr_code", config: { filename: '../evil"name.png' } },
      });
      expect((await filesOf((res.json() as { id: string }).id))[0]?.filename).toBe(
        ".._evil_name.png",
      );

      // Defaults still apply without the config field.
      res = await app.inject({
        method: "POST",
        url: "/api/v1/tokens",
        payload: { type: "word_doc" },
      });
      expect((await filesOf((res.json() as { id: string }).id))[0]?.filename).toBe(
        "quarterly_report.docx",
      );
    } finally {
      await app.close();
    }
  });
});
