import { describe, it, expect, afterEach } from "vitest";
import { buildServer } from "./server.js";

const ENV = ["F0_ADMIN_TOKEN", "F0_INTERNAL_SECRET"] as const;
const saved: Record<string, string | undefined> = {};
for (const v of ENV) saved[v] = process.env[v];

const MASK = "•••";

describe("alert channel editing", () => {
  afterEach(() => {
    for (const v of ENV) {
      if (saved[v] === undefined) delete process.env[v];
      else process.env[v] = saved[v];
    }
  });

  async function openServer() {
    delete process.env["F0_ADMIN_TOKEN"];
    delete process.env["F0_INTERNAL_SECRET"];
    const { app } = buildServer({ dbPath: ":memory:" });
    await app.ready();
    return app;
  }

  it("edits config while preserving a secret the client never saw", async () => {
    const app = await openServer();
    try {
      const created = await app.inject({
        method: "POST",
        url: "/api/v1/alert-channels",
        payload: {
          kind: "webhook",
          config: { url: "https://old.example.com/hook", secret: "s3cr3t-value" },
        },
      });
      expect(created.statusCode).toBe(201);
      const { id } = created.json() as { id: string };

      // The list masks the secret, so an edit form can only send the mask back.
      const listed = await app.inject({ method: "GET", url: "/api/v1/alert-channels" });
      const row = (listed.json() as { id: string; config: Record<string, unknown> }[])[0];
      expect(row?.config["secret"]).toBe(MASK);

      const edited = await app.inject({
        method: "PATCH",
        url: `/api/v1/alert-channels/${id}`,
        payload: {
          config: { url: "https://new.example.com/hook", secret: MASK },
        },
      });
      expect(edited.statusCode).toBe(200);

      // The URL changed; the secret must still be the original, NOT the mask.
      const after = await app.inject({ method: "GET", url: "/api/v1/alert-channels" });
      const updated = (after.json() as { config: Record<string, unknown> }[])[0];
      expect(updated?.config["url"]).toBe("https://new.example.com/hook");
      expect(updated?.config["secret"]).toBe(MASK); // still masked on read

      // Prove the stored value is the real one by delivering through it.
      const sent: string[] = [];
      const server = (await import("node:http")).createServer((req, res) => {
        sent.push(String(req.headers["x-f0-signature"]));
        res.writeHead(200).end("{}");
      });
      await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
      const port = (server.address() as { port: number }).port;
      await app.inject({
        method: "PATCH",
        url: `/api/v1/alert-channels/${id}`,
        payload: { config: { url: `http://127.0.0.1:${port}/hook`, secret: MASK } },
      });
      await app.inject({ method: "POST", url: `/api/v1/alert-channels/${id}/test` });
      server.close();
      expect(sent[0]).toBe("s3cr3t-value");
    } finally {
      await app.close();
    }
  });

  it("keeps the secret when the field is OMITTED, as the console form sends it", async () => {
    // The add/edit form drops blank fields instead of sending the mask, so
    // the key never reaches the server. Merging driven off the incoming keys
    // silently dropped the stored credential on every edit.
    const app = await openServer();
    try {
      const created = await app.inject({
        method: "POST",
        url: "/api/v1/alert-channels",
        payload: {
          kind: "webhook",
          config: { url: "https://old.example/h", secret: "kept-secret" },
        },
      });
      const { id } = created.json() as { id: string };

      const sent: (string | undefined)[] = [];
      const server = (await import("node:http")).createServer((req, res) => {
        sent.push(req.headers["x-f0-signature"] as string | undefined);
        res.writeHead(200).end("{}");
      });
      await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
      const port = (server.address() as { port: number }).port;

      // Note: no `secret` key at all.
      const edited = await app.inject({
        method: "PATCH",
        url: `/api/v1/alert-channels/${id}`,
        payload: { config: { url: `http://127.0.0.1:${port}/after` } },
      });
      expect(edited.statusCode).toBe(200);

      await app.inject({ method: "POST", url: `/api/v1/alert-channels/${id}/test` });
      server.close();
      expect(sent[0]).toBe("kept-secret");
    } finally {
      await app.close();
    }
  });

  it("replaces a secret when a new value is supplied", async () => {
    const app = await openServer();
    try {
      const created = await app.inject({
        method: "POST",
        url: "/api/v1/alert-channels",
        payload: { kind: "webhook", config: { url: "https://x.example/h", secret: "old" } },
      });
      const { id } = created.json() as { id: string };
      const res = await app.inject({
        method: "PATCH",
        url: `/api/v1/alert-channels/${id}`,
        payload: { config: { url: "https://x.example/h", secret: "brand-new" } },
      });
      expect(res.statusCode).toBe(200);

      const sent: string[] = [];
      const server = (await import("node:http")).createServer((req, res2) => {
        sent.push(String(req.headers["x-f0-signature"]));
        res2.writeHead(200).end("{}");
      });
      await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
      const port = (server.address() as { port: number }).port;
      await app.inject({
        method: "PATCH",
        url: `/api/v1/alert-channels/${id}`,
        payload: { config: { url: `http://127.0.0.1:${port}/h`, secret: MASK } },
      });
      await app.inject({ method: "POST", url: `/api/v1/alert-channels/${id}/test` });
      server.close();
      expect(sent[0]).toBe("brand-new");
    } finally {
      await app.close();
    }
  });

  it("rejects an edit that would make the config invalid", async () => {
    const app = await openServer();
    try {
      const created = await app.inject({
        method: "POST",
        url: "/api/v1/alert-channels",
        payload: { kind: "webhook", config: { url: "https://x.example/h" } },
      });
      const { id } = created.json() as { id: string };
      const res = await app.inject({
        method: "PATCH",
        url: `/api/v1/alert-channels/${id}`,
        payload: { config: { url: "not-a-url" } },
      });
      expect(res.statusCode).toBe(400);
    } finally {
      await app.close();
    }
  });

  it("still supports the enable/disable-only patch", async () => {
    const app = await openServer();
    try {
      const created = await app.inject({
        method: "POST",
        url: "/api/v1/alert-channels",
        payload: { kind: "webhook", config: { url: "https://x.example/h" } },
      });
      const { id } = created.json() as { id: string };
      const res = await app.inject({
        method: "PATCH",
        url: `/api/v1/alert-channels/${id}`,
        payload: { enabled: false },
      });
      expect(res.statusCode).toBe(200);
      const listed = await app.inject({ method: "GET", url: "/api/v1/alert-channels" });
      expect((listed.json() as { enabled: boolean }[])[0]?.enabled).toBe(false);
    } finally {
      await app.close();
    }
  });

  it("rejects an empty patch rather than silently doing nothing", async () => {
    const app = await openServer();
    try {
      const created = await app.inject({
        method: "POST",
        url: "/api/v1/alert-channels",
        payload: { kind: "webhook", config: { url: "https://x.example/h" } },
      });
      const { id } = created.json() as { id: string };
      const res = await app.inject({
        method: "PATCH",
        url: `/api/v1/alert-channels/${id}`,
        payload: {},
      });
      expect(res.statusCode).toBe(400);
    } finally {
      await app.close();
    }
  });
});
