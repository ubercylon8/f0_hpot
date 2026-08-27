import { describe, it, expect, afterEach } from "vitest";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import type { FastifyInstance } from "fastify";
import { buildServer } from "./server.js";

const ENV_VARS = ["F0_ADMIN_TOKEN", "F0_INTERNAL_SECRET", "F0_AGENT_RELEASE_DIR"] as const;

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

async function makeServer(): Promise<FastifyInstance> {
  delete process.env.F0_ADMIN_TOKEN;
  delete process.env.F0_INTERNAL_SECRET;
  const { app } = buildServer({ dbPath: ":memory:" });
  await app.ready();
  return app;
}

function hasTool(name: string): boolean {
  try {
    execFileSync("which", [name], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

describe("agent release build + delete", () => {
  const saved = savedEnv();
  afterEach(() => restoreEnv(saved));

  it("delete removes binaries and the manifest, validates filenames", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "f0-del-test-"));
    process.env.F0_AGENT_RELEASE_DIR = dir;
    const app = await makeServer();
    try {
      writeFileSync(path.join(dir, "f0-deception-agent-linux-amd64"), "x");
      writeFileSync(path.join(dir, "release-manifest.json"), "{}");

      let res = await app.inject({
        method: "DELETE",
        url: "/api/v1/agent-releases/f0-deception-agent-linux-amd64",
      });
      expect(res.statusCode).toBe(200);
      expect(existsSync(path.join(dir, "f0-deception-agent-linux-amd64"))).toBe(false);

      res = await app.inject({
        method: "DELETE",
        url: "/api/v1/agent-releases/release-manifest.json",
      });
      expect(res.statusCode).toBe(200);

      res = await app.inject({
        method: "DELETE",
        url: "/api/v1/agent-releases/f0-deception-agent-linux-amd64",
      });
      expect(res.statusCode).toBe(404);

      res = await app.inject({
        method: "DELETE",
        url: "/api/v1/agent-releases/..%2F..%2Fetc%2Fpasswd",
      });
      expect(res.statusCode).toBe(400);
    } finally {
      rmSync(dir, { recursive: true, force: true });
      await app.close();
    }
  });

  it("build validates the version string", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "f0-build-test-"));
    process.env.F0_AGENT_RELEASE_DIR = dir;
    const app = await makeServer();
    try {
      for (const bad of ["", "bad version!", "v1;rm -rf /", "../x"]) {
        const res = await app.inject({
          method: "POST",
          url: "/api/v1/agent-releases/build",
          payload: { version: bad },
        });
        expect(res.statusCode).toBe(400);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
      await app.close();
    }
  });

  const canBuild =
    hasTool("go") && hasTool("make") && existsSync(path.resolve("../../agent/main.go"));
  it.runIf(canBuild)(
    "builds all 5 platform binaries at a given version and clears the stale manifest",
    async () => {
      const dir = mkdtempSync(path.join(tmpdir(), "f0-build-real-"));
      // Stale manifest must be removed by the build.
      writeFileSync(path.join(dir, "release-manifest.json"), '{"stale":true}');
      process.env.F0_AGENT_RELEASE_DIR = dir;
      const app = await makeServer();
      try {
        const res = await app.inject({
          method: "POST",
          url: "/api/v1/agent-releases/build",
          payload: { version: "v9.9.9-test" },
        });
        expect(res.statusCode).toBe(200);
        const body = res.json() as {
          version: string;
          files: { filename: string; size: number }[];
        };
        expect(body.version).toBe("v9.9.9-test");
        expect(body.files.length).toBe(5);
        for (const f of body.files) expect(f.size).toBeGreaterThan(1_000_000);
        expect(existsSync(path.join(dir, "release-manifest.json"))).toBe(false);
      } finally {
        rmSync(dir, { recursive: true, force: true });
        await app.close();
      }
    },
    300_000,
  );
});
