import { readdirSync, statSync, existsSync } from "node:fs";
import path from "node:path";
import type { FastifyInstance } from "fastify";

/**
 * Agent release downloads: serves binaries + signed manifest from
 * F0_AGENT_RELEASE_DIR (populated by `make release` in agent/).
 * GET /api/v1/agent-releases          -> list
 * GET /api/v1/agent-releases/:file    -> download (filename-validated)
 */
export function registerReleaseRoutes(app: FastifyInstance): void {
  const dir = process.env.F0_AGENT_RELEASE_DIR ?? "";

  app.get("/api/v1/agent-releases", async () => {
    if (!dir || !existsSync(dir)) return { files: [], manifest: null };
    const manifestPath = path.join(dir, "release-manifest.json");
    let manifest: unknown = null;
    if (existsSync(manifestPath)) {
      manifest = (await import("node:fs")).readFileSync(manifestPath, "utf8");
    }
    const files = readdirSync(dir)
      .filter((f) => f.startsWith("f0-deception-agent-") && statSync(path.join(dir, f)).isFile())
      .map((f) => ({
        filename: f,
        size: statSync(path.join(dir, f)).size,
        url: `/api/v1/agent-releases/${f}`,
      }));
    return { files, manifest };
  });

  app.get("/api/v1/agent-releases/:file", async (request, reply) => {
    const { file } = request.params as { file: string };
    // Strict filename validation — no path traversal, known prefix only.
    if (!/^f0-deception-agent-[a-z0-9.-]+$/.test(file)) {
      return reply.badRequest("invalid filename");
    }
    const full = path.join(dir, file);
    if (!dir || !existsSync(full) || !statSync(full).isFile()) {
      return reply.notFound("release not found");
    }
    reply.header("content-type", "application/octet-stream");
    reply.header("content-disposition", `attachment; filename="${file}"`);
    return reply.send((await import("node:fs")).createReadStream(full));
  });
}
