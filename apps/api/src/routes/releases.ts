import { readdirSync, statSync, existsSync } from "node:fs";
import path from "node:path";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { Db } from "../db/index.js";
import {
  generateReleaseKey,
  listReleaseKeys,
  signReleaseDir,
} from "../release-signing.js";

/**
 * Agent release downloads: serves binaries + signed manifest from
 * F0_AGENT_RELEASE_DIR (populated by `make release` in agent/).
 * GET  /api/v1/agent-releases          -> list
 * GET  /api/v1/agent-releases/:file    -> download (filename-validated)
 *
 * Server-side manifest signing (Ed25519 keys in the release_keys table;
 * canonical bytes match the agent verifier exactly — see release-signing.ts):
 * POST /api/v1/release-keys            -> generate keypair {label}
 * GET  /api/v1/release-keys            -> list (raw embeddable public keys)
 * POST /api/v1/agent-releases/sign     -> hash dir + sign {keyId, version?}
 */
export function registerReleaseRoutes(app: FastifyInstance, db: Db): void {
  const dir = process.env.F0_AGENT_RELEASE_DIR ?? "";

  app.post("/api/v1/release-keys", async (request, reply) => {
    const parsed = z
      .object({ label: z.string().min(1).max(200) })
      .safeParse(request.body);
    if (!parsed.success) {
      return reply.badRequest(parsed.error.issues.map((i) => i.message).join("; "));
    }
    const key = generateReleaseKey(db, parsed.data.label);
    app.log.warn(
      `release key ${key.id} ("${key.label}") generated — private key lives in the DB; protect it`,
    );
    return reply.code(201).send(key);
  });

  app.get("/api/v1/release-keys", async () => listReleaseKeys(db));

  app.post("/api/v1/agent-releases/sign", async (request, reply) => {
    const parsed = z
      .object({
        keyId: z.string().min(1),
        version: z.string().min(1).max(100).optional(),
      })
      .safeParse(request.body);
    if (!parsed.success) {
      return reply.badRequest(parsed.error.issues.map((i) => i.message).join("; "));
    }
    if (!dir || !existsSync(dir)) {
      return reply.badRequest("F0_AGENT_RELEASE_DIR is not set or missing");
    }
    const version =
      parsed.data.version ??
      `dev-${new Date().toISOString().slice(0, 10).replaceAll("-", "")}`;
    const manifest = signReleaseDir(db, parsed.data.keyId, dir, version);
    if (!manifest) {
      return reply.badRequest(
        "unknown keyId, or no f0-deception-agent-* binaries in the release dir",
      );
    }
    return reply.send({ ok: true, version: manifest.version, files: Object.keys(manifest.files) });
  });

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
