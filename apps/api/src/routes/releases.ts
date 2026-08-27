import { readdirSync, statSync, existsSync, unlinkSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { Db } from "../db/index.js";
import {
  generateReleaseKey,
  listReleaseKeys,
  signReleaseDir,
} from "../release-signing.js";
import { releaseKeys } from "../db/schema.js";
import { eq } from "drizzle-orm";
import { runTool } from "../codesign.js";

const FILENAME_RE = /^f0-deception-agent-[a-z0-9.-]+$/;
const VERSION_RE = /^v?[A-Za-z0-9][A-Za-z0-9._-]{0,39}$/;

/** Agent Go module to build from (overridable for slim deployments). */
function agentSourceDir(): string {
  return (
    process.env.F0_AGENT_SOURCE_DIR ??
    fileURLToPath(new URL("../../../../agent", import.meta.url))
  );
}

function listFiles(dir: string) {
  return readdirSync(dir)
    .filter((f) => f.startsWith("f0-deception-agent-") && statSync(path.join(dir, f)).isFile())
    .map((f) => ({
      filename: f,
      size: statSync(path.join(dir, f)).size,
      url: `/api/v1/agent-releases/${f}`,
    }));
}

/**
 * Agent release downloads: serves binaries + signed manifest from
 * F0_AGENT_RELEASE_DIR (populated by `make release` in agent/).
 * GET    /api/v1/agent-releases          -> list
 * GET    /api/v1/agent-releases/:file    -> download (filename-validated)
 * POST   /api/v1/agent-releases/build    -> cross-compile all platforms {version}
 * DELETE /api/v1/agent-releases/:file    -> remove a binary (or the manifest)
 *
 * Server-side manifest signing (Ed25519 keys in the release_keys table;
 * canonical bytes match the agent verifier exactly — see release-signing.ts):
 * POST /api/v1/release-keys            -> generate keypair {label}
 * GET  /api/v1/release-keys            -> list (raw embeddable public keys)
 * POST /api/v1/agent-releases/sign     -> hash dir + sign {keyId, version?}
 */
export function registerReleaseRoutes(app: FastifyInstance, db: Db): void {
  const dir = process.env.F0_AGENT_RELEASE_DIR ?? "";

  app.post("/api/v1/agent-releases/build", async (request, reply) => {
    const parsed = z
      .object({ version: z.string().regex(VERSION_RE, "invalid version") })
      .safeParse(request.body);
    if (!parsed.success) {
      return reply.badRequest(parsed.error.issues.map((i) => i.message).join("; "));
    }
    if (!dir || !existsSync(dir)) {
      return reply.badRequest("F0_AGENT_RELEASE_DIR is not set or missing");
    }
    const version = parsed.data.version;
    try {
      // OUT overrides the Makefile's default (agent/bin) so binaries land
      // directly in F0_AGENT_RELEASE_DIR.
      await runTool("make", ["-C", agentSourceDir(), "release", `OUT=${dir}`], {
        env: { ...process.env, VERSION: version },
        timeoutMs: 300_000,
      });
    } catch (err) {
      return reply.badRequest(err instanceof Error ? err.message : String(err));
    }
    // The manifest no longer matches the fresh binaries — drop it so it
    // can't be served stale (operator re-signs via /agent-releases/sign).
    const manifestPath = path.join(dir, "release-manifest.json");
    if (existsSync(manifestPath)) unlinkSync(manifestPath);
    app.log.warn(`agent release binaries rebuilt at ${version}`);
    return reply.send({ ok: true, version, files: listFiles(dir) });
  });

  app.get("/api/v1/agent-releases", async () => {
    if (!dir || !existsSync(dir)) return { files: [], manifest: null };
    const manifestPath = path.join(dir, "release-manifest.json");
    let manifest: unknown = null;
    if (existsSync(manifestPath)) {
      manifest = (await import("node:fs")).readFileSync(manifestPath, "utf8");
    }
    return { files: listFiles(dir), manifest };
  });

  app.get("/api/v1/agent-releases/:file", async (request, reply) => {
    const { file } = request.params as { file: string };
    // Strict filename validation — no path traversal, known prefix only.
    if (!FILENAME_RE.test(file)) {
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

  app.delete("/api/v1/agent-releases/:file", async (request, reply) => {
    const { file } = request.params as { file: string };
    if (file !== "release-manifest.json" && !FILENAME_RE.test(file)) {
      return reply.badRequest("invalid filename");
    }
    if (!dir) return reply.badRequest("F0_AGENT_RELEASE_DIR is not set");
    const full = path.join(dir, file);
    if (!existsSync(full) || !statSync(full).isFile()) {
      return reply.notFound("release not found");
    }
    unlinkSync(full);
    app.log.warn(`release file deleted: ${file}`);
    return reply.send({ ok: true, deleted: file });
  });

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

  // Delete a signing key. Note: deployed agents embed a public key at
  // build time — deleting the key it belongs to means you can no longer
  // sign updates those agents will accept (they keep their embedded key).
  app.delete("/api/v1/release-keys/:id", async (request, reply) => {
    const { id } = request.params as { id: string };
    const result = db.delete(releaseKeys).where(eq(releaseKeys.id, id)).run();
    if (result.changes === 0) return reply.notFound("release key not found");
    app.log.warn(`release key ${id} deleted`);
    return reply.send({ ok: true });
  });

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
}
