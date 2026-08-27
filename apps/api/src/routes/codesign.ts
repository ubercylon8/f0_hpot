import { existsSync } from "node:fs";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { Db } from "../db/index.js";
import {
  deleteCodeSignCert,
  generateCodeSignCert,
  listCodeSignCerts,
  signReleaseExe,
  storeUploadedCodeSignCert,
} from "../codesign.js";

/**
 * Code-signing certificate management + Authenticode signing of the
 * Windows release binary. See codesign.ts for how this layer differs
 * from Ed25519 release-manifest signing.
 */
export function registerCodeSignRoutes(app: FastifyInstance, db: Db): void {
  app.post("/api/v1/codesign-certs", async (request, reply) => {
    const parsed = z
      .union([
        z.object({
          label: z.string().min(1).max(128),
          generate: z.literal(true),
          commonName: z
            .string()
            .min(1)
            .max(64)
            .regex(/^[A-Za-z0-9_ .,'()-]+$/, "invalid characters in common name"),
          passphrase: z.string().min(4).max(128),
        }),
        z.object({
          label: z.string().min(1).max(128),
          pfx: z.string().min(100),
          passphrase: z.string().min(1).max(128),
        }),
      ])
      .safeParse(request.body);
    if (!parsed.success) {
      return reply.badRequest(parsed.error.issues.map((i) => i.message).join("; "));
    }
    try {
      const view =
        "generate" in parsed.data
          ? await generateCodeSignCert(db, parsed.data)
          : await storeUploadedCodeSignCert(db, {
              label: parsed.data.label,
              pfx: Buffer.from(parsed.data.pfx, "base64"),
              passphrase: parsed.data.passphrase,
            });
      return reply.code(201).send(view);
    } catch (err) {
      return reply.badRequest(err instanceof Error ? err.message : String(err));
    }
  });

  app.get("/api/v1/codesign-certs", async () => listCodeSignCerts(db));

  app.delete("/api/v1/codesign-certs/:id", async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!deleteCodeSignCert(db, id)) return reply.notFound("cert not found");
    return reply.send({ ok: true });
  });

  app.post("/api/v1/agent-releases/codesign", async (request, reply) => {
    const parsed = z
      .object({
        certId: z.string().min(1),
        file: z.string().max(120).optional(),
      })
      .safeParse(request.body);
    if (!parsed.success) {
      return reply.badRequest(parsed.error.issues.map((i) => i.message).join("; "));
    }
    const dir = process.env.F0_AGENT_RELEASE_DIR ?? "";
    if (!dir || !existsSync(dir)) {
      return reply.badRequest("F0_AGENT_RELEASE_DIR is not set or missing");
    }
    try {
      const result = await signReleaseExe(db, parsed.data.certId, dir, parsed.data.file);
      app.log.warn(
        `agent binary ${result.file} Authenticode-signed with cert ${parsed.data.certId}`,
      );
      return reply.send({ ok: true, ...result });
    } catch (err) {
      return reply.badRequest(err instanceof Error ? err.message : String(err));
    }
  });
}
