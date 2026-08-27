import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { Db } from "../db/index.js";
import {
  createEnrollmentToken,
  deleteEnrollmentToken,
  listEnrollmentTokens,
} from "../enrollment.js";

/**
 * Managed enrollment tokens (see enrollment.ts). Console scope via the
 * global auth hook. The raw token is returned exactly once at creation.
 */
export function registerEnrollmentRoutes(app: FastifyInstance, db: Db): void {
  app.post("/api/v1/enrollment-tokens", async (request, reply) => {
    const parsed = z
      .object({
        label: z.string().min(1).max(128),
        expires_in_hours: z.number().int().min(1).max(8760).optional(),
      })
      .safeParse(request.body);
    if (!parsed.success) {
      return reply.badRequest(parsed.error.issues.map((i) => i.message).join("; "));
    }
    const created = createEnrollmentToken(
      db,
      parsed.data.label,
      parsed.data.expires_in_hours,
    );
    app.log.warn(`enrollment token ${created.id} ("${created.label}") created`);
    return reply.code(201).send(created);
  });

  app.get("/api/v1/enrollment-tokens", async () => listEnrollmentTokens(db));

  app.delete("/api/v1/enrollment-tokens/:id", async (request, reply) => {
    const { id } = request.params as { id: string };
    if (!deleteEnrollmentToken(db, id)) return reply.notFound("enrollment token not found");
    app.log.warn(`enrollment token ${id} deleted`);
    return reply.send({ ok: true });
  });
}
