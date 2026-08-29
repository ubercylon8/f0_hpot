import type { FastifyInstance } from "fastify";
import { capabilities } from "../capabilities.js";

export interface StatusDeps {
  geoEnabled: boolean;
  /** Evaluated per request (open mode flips without a restart). */
  isOpenMode: () => boolean;
}

/**
 * Server/runtime status for the settings page. Console scope (the global
 * auth hook gates it like every other console route).
 */
export function registerStatusRoutes(app: FastifyInstance, deps: StatusDeps): void {
  app.get("/api/v1/status", async () => ({
    geoipEnabled: deps.geoEnabled,
    authOpenMode: deps.isOpenMode(),
    enrollmentConfigured: !!process.env.F0_ENROLLMENT_TOKEN,
    alertThrottlePerMinute: Number(process.env.F0_MAX_ALERTS_PER_MINUTE ?? 1),
    // Host-dependent console actions; the UI disables what cannot work here
    // instead of letting the button fail with an opaque 400.
    capabilities: capabilities(),
  }));
}
