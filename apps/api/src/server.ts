import Fastify from "fastify";
import sensible from "@fastify/sensible";
import rateLimit from "@fastify/rate-limit";
import { createDb, migrate } from "./db/index.js";
import { registerTokenRoutes } from "./routes/tokens.js";
import { registerAlertRoutes } from "./routes/alerts.js";
import { registerAgentRoutes } from "./routes/agents.js";
import { registerReleaseRoutes } from "./routes/releases.js";
import { registerAuthRoutes } from "./routes/auth.js";
import { AlertDispatcher } from "./alerts/dispatcher.js";
import { buildAuthContext, isOpenMode, makeAuthHook } from "./auth.js";
import { createGeoLookup } from "./geoip.js";

export function buildServer(opts: { dbPath?: string } = {}) {
  const dbPath = opts.dbPath ?? process.env.F0_DB_PATH ?? "./f0_deception.db";
  const db = createDb(dbPath);
  migrate(db);

  const app = Fastify({
    logger: true,
    bodyLimit: 1024 * 1024,
  });
  app.register(sensible);
  // Generous global ceiling; sensitive public endpoints tighten it per-route.
  app.register(rateLimit, { max: 300, timeWindow: "1 minute" });

  const authCtx = buildAuthContext();
  app.addHook("onRequest", makeAuthHook(db, authCtx));
  if (isOpenMode(db, authCtx)) {
    app.log.warn(
      "API AUTH IS OPEN: no F0_ADMIN_TOKEN/F0_INTERNAL_SECRET set and no API " +
        "keys exist. All console routes are unauthenticated until you set " +
        "F0_ADMIN_TOKEN or create a key via POST /api/v1/auth/keys.",
    );
  }

  const dispatcher = new AlertDispatcher(db, {
    maxAlertsPerMinute: Number(process.env.F0_MAX_ALERTS_PER_MINUTE ?? 1),
  });
  const geo = createGeoLookup(process.env.F0_GEOIP_DB, {
    warn: (msg) => app.log.warn(msg),
  });

  registerAuthRoutes(app, db, authCtx);
  registerTokenRoutes(app, db, dispatcher, geo);
  registerAlertRoutes(app, db, dispatcher);
  registerAgentRoutes(app, db);
  registerReleaseRoutes(app, db);

  return { app, db };
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].split("/").pop()!)) {
  const { app } = buildServer();
  const port = Number(process.env.F0_API_PORT ?? 8443);
  app
    .listen({ port, host: "0.0.0.0" })
    .then((addr) => app.log.info(`f0_deception API listening on ${addr}`))
    .catch((err) => {
      app.log.error(err);
      process.exit(1);
    });
}
