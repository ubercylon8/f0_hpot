import Fastify from "fastify";
import sensible from "@fastify/sensible";
import { createDb, migrate } from "./db/index.js";
import { registerTokenRoutes } from "./routes/tokens.js";

export function buildServer(opts: { dbPath?: string } = {}) {
  const dbPath = opts.dbPath ?? process.env.F0_DB_PATH ?? "./f0_deception.db";
  const db = createDb(dbPath);
  migrate(db);

  const app = Fastify({
    logger: true,
    bodyLimit: 1024 * 1024,
  });
  app.register(sensible);
  registerTokenRoutes(app, db);

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
