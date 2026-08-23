import { drizzle } from "drizzle-orm/better-sqlite3";
import type { BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import Database from "better-sqlite3";
import * as schema from "./schema.js";

export type Db = BetterSQLite3Database<typeof schema>;

export function createDb(path: string): Db {
  const sqlite = new Database(path);
  sqlite.pragma("journal_mode = WAL");
  sqlite.pragma("foreign_keys = ON");
  return drizzle(sqlite, { schema });
}

export function migrate(db: Db): void {
  const client = (db as unknown as { $client: Database.Database }).$client;
  client.exec(`
    CREATE TABLE IF NOT EXISTS tokens (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL,
      memo TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      config TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS tokens_type_idx ON tokens (type);

    CREATE TABLE IF NOT EXISTS incidents (
      id TEXT PRIMARY KEY,
      token_id TEXT NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
      severity TEXT NOT NULL DEFAULT 'medium',
      acknowledged INTEGER NOT NULL DEFAULT 0,
      event TEXT NOT NULL,
      seen_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS incidents_token_idx ON incidents (token_id);
    CREATE INDEX IF NOT EXISTS incidents_seen_idx ON incidents (seen_at);

    CREATE TABLE IF NOT EXISTS agents (
      id TEXT PRIMARY KEY,
      agent_key_hash TEXT NOT NULL,
      hostname TEXT NOT NULL,
      platform TEXT NOT NULL DEFAULT 'unknown',
      version TEXT NOT NULL DEFAULT '0.0.0',
      status TEXT NOT NULL DEFAULT 'online',
      last_seen_at TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS agent_sensors (
      id TEXT PRIMARY KEY,
      agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
      kind TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      config TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS agent_sensors_agent_idx ON agent_sensors (agent_id);

    CREATE TABLE IF NOT EXISTS alert_channels (
      id TEXT PRIMARY KEY,
      kind TEXT NOT NULL,
      config TEXT NOT NULL DEFAULT '{}',
      enabled INTEGER NOT NULL DEFAULT 1,
      failure_count INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS api_keys (
      id TEXT PRIMARY KEY,
      key_hash TEXT NOT NULL,
      label TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
  `);
}
