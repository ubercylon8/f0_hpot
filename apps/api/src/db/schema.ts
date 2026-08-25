import { sqliteTable, text, integer, index } from "drizzle-orm/sqlite-core";

export const tokens = sqliteTable(
  "tokens",
  {
    id: text("id").primaryKey(),
    type: text("type").notNull(),
    memo: text("memo"),
    status: text("status").notNull().default("active"),
    config: text("config", { mode: "json" }).notNull().default("{}"),
    createdAt: text("created_at")
      .notNull()
      .$defaultFn(() => new Date().toISOString()),
  },
  (t) => [index("tokens_type_idx").on(t.type)],
);

export const incidents = sqliteTable(
  "incidents",
  {
    id: text("id").primaryKey(),
    tokenId: text("token_id")
      .notNull()
      .references(() => tokens.id, { onDelete: "cascade" }),
    severity: text("severity").notNull().default("medium"),
    acknowledged: integer("acknowledged", { mode: "boolean" })
      .notNull()
      .default(false),
    event: text("event", { mode: "json" }).notNull(),
    seenAt: text("seen_at")
      .notNull()
      .$defaultFn(() => new Date().toISOString()),
    notes: text("notes"),
    // Extracted at insert time for filtering/enrichment (event JSON holds
    // the authoritative full record).
    sourceIp: text("source_ip"),
    geo: text("geo", { mode: "json" }),
  },
  (t) => [
    index("incidents_token_idx").on(t.tokenId),
    index("incidents_seen_idx").on(t.seenAt),
    index("incidents_source_ip_idx").on(t.sourceIp),
  ],
);

export const agents = sqliteTable("agents", {
  id: text("id").primaryKey(),
  agentKeyHash: text("agent_key_hash").notNull(),
  hostname: text("hostname").notNull(),
  platform: text("platform").notNull().default("unknown"),
  version: text("version").notNull().default("0.0.0"),
  status: text("status").notNull().default("online"),
  lastSeenAt: text("last_seen_at"),
  createdAt: text("created_at")
    .notNull()
    .$defaultFn(() => new Date().toISOString()),
});

export const agentSensors = sqliteTable(
  "agent_sensors",
  {
    id: text("id").primaryKey(),
    agentId: text("agent_id")
      .notNull()
      .references(() => agents.id, { onDelete: "cascade" }),
    kind: text("kind").notNull(),
    enabled: integer("enabled", { mode: "boolean" }).notNull().default(true),
    config: text("config", { mode: "json" }).notNull().default("{}"),
    createdAt: text("created_at")
      .notNull()
      .$defaultFn(() => new Date().toISOString()),
  },
  (t) => [index("agent_sensors_agent_idx").on(t.agentId)],
);

export const tokenFiles = sqliteTable(
  "token_files",
  {
    id: text("id").primaryKey(),
    tokenId: text("token_id")
      .notNull()
      .references(() => tokens.id, { onDelete: "cascade" }),
    idx: integer("idx").notNull(),
    filename: text("filename").notNull(),
    contentType: text("content_type").notNull(),
    // Base64-encoded contents (SQLite blob mode isn't exposed by drizzle).
    data: text("data").notNull(),
    createdAt: text("created_at")
      .notNull()
      .$defaultFn(() => new Date().toISOString()),
  },
  (t) => [index("token_files_token_idx").on(t.tokenId)],
);

export const alertChannels = sqliteTable("alert_channels", {
  id: text("id").primaryKey(),
  kind: text("kind").notNull(),
  config: text("config", { mode: "json" }).notNull().default("{}"),
  enabled: integer("enabled", { mode: "boolean" }).notNull().default(true),
  failureCount: integer("failure_count").notNull().default(0),
  createdAt: text("created_at")
    .notNull()
    .$defaultFn(() => new Date().toISOString()),
});

export const apiKeys = sqliteTable("api_keys", {
  id: text("id").primaryKey(),
  keyHash: text("key_hash").notNull(),
  label: text("label").notNull(),
  createdAt: text("created_at")
    .notNull()
    .$defaultFn(() => new Date().toISOString()),
  lastUsedAt: text("last_used_at"),
});

export const releaseKeys = sqliteTable("release_keys", {
  id: text("id").primaryKey(),
  label: text("label").notNull(),
  // base64 SPKI DER (raw 32-byte Ed25519 key = last 32 bytes).
  publicKey: text("public_key").notNull(),
  // base64 PKCS8 DER — signs release manifests server-side. Protect the DB.
  privateKey: text("private_key").notNull(),
  createdAt: text("created_at")
    .notNull()
    .$defaultFn(() => new Date().toISOString()),
});
