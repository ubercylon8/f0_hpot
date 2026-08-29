import { z } from "zod";

export const agentStatusSchema = z.enum([
  "online",
  "offline",
  "degraded",
  "retired",
]);
export type AgentStatus = z.infer<typeof agentStatusSchema>;

export const sensorKindSchema = z.enum([
  "ssh",
  "http_login",
  "smb_share",
  "rdp_banner",
  "planted_credential",
  "file_watch",
]);
export type SensorKind = z.infer<typeof sensorKindSchema>;

export const agentInfoSchema = z.object({
  id: z.string(),
  hostname: z.string(),
  platform: z.string(),
  version: z.string(),
  status: agentStatusSchema,
  lastSeenAt: z.string().datetime(),
  sensors: z.array(
    z.object({
      kind: sensorKindSchema,
      enabled: z.boolean(),
      config: z.record(z.string(), z.unknown()).default({}),
    }),
  ),
});
export type AgentInfo = z.infer<typeof agentInfoSchema>;

/**
 * Alert channel kinds. Cross-app shape: the API validates against this and
 * the console renders from it. It previously lived here unused while the
 * API redefined its own copy inline, and the two drifted (this list was
 * missing "loki") — exactly what AGENTS.md invariant 3 forbids.
 */
export const alertChannelKindSchema = z.enum([
  "email",
  "webhook",
  "syslog",
  "elasticsearch",
  "loki",
]);
export type AlertChannelKind = z.infer<typeof alertChannelKindSchema>;
