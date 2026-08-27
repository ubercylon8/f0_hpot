import { z } from "zod";

/**
 * Dashboard aggregate rollups (GET /api/v1/stats). Server-computed so the
 * console renders KPIs and charts without scanning the full incident feed.
 */
export const dashboardStatsSchema = z.object({
  tokens: z.object({
    total: z.number(),
    active: z.number(),
    paused: z.number(),
    revoked: z.number(),
  }),
  incidents: z.object({
    total: z.number(),
    unacked: z.number(),
    last24h: z.number(),
    last7d: z.number(),
  }),
  agents: z.object({
    total: z.number(),
    /** lastSeenAt within 2x the configured agent poll interval. */
    online: z.number(),
  }),
  /** Daily incident counts, oldest first, zero-filled (30 entries). */
  timeline: z.array(z.object({ day: z.string(), count: z.number() })),
  bySeverity: z.object({
    low: z.number(),
    medium: z.number(),
    high: z.number(),
  }),
  /** Unacknowledged incidents by severity — what triage should hit first. */
  unackedBySeverity: z.object({
    low: z.number(),
    medium: z.number(),
    high: z.number(),
  }),
  /** Remote token deployments by status (failed is all-time). */
  deployments: z.object({
    pending: z.number(),
    failed: z.number(),
  }),
  byType: z.array(z.object({ type: z.string(), count: z.number() })),
  topSourceIps: z.array(z.object({ ip: z.string(), count: z.number() })),
  /** ISO country codes from GeoIP enrichment (empty when disabled). */
  byCountry: z.array(z.object({ country: z.string(), count: z.number() })),
});
export type DashboardStats = z.infer<typeof dashboardStatsSchema>;
