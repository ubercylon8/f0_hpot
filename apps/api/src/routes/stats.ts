import { and, desc, eq, gte, isNotNull, sql, type SQL } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import type { DashboardStats } from "@f0/deception-shared";
import type { Db } from "../db/index.js";
import { agentDeployments, agents, incidents, tokens } from "../db/schema.js";

const DAY_MS = 86_400_000;

/**
 * Dashboard rollups (shape lives in @f0/deception-shared). seenAt and
 * lastSeenAt are ISO-8601 strings, so cutoffs compare lexicographically.
 */
export function registerStatsRoutes(app: FastifyInstance, db: Db): void {
  app.get("/api/v1/stats", async () => {
    const now = Date.now();
    const cutoff = (ms: number) => new Date(now - ms).toISOString();

    const countWhere = (where?: SQL): number =>
      (where
        ? db
            .select({ count: sql<number>`count(*)` })
            .from(incidents)
            .where(where)
            .get()
        : db.select({ count: sql<number>`count(*)` }).from(incidents).get()
      )?.count ?? 0;

    const tokenRows = db
      .select({ status: tokens.status, count: sql<number>`count(*)` })
      .from(tokens)
      .groupBy(tokens.status)
      .all();
    const tokenCount = (status: string) =>
      tokenRows.find((r) => r.status === status)?.count ?? 0;

    // Fleet health: an agent is "online" if it beat within 2x the poll
    // interval it was told to use (default 60s).
    const pollSec = Number(process.env.F0_AGENT_POLL_INTERVAL ?? 60);
    const agentRows = db
      .select({ lastSeenAt: agents.lastSeenAt })
      .from(agents)
      .all();
    const onlineCutoff = cutoff(2 * pollSec * 1000);
    const online = agentRows.filter(
      (a) => a.lastSeenAt !== null && a.lastSeenAt >= onlineCutoff,
    ).length;

    // 30-day incident timeline, zero-filled, oldest first.
    const dayRows = db
      .select({ day: sql<string>`date(seen_at)`, count: sql<number>`count(*)` })
      .from(incidents)
      .where(gte(incidents.seenAt, cutoff(29 * DAY_MS)))
      .groupBy(sql`date(seen_at)`)
      .all();
    const byDay = new Map(dayRows.map((r) => [r.day, r.count]));
    const timeline = Array.from({ length: 30 }, (_, i) => {
      const day = new Date(now - (29 - i) * DAY_MS).toISOString().slice(0, 10);
      return { day, count: byDay.get(day) ?? 0 };
    });

    const severityRows = db
      .select({ severity: incidents.severity, count: sql<number>`count(*)` })
      .from(incidents)
      .groupBy(incidents.severity)
      .all();
    const sevCount = (s: string) =>
      severityRows.find((r) => r.severity === s)?.count ?? 0;

    const unackedSevRows = db
      .select({ severity: incidents.severity, count: sql<number>`count(*)` })
      .from(incidents)
      .where(eq(incidents.acknowledged, false))
      .groupBy(incidents.severity)
      .all();
    const unackedSevCount = (s: string) =>
      unackedSevRows.find((r) => r.severity === s)?.count ?? 0;

    const deploymentRows = db
      .select({ status: agentDeployments.status, count: sql<number>`count(*)` })
      .from(agentDeployments)
      .groupBy(agentDeployments.status)
      .all();
    const depCount = (s: string) =>
      deploymentRows.find((r) => r.status === s)?.count ?? 0;

    const byType = db
      .select({ type: tokens.type, count: sql<number>`count(*)` })
      .from(incidents)
      .innerJoin(tokens, eq(incidents.tokenId, tokens.id))
      .groupBy(tokens.type)
      .orderBy(desc(sql`count(*)`))
      .all();

    const topSourceIps = db
      .select({ ip: incidents.sourceIp, count: sql<number>`count(*)` })
      .from(incidents)
      .where(isNotNull(incidents.sourceIp))
      .groupBy(incidents.sourceIp)
      .orderBy(desc(sql`count(*)`))
      .limit(10)
      .all()
      .filter((r): r is { ip: string; count: number } => r.ip !== null);

    const country = sql<string>`json_extract(geo, '$.country')`;
    const byCountry = db
      .select({ country, count: sql<number>`count(*)` })
      .from(incidents)
      .where(and(isNotNull(incidents.geo), sql`${country} IS NOT NULL`))
      .groupBy(country)
      .orderBy(desc(sql`count(*)`))
      .limit(10)
      .all();

    // Map points: incident counts at enriched coordinates.
    const geoPoints = db
      .select({
        lat: sql<number>`json_extract(geo, '$.lat')`,
        lon: sql<number>`json_extract(geo, '$.lon')`,
        country,
        count: sql<number>`count(*)`,
      })
      .from(incidents)
      .where(sql`json_extract(geo, '$.lat') IS NOT NULL`)
      .groupBy(
        sql`json_extract(geo, '$.lat')`,
        sql`json_extract(geo, '$.lon')`,
        country,
      )
      .all();

    const stats: DashboardStats = {
      tokens: {
        total: tokenRows.reduce((n, r) => n + r.count, 0),
        active: tokenCount("active"),
        paused: tokenCount("paused"),
        revoked: tokenCount("revoked"),
      },
      incidents: {
        total: countWhere(),
        unacked: countWhere(eq(incidents.acknowledged, false)),
        last24h: countWhere(gte(incidents.seenAt, cutoff(DAY_MS))),
        last7d: countWhere(gte(incidents.seenAt, cutoff(7 * DAY_MS))),
      },
      agents: { total: agentRows.length, online },
      timeline,
      bySeverity: {
        low: sevCount("low"),
        medium: sevCount("medium"),
        high: sevCount("high"),
      },
      unackedBySeverity: {
        low: unackedSevCount("low"),
        medium: unackedSevCount("medium"),
        high: unackedSevCount("high"),
      },
      deployments: { pending: depCount("pending"), failed: depCount("failed") },
      byType,
      topSourceIps,
      geoPoints: geoPoints.map((p) => ({
        lat: p.lat,
        lon: p.lon,
        country: p.country,
        count: p.count,
      })),
      byCountry,
    };
    return stats;
  });
}
