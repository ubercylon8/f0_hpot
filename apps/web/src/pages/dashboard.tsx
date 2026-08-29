import { Link } from "react-router-dom";
import { ComposableMap, Geographies, Geography, Marker } from "react-simple-maps";
import { numericToAlpha2 } from "i18n-iso-countries";
import geoData from "world-atlas/countries-110m.json";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip as ChartTooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Activity, Crosshair, DownloadCloud, Server, ShieldAlert, ShieldCheck, Siren } from "lucide-react";
import { api, type AgentRow, type AlertChannel, type DashboardStats, type Incident, type ServerStatus, type TokenRow } from "../api.js";
import { usePoll } from "@/lib/use-poll";
import { incidentSummary } from "@/lib/incident";
import { timeAgo } from "@/lib/time";
import { PageHeader } from "@/components/layout/PageHeader";
import { SeverityBadge } from "@/components/SeverityBadge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

const ACCENT = "var(--color-accent)";
const MUTED = "var(--color-faint)";
const SEVERITY_FILL = {
  high: "var(--color-danger)",
  medium: "var(--color-warning)",
  low: "var(--color-info)",
} as const;

function Kpi({
  label,
  value,
  sub,
  icon: Icon,
  alert,
  to,
}: {
  label: string;
  value: string | number;
  sub?: string;
  icon: React.ComponentType<{ className?: string }>;
  alert?: boolean;
  to?: string;
}) {
  const card = (
    <Card className="flex h-full flex-col p-4">
      <div className="flex items-center justify-between gap-2">
        <span
          className="truncate text-[11px] font-medium uppercase tracking-wider text-faint"
          title={label}
        >
          {label}
        </span>
        <Icon className={cn("h-4 w-4 shrink-0", alert ? "text-danger" : "text-accent")} />
      </div>
      <div className={cn("mt-2 text-2xl font-semibold tracking-tight", alert && "text-danger")}>
        {value}
      </div>
      {/* Sub is always one line so every card has identical rhythm. */}
      <div className="mt-auto truncate pt-0.5 text-xs text-muted" title={sub}>
        {sub ?? "—"}
      </div>
    </Card>
  );
  if (!to) return card;
  return (
    <Link to={to} className="block h-full transition-transform hover:-translate-y-0.5">
      {card}
    </Link>
  );
}

/** "Act now" strip: open auth, failing channels, offline agents,
 *  pending deployments, high-severity unacked. All-clear when quiet. */
function AttentionCard({
  status,
  channels,
  agents,
  stats,
}: {
  status: ServerStatus;
  channels: AlertChannel[];
  agents: AgentRow[];
  stats: DashboardStats;
}) {
  const items: { text: string; to: string; tone: "danger" | "warn" }[] = [];
  if (status.authOpenMode) {
    items.push({ text: "API is in open mode — no authentication", to: "/settings", tone: "danger" });
  }
  const failing = channels.filter((c) => c.enabled && c.failureCount > 0);
  if (failing.length > 0) {
    items.push({ text: `${failing.length} alert channel(s) failing`, to: "/channels", tone: "warn" });
  }
  const offline = agents.filter((a) => a.status !== "online");
  if (offline.length > 0) {
    items.push({ text: `${offline.length} agent(s) offline`, to: "/agents", tone: "warn" });
  }
  if (stats.deployments.pending > 0) {
    items.push({
      text: `${stats.deployments.pending} token deployment(s) pending`,
      to: "/agents",
      tone: "warn",
    });
  }
  if (stats.unackedBySeverity.high > 0) {
    items.push({
      text: `${stats.unackedBySeverity.high} high-severity incident(s) unacknowledged`,
      to: "/incidents?severity=high",
      tone: "danger",
    });
  }

  if (items.length === 0) {
    return (
      <Card className="border-accent/30 bg-accent-dim">
        <CardContent className="flex items-center gap-2 p-3 text-sm text-accent">
          <ShieldCheck className="h-4 w-4" />
          all clear — nothing needs attention
        </CardContent>
      </Card>
    );
  }
  return (
    <Card className="border-warning/40 bg-warning-dim">
      <CardContent className="flex flex-wrap items-center gap-x-5 gap-y-1.5 p-3">
        <span className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wider text-warning">
          <ShieldAlert className="h-4 w-4" /> needs attention
        </span>
        {items.map((it) => (
          <Link
            key={it.text}
            to={it.to}
            className={cn(
              "text-sm underline-offset-4 hover:underline",
              it.tone === "danger" ? "text-danger" : "text-warning",
            )}
          >
            {it.text} →
          </Link>
        ))}
      </CardContent>
    </Card>
  );
}

function Timeline({ data }: { data: DashboardStats["timeline"] }) {
  const total = data.reduce((n, d) => n + d.count, 0);
  return (
    <Card>
      <CardHeader>
        <CardTitle>Incidents — last 30 days</CardTitle>
        <CardDescription>{total} trigger events in the window</CardDescription>
      </CardHeader>
      <CardContent>
        {total === 0 ? (
          <Empty text="No incidents in the last 30 days." />
        ) : (
          <div className="h-52">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: -18 }}>
                <defs>
                  <linearGradient id="incidentFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={ACCENT} stopOpacity={0.35} />
                    <stop offset="100%" stopColor={ACCENT} stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="var(--color-border)" strokeDasharray="3 3" vertical={false} />
                <XAxis
                  dataKey="day"
                  tickFormatter={(d: string) => d.slice(5)}
                  tick={{ fill: MUTED, fontSize: 10 }}
                  tickLine={false}
                  axisLine={false}
                  interval={6}
                />
                <YAxis
                  allowDecimals={false}
                  tick={{ fill: MUTED, fontSize: 10 }}
                  tickLine={false}
                  axisLine={false}
                />
                <ChartTooltip
                  contentStyle={{
                    background: "var(--color-overlay)",
                    border: "1px solid var(--color-border)",
                    borderRadius: 6,
                    fontSize: 12,
                  }}
                  labelStyle={{ color: "var(--color-muted)" }}
                  itemStyle={{ color: ACCENT }}
                />
                <Area
                  type="monotone"
                  dataKey="count"
                  stroke={ACCENT}
                  strokeWidth={1.5}
                  fill="url(#incidentFill)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function SeverityDonut({ bySeverity }: { bySeverity: DashboardStats["bySeverity"] }) {
  const rows = (["high", "medium", "low"] as const)
    .map((name) => ({ name, value: bySeverity[name] }))
    .filter((r) => r.value > 0);
  const total = rows.reduce((n, r) => n + r.value, 0);
  return (
    <Card>
      <CardHeader>
        <CardTitle>Severity</CardTitle>
        <CardDescription>All-time incident mix</CardDescription>
      </CardHeader>
      <CardContent>
        {total === 0 ? (
          <Empty text="No incidents yet." />
        ) : (
          <div className="relative mx-auto h-44 w-44">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={rows}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={56}
                  outerRadius={78}
                  strokeWidth={0}
                >
                  {rows.map((r) => (
                    <Cell key={r.name} fill={SEVERITY_FILL[r.name]} />
                  ))}
                </Pie>
                <ChartTooltip
                  contentStyle={{
                    background: "var(--color-overlay)",
                    border: "1px solid var(--color-border)",
                    borderRadius: 6,
                    fontSize: 12,
                  }}
                  itemStyle={{ color: "var(--color-foreground)" }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-2xl font-semibold">{total}</span>
              <span className="text-[10px] uppercase tracking-wider text-faint">total</span>
            </div>
          </div>
        )}
        {total > 0 && (
          <div className="mt-3 flex justify-center gap-4">
            {(["high", "medium", "low"] as const).map((s) => (
              <Link
                key={s}
                to={`/incidents?severity=${s}`}
                className="flex items-center gap-1.5 text-xs text-muted hover:text-accent"
              >
                <span className="h-2 w-2 rounded-full" style={{ background: SEVERITY_FILL[s] }} />
                {s} {bySeverity[s]}
              </Link>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function BarList({
  title,
  description,
  rows,
  mono,
}: {
  title: string;
  description: string;
  rows: { label: string; count: number; href?: string }[];
  mono?: boolean;
}) {
  const max = Math.max(1, ...rows.map((r) => r.count));
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent>
        {rows.length === 0 ? (
          <Empty text="Nothing recorded yet." />
        ) : (
          <div className="space-y-2">
            {rows.map((r) => (
              <div key={r.label} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className={cn("truncate", mono && "font-mono")}>
                    {r.href ? (
                      <Link className="hover:text-accent hover:underline" to={r.href}>
                        {r.label}
                      </Link>
                    ) : (
                      r.label
                    )}
                  </span>
                  <span className="font-mono text-muted">{r.count}</span>
                </div>
                <div className="h-1.5 overflow-hidden rounded-full bg-raised">
                  <div
                    className="h-full rounded-full bg-accent/70"
                    style={{ width: `${(r.count / max) * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function Empty({ text }: { text: string }) {
  return (
    <div className="flex h-32 items-center justify-center text-sm text-faint">{text}</div>
  );
}

/** World map of incident origins, from GeoIP lat/lon enrichment.
 *  Auto-fits the frame to the current data extent (falls back to a
 *  full-world frame when there's little data); countries with hits are
 *  tinted; Antarctica is dropped to reclaim vertical space. */
const ANTARCTICA_ID = "010";

interface MapFrame {
  center: [number, number];
  scale: number;
}

const WORLD_FRAME: MapFrame = { center: [10, 45], scale: 140 };

function computeFrame(points: DashboardStats["geoPoints"]): MapFrame {
  if (points.length === 0) return WORLD_FRAME;
  const total = points.reduce((n, p) => n + p.count, 0);
  const cLat = points.reduce((n, p) => n + p.lat * p.count, 0) / total;
  const cLon = points.reduce((n, p) => n + p.lon * p.count, 0) / total;
  let deltaLon = 0;
  let deltaLat = 0;
  for (const p of points) {
    deltaLon = Math.max(deltaLon, Math.abs(p.lon - cLon));
    deltaLat = Math.max(deltaLat, Math.abs(p.lat - cLat));
  }
  // Full spans (clamped so tiny clusters don't over-zoom).
  deltaLon = Math.max(deltaLon * 2, 24);
  deltaLat = Math.max(deltaLat * 2, 18);
  // geoMercator: the world spans 2π·scale px wide, π·scale px tall.
  const scaleX = (800 * 360) / (2 * Math.PI * deltaLon);
  const scaleY = (450 * 180) / (Math.PI * deltaLat);
  const scale = Math.min(800, Math.max(WORLD_FRAME.scale, Math.min(scaleX, scaleY) * 0.85));
  return { center: [cLon, Math.max(-60, Math.min(70, cLat))], scale };
}

function GeoMapPanel({
  points,
  countries,
  geoipEnabled,
}: {
  points: DashboardStats["geoPoints"];
  countries: DashboardStats["byCountry"];
  geoipEnabled: boolean;
}) {
  const max = Math.max(1, ...points.map((p) => p.count));
  const hitCountries = new Set(points.map((p) => p.country).filter(Boolean));
  const frame = computeFrame(points);
  return (
    <Card>
      <CardHeader>
        <CardTitle>Incident origins</CardTitle>
        <CardDescription>
          {geoipEnabled
            ? "source-IP geolocation"
            : "source-IP geolocation — set F0_GEOIP_DB on the API to enable"}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-2">
        <ComposableMap
          projection="geoMercator"
          projectionConfig={{ scale: frame.scale, center: frame.center }}
          className="h-52 w-full"
        >
          <Geographies geography={geoData}>
            {({ geographies }) =>
              geographies
                .filter((geo) => geo.id !== ANTARCTICA_ID)
                .map((geo) => {
                  const hit = hitCountries.has(numericToAlpha2(String(geo.id)) ?? "");
                  return (
                    <Geography
                      key={geo.rsmKey}
                      geography={geo}
                      fill={hit ? "var(--color-accent-dim)" : "var(--color-border-strong)"}
                      stroke={hit ? "var(--color-accent)" : "var(--color-border)"}
                      strokeOpacity={hit ? 0.5 : 1}
                      strokeWidth={hit ? 0.7 : 0.4}
                      style={{
                        default: { outline: "none" },
                        hover: { outline: "none", fill: "var(--color-muted)" },
                        pressed: { outline: "none" },
                      }}
                    />
                  );
                })
            }
          </Geographies>
          {points.map((p, i) => (
            <Marker key={i} coordinates={[p.lon, p.lat]}>
              <circle
                r={2.5 + (p.count / max) * 6}
                fill="var(--color-accent)"
                fillOpacity={0.85}
                stroke="var(--color-accent)"
                strokeOpacity={0.25}
                strokeWidth={5}
              >
                <title>{`${p.country ?? "unknown"}: ${p.count} incident(s)`}</title>
              </circle>
            </Marker>
          ))}
        </ComposableMap>
        {countries.length > 0 ? (
          <div className="flex flex-wrap gap-x-4 gap-y-1 pt-1">
            {countries.slice(0, 5).map((c) => (
              <span key={c.country} className="font-mono text-xs text-muted">
                {c.country} <span className="text-accent">{c.count}</span>
              </span>
            ))}
          </div>
        ) : (
          <p className="text-xs text-faint">
            No geolocated incidents yet — markers appear here as enriched
            incidents arrive.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

function RecentIncidents({ incidents }: { incidents: Incident[] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent incidents</CardTitle>
        <CardDescription>Latest trigger events (15s refresh)</CardDescription>
      </CardHeader>
      <CardContent>
        {incidents.length === 0 ? (
          <Empty text="No incidents yet — plant some tokens." />
        ) : (
          <div className="space-y-2.5">
            {incidents.slice(0, 6).map((i) => {
              const { label, sourceIp } = incidentSummary(i);
              return (
                <Link
                  key={i.id}
                  to={`/incidents?expanded=${i.id}`}
                  className="flex items-center gap-3 text-xs transition-colors hover:text-accent"
                >
                  <SeverityBadge severity={i.severity} />
                  <span className="min-w-0 flex-1 truncate">{label}</span>
                  <span className="hidden font-mono text-muted sm:inline">{sourceIp}</span>
                  <span className="shrink-0 text-faint">{timeAgo(i.seenAt)}</span>
                </Link>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export function DashboardPage() {
  const { data, error, loading } = usePoll(async () => {
    const [stats, tokens, incidents, status, channels, agents] = await Promise.all([
      api.getStats(),
      api.listTokens(),
      api.listIncidents(),
      api.getStatus(),
      api.listChannels(),
      api.listAgents(),
    ]);
    return { stats, tokens, incidents, status, channels, agents };
  });

  if (loading && !data) {
    return (
      <section className="space-y-4">
        <PageHeader title="Security Dashboard" description="Posture across tokens, incidents, and fleet" />
        <div className="grid grid-cols-2 gap-4 md:grid-cols-6">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-24" />
          ))}
        </div>
        <Skeleton className="h-72" />
      </section>
    );
  }

  const stats = data?.stats;
  const tokens: TokenRow[] = data?.tokens ?? [];
  const incidents: Incident[] = data?.incidents ?? [];
  const leaderboard = [...tokens]
    .filter((t) => (t.hitCount ?? 0) > 0)
    .sort((a, b) => (b.hitCount ?? 0) - (a.hitCount ?? 0))
    .slice(0, 6)
    .map((t) => ({ label: `${t.id} · ${t.type}`, count: t.hitCount ?? 0, href: `/tokens?id=${t.id}` }));

  return (
    <section className="space-y-4">
      <PageHeader title="Security Dashboard" description="Posture across tokens, incidents, and fleet" />
      {error && <p className="text-sm text-danger">{error}</p>}
      {stats && data && (
        <>
          <AttentionCard
            status={data.status}
            channels={data.channels}
            agents={data.agents}
            stats={stats}
          />
          <div className="grid auto-rows-fr grid-cols-2 gap-4 md:grid-cols-3 lg:grid-cols-6">
            <Kpi
              label="Unacknowledged"
              value={stats.incidents.unacked}
              sub={
                stats.unackedBySeverity.high > 0
                  ? `${stats.unackedBySeverity.high} high severity`
                  : "needs triage"
              }
              icon={ShieldAlert}
              alert={stats.incidents.unacked > 0}
              to="/incidents?acknowledged=false"
            />
            <Kpi
              label="Incidents 24h"
              value={stats.incidents.last24h}
              sub="last 24 hours"
              icon={Siren}
              to="/incidents"
            />
            <Kpi
              label="Incidents 7d"
              value={stats.incidents.last7d}
              sub="last 7 days"
              icon={Activity}
              to="/incidents"
            />
            <Kpi
              label="Pending deploys"
              value={stats.deployments.pending}
              sub={stats.deployments.failed > 0 ? `${stats.deployments.failed} failed` : "token deployments"}
              icon={DownloadCloud}
              alert={stats.deployments.failed > 0}
              to="/agents"
            />
            <Kpi
              label="Active tokens"
              value={stats.tokens.active}
              sub={`${stats.tokens.total} total`}
              icon={Crosshair}
              to="/tokens"
            />
            <Kpi
              label="Agents online"
              value={`${stats.agents.online}/${stats.agents.total}`}
              sub="honeypot fleet"
              icon={Server}
              to="/agents"
            />
          </div>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <div className="lg:col-span-2">
              <Timeline data={stats.timeline} />
            </div>
            <SeverityDonut bySeverity={stats.bySeverity} />
          </div>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <div className="lg:col-span-2">
              <GeoMapPanel points={stats.geoPoints} countries={stats.byCountry} geoipEnabled={data.status.geoipEnabled} />
            </div>
            <BarList
              title="Top source IPs"
              description="Most active origins"
              rows={stats.topSourceIps.slice(0, 7).map((s) => ({
                label: s.ip,
                count: s.count,
                href: `/incidents?source_ip=${s.ip}`,
              }))}
              mono
            />
          </div>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <BarList
              title="Incidents by token type"
              description="All-time"
              rows={stats.byType.slice(0, 7).map((t) => ({
                label: t.type,
                count: t.count,
                href: `/incidents?type=${t.type}`,
              }))}
              mono
            />
            <BarList
              title="Token leaderboard"
              description="Most-hit tokens"
              rows={leaderboard}
              mono
            />
            <RecentIncidents incidents={incidents} />
          </div>
        </>
      )}
    </section>
  );
}
