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
import { Activity, Crosshair, Server, ShieldAlert, Siren } from "lucide-react";
import { api, type DashboardStats, type Incident, type TokenRow } from "../api.js";
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
}: {
  label: string;
  value: string | number;
  sub?: string;
  icon: React.ComponentType<{ className?: string }>;
  alert?: boolean;
}) {
  return (
    <Card className="p-4">
      <div className="flex items-center justify-between">
        <span className="text-[11px] font-medium uppercase tracking-wider text-faint">
          {label}
        </span>
        <Icon className={cn("h-4 w-4", alert ? "text-danger" : "text-accent")} />
      </div>
      <div className={cn("mt-2 text-2xl font-semibold tracking-tight", alert && "text-danger")}>
        {value}
      </div>
      {sub && <div className="mt-0.5 text-xs text-muted">{sub}</div>}
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
              <span key={s} className="flex items-center gap-1.5 text-xs text-muted">
                <span className="h-2 w-2 rounded-full" style={{ background: SEVERITY_FILL[s] }} />
                {s} {bySeverity[s]}
              </span>
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
  rows: { label: string; count: number }[];
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
                  <span className={cn("truncate", mono && "font-mono")}>{r.label}</span>
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
                <div key={i.id} className="flex items-center gap-3 text-xs">
                  <SeverityBadge severity={i.severity} />
                  <span className="min-w-0 flex-1 truncate">{label}</span>
                  <span className="hidden font-mono text-muted sm:inline">{sourceIp}</span>
                  <span className="shrink-0 text-faint">{timeAgo(i.seenAt)}</span>
                </div>
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
    const [stats, tokens, incidents] = await Promise.all([
      api.getStats(),
      api.listTokens(),
      api.listIncidents(),
    ]);
    return { stats, tokens, incidents };
  });

  if (loading && !data) {
    return (
      <section className="space-y-4">
        <PageHeader title="Security Dashboard" description="Posture across tokens, incidents, and fleet" />
        <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
          {Array.from({ length: 5 }).map((_, i) => (
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
    .map((t) => ({ label: `${t.id} · ${t.type}`, count: t.hitCount ?? 0 }));

  return (
    <section className="space-y-4">
      <PageHeader title="Security Dashboard" description="Posture across tokens, incidents, and fleet" />
      {error && <p className="text-sm text-danger">{error}</p>}
      {stats && (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
            <Kpi
              label="Unacknowledged"
              value={stats.incidents.unacked}
              sub="needs triage"
              icon={ShieldAlert}
              alert={stats.incidents.unacked > 0}
            />
            <Kpi label="Incidents 24h" value={stats.incidents.last24h} icon={Siren} />
            <Kpi label="Incidents 7d" value={stats.incidents.last7d} icon={Activity} />
            <Kpi
              label="Active tokens"
              value={stats.tokens.active}
              sub={`${stats.tokens.total} total`}
              icon={Crosshair}
            />
            <Kpi
              label="Agents online"
              value={`${stats.agents.online}/${stats.agents.total}`}
              sub="honeypot fleet"
              icon={Server}
            />
          </div>
          <Timeline data={stats.timeline} />
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <SeverityDonut bySeverity={stats.bySeverity} />
            <BarList
              title="Incidents by token type"
              description="All-time"
              rows={stats.byType.slice(0, 7).map((t) => ({ label: t.type, count: t.count }))}
              mono
            />
            <BarList
              title="Top source IPs"
              description="Most active origins"
              rows={stats.topSourceIps.slice(0, 7).map((s) => ({ label: s.ip, count: s.count }))}
              mono
            />
          </div>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <BarList
              title="Countries"
              description="GeoIP of source IPs (needs F0_GEOIP_DB)"
              rows={stats.byCountry.slice(0, 7).map((c) => ({ label: c.country, count: c.count }))}
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
