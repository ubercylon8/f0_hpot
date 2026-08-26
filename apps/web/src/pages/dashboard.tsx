import { api } from "../api.js";
import { usePoll } from "@/lib/use-poll";
import { PageHeader } from "@/components/layout/PageHeader";
import { Card } from "@/components/ui/card";

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <Card className="p-5">
      <div className="text-3xl font-semibold tracking-tight">{value}</div>
      <div className="mt-1 text-sm text-muted">{label}</div>
    </Card>
  );
}

export function DashboardPage() {
  const { data, error } = usePoll(async () => {
    const [tokens, incidents] = await Promise.all([api.listTokens(), api.listIncidents()]);
    return { tokens, incidents };
  });
  const tokens = data?.tokens ?? [];
  const incidents = data?.incidents ?? [];
  const last24h = incidents.filter(
    (i) => Date.now() - new Date(i.seenAt).getTime() < 86_400_000,
  );

  return (
    <section>
      <PageHeader title="Dashboard" description="Platform posture at a glance" />
      {error && <p className="mb-4 text-sm text-danger">{error}</p>}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Stat label="Active tokens" value={tokens.filter((t) => t.status === "active").length} />
        <Stat label="Incidents (24h)" value={last24h.length} />
        <Stat label="Unacknowledged" value={incidents.filter((i) => !i.acknowledged).length} />
      </div>
      <p className="mt-6 text-sm text-faint">
        The full security dashboard (timeline, severity breakdown, geo, fleet
        health) lands in Phase C — this page keeps the basic counters for now.
      </p>
    </section>
  );
}
