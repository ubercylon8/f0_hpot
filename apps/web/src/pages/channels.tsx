import { useState } from "react";
import { toast } from "sonner";
import { api, type AlertChannel } from "../api.js";
import { usePoll } from "@/lib/use-poll";
import { PageHeader } from "@/components/layout/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

const selectClass =
  "h-9 rounded-md border border-border bg-raised px-3 text-sm text-foreground focus-visible:outline-2 focus-visible:outline-accent";

function AddChannelForm({ onCreated }: { onCreated: () => void }) {
  const [kind, setKind] = useState("webhook");
  const [url, setUrl] = useState("");
  const [host, setHost] = useState("");
  const [busy, setBusy] = useState(false);

  async function create() {
    const config =
      kind === "webhook"
        ? { url }
        : kind === "syslog"
          ? { host, port: 514 }
          : { url }; // elasticsearch / loki take a url too
    setBusy(true);
    try {
      await api.createChannel(kind, config);
      setUrl("");
      setHost("");
      toast.success(`${kind} channel added`);
      onCreated();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="space-y-3 p-5">
      <h2 className="text-sm font-semibold">Add alert channel</h2>
      <div className="flex flex-wrap gap-3">
        <select value={kind} onChange={(e) => setKind(e.target.value)} className={selectClass}>
          <option value="webhook">Webhook</option>
          <option value="syslog">Syslog (UDP)</option>
          <option value="elasticsearch">Elasticsearch</option>
          <option value="loki">Grafana Loki</option>
        </select>
        {kind === "syslog" ? (
          <Input
            placeholder="siem host"
            value={host}
            onChange={(e) => setHost(e.target.value)}
            className="min-w-64 flex-1"
          />
        ) : (
          <Input
            placeholder="http(s):// endpoint url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="min-w-64 flex-1"
          />
        )}
        <Button onClick={() => void create()} disabled={busy}>
          {busy ? "adding…" : "Add"}
        </Button>
      </div>
    </Card>
  );
}

export function ChannelsPage() {
  const { data: channels, error, reload } = usePoll<AlertChannel[]>(() => api.listChannels());

  return (
    <section className="space-y-6">
      <PageHeader title="Alert Channels" description="Where incident alerts are delivered" />
      {error && <p className="text-sm text-danger">{error}</p>}
      <AddChannelForm onCreated={() => void reload()} />
      <div className="space-y-2">
        {(channels ?? []).map((c) => (
          <Card key={c.id} className="flex items-center justify-between px-4 py-3">
            <div className="flex items-center gap-3 text-sm">
              <Badge variant="accent">{c.kind}</Badge>
              <span className="font-mono text-xs text-faint">{c.id}</span>
              {c.failureCount > 0 && (
                <Badge variant="high">{c.failureCount} failures</Badge>
              )}
            </div>
            <Button
              variant="ghost"
              size="sm"
              className="text-danger hover:text-danger"
              onClick={() =>
                void api
                  .deleteChannel(c.id)
                  .then(() => void reload())
                  .catch((err: unknown) =>
                    toast.error(err instanceof Error ? err.message : String(err)),
                  )
              }
            >
              delete
            </Button>
          </Card>
        ))}
        {(channels ?? []).length === 0 && (
          <p className="text-sm text-faint">No channels yet — alerts only show in the console.</p>
        )}
      </div>
    </section>
  );
}
