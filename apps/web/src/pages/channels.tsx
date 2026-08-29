import { useState } from "react";
import { Plus, Send } from "lucide-react";
import { toast } from "sonner";
import { api, type AlertChannel } from "../api.js";
import { usePoll } from "@/lib/use-poll";
import { timeAgo } from "@/lib/time";
import { PageHeader } from "@/components/layout/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ConfirmButton } from "@/components/ConfirmButton";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";

interface FieldSpec {
  key: string;
  label: string;
  required?: boolean;
  secret?: boolean;
  number?: boolean;
  placeholder?: string;
}

const KIND_FIELDS: Record<string, FieldSpec[]> = {
  webhook: [
    { key: "url", label: "URL", required: true, placeholder: "https://hooks.slack.com/…" },
    { key: "secret", label: "Signing secret (optional)", secret: true },
  ],
  email: [
    { key: "smtp_host", label: "SMTP host", required: true },
    { key: "smtp_port", label: "SMTP port", number: true, placeholder: "587" },
    { key: "smtp_user", label: "SMTP user (optional)" },
    { key: "smtp_pass", label: "SMTP password (optional)", secret: true },
    { key: "from", label: "From address", required: true, placeholder: "f0_hpot@example.com" },
    { key: "to", label: "To address", required: true, placeholder: "soc@example.com" },
    { key: "subject_prefix", label: "Subject prefix (optional)", placeholder: "[f0_hpot]" },
  ],
  syslog: [
    { key: "host", label: "SIEM host", required: true },
    { key: "port", label: "Port", number: true, placeholder: "514" },
    { key: "app_name", label: "App name (optional)", placeholder: "f0_hpot" },
  ],
  elasticsearch: [
    { key: "url", label: "URL", required: true, placeholder: "https://es.example.com:9200" },
    { key: "index", label: "Index (optional)", placeholder: "f0-incidents" },
    { key: "username", label: "Username (optional)" },
    { key: "password", label: "Password (optional)", secret: true },
  ],
  loki: [
    { key: "url", label: "Push URL", required: true, placeholder: "http://loki:3100/loki/api/v1/push" },
    { key: "tenant_id", label: "Tenant ID (optional)" },
  ],
};

const KIND_LABELS: Record<string, string> = {
  webhook: "Webhook",
  email: "Email (SMTP)",
  syslog: "Syslog (UDP)",
  elasticsearch: "Elasticsearch",
  loki: "Grafana Loki",
};

function endpointSummary(c: AlertChannel): string {
  const g = (k: string) => (typeof c.config[k] === "string" ? String(c.config[k]) : "");
  switch (c.kind) {
    case "webhook":
    case "elasticsearch":
    case "loki":
      return g("url");
    case "syslog":
      return `${g("host")}:${typeof c.config["port"] === "number" ? c.config["port"] : 514}`;
    case "email":
      return `${g("from")} → ${g("to")} via ${g("smtp_host")}`;
    default:
      return "";
  }
}

function AddChannelDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onCreated: () => void;
}) {
  const [kind, setKind] = useState("webhook");
  const [values, setValues] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);

  const fields = KIND_FIELDS[kind] ?? [];

  async function create() {
    const config: Record<string, unknown> = {};
    for (const f of fields) {
      const v = (values[f.key] ?? "").trim();
      if (f.required && !v) {
        toast.error(`${f.label} is required`);
        return;
      }
      if (!v) continue;
      config[f.key] = f.number ? Number(v) : v;
    }
    setBusy(true);
    try {
      await api.createChannel(kind, config);
      toast.success(`${KIND_LABELS[kind]} channel added`);
      setValues({});
      onCreated();
      onOpenChange(false);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add alert channel</DialogTitle>
          <DialogDescription>
            New incidents are dispatched to every enabled channel (throttled per
            token + source IP).
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label>Kind</Label>
            <Select value={kind} onValueChange={setKind}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {Object.entries(KIND_LABELS).map(([id, label]) => (
                  <SelectItem key={id} value={id}>
                    {label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {fields.map((f) => (
            <div key={f.key} className="space-y-1.5">
              <Label>{f.label}</Label>
              <Input
                type={f.secret ? "password" : f.number ? "number" : "text"}
                placeholder={f.placeholder}
                value={values[f.key] ?? ""}
                onChange={(e) => setValues({ ...values, [f.key]: e.target.value })}
              />
            </div>
          ))}
        </div>
        <DialogFooter>
          <Button onClick={() => void create()} disabled={busy}>
            {busy ? "adding…" : "Add channel"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ChannelCard({ channel, onChanged }: { channel: AlertChannel; onChanged: () => void }) {
  const [busy, setBusy] = useState<"test" | "toggle" | null>(null);

  async function test() {
    setBusy("test");
    try {
      await api.testChannel(channel.id);
      toast.success(`test alert delivered via ${channel.kind}`);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  }

  async function toggle(enabled: boolean) {
    setBusy("toggle");
    try {
      await api.patchChannel(channel.id, enabled);
      toast.success(enabled ? "channel enabled" : "channel disabled (failure counter reset)");
      onChanged();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  }

  return (
    <Card>
      <CardContent className="flex items-center justify-between gap-4 p-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2.5">
            <Badge variant="accent">{KIND_LABELS[channel.kind] ?? channel.kind}</Badge>
            <span className="font-mono text-xs text-faint">{channel.id}</span>
            {channel.failureCount > 0 && (
              <Badge variant="high">{channel.failureCount} consecutive failures</Badge>
            )}
            {!channel.enabled && <Badge variant="default">disabled</Badge>}
          </div>
          <p className="mt-1 truncate font-mono text-xs text-muted">{endpointSummary(channel)}</p>
          <p className="mt-0.5 text-[11px] text-faint">added {timeAgo(channel.createdAt)}</p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <Button variant="outline" size="sm" disabled={busy !== null} onClick={() => void test()}>
            <Send className="h-3.5 w-3.5" />
            {busy === "test" ? "sending…" : "test"}
          </Button>
          <Switch
            checked={channel.enabled}
            disabled={busy !== null}
            onCheckedChange={(v) => void toggle(v)}
            title={channel.enabled ? "disable channel" : "enable channel"}
          />
          <ConfirmButton
            label="delete"
            disabled={busy !== null}
            onConfirm={() =>
              void api
                .deleteChannel(channel.id)
                .then(onChanged)
                .then(() => toast.success("channel deleted"))
                .catch((err: unknown) =>
                  toast.error(err instanceof Error ? err.message : String(err)),
                )
            }
          />
        </div>
      </CardContent>
    </Card>
  );
}

export function ChannelsPage() {
  const { data: channels, error, reload } = usePoll<AlertChannel[]>(() => api.listChannels());
  const [addOpen, setAddOpen] = useState(false);
  const list = channels ?? [];

  return (
    <section className="space-y-4">
      <PageHeader title="Alert Channels" description="Where incident alerts are delivered">
        <Button onClick={() => setAddOpen(true)}>
          <Plus className="h-4 w-4" />
          Add channel
        </Button>
      </PageHeader>
      {error && <p className="text-sm text-danger">{error}</p>}
      <div className="space-y-2">
        {list.map((c) => (
          <ChannelCard key={c.id} channel={c} onChanged={() => void reload()} />
        ))}
        {list.length === 0 && (
          <Card>
            <CardHeader>
              <CardTitle>No channels yet</CardTitle>
              <CardDescription>
                Alerts only appear in the console until you add a delivery channel.
              </CardDescription>
            </CardHeader>
          </Card>
        )}
      </div>
      <AddChannelDialog open={addOpen} onOpenChange={setAddOpen} onCreated={() => void reload()} />
    </section>
  );
}
