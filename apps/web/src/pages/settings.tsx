import { useState } from "react";
import { KeyRound, Plus, ShieldAlert } from "lucide-react";
import { toast } from "sonner";
import { api, type AuthKeyRow, type ServerStatus } from "../api.js";
import { usePoll } from "@/lib/use-poll";
import { timeAgo } from "@/lib/time";
import { PageHeader } from "@/components/layout/PageHeader";
import { CopyButton } from "@/components/CopyButton";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

function StatusRow({ label, ok, okText, badText }: { label: string; ok: boolean; okText: string; badText: string }) {
  return (
    <div className="flex items-center justify-between text-sm">
      <span className="text-muted">{label}</span>
      <Badge variant={ok ? "accent" : "medium"}>{ok ? okText : badText}</Badge>
    </div>
  );
}

function ServerStatusCard({ status }: { status: ServerStatus }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Server status</CardTitle>
        <CardDescription>Runtime configuration of this f0_hpot API</CardDescription>
      </CardHeader>
      <CardContent className="space-y-2.5">
        <StatusRow
          label="GeoIP enrichment (F0_GEOIP_DB)"
          ok={status.geoipEnabled}
          okText="enabled"
          badText="disabled"
        />
        <StatusRow
          label="Agent enrollment (F0_ENROLLMENT_TOKEN)"
          ok={status.enrollmentConfigured}
          okText="configured"
          badText="not set"
        />
        <div className="flex items-center justify-between text-sm">
          <span className="text-muted">Alert throttle</span>
          <span className="font-mono text-xs">
            {status.alertThrottlePerMinute}/min per token+IP
          </span>
        </div>
      </CardContent>
    </Card>
  );
}

function ApiKeysCard() {
  const { data: keys, reload } = usePoll<AuthKeyRow[]>(() => api.listAuthKeys());
  const [label, setLabel] = useState("");
  const [fresh, setFresh] = useState<{ id: string; key: string; label: string } | null>(null);
  const [busy, setBusy] = useState(false);

  async function create() {
    if (!label.trim()) {
      toast.error("label is required");
      return;
    }
    setBusy(true);
    try {
      const k = await api.createAuthKey(label.trim());
      setFresh(k);
      setLabel("");
      void reload();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <KeyRound className="h-4 w-4 text-accent" /> API keys
        </CardTitle>
        <CardDescription>
          Persistent console keys (also used by the MCP server via F0_API_TOKEN).
          Keys are sha256-hashed server-side and shown exactly once.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {fresh && (
          <div className="space-y-2 rounded-md border border-accent/30 bg-accent-dim p-3">
            <p className="text-xs text-foreground">
              Key <strong>{fresh.label}</strong> created — copy it now, it will
              never be shown again:
            </p>
            <div className="flex items-center gap-2 rounded border border-border bg-background px-2.5 py-2">
              <code className="min-w-0 flex-1 truncate font-mono text-xs text-accent">
                {fresh.key}
              </code>
              <CopyButton value={fresh.key} label="copy new API key" />
            </div>
            <Button variant="outline" size="sm" onClick={() => setFresh(null)}>
              done
            </Button>
          </div>
        )}
        <div className="flex gap-2">
          <Input
            placeholder="key label (e.g. laptop, ci-runner)"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            className="h-8 max-w-64"
          />
          <Button size="sm" variant="outline" disabled={busy} onClick={() => void create()}>
            <Plus className="h-3.5 w-3.5" />
            {busy ? "creating…" : "create key"}
          </Button>
        </div>
        <div className="space-y-1.5">
          {(keys ?? []).map((k) => (
            <div key={k.id} className="flex items-center gap-3 text-xs">
              <Badge variant="outline">{k.label}</Badge>
              <span className="font-mono text-faint">{k.id}</span>
              <span className="text-muted">
                created {timeAgo(k.createdAt)} · last used{" "}
                {k.lastUsedAt ? timeAgo(k.lastUsedAt) : "never"}
              </span>
              <Button
                variant="ghost"
                size="sm"
                className="ml-auto text-danger hover:text-danger"
                onClick={() =>
                  void api
                    .deleteAuthKey(k.id)
                    .then(() => void reload())
                    .then(() => toast.success(`key "${k.label}" revoked`))
                    .catch((err: unknown) =>
                      toast.error(err instanceof Error ? err.message : String(err)),
                    )
                }
              >
                revoke
              </Button>
            </div>
          ))}
          {(keys ?? []).length === 0 && (
            <p className="text-xs text-faint">
              No persistent keys. While no keys exist and no env tokens are set,
              the API runs in open mode (see above).
            </p>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

export function SettingsPage() {
  const { data: status, error } = usePoll<ServerStatus>(() => api.getStatus());

  return (
    <section className="space-y-4">
      <PageHeader title="Settings" description="Access control and server configuration" />
      {error && <p className="text-sm text-danger">{error}</p>}
      {status?.authOpenMode && (
        <Card className="border-warning/40 bg-warning-dim">
          <CardContent className="flex items-start gap-3 p-4">
            <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-warning" />
            <div className="text-sm">
              <p className="font-medium text-warning">API is running in open mode</p>
              <p className="mt-1 text-muted">
                No F0_ADMIN_TOKEN / F0_INTERNAL_SECRET is set and no API keys
                exist — every console route is unauthenticated. Set the env
                tokens or create an API key below to close it (takes effect
                immediately, no restart).
              </p>
            </div>
          </CardContent>
        </Card>
      )}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {status && <ServerStatusCard status={status} />}
        <ApiKeysCard />
      </div>
    </section>
  );
}
