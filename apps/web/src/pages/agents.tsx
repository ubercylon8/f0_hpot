import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api, type AgentRow } from "../api.js";
import { usePoll } from "@/lib/use-poll";
import { PageHeader } from "@/components/layout/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/utils";

const selectClass =
  "h-8 rounded-md border border-border bg-raised px-2 text-sm text-foreground focus-visible:outline-2 focus-visible:outline-accent";

function ReleasesPanel() {
  const [files, setFiles] = useState<{ filename: string; size: number; url: string }[]>([]);
  const [manifest, setManifest] = useState<string | null>(null);

  useEffect(() => {
    api
      .listReleases()
      .then((r) => {
        setFiles(r.files);
        setManifest(r.manifest);
      })
      .catch(() => {});
  }, []);

  return (
    <Card className="space-y-2 p-5">
      <h2 className="text-sm font-semibold">Agent downloads</h2>
      {files.length === 0 ? (
        <p className="text-xs text-faint">
          No release binaries found. Build with{" "}
          <code className="font-mono text-muted">cd agent && make release</code> and set{" "}
          <code className="font-mono text-muted">F0_AGENT_RELEASE_DIR</code> on the API.
        </p>
      ) : (
        <ul className="space-y-1">
          {files.map((f) => (
            <li key={f.filename} className="flex items-center justify-between text-sm">
              <span className="font-mono text-xs">{f.filename}</span>
              <span className="flex items-center gap-3 text-xs text-muted">
                {(f.size / 1e6).toFixed(1)} MB
                <a href={f.url} download>
                  <Button variant="outline" size="sm">
                    download
                  </Button>
                </a>
              </span>
            </li>
          ))}
        </ul>
      )}
      {manifest && <p className="text-xs text-accent">✓ signed release manifest present</p>}
      <p className="text-xs text-faint">
        Install:{" "}
        <code className="font-mono text-muted">
          ./f0-deception-agent --server &lt;api-url&gt; --enroll &lt;token&gt; --install
        </code>
      </p>
    </Card>
  );
}

const SENSOR_KINDS = [
  { id: "ssh", fields: ["port", "token_id"] },
  { id: "http_login", fields: ["port", "token_id"] },
  { id: "smb", fields: ["port", "token_id"] },
  { id: "rdp", fields: ["port", "token_id"] },
  { id: "planted_credential", fields: ["path", "label", "token_id"] },
  { id: "file_watch", fields: ["path", "label", "token_id"] },
] as const;

type SensorField = (typeof SENSOR_KINDS)[number]["fields"][number];

function fieldsFor(kind: string): readonly SensorField[] {
  return SENSOR_KINDS.find((k) => k.id === kind)?.fields ?? ["port", "token_id"];
}

interface SensorRowState {
  kind: string;
  enabled: boolean;
  port: string;
  path: string;
  label: string;
  token_id: string;
}

function SensorEditor({
  agentId,
  initial,
  onDone,
}: {
  agentId: string;
  initial: { kind: string; enabled: boolean; config: Record<string, unknown> }[];
  onDone: () => void;
}) {
  const [rows, setRows] = useState<SensorRowState[]>(
    initial.map((s) => ({
      kind: s.kind,
      enabled: s.enabled,
      port: String(s.config["port"] ?? ""),
      path: String(s.config["path"] ?? ""),
      label: String(s.config["label"] ?? ""),
      token_id: String(s.config["token_id"] ?? ""),
    })),
  );
  const [busy, setBusy] = useState(false);

  function update(i: number, patch: Partial<SensorRowState>) {
    setRows(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  }

  async function save() {
    setBusy(true);
    try {
      await api.setAgentSensors(
        agentId,
        rows.map((r) => ({
          kind: r.kind,
          enabled: r.enabled,
          config: {
            port: r.port ? Number(r.port) : undefined,
            path: r.path || undefined,
            label: r.label || undefined,
            token_id: r.token_id || undefined,
          },
        })),
      );
      toast.success("Sensor config deployed");
      onDone();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="space-y-2 bg-background p-4">
      {rows.map((r, i) => (
        <div key={i} className="flex flex-wrap items-center gap-2">
          <select value={r.kind} onChange={(e) => update(i, { kind: e.target.value })} className={`${selectClass} w-44`}>
            {SENSOR_KINDS.map((k) => (
              <option key={k.id}>{k.id}</option>
            ))}
          </select>
          {fieldsFor(r.kind).includes("port") && (
            <Input placeholder="port" value={r.port} onChange={(e) => update(i, { port: e.target.value })} className="h-8 w-20" />
          )}
          {fieldsFor(r.kind).includes("path") && (
            <Input placeholder="/absolute/path" value={r.path} onChange={(e) => update(i, { path: e.target.value })} className="h-8 min-w-40 flex-1" />
          )}
          {fieldsFor(r.kind).includes("label") && (
            <Input placeholder="label" value={r.label} onChange={(e) => update(i, { label: e.target.value })} className="h-8 w-32" />
          )}
          {fieldsFor(r.kind).includes("token_id") && (
            <Input placeholder="token id" value={r.token_id} onChange={(e) => update(i, { token_id: e.target.value })} className="h-8 w-36" />
          )}
          <div className="flex items-center gap-1.5">
            <Switch checked={r.enabled} onCheckedChange={(v) => update(i, { enabled: v })} />
            <span className="text-xs text-muted">enabled</span>
          </div>
          <Button variant="ghost" size="sm" className="text-danger hover:text-danger" onClick={() => setRows(rows.filter((_, j) => j !== i))}>
            remove
          </Button>
        </div>
      ))}
      <div className="flex gap-2 pt-1">
        <Button
          variant="outline"
          size="sm"
          onClick={() => setRows([...rows, { kind: "http_login", enabled: true, port: "", path: "", label: "", token_id: "" }])}
        >
          + add sensor
        </Button>
        <Button size="sm" disabled={busy} onClick={() => void save()}>
          {busy ? "deploying…" : "save & deploy"}
        </Button>
      </div>
    </Card>
  );
}

export function AgentsPage() {
  const { data: agents, error, reload } = usePoll<AgentRow[]>(() => api.listAgents());
  const [editing, setEditing] = useState<string | null>(null);
  const list = agents ?? [];

  return (
    <section className="space-y-4">
      <PageHeader title="Agents" description="Honeypot fleet and sensor configuration" />
      {error && <p className="text-sm text-danger">{error}</p>}
      <ReleasesPanel />
      {list.length === 0 && (
        <p className="text-sm text-faint">
          No agents enrolled. Run the agent with{" "}
          <code className="font-mono text-muted">--server &lt;api-url&gt; --enroll &lt;token&gt;</code>.
        </p>
      )}
      {list.map((a) => {
        const online =
          a.status === "online" &&
          a.lastSeenAt !== null &&
          Date.now() - new Date(a.lastSeenAt).getTime() < 180_000;
        return (
          <Card key={a.id} className="space-y-3 p-5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <span className="font-medium">{a.hostname}</span>
                <span className={cn("flex items-center gap-1.5 text-xs", online ? "text-accent" : "text-danger")}>
                  <span className={cn("inline-block h-1.5 w-1.5 rounded-full", online ? "bg-accent" : "bg-danger")} />
                  {online ? "online" : "offline"}
                </span>
                {a.memo && <span className="text-xs text-faint">{a.memo}</span>}
              </div>
              <span className="text-xs text-muted">
                {a.platform} · v{a.version} · last seen{" "}
                {a.lastSeenAt ? new Date(a.lastSeenAt).toLocaleString() : "never"}
              </span>
            </div>

            <div className="space-y-1">
              {a.sensors.map((s) => (
                <div key={s.id} className="flex items-center gap-3 text-sm text-foreground">
                  <Badge variant={s.enabled ? "accent" : "default"} className="font-mono">
                    {s.kind}
                  </Badge>
                  <span className="font-mono text-xs text-faint">{JSON.stringify(s.config)}</span>
                </div>
              ))}
              {a.sensors.length === 0 && <p className="text-xs text-faint">No sensors configured.</p>}
            </div>

            <div>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setEditing(editing === a.id ? null : a.id)}
              >
                {editing === a.id ? "close editor" : "edit sensors"}
              </Button>
            </div>
            {editing === a.id && (
              <SensorEditor
                agentId={a.id}
                initial={a.sensors}
                onDone={() => {
                  setEditing(null);
                  void reload();
                }}
              />
            )}
          </Card>
        );
      })}
    </section>
  );
}
