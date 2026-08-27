import { useEffect, useState } from "react";
import { Hammer, KeyRound, Plus, ShieldCheck, Terminal, Trash2, Upload } from "lucide-react";
import { toast } from "sonner";
import { api, downloadFile, type AgentRow, type CodeSignCertRow, type ReleaseKeyRow } from "../api.js";
import { usePoll } from "@/lib/use-poll";
import { timeAgo } from "@/lib/time";
import { PageHeader } from "@/components/layout/PageHeader";
import { CopyButton } from "@/components/CopyButton";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
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
import {
  Sheet,
  SheetBody,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";

function OnlineDot({ agent }: { agent: AgentRow }) {
  const online =
    agent.status === "online" &&
    agent.lastSeenAt !== null &&
    Date.now() - new Date(agent.lastSeenAt).getTime() < 180_000;
  return (
    <span className={cn("flex items-center gap-1.5 text-xs", online ? "text-accent" : "text-danger")}>
      <span className={cn("inline-block h-1.5 w-1.5 rounded-full", online ? "bg-accent" : "bg-danger")} />
      {online ? "online" : "offline"}
    </span>
  );
}

function AddAgentDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const [token, setToken] = useState<string | null>(null);
  useEffect(() => {
    if (open) api.getAgentBootstrap().then((b) => setToken(b.enrollmentToken)).catch(() => {});
  }, [open]);

  const origin = window.location.origin;
  const oneLiner = token
    ? `curl -LO ${origin}/api/v1/agent-releases/f0-deception-agent-linux-amd64 && ` +
      `chmod +x f0-deception-agent-linux-amd64 && ` +
      `sudo ./f0-deception-agent-linux-amd64 --server ${origin} --enroll ${token} --install`
    : null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Terminal className="h-4 w-4 text-accent" /> Add an agent
          </DialogTitle>
          <DialogDescription>
            Run this on the honeypot host (linux/amd64). Other platforms: download
            the matching binary from the releases card and use the same flags.
          </DialogDescription>
        </DialogHeader>
        {oneLiner ? (
          <div className="space-y-3">
            <div className="flex items-start gap-2 rounded-md border border-border bg-background p-3">
              <code className="min-w-0 flex-1 break-all font-mono text-xs text-accent">
                {oneLiner}
              </code>
              <CopyButton value={oneLiner} label="copy one-liner" />
            </div>
            <p className="text-xs text-faint">
              The enrollment token authenticates the host once; the agent receives
              its own key at enrollment. Re-running with the same hostname
              re-keys the existing agent.
            </p>
          </div>
        ) : (
          <p className="text-sm text-warning">
            F0_ENROLLMENT_TOKEN is not set on the API — agent enrollment is
            disabled. Set it and restart the API.
          </p>
        )}
      </DialogContent>
    </Dialog>
  );
}

function SigningKeysCard() {
  const [keys, setKeys] = useState<ReleaseKeyRow[] | null>(null);
  const [label, setLabel] = useState("");
  const [signKey, setSignKey] = useState("");
  const [version, setVersion] = useState("");
  const [busy, setBusy] = useState(false);

  const reload = () => api.listReleaseKeys().then(setKeys).catch(() => setKeys([]));
  useEffect(() => {
    void reload();
  }, []);

  async function generate() {
    setBusy(true);
    try {
      const k = await api.createReleaseKey(label.trim() || "release");
      setLabel("");
      toast.success(`key ${k.id} generated`, {
        description: "Embed the public key in the agent build via -ldflags (copied to clipboard on click).",
      });
      await navigator.clipboard.writeText(k.publicKey).catch(() => {});
      void reload();
      setSignKey(k.id);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function sign() {
    setBusy(true);
    try {
      const r = await api.signReleases(signKey, version.trim() || undefined);
      toast.success(`signed manifest ${r.version} covering ${r.files.length} file(s)`);
      setVersion("");
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
          <KeyRound className="h-4 w-4 text-accent" /> Release signing keys
        </CardTitle>
        <CardDescription>
          Ed25519 keys stored server-side; the public half is embedded in the agent
          binary to verify self-updates.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {(keys ?? []).map((k) => (
          <div key={k.id} className="flex items-center gap-3 text-xs">
            <Badge variant="outline">{k.label}</Badge>
            <span className="font-mono text-faint">{k.id}</span>
            <span className="min-w-0 flex-1 truncate font-mono text-muted">{k.publicKey}</span>
            <CopyButton value={k.publicKey} label="copy embeddable public key" />
            <span className="shrink-0 text-faint">{new Date(k.createdAt).toLocaleDateString()}</span>
            <Button
              variant="ghost"
              size="sm"
              className="text-danger hover:text-danger"
              title="delete key (deployed agents keep their embedded public key)"
              onClick={() =>
                void api
                  .deleteReleaseKey(k.id)
                  .then(() => {
                    toast.success(`key "${k.label}" deleted`);
                    void reload();
                  })
                  .catch((err: unknown) =>
                    toast.error(err instanceof Error ? err.message : String(err)),
                  )
              }
            >
              delete
            </Button>
          </div>
        ))}
        {(keys ?? []).length === 0 && (
          <p className="text-xs text-faint">No signing keys yet — generate one below.</p>
        )}
        <div className="flex flex-wrap items-center gap-2 pt-1">
          <Input
            placeholder="key label (e.g. prod-2026)"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            className="h-8 w-52"
          />
          <Button size="sm" variant="outline" disabled={busy} onClick={() => void generate()}>
            generate key
          </Button>
        </div>
        {(keys ?? []).length > 0 && (
          <div className="flex flex-wrap items-center gap-2 border-t border-border pt-3">
            <Select value={signKey} onValueChange={setSignKey}>
              <SelectTrigger className="h-8 w-52">
                <SelectValue placeholder="sign with key…" />
              </SelectTrigger>
              <SelectContent>
                {(keys ?? []).map((k) => (
                  <SelectItem key={k.id} value={k.id}>
                    {k.label} ({k.id})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Input
              placeholder="version (default: dev-<date>)"
              value={version}
              onChange={(e) => setVersion(e.target.value)}
              className="h-8 w-52"
            />
            <Button size="sm" disabled={busy || !signKey} onClick={() => void sign()}>
              sign release dir
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function ReleasesCard() {
  const [files, setFiles] = useState<{ filename: string; size: number; url: string }[]>([]);
  const [manifest, setManifest] = useState<string | null>(null);
  const [version, setVersion] = useState("v1.0.0");
  const [busy, setBusy] = useState(false);

  const reload = () =>
    api
      .listReleases()
      .then((r) => {
        setFiles(r.files);
        setManifest(r.manifest);
      })
      .catch(() => {});
  useEffect(() => {
    void reload();
  }, []);

  async function build() {
    if (!version.trim()) {
      toast.error("version is required");
      return;
    }
    setBusy(true);
    try {
      const r = await api.buildReleases(version.trim());
      toast.success(`built ${r.files.length} binaries at ${r.version} — manifest cleared, re-sign to publish`);
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
        <CardTitle>Release binaries</CardTitle>
        <CardDescription>
          Cross-compiled for 5 platforms, served from{" "}
          <code className="font-mono text-muted">F0_AGENT_RELEASE_DIR</code>
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-1.5">
        <div className="flex flex-wrap items-center gap-2 pb-2">
          <Input
            placeholder="v1.0.0"
            value={version}
            onChange={(e) => setVersion(e.target.value)}
            className="h-8 w-36 font-mono"
          />
          <Button size="sm" variant="outline" disabled={busy} onClick={() => void build()}>
            <Hammer className="h-3.5 w-3.5" />
            {busy ? "building…" : "build binaries"}
          </Button>
          {busy && (
            <span className="text-xs text-faint">cross-compiling 5 platforms, ~1 min</span>
          )}
        </div>
        {files.length === 0 ? (
          <p className="text-xs text-faint">No release binaries found.</p>
        ) : (
          files.map((f) => (
            <div key={f.filename} className="flex items-center justify-between text-sm">
              <span className="font-mono text-xs">{f.filename}</span>
              <span className="flex items-center gap-2 text-xs text-muted">
                {(f.size / 1e6).toFixed(1)} MB
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() =>
                    void downloadFile(f.url.replace(/^\/api\/v1/, ""), f.filename)
                      .then(() => toast.success(`downloaded ${f.filename}`))
                      .catch((err: unknown) =>
                        toast.error(err instanceof Error ? err.message : String(err)),
                      )
                  }
                >
                  download
                </Button>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8 text-danger hover:text-danger"
                  title={`delete ${f.filename}`}
                  onClick={() =>
                    void api
                      .deleteRelease(f.filename)
                      .then(() => {
                        toast.success(`deleted ${f.filename}`);
                        void reload();
                      })
                      .catch((err: unknown) =>
                        toast.error(err instanceof Error ? err.message : String(err)),
                      )
                  }
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              </span>
            </div>
          ))
        )}
        {manifest && <p className="pt-1 text-xs text-accent">✓ signed release manifest present</p>}
      </CardContent>
    </Card>
  );
}

function CodeSigningCard() {
  const [certs, setCerts] = useState<CodeSignCertRow[] | null>(null);
  const [label, setLabel] = useState("");
  const [cn, setCn] = useState("f0_hpot Local Code Signing");
  const [genPass, setGenPass] = useState("");
  const [upLabel, setUpLabel] = useState("");
  const [upPass, setUpPass] = useState("");
  const [busy, setBusy] = useState(false);

  const reload = () => api.listCodeSignCerts().then(setCerts).catch(() => setCerts([]));
  useEffect(() => {
    void reload();
  }, []);

  async function run(fn: () => Promise<unknown>, done: string) {
    setBusy(true);
    try {
      await fn();
      toast.success(done);
      void reload();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  function upload(file: File) {
    if (!upLabel.trim() || !upPass) {
      toast.error("set a label and the .p12 passphrase before choosing the file");
      return;
    }
    void run(async () => {
      const dataUrl = await new Promise<string>((resolve, reject) => {
        const r = new FileReader();
        r.onload = () => resolve(String(r.result));
        r.onerror = () => reject(new Error("read failed"));
        r.readAsDataURL(file);
      });
      const b64 = dataUrl.split(",")[1] ?? "";
      await api.uploadCodeSignCert(upLabel.trim(), b64, upPass);
      setUpLabel("");
      setUpPass("");
    }, `certificate "${upLabel.trim()}" stored`);
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-accent" /> Code signing (Authenticode)
        </CardTitle>
        <CardDescription>
          Sign the Windows agent binary with an org-trusted certificate so
          SmartScreen/ASR accept it. Distinct from the Ed25519 update-manifest
          keys above: those keep <em>updates</em> honest — this gets the binary{" "}
          <em>running</em> on org endpoints where the cert is deployed.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {(certs ?? []).map((c) => (
          <div key={c.id} className="flex items-center gap-3 text-xs">
            <Badge variant="outline">{c.label}</Badge>
            <span className="min-w-0 flex-1 truncate text-muted" title={c.subject}>
              {c.subject}
            </span>
            <span className="shrink-0 text-faint">
              expires {new Date(c.notAfter).toLocaleDateString()}
            </span>
            <Button
              size="sm"
              variant="outline"
              disabled={busy}
              onClick={() => {
                setBusy(true);
                void api
                  .codeSignRelease(c.id)
                  .then((r) =>
                    toast.success(
                      `signed ${r.signed.length} binary(ies) with ${c.label}` +
                        (r.skipped.length ? ` — skipped: ${r.skipped.join(", ")}` : ""),
                    ),
                  )
                  .catch((err: unknown) =>
                    toast.error(err instanceof Error ? err.message : String(err)),
                  )
                  .finally(() => setBusy(false));
              }}
            >
              sign binaries
            </Button>
            <Button
              size="sm"
              variant="ghost"
              className="text-danger hover:text-danger"
              disabled={busy}
              onClick={() => void run(() => api.deleteCodeSignCert(c.id), `cert "${c.label}" deleted`)}
            >
              delete
            </Button>
          </div>
        ))}
        {(certs ?? []).length === 0 && (
          <p className="text-xs text-faint">
            No certificates yet — generate an org-local one below or upload an
            existing .p12.
          </p>
        )}
        <div className="space-y-2 border-t border-border pt-3">
          <p className="text-[11px] font-medium uppercase tracking-wider text-faint">
            generate self-signed (org-local)
          </p>
          <div className="flex flex-wrap gap-2">
            <Input placeholder="label" value={label} onChange={(e) => setLabel(e.target.value)} className="h-8 w-36" />
            <Input placeholder="common name (CN)" value={cn} onChange={(e) => setCn(e.target.value)} className="h-8 min-w-52 flex-1" />
            <Input type="password" placeholder="passphrase" value={genPass} onChange={(e) => setGenPass(e.target.value)} className="h-8 w-36" />
            <Button
              size="sm"
              variant="outline"
              disabled={busy || !label.trim() || !cn.trim() || genPass.length < 4}
              onClick={() =>
                void run(async () => {
                  await api.generateCodeSignCert(label.trim(), cn.trim(), genPass);
                  setLabel("");
                  setGenPass("");
                }, `certificate "${label.trim()}" generated`)
              }
            >
              generate
            </Button>
          </div>
        </div>
        <div className="space-y-2 border-t border-border pt-3">
          <p className="text-[11px] font-medium uppercase tracking-wider text-faint">
            or upload .p12 / .pfx
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <Input placeholder="label" value={upLabel} onChange={(e) => setUpLabel(e.target.value)} className="h-8 w-36" />
            <Input type="password" placeholder="passphrase" value={upPass} onChange={(e) => setUpPass(e.target.value)} className="h-8 w-36" />
            <label className="inline-flex cursor-pointer items-center gap-2">
              <input
                type="file"
                accept=".p12,.pfx,application/x-pkcs12"
                className="hidden"
                disabled={busy}
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) upload(f);
                  e.target.value = "";
                }}
              />
              <span className="inline-flex h-8 items-center gap-2 rounded-md border border-border bg-raised px-3 text-xs text-foreground hover:bg-overlay">
                <Upload className="h-3.5 w-3.5" />
                choose .p12
              </span>
            </label>
          </div>
        </div>
      </CardContent>
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

const selectClass =
  "h-8 rounded-md border border-border bg-raised px-2 text-sm text-foreground focus-visible:outline-2 focus-visible:outline-accent";

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
      toast.success("Sensor config deployed — agent picks it up on next heartbeat");
      onDone();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-2 rounded-md border border-border bg-background p-3">
      {rows.map((r, i) => (
        <div key={i} className="flex flex-wrap items-center gap-2">
          <select value={r.kind} onChange={(e) => update(i, { kind: e.target.value })} className={`${selectClass} w-40`}>
            {SENSOR_KINDS.map((k) => (
              <option key={k.id}>{k.id}</option>
            ))}
          </select>
          {fieldsFor(r.kind).includes("port") && (
            <Input placeholder="port" value={r.port} onChange={(e) => update(i, { port: e.target.value })} className="h-8 w-20" />
          )}
          {fieldsFor(r.kind).includes("path") && (
            <Input placeholder="/absolute/path" value={r.path} onChange={(e) => update(i, { path: e.target.value })} className="h-8 min-w-36 flex-1" />
          )}
          {fieldsFor(r.kind).includes("label") && (
            <Input placeholder="label" value={r.label} onChange={(e) => update(i, { label: e.target.value })} className="h-8 w-28" />
          )}
          {fieldsFor(r.kind).includes("token_id") && (
            <Input placeholder="token id" value={r.token_id} onChange={(e) => update(i, { token_id: e.target.value })} className="h-8 w-32" />
          )}
          <div className="flex items-center gap-1.5">
            <Switch checked={r.enabled} onCheckedChange={(v) => update(i, { enabled: v })} />
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
    </div>
  );
}

function AgentDrawer({
  agent,
  onClose,
  onChanged,
}: {
  agent: AgentRow | null;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [memo, setMemo] = useState("");
  const [editingSensors, setEditingSensors] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setMemo(agent?.memo ?? "");
    setEditingSensors(false);
    setConfirming(false);
  }, [agent]);

  async function act(fn: () => Promise<unknown>, done: string) {
    setBusy(true);
    try {
      await fn();
      toast.success(done);
      onChanged();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Sheet open={agent !== null} onOpenChange={(o) => !o && onClose()}>
      <SheetContent>
        {agent && (
          <>
            <SheetHeader>
              <SheetTitle className="flex items-center gap-3">
                {agent.hostname}
                <OnlineDot agent={agent} />
              </SheetTitle>
              <SheetDescription className="font-mono text-xs">
                {agent.id} · {agent.platform} · v{agent.version} · last seen{" "}
                {agent.lastSeenAt ? timeAgo(agent.lastSeenAt) : "never"}
              </SheetDescription>
            </SheetHeader>
            <SheetBody className="space-y-5">
              <div className="space-y-1.5">
                <Label>Memo</Label>
                <div className="flex gap-2">
                  <Input
                    placeholder="e.g. dmz honeypot, rack 3"
                    value={memo}
                    onChange={(e) => setMemo(e.target.value)}
                    className="h-8"
                  />
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={busy || memo === (agent.memo ?? "")}
                    onClick={() => void act(() => api.patchAgent(agent.id, memo.trim() || null), "memo saved")}
                  >
                    save
                  </Button>
                </div>
              </div>

              <Separator />

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-medium uppercase tracking-wider text-faint">Sensors</h3>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setEditingSensors(!editingSensors)}
                  >
                    {editingSensors ? "close editor" : "edit sensors"}
                  </Button>
                </div>
                {agent.sensors.map((s) => (
                  <div key={s.id} className="flex items-center gap-2.5 text-sm">
                    <Badge variant={s.enabled ? "accent" : "default"} className="font-mono">
                      {s.kind}
                    </Badge>
                    <span className="truncate font-mono text-xs text-faint">
                      {JSON.stringify(s.config)}
                    </span>
                  </div>
                ))}
                {agent.sensors.length === 0 && (
                  <p className="text-xs text-faint">No sensors configured.</p>
                )}
                {editingSensors && (
                  <SensorEditor
                    agentId={agent.id}
                    initial={agent.sensors}
                    onDone={() => {
                      setEditingSensors(false);
                      onChanged();
                    }}
                  />
                )}
              </div>

              <Separator />

              <div className="space-y-2">
                <h3 className="text-xs font-medium uppercase tracking-wider text-faint">Danger zone</h3>
                {confirming ? (
                  <div className="space-y-3 rounded-md border border-danger/30 bg-danger-dim p-3">
                    <p className="text-xs text-foreground">
                      Retire <strong>{agent.hostname}</strong>? Its key stops working
                      immediately (heartbeats and incident reports will be rejected).
                      Past incidents are kept.
                    </p>
                    <div className="flex gap-2">
                      <Button
                        variant="destructive"
                        size="sm"
                        disabled={busy}
                        onClick={() =>
                          void act(async () => {
                            await api.deleteAgent(agent.id);
                            onClose();
                          }, "agent retired")
                        }
                      >
                        {busy ? "retiring…" : "retire agent"}
                      </Button>
                      <Button variant="outline" size="sm" onClick={() => setConfirming(false)}>
                        cancel
                      </Button>
                    </div>
                  </div>
                ) : (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-danger hover:text-danger"
                    onClick={() => setConfirming(true)}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                    retire agent…
                  </Button>
                )}
              </div>
            </SheetBody>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}

export function AgentsPage() {
  const { data: agents, error, reload } = usePoll<AgentRow[]>(() => api.listAgents());
  const [addOpen, setAddOpen] = useState(false);
  const [selected, setSelected] = useState<AgentRow | null>(null);
  const list = agents ?? [];

  return (
    <section className="space-y-4">
      <PageHeader title="Agents" description="Honeypot fleet, sensors, and releases">
        <Button onClick={() => setAddOpen(true)}>
          <Plus className="h-4 w-4" />
          Add agent
        </Button>
      </PageHeader>
      {error && <p className="text-sm text-danger">{error}</p>}

      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Hostname</TableHead>
              <TableHead>Memo</TableHead>
              <TableHead>Platform</TableHead>
              <TableHead>Sensors</TableHead>
              <TableHead>Last seen</TableHead>
              <TableHead>Status</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {list.map((a) => (
              <TableRow key={a.id} className="cursor-pointer" onClick={() => setSelected(a)}>
                <TableCell className="font-medium">{a.hostname}</TableCell>
                <TableCell className="max-w-40 truncate text-muted">{a.memo ?? "—"}</TableCell>
                <TableCell className="text-muted">
                  {a.platform} · v{a.version}
                </TableCell>
                <TableCell>
                  <span className="flex flex-wrap gap-1">
                    {a.sensors.length === 0 && <span className="text-faint">—</span>}
                    {a.sensors.map((s) => (
                      <Badge key={s.id} variant={s.enabled ? "outline" : "default"} className="font-mono text-[10px]">
                        {s.kind}
                      </Badge>
                    ))}
                  </span>
                </TableCell>
                <TableCell className="text-muted">
                  {a.lastSeenAt ? timeAgo(a.lastSeenAt) : "never"}
                </TableCell>
                <TableCell>
                  <OnlineDot agent={a} />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {list.length === 0 && (
          <p className="p-5 text-sm text-faint">
            No agents enrolled — use Add agent to get an install one-liner.
          </p>
        )}
      </Card>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <ReleasesCard />
        <SigningKeysCard />
        <div className="lg:col-span-2">
          <CodeSigningCard />
        </div>
      </div>

      <AddAgentDialog open={addOpen} onOpenChange={setAddOpen} />
      <AgentDrawer agent={selected} onClose={() => setSelected(null)} onChanged={() => void reload()} />
    </section>
  );
}
