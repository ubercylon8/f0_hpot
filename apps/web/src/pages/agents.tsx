import { useEffect, useState } from "react";
import { DownloadCloud, Hammer, KeyRound, Plus, RefreshCw, ShieldCheck, Terminal, Trash2, Upload } from "lucide-react";
import { toast } from "sonner";
import { api, downloadFile, type AgentRow, type Capabilities, type CodeSignCertRow, type DeploymentRow, type EnrollmentTokenRow, type ReleaseKeyRow, type TokenRow } from "../api.js";
import { usePoll } from "@/lib/use-poll";
import { timeAgo } from "@/lib/time";
import { PageHeader } from "@/components/layout/PageHeader";
import { CopyButton } from "@/components/CopyButton";
import { ConfirmButton } from "@/components/ConfirmButton";
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

/** Checkbox selection state shared by the four removable lists on this page. */
function useSelection() {
  const [sel, setSel] = useState<ReadonlySet<string>>(new Set());
  const [confirm, setConfirm] = useState(false);
  const toggle = (id: string) => {
    const next = new Set(sel);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSel(next);
    setConfirm(false);
  };
  const toggleAll = (ids: string[]) => {
    setSel((cur) =>
      ids.length > 0 && ids.every((i) => cur.has(i)) ? new Set() : new Set(ids),
    );
    setConfirm(false);
  };
  const clear = () => {
    setSel(new Set());
    setConfirm(false);
  };
  return { sel, confirm, setConfirm, toggle, toggleAll, clear };
}

function SelectionBar({
  count,
  label,
  confirm,
  setConfirm,
  onDelete,
  onClear,
  busy,
  twoStep = true,
}: {
  count: number;
  label: string;
  confirm: boolean;
  setConfirm: (v: boolean) => void;
  onDelete: () => void;
  onClear: () => void;
  busy: boolean;
  twoStep?: boolean;
}) {
  return (
    <div className="flex items-center gap-2 rounded-md border border-border bg-raised px-3 py-2 text-xs">
      <span className="font-medium">{count} selected</span>
      {confirm || !twoStep ? (
        <Button variant={twoStep ? "destructive" : "outline"} size="sm" disabled={busy} onClick={onDelete}>
          <Trash2 className="h-3.5 w-3.5" />
          {busy ? "deleting…" : twoStep ? `confirm ${label}` : label}
        </Button>
      ) : null}
      {confirm && (
        <Button variant="ghost" size="sm" onClick={() => setConfirm(false)}>
          cancel
        </Button>
      )}
      {!confirm && twoStep && (
        <Button
          variant="ghost"
          size="sm"
          className="text-danger hover:text-danger"
          onClick={() => setConfirm(true)}
        >
          <Trash2 className="h-3.5 w-3.5" />
          {label}…
        </Button>
      )}
      <Button variant="ghost" size="sm" className="ml-auto" onClick={onClear}>
        clear
      </Button>
    </div>
  );
}

/** Delete a list of ids with per-item delete calls; report the tally. */
async function deleteMany(
  ids: string[],
  del: (id: string) => Promise<unknown>,
): Promise<{ ok: number; failed: number }> {
  const results = await Promise.allSettled(ids.map((id) => del(id)));
  return {
    ok: results.filter((r) => r.status === "fulfilled").length,
    failed: results.filter((r) => r.status === "rejected").length,
  };
}

function OnlineDot({ agent }: { agent: AgentRow }) {
  // The API derives `status` from lastSeenAt on every read (agent-status.ts),
  // so trust it rather than re-deriving liveness against a second threshold.
  const online = agent.status === "online";
  return (
    <span className={cn("flex items-center gap-1.5 text-xs", online ? "text-accent" : "text-danger")}>
      <span className={cn("inline-block h-1.5 w-1.5 rounded-full", online ? "bg-accent" : "bg-danger")} />
      {online ? "online" : "offline"}
    </span>
  );
}

const AGENT_OS_OPTIONS = [
  { id: "linux-amd64", label: "Linux · amd64", binary: "f0-deception-agent-linux-amd64", kind: "shell", note: "installs as a systemd service" },
  { id: "linux-arm64", label: "Linux · arm64", binary: "f0-deception-agent-linux-arm64", kind: "shell", note: "installs as a systemd service" },
  { id: "darwin-amd64", label: "macOS · Intel", binary: "f0-deception-agent-darwin-amd64", kind: "shell", note: "installs as a launchd agent" },
  { id: "darwin-arm64", label: "macOS · Apple Silicon", binary: "f0-deception-agent-darwin-arm64", kind: "shell", note: "installs as a launchd agent" },
  {
    id: "windows-amd64",
    label: "Windows · amd64",
    binary: "f0-deception-agent-windows-amd64.exe",
    kind: "powershell",
    note: "installs as a Windows service — run the one-liner from an elevated PowerShell",
  },
] as const;

function AddAgentDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const [bootstrap, setBootstrap] = useState<string | null>(null);
  const [managed, setManaged] = useState<EnrollmentTokenRow[]>([]);
  const [fresh, setFresh] = useState<{ id: string; token: string; label: string } | null>(null);
  const [label, setLabel] = useState("");
  const [expires, setExpires] = useState("");
  const [osId, setOsId] = useState<string>("linux-amd64");
  const [busy, setBusy] = useState(false);

  const reload = () => {
    api.getAgentBootstrap().then((b) => setBootstrap(b.enrollmentToken)).catch(() => {});
    api.listEnrollmentTokens().then(setManaged).catch(() => setManaged([]));
  };
  useEffect(() => {
    if (open) {
      setFresh(null);
      reload();
    }
  }, [open]);

  // The one-liner uses the freshly created token if there is one (older
  // managed tokens are hash-only server-side, so they can't be embedded);
  // otherwise the env bootstrap token.
  const token = fresh?.token ?? bootstrap;
  const tokenNote = fresh
    ? `using new token "${fresh.label}" (shown now — store it)`
    : bootstrap
      ? "using the F0_ENROLLMENT_TOKEN bootstrap value"
      : null;

  const origin = window.location.origin;
  const osOption = AGENT_OS_OPTIONS.find((o) => o.id === osId) ?? AGENT_OS_OPTIONS[0];
  const oneLiner = token
    ? osOption.kind === "powershell"
      ? `iwr -Uri ${origin}/api/v1/agent-releases/${osOption.binary} -Headers @{authorization='Bearer ${token}'} -OutFile ${osOption.binary}; ` +
        `.\\${osOption.binary} --server ${origin} --enroll ${token} --install`
      : `curl -fLO -H 'authorization: Bearer ${token}' ${origin}/api/v1/agent-releases/${osOption.binary} && ` +
        `chmod +x ${osOption.binary} && ` +
        `sudo ./${osOption.binary} --server ${origin} --enroll ${token} --install`
    : null;

  async function create() {
    if (!label.trim()) {
      toast.error("label is required");
      return;
    }
    setBusy(true);
    try {
      // Number("abc") is NaN, which is falsy — the field used to be dropped
      // silently and a NON-EXPIRING token was created instead.
      let hours: number | undefined;
      if (expires.trim()) {
        const n = Number(expires.trim());
        if (!Number.isInteger(n) || n < 1 || n > 8760) {
          toast.error("expiry must be a whole number of hours between 1 and 8760");
          setBusy(false);
          return;
        }
        hours = n;
      }
      const created = await api.createEnrollmentToken(label.trim(), hours);
      setFresh(created);
      setLabel("");
      setExpires("");
      toast.success(`enrollment token "${created.label}" created`);
      reload();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Terminal className="h-4 w-4 text-accent" /> Add an agent
          </DialogTitle>
          <DialogDescription>
            Pick the target platform, then run this on the honeypot host with
            administrator or root privileges — it downloads the agent, enrolls it,
            and installs it as a service.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted">Target OS</span>
              <Select value={osId} onValueChange={setOsId}>
                <SelectTrigger className="h-8 w-56">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {AGENT_OS_OPTIONS.map((o) => (
                    <SelectItem key={o.id} value={o.id}>
                      {o.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <span className="text-xs text-faint">{osOption.note}</span>
            </div>
          </div>
          {oneLiner ? (
            <div className="space-y-1.5">
              <div className="flex items-start gap-2 rounded-md border border-border bg-background p-3">
                <code className="min-w-0 flex-1 break-all font-mono text-xs text-accent">
                  {oneLiner}
                </code>
                <CopyButton value={oneLiner} label="copy one-liner" />
              </div>
              <p className="text-xs text-faint">{tokenNote}</p>
            </div>
          ) : (
            <p className="text-sm text-warning">
              No enrollment token available — create one below (or set
              F0_ENROLLMENT_TOKEN on the API).
            </p>
          )}

          <div className="space-y-2 border-t border-border pt-3">
            <p className="text-[11px] font-medium uppercase tracking-wider text-faint">
              new enrollment token (per-install, revocable)
            </p>
            <div className="flex flex-wrap items-center gap-2">
              <Input
                placeholder="label (e.g. dmz-host-01 install)"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                className="h-8 min-w-48 flex-1"
              />
              <Input
                placeholder="expires in hours (optional)"
                value={expires}
                onChange={(e) => setExpires(e.target.value)}
                className="h-8 w-44"
              />
              <Button size="sm" variant="outline" disabled={busy} onClick={() => void create()}>
                <Plus className="h-3.5 w-3.5" />
                {busy ? "creating…" : "create token"}
              </Button>
            </div>
          </div>

          <div className="space-y-1.5 border-t border-border pt-3">
            <p className="text-[11px] font-medium uppercase tracking-wider text-faint">
              managed tokens
            </p>
            {managed.length === 0 && (
              <p className="text-xs text-faint">None yet — per-install tokens you create appear here.</p>
            )}
            {managed.map((t) => (
              <div key={t.id} className="flex items-center gap-3 text-xs">
                <Badge variant="outline">{t.label}</Badge>
                <span className="text-muted">
                  {t.uses} use(s)
                  {t.lastUsedAt ? ` · last ${timeAgo(t.lastUsedAt)}` : ""}
                  {t.expiresAt ? ` · expires ${new Date(t.expiresAt).toLocaleDateString()}` : ""}
                </span>
                <ConfirmButton
                  label="delete"
                  className="ml-auto"
                  onConfirm={() =>
                    void api
                      .deleteEnrollmentToken(t.id)
                      .then(() => {
                        toast.success(`token "${t.label}" deleted`);
                        reload();
                      })
                      .catch((err: unknown) =>
                        toast.error(err instanceof Error ? err.message : String(err)),
                      )
                  }
                />
              </div>
            ))}
          </div>

          <p className="text-xs text-faint">
            The enrollment token authenticates the host once; the agent receives
            its own key at enrollment. Re-running with the same hostname re-keys
            the existing agent.
          </p>
        </div>
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
  const sel = useSelection();

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
        {sel.sel.size > 0 && (
          <SelectionBar
            count={sel.sel.size}
            label="delete keys"
            confirm={sel.confirm}
            setConfirm={sel.setConfirm}
            busy={busy}
            onClear={sel.clear}
            onDelete={() => {
              setBusy(true);
              void deleteMany([...sel.sel], (id) => api.deleteReleaseKey(id)).then((r) => {
                setBusy(false);
                if (r.failed > 0) toast.error(`${r.failed} key(s) failed to delete`);
                else toast.success(`${r.ok} key(s) deleted`);
                sel.clear();
                void reload();
              });
            }}
          />
        )}
        <label className="flex items-center gap-2 text-[11px] text-faint">
          <input
            type="checkbox"
            className="h-3 w-3 accent-accent"
            checked={(keys ?? []).length > 0 && (keys ?? []).every((k) => sel.sel.has(k.id))}
            onChange={() => sel.toggleAll((keys ?? []).map((k) => k.id))}
          />
          select all
        </label>
        {(keys ?? []).map((k) => (
          <div key={k.id} className="flex items-center gap-3 text-xs">
            <input
              type="checkbox"
              className="h-3 w-3 accent-accent"
              checked={sel.sel.has(k.id)}
              onChange={() => sel.toggle(k.id)}
            />
            <Badge variant="outline">{k.label}</Badge>
            <span className="font-mono text-faint">{k.id}</span>
            <span className="min-w-0 flex-1 truncate font-mono text-muted">{k.publicKey}</span>
            <CopyButton value={k.publicKey} label="copy embeddable public key" />
            <span className="shrink-0 text-faint">{new Date(k.createdAt).toLocaleDateString()}</span>
            <ConfirmButton
              label="delete"
              title="delete key (deployed agents keep their embedded public key)"
              onConfirm={() =>
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
            />
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
  const sel = useSelection();

  const [caps, setCaps] = useState<Capabilities | null>(null);

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
    // Host-dependent actions: an older API omits this, so treat it as
    // available rather than disabling a button that would have worked.
    api.getStatus().then((st) => setCaps(st.capabilities ?? null)).catch(() => {});
  }, []);

  const canBuild = caps?.buildReleases ?? true;
  const buildBlockedReason = caps?.reasons?.["buildReleases"];

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

  async function deleteSelected() {
    setBusy(true);
    const r = await deleteMany([...sel.sel], (f) => api.deleteRelease(f));
    setBusy(false);
    if (r.failed > 0) toast.error(`${r.failed} file(s) failed to delete`);
    else toast.success(`${r.ok} file(s) deleted`);
    sel.clear();
    void reload();
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
          <Button
            size="sm"
            variant="outline"
            disabled={busy || !canBuild}
            title={canBuild ? undefined : buildBlockedReason}
            onClick={() => void build()}
          >
            <Hammer className="h-3.5 w-3.5" />
            {busy ? "building…" : "build binaries"}
          </Button>
          {busy && (
            <span className="text-xs text-faint">cross-compiling 5 platforms, ~1 min</span>
          )}
          {!canBuild && buildBlockedReason && (
            <span className="text-xs text-faint">unavailable — {buildBlockedReason}</span>
          )}
        </div>
        {sel.sel.size > 0 && (
          <SelectionBar
            count={sel.sel.size}
            label="delete files"
            confirm={sel.confirm}
            setConfirm={sel.setConfirm}
            onDelete={() => void deleteSelected()}
            onClear={sel.clear}
            busy={busy}
            twoStep={false}
          />
        )}
        {files.length === 0 ? (
          <p className="text-xs text-faint">No release binaries found.</p>
        ) : (
          <>
            <label className="flex items-center gap-2 text-[11px] text-faint">
              <input
                type="checkbox"
                className="h-3 w-3 accent-accent"
                checked={files.every((f) => sel.sel.has(f.filename))}
                onChange={() => sel.toggleAll(files.map((f) => f.filename))}
              />
              select all
            </label>
            {files.map((f) => (
              <div key={f.filename} className="flex items-center justify-between text-sm">
                <span className="flex items-center gap-2 font-mono text-xs">
                  <input
                    type="checkbox"
                    className="h-3 w-3 accent-accent"
                    checked={sel.sel.has(f.filename)}
                    onChange={() => sel.toggle(f.filename)}
                  />
                  {f.filename}
                </span>
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
                  <ConfirmButton
                    label="delete"
                    title={`delete ${f.filename}`}
                    onConfirm={() =>
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
                  />
                </span>
              </div>
            ))}
          </>
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
  const sel = useSelection();

  const [caps, setCaps] = useState<Capabilities | null>(null);
  // Two different tools: signing a binary needs osslsigncode, while
  // generating or importing a certificate only needs openssl. Gating both
  // on osslsigncode left "generate" enabled on a host without openssl,
  // where it failed with "spawn openssl ENOENT".
  const canSign = caps?.codeSigning ?? true;
  const signBlockedReason = caps?.reasons?.["codeSigning"];
  const canManageCerts = caps?.releaseSigning ?? true;
  const certBlockedReason = caps?.reasons?.["releaseSigning"];

  const reload = () => api.listCodeSignCerts().then(setCerts).catch(() => setCerts([]));
  useEffect(() => {
    api.getStatus().then((st) => setCaps(st.capabilities ?? null)).catch(() => {});
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
          {!canSign && signBlockedReason && (
            <span className="mt-1.5 block text-danger">
              Signing is unavailable here — {signBlockedReason}.
            </span>
          )}
          {!canManageCerts && certBlockedReason && (
            <span className="mt-1.5 block text-danger">
              Certificate generation and import are unavailable here — {certBlockedReason}.
            </span>
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {sel.sel.size > 0 && (
          <SelectionBar
            count={sel.sel.size}
            label="delete certs"
            confirm={sel.confirm}
            setConfirm={sel.setConfirm}
            busy={busy}
            onClear={sel.clear}
            onDelete={() => {
              setBusy(true);
              void deleteMany([...sel.sel], (id) => api.deleteCodeSignCert(id)).then((r) => {
                setBusy(false);
                if (r.failed > 0) toast.error(`${r.failed} cert(s) failed to delete`);
                else toast.success(`${r.ok} cert(s) deleted`);
                sel.clear();
                void reload();
              });
            }}
          />
        )}
        <label className="flex items-center gap-2 text-[11px] text-faint">
          <input
            type="checkbox"
            className="h-3 w-3 accent-accent"
            checked={(certs ?? []).length > 0 && (certs ?? []).every((c) => sel.sel.has(c.id))}
            onChange={() => sel.toggleAll((certs ?? []).map((c) => c.id))}
          />
          select all
        </label>
        {(certs ?? []).map((c) => (
          <div key={c.id} className="flex items-center gap-3 text-xs">
            <input
              type="checkbox"
              className="h-3 w-3 accent-accent"
              checked={sel.sel.has(c.id)}
              onChange={() => sel.toggle(c.id)}
            />
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
              disabled={busy || !canSign}
              title={canSign ? undefined : signBlockedReason}
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
            <ConfirmButton
              label="delete"
              busy={busy}
              onConfirm={() => void run(() => api.deleteCodeSignCert(c.id), `cert "${c.label}" deleted`)}
            />
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
              disabled={busy || !canManageCerts || !label.trim() || !cn.trim() || genPass.length < 4}
              title={canManageCerts ? undefined : certBlockedReason}
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
            {/* `cn` here is the Common Name state, not the class helper. */}
            <label
              className={
                canManageCerts
                  ? "inline-flex cursor-pointer items-center gap-2"
                  : "inline-flex cursor-not-allowed items-center gap-2 opacity-50"
              }
              title={canManageCerts ? undefined : certBlockedReason}
            >
              <input
                type="file"
                accept=".p12,.pfx,application/x-pkcs12"
                className="hidden"
                disabled={busy || !canManageCerts}
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

// token_id is deliberately absent here: every sensor needs one, and the API
// provisions it when a row arrives without one. It lives behind the per-row
// "token:" disclosure for the case where several sensors should share a token.
const SENSOR_KINDS = [
  { id: "ssh", fields: ["port"] },
  { id: "http_login", fields: ["port"] },
  { id: "smb", fields: ["port"] },
  { id: "rdp", fields: ["port"] },
  { id: "planted_credential", fields: ["path", "label"] },
  { id: "file_watch", fields: ["path", "label"] },
] as const;

// Server personas the agent ships (agent/internal/sensors/persona.go is the
// authority). An id the agent does not know falls back to its default and is
// logged, so a stale entry here costs a missing menu option, never a dead
// sensor. Deliberately not shared via packages/shared: a list that degrades
// when it drifts beats one that lies.
const SENSOR_PERSONAS = [
  "windows-server-2019",
  "windows-server-2022",
  "windows-11",
  "samba-ubuntu-2204",
] as const;

/** Sensor kinds whose advertised server identity is configurable. */
const IDENTITY_KINDS = new Set(["smb", "rdp"]);

type SensorField = (typeof SENSOR_KINDS)[number]["fields"][number];

function fieldsFor(kind: string): readonly SensorField[] {
  return SENSOR_KINDS.find((k) => k.id === kind)?.fields ?? ["port"];
}

/** Render a sensor's config for the read-only list. */
function sensorSummary(config: Record<string, unknown>): string {
  const bits: string[] = [];
  if (config["port"] !== undefined && config["port"] !== null) bits.push(`port ${String(config["port"])}`);
  if (config["path"]) bits.push(String(config["path"]));
  if (config["label"]) bits.push(`“${String(config["label"])}”`);
  return bits.join(" · ");
}

interface SensorRowState {
  kind: string;
  enabled: boolean;
  port: string;
  path: string;
  label: string;
  token_id: string;
  persona: string;
  domain: string;
  hostname: string;
  /** UI-only: whether this row's token override is expanded. */
  advanced: boolean;
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
      persona: String(s.config["persona"] ?? ""),
      domain: String(s.config["domain"] ?? ""),
      hostname: String(s.config["hostname"] ?? ""),
      advanced: false,
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
            persona: r.persona || undefined,
            domain: r.domain || undefined,
            hostname: r.hostname || undefined,
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
        <div key={i} className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
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
            <div className="flex items-center gap-1.5">
              <Switch checked={r.enabled} onCheckedChange={(v) => update(i, { enabled: v })} />
            </div>
            <Button
              variant="ghost"
              size="sm"
              className="font-mono text-xs text-faint"
              aria-expanded={r.advanced}
              onClick={() => update(i, { advanced: !r.advanced })}
            >
              {r.advanced ? "▾" : "▸"} token: {r.token_id || "auto"}
            </Button>
            <Button variant="ghost" size="sm" className="text-danger hover:text-danger" onClick={() => setRows(rows.filter((_, j) => j !== i))}>
              remove
            </Button>
          </div>
          {r.advanced && (
            <div className="flex flex-wrap items-center gap-2 pl-2 text-xs text-faint">
              <span>reports to</span>
              <Input
                placeholder="auto"
                value={r.token_id}
                onChange={(e) => update(i, { token_id: e.target.value })}
                className="h-7 w-40 font-mono text-xs"
              />
              <span>
                {r.token_id
                  ? "existing token — several sensors may share one"
                  : "a honeypot token is created for this sensor on save"}
              </span>
            </div>
          )}
          {r.advanced && IDENTITY_KINDS.has(r.kind) && (
            <div className="flex flex-wrap items-center gap-2 pl-2 text-xs text-faint">
              <span>advertises as</span>
              <select
                value={r.persona}
                onChange={(e) => update(i, { persona: e.target.value })}
                className={`${selectClass} h-7 w-48 text-xs`}
              >
                <option value="">windows-server-2019 (default)</option>
                {SENSOR_PERSONAS.map((p) => (
                  <option key={p} value={p}>{p}</option>
                ))}
              </select>
              <Input
                placeholder="WORKGROUP"
                value={r.domain}
                onChange={(e) => update(i, { domain: e.target.value })}
                className="h-7 w-32 font-mono text-xs"
              />
              <Input
                placeholder="(agent hostname)"
                value={r.hostname}
                onChange={(e) => update(i, { hostname: e.target.value })}
                className="h-7 w-40 font-mono text-xs"
              />
              <span>set the domain to blend into a real AD estate</span>
            </div>
          )}
        </div>
      ))}
      <div className="flex gap-2 pt-1">
        <Button
          variant="outline"
          size="sm"
          onClick={() =>
            setRows([
              ...rows,
              {
                kind: "http_login",
                enabled: true,
                port: "",
                path: "",
                label: "",
                token_id: "",
                persona: "",
                domain: "",
                hostname: "",
                advanced: false,
              },
            ])
          }
        >
          + add sensor
        </Button>
        {rows.length === 0 ? (
          // Saving an empty set replaces the agent's whole sensor config,
          // silently disabling every honeypot on that host. Make it a
          // deliberate act rather than a stray click.
          <ConfirmButton
            label="remove all sensors"
            confirmLabel="confirm — disables every sensor on this agent"
            busy={busy}
            onConfirm={() => void save()}
          />
        ) : (
          <Button size="sm" disabled={busy} onClick={() => void save()}>
            {busy ? "deploying…" : "save & deploy"}
          </Button>
        )}
      </div>
    </div>
  );
}

function DeployTokenSection({ agentId }: { agentId: string }) {
  const [tokens, setTokens] = useState<TokenRow[]>([]);
  const [deployments, setDeployments] = useState<DeploymentRow[]>([]);
  const [tokenId, setTokenId] = useState("");
  const [targetDir, setTargetDir] = useState("/tmp/f0-tokens");
  const [busy, setBusy] = useState(false);

  const reload = () => api.listAgentDeployments(agentId).then(setDeployments).catch(() => {});

  // Deployments complete on the agent's next heartbeat, but the list only
  // refreshed on a manual click — so rows sat at "pending" indefinitely
  // even after the work was done. Poll while any row is still pending.
  const hasPending = deployments.some((d) => d.status === "pending");
  useEffect(() => {
    if (!hasPending) return;
    const t = setInterval(() => void reload(), 10_000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hasPending, agentId]);

  useEffect(() => {
    api
      .listTokens()
      .then((rows) => {
        const active = rows.filter((t) => t.status === "active");
        setTokens(active);
        if (active.length > 0) setTokenId((cur) => cur || active[0]!.id);
      })
      .catch(() => {});
    void reload();
  }, [agentId]);

  async function deploy() {
    if (!tokenId) return;
    setBusy(true);
    try {
      const r = await api.deployToAgent(agentId, tokenId, targetDir.trim() || "/tmp/f0-tokens");
      toast.success(`deployment ${r.id} queued — agent picks it up on the next heartbeat`);
      void reload();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <h3 className="text-xs font-medium uppercase tracking-wider text-faint">
          Deploy token to host
        </h3>
        <Button variant="ghost" size="icon" className="h-7 w-7" title="refresh deployments" onClick={() => void reload()}>
          <RefreshCw className="h-3.5 w-3.5" />
        </Button>
      </div>
      <div className="flex flex-wrap gap-2">
        <Select value={tokenId} onValueChange={setTokenId}>
          <SelectTrigger className="h-8 min-w-44 flex-1">
            <SelectValue placeholder="token…" />
          </SelectTrigger>
          <SelectContent>
            {tokens.map((t) => (
              <SelectItem key={t.id} value={t.id}>
                {t.type} · {t.memo ?? t.id}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Input
          value={targetDir}
          onChange={(e) => setTargetDir(e.target.value)}
          placeholder="/tmp/f0-tokens"
          className="h-8 w-44 font-mono text-xs"
        />
        <Button size="sm" disabled={busy || !tokenId} onClick={() => void deploy()}>
          <DownloadCloud className="h-3.5 w-3.5" />
          {busy ? "queuing…" : "deploy"}
        </Button>
      </div>
      {deployments.length === 0 ? (
        <p className="text-xs text-faint">
          No deployments yet — artifacts land on the next heartbeat.
        </p>
      ) : (
        <div className="space-y-1.5">
          {deployments.map((d) => (
            <div key={d.id} className="flex items-center gap-2.5 text-xs">
              <Badge variant="outline" className="font-mono">
                {d.kind}
              </Badge>
              <span className="min-w-0 flex-1 truncate font-mono">{d.filename}</span>
              <span className="max-w-40 truncate text-muted">{d.targetDir}</span>
              {d.status === "done" ? (
                <Badge variant="accent">done</Badge>
              ) : d.status === "failed" ? (
                <Badge variant="high" title={d.error ?? ""}>
                  failed
                </Badge>
              ) : (
                <Badge variant="medium">pending</Badge>
              )}
            </div>
          ))}
        </div>
      )}
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
                    <span className="truncate text-xs text-faint">{sensorSummary(s.config)}</span>
                    <span className="ml-auto shrink-0 font-mono text-xs text-faint">
                      → {String(s.config["token_id"] ?? "no token")}
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

              <DeployTokenSection agentId={agent.id} />

              <Separator />

              <div className="space-y-2">
                <h3 className="text-xs font-medium uppercase tracking-wider text-faint">Danger zone</h3>
                {confirming ? (
                  <div className="space-y-3 rounded-md border border-danger/30 bg-danger-dim p-3">
                    <p className="text-xs text-foreground">
                      Retire <strong>{agent.hostname}</strong>? Its key stops working
                      immediately and past incidents are kept.
                    </p>
                    {/* Retiring is server-side only. Saying so plainly beats
                        letting an operator assume the host was cleaned up. */}
                    <p className="text-xs text-muted">
                      This does not uninstall anything. On its next heartbeat the agent
                      learns it was retired and shuts its sensors down, but the service
                      stays installed. To remove it, run on the host:
                    </p>
                    <code className="block rounded bg-overlay px-2 py-1 font-mono text-[11px] text-foreground">
                      {agent.platform.startsWith("windows")
                        ? "f0-deception-agent-windows-amd64.exe --uninstall"
                        : "sudo f0-deception-agent --uninstall"}
                    </code>
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
  const { data: agents, error, loading, reload } = usePoll<AgentRow[]>(() => api.listAgents());
  const [addOpen, setAddOpen] = useState(false);
  // Track the id, not the row object: the drawer must re-render from the
  // polled list after a mutation, or it keeps showing pre-save sensors and
  // leaves the memo save button enabled as though nothing landed.
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const sel = useSelection();
  const [bulkBusy, setBulkBusy] = useState(false);
  const list = agents ?? [];
  const selected = list.find((a) => a.id === selectedId) ?? null;

  async function retireSelected() {
    setBulkBusy(true);
    const r = await deleteMany([...sel.sel], (id) => api.deleteAgent(id));
    setBulkBusy(false);
    if (r.failed > 0) toast.error(`${r.failed} agent(s) failed to retire`);
    else toast.success(`${r.ok} agent(s) retired — sensors stop on next heartbeat; uninstall on the host`);
    sel.clear();
    void reload();
  }

  return (
    <section className="space-y-4">
      <PageHeader title="Agents" description="Honeypot fleet, sensors, and releases">
        <Button onClick={() => setAddOpen(true)}>
          <Plus className="h-4 w-4" />
          Add agent
        </Button>
      </PageHeader>
      {error && <p className="text-sm text-danger">{error}</p>}

      {sel.sel.size > 0 && (
        <SelectionBar
          count={sel.sel.size}
          label="retire permanently"
          confirm={sel.confirm}
          setConfirm={sel.setConfirm}
          onDelete={() => void retireSelected()}
          onClear={sel.clear}
          busy={bulkBusy}
        />
      )}

      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-8">
                <input
                  type="checkbox"
                  className="h-3.5 w-3.5 accent-accent"
                  checked={list.length > 0 && list.every((a) => sel.sel.has(a.id))}
                  onChange={() => sel.toggleAll(list.map((a) => a.id))}
                />
              </TableHead>
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
              <TableRow key={a.id} className="cursor-pointer" onClick={() => setSelectedId(a.id)}>
                <TableCell onClick={(e) => e.stopPropagation()}>
                  <input
                    type="checkbox"
                    className="h-3.5 w-3.5 accent-accent"
                    checked={sel.sel.has(a.id)}
                    onChange={() => sel.toggle(a.id)}
                  />
                </TableCell>
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
            {loading && !agents
              ? "Loading agents…"
              : "No agents enrolled — use Add agent to get an install one-liner."}
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
      <AgentDrawer agent={selected} onClose={() => setSelectedId(null)} onChanged={() => void reload()} />
    </section>
  );
}
