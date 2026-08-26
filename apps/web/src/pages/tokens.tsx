import { useEffect, useMemo, useState } from "react";
import { FileDown, Globe, Link2, Plus, Search, Trash2, Upload } from "lucide-react";
import { toast } from "sonner";
import {
  api,
  type Incident,
  type TokenArtifact,
  type TokenDetail,
  type TokenRow,
} from "../api.js";
import { usePoll } from "@/lib/use-poll";
import { TOKEN_TYPES, tokenFields } from "@/lib/token-types";
import { incidentSummary } from "@/lib/incident";
import { PageHeader } from "@/components/layout/PageHeader";
import { CopyButton } from "@/components/CopyButton";
import { SeverityBadge } from "@/components/SeverityBadge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
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
  SelectGroup,
  SelectItem,
  SelectLabel,
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Separator } from "@/components/ui/separator";

function StatusBadge({ status }: { status: string }) {
  if (status === "active") return <Badge variant="accent">active</Badge>;
  if (status === "paused") return <Badge variant="medium">paused</Badge>;
  return <Badge variant="high">revoked</Badge>;
}

function ArtifactIcon({ kind }: { kind: string }) {
  if (kind === "file_download") return <FileDown className="h-3.5 w-3.5 text-muted" />;
  if (kind === "hostname") return <Globe className="h-3.5 w-3.5 text-muted" />;
  return <Link2 className="h-3.5 w-3.5 text-muted" />;
}

/** Artifact rows with copy/download affordances (create dialog + drawer). */
function ArtifactsList({ artifacts }: { artifacts: TokenArtifact[] }) {
  if (artifacts.length === 0)
    return <p className="text-xs text-faint">No artifacts for this token type.</p>;
  return (
    <div className="space-y-1.5">
      {artifacts.map((a, i) => (
        <div
          key={i}
          className="flex items-center gap-2 rounded-md border border-border bg-background px-2.5 py-2"
        >
          <ArtifactIcon kind={a.kind} />
          <span className="w-32 shrink-0 text-xs text-muted">{a.label}</span>
          <span className="min-w-0 flex-1 truncate font-mono text-xs">{a.value}</span>
          {a.kind === "file_download" ? (
            <a href={a.value} download onClick={(e) => e.stopPropagation()}>
              <Button variant="ghost" size="icon" className="h-7 w-7" title="download">
                <FileDown className="h-3.5 w-3.5" />
              </Button>
            </a>
          ) : (
            <CopyButton value={a.value} />
          )}
        </div>
      ))}
    </div>
  );
}

function CreateTokenDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: () => void;
}) {
  const [type, setType] = useState<string>("web_bug");
  const [memo, setMemo] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [decoyPath, setDecoyPath] = useState("");
  const [serverKind, setServerKind] = useState("nginx");
  const [cmdName, setCmdName] = useState("ifconfig");
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<{ id: string; artifacts: TokenArtifact[] } | null>(null);

  const typeInfo = TOKEN_TYPES.find((t) => t.id === type);

  function reset() {
    setCreated(null);
    setMemo("");
    setTargetUrl("");
    setDecoyPath("");
  }

  async function create() {
    const config: Record<string, unknown> = {};
    if (type === "fast_redirect" || type === "cloned_website") config["target_url"] = targetUrl;
    if (type === "sql_injection") {
      config["path"] = decoyPath || "/search.php";
      config["server_kind"] = serverKind;
    }
    if (type === "sensitive_cmd") config["cmd_name"] = cmdName;
    setBusy(true);
    try {
      const t = await api.createToken(type, memo || undefined, config);
      setCreated({ id: t.id, artifacts: t.artifacts ?? [] });
      toast.success(`Token ${t.id} created`);
      onCreated();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={(o) => { onOpenChange(o); if (!o) reset(); }}>
      <DialogContent>
        {created === null ? (
          <>
            <DialogHeader>
              <DialogTitle>New token</DialogTitle>
              <DialogDescription>
                Plant the artifact where an attacker will trip over it.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-3">
              <div className="space-y-1.5">
                <Label>Type</Label>
                <Select value={type} onValueChange={setType}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {["Network", "Documents", "Cloud Decoys", "Agent"].map((group) => (
                      <SelectGroup key={group}>
                        <SelectLabel>{group}</SelectLabel>
                        {TOKEN_TYPES.filter((t) => t.group === group).map((t) => (
                          <SelectItem key={t.id} value={t.id}>
                            {t.label}
                          </SelectItem>
                        ))}
                      </SelectGroup>
                    ))}
                  </SelectContent>
                </Select>
                {typeInfo && <p className="text-xs text-faint">{typeInfo.hint}</p>}
              </div>
              {tokenFields(type).includes("target_url") && (
                <div className="space-y-1.5">
                  <Label>Target URL</Label>
                  <Input
                    placeholder="https://target.example.com/"
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                  />
                </div>
              )}
              {tokenFields(type).includes("decoy_path") && (
                <div className="space-y-1.5">
                  <Label>Decoy path</Label>
                  <Input
                    placeholder="/search.php"
                    value={decoyPath}
                    onChange={(e) => setDecoyPath(e.target.value)}
                  />
                </div>
              )}
              {tokenFields(type).includes("server_kind") && (
                <div className="space-y-1.5">
                  <Label>Server kind</Label>
                  <Select value={serverKind} onValueChange={setServerKind}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="nginx">nginx</SelectItem>
                      <SelectItem value="apache">apache</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              )}
              {tokenFields(type).includes("cmd_name") && (
                <div className="space-y-1.5">
                  <Label>Command</Label>
                  <Select value={cmdName} onValueChange={setCmdName}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="ifconfig">ifconfig</SelectItem>
                      <SelectItem value="ipconfig">ipconfig</SelectItem>
                      <SelectItem value="whoami">whoami</SelectItem>
                      <SelectItem value="cat_etc_shadow">cat /etc/shadow</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              )}
              <div className="space-y-1.5">
                <Label>Memo (optional)</Label>
                <Input
                  placeholder="where this is planted"
                  value={memo}
                  onChange={(e) => setMemo(e.target.value)}
                />
              </div>
            </div>
            <DialogFooter>
              <Button onClick={() => void create()} disabled={busy}>
                {busy ? "creating…" : "Create token"}
              </Button>
            </DialogFooter>
          </>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle>
                Token <span className="font-mono text-accent">{created.id}</span> ready
              </DialogTitle>
              <DialogDescription>
                Deploy these artifacts — the URL/hostname ones copy to your clipboard.
              </DialogDescription>
            </DialogHeader>
            <ArtifactsList artifacts={created.artifacts} />
            <DialogFooter>
              <Button variant="outline" onClick={reset}>
                create another
              </Button>
              <Button onClick={() => onOpenChange(false)}>done</Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

function ImageUploadCard({ token, onUploaded }: { token: TokenDetail; onUploaded: () => void }) {
  const [busy, setBusy] = useState(false);
  const hasImage = (token.files ?? []).some((f) => f.contentType.startsWith("image/"));

  async function pick(file: File) {
    if (file.size > 4 * 1024 * 1024) {
      toast.error("image must be under 4 MiB");
      return;
    }
    setBusy(true);
    try {
      const dataUrl = await new Promise<string>((resolve, reject) => {
        const r = new FileReader();
        r.onload = () => resolve(String(r.result));
        r.onerror = () => reject(new Error("read failed"));
        r.readAsDataURL(file);
      });
      const b64 = dataUrl.split(",")[1] ?? "";
      await api.uploadTokenImage(token.id, {
        data: b64,
        contentType: file.type || "image/png",
        filename: file.name,
      });
      toast.success("image uploaded — gateway serves it at /<id>/image");
      onUploaded();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-2">
      <h3 className="text-xs font-medium uppercase tracking-wider text-faint">Custom image</h3>
      {hasImage && (
        <img
          src={`/api/v1/tokens/${token.id}/files/0`}
          alt="current bait"
          className="max-h-32 rounded-md border border-border"
        />
      )}
      <label className="inline-flex cursor-pointer items-center gap-2">
        <input
          type="file"
          accept="image/png,image/jpeg,image/gif,image/webp,image/avif,image/bmp"
          className="hidden"
          disabled={busy}
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) void pick(f);
            e.target.value = "";
          }}
        />
        <span className="inline-flex h-8 items-center gap-2 rounded-md border border-border bg-raised px-3 text-xs text-foreground hover:bg-overlay">
          <Upload className="h-3.5 w-3.5" />
          {busy ? "uploading…" : hasImage ? "replace image" : "upload image"}
        </span>
        <span className="text-xs text-faint">raster only, ≤ 4 MiB</span>
      </label>
    </div>
  );
}

function TokenIncidents({ tokenId }: { tokenId: string }) {
  const [incidents, setIncidents] = useState<Incident[] | null>(null);

  useEffect(() => {
    api
      .tokenIncidents(tokenId)
      .then(setIncidents)
      .catch(() => setIncidents([]));
  }, [tokenId]);

  if (incidents === null) return <p className="text-xs text-faint">loading…</p>;
  if (incidents.length === 0)
    return <p className="text-xs text-faint">No incidents for this token yet.</p>;
  return (
    <div className="space-y-1.5">
      {incidents.map((i) => {
        const { label, sourceIp } = incidentSummary(i);
        return (
          <div key={i.id} className="flex items-center gap-2.5 text-xs">
            <SeverityBadge severity={i.severity} />
            <span className="min-w-0 flex-1 truncate">{label}</span>
            <span className="font-mono text-muted">{sourceIp}</span>
            <span className="shrink-0 text-faint">{new Date(i.seenAt).toLocaleString()}</span>
          </div>
        );
      })}
    </div>
  );
}

function ConfirmDelete({
  token,
  onCancel,
  onConfirm,
  busy,
}: {
  token: TokenDetail;
  onCancel: () => void;
  onConfirm: () => void;
  busy: boolean;
}) {
  return (
    <div className="space-y-3 rounded-md border border-danger/30 bg-danger-dim p-3">
      <p className="text-xs text-foreground">
        Permanently delete token <span className="font-mono">{token.id}</span>, its files,
        and <strong>{token.hitCount ?? 0} incident(s)</strong>? This cannot be undone —
        revoke keeps history instead.
      </p>
      <div className="flex gap-2">
        <Button variant="destructive" size="sm" disabled={busy} onClick={onConfirm}>
          <Trash2 className="h-3.5 w-3.5" />
          {busy ? "deleting…" : "delete permanently"}
        </Button>
        <Button variant="outline" size="sm" onClick={onCancel}>
          cancel
        </Button>
      </div>
    </div>
  );
}

function TokenDrawer({
  tokenId,
  onClose,
  onChanged,
}: {
  tokenId: string | null;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [detail, setDetail] = useState<TokenDetail | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);

  const refresh = () => {
    if (tokenId) api.getToken(tokenId).then(setDetail).catch(() => setDetail(null));
  };
  useEffect(refresh, [tokenId]);
  useEffect(() => setConfirming(false), [tokenId]);

  async function act(fn: () => Promise<unknown>, done: string) {
    setBusy(true);
    try {
      await fn();
      toast.success(done);
      refresh();
      onChanged();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Sheet open={tokenId !== null} onOpenChange={(o) => !o && onClose()}>
      <SheetContent>
        {detail ? (
          <>
            <SheetHeader>
              <SheetTitle className="flex items-center gap-2">
                <Badge variant="outline">{detail.type}</Badge>
                <StatusBadge status={detail.status} />
              </SheetTitle>
              <SheetDescription className="flex items-center gap-1 font-mono text-xs">
                {detail.id} <CopyButton value={detail.id} label="copy token id" />
              </SheetDescription>
            </SheetHeader>
            <SheetBody className="space-y-5">
              <div className="text-xs text-muted">
                {detail.memo && <p className="mb-1 text-sm text-foreground">{detail.memo}</p>}
                created {new Date(detail.createdAt).toLocaleString()} · {detail.hitCount ?? 0} hit(s)
              </div>

              <div className="space-y-2">
                <h3 className="text-xs font-medium uppercase tracking-wider text-faint">Artifacts</h3>
                <ArtifactsList artifacts={detail.artifacts ?? []} />
              </div>

              {detail.type === "custom_image" && (
                <ImageUploadCard token={detail} onUploaded={() => { refresh(); onChanged(); }} />
              )}

              <Separator />

              <div className="space-y-2">
                <h3 className="text-xs font-medium uppercase tracking-wider text-faint">Actions</h3>
                <div className="flex flex-wrap gap-2">
                  {detail.status === "active" && (
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={busy}
                      onClick={() => void act(() => api.setTokenStatus(detail.id, "paused"), "token paused")}
                    >
                      pause
                    </Button>
                  )}
                  {detail.status === "paused" && (
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={busy}
                      onClick={() => void act(() => api.setTokenStatus(detail.id, "active"), "token resumed")}
                    >
                      resume
                    </Button>
                  )}
                  {detail.status !== "revoked" && (
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={busy}
                      onClick={() => void act(() => api.deleteToken(detail.id), "token revoked (history kept)")}
                    >
                      revoke
                    </Button>
                  )}
                </div>
                {confirming ? (
                  <ConfirmDelete
                    token={detail}
                    busy={busy}
                    onCancel={() => setConfirming(false)}
                    onConfirm={() =>
                      void act(async () => {
                        await api.deleteToken(detail.id, true);
                        onClose();
                      }, "token deleted with its history")
                    }
                  />
                ) : (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-danger hover:text-danger"
                    onClick={() => setConfirming(true)}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                    delete permanently…
                  </Button>
                )}
              </div>

              <Separator />

              <div className="space-y-2">
                <h3 className="text-xs font-medium uppercase tracking-wider text-faint">
                  Incident history
                </h3>
                <TokenIncidents tokenId={detail.id} />
              </div>
            </SheetBody>
          </>
        ) : (
          <SheetHeader>
            <SheetTitle>Loading…</SheetTitle>
          </SheetHeader>
        )}
      </SheetContent>
    </Sheet>
  );
}

export function TokensPage() {
  const { data: tokens, error, reload } = usePoll<TokenRow[]>(() => api.listTokens());
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [createOpen, setCreateOpen] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return (tokens ?? []).filter((t) => {
      if (statusFilter !== "all" && t.status !== statusFilter) return false;
      if (!q) return true;
      return (
        t.id.toLowerCase().includes(q) ||
        t.type.toLowerCase().includes(q) ||
        (t.memo ?? "").toLowerCase().includes(q)
      );
    });
  }, [tokens, search, statusFilter]);

  return (
    <section className="space-y-4">
      <PageHeader title="Tokens" description="Create, plant, and manage canarytokens">
        <Button onClick={() => setCreateOpen(true)}>
          <Plus className="h-4 w-4" />
          New token
        </Button>
      </PageHeader>
      {error && <p className="text-sm text-danger">{error}</p>}

      <div className="flex flex-wrap items-center gap-3">
        <div className="relative min-w-64 flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-faint" />
          <Input
            placeholder="search id, type, or memo…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">all statuses</SelectItem>
            <SelectItem value="active">active</SelectItem>
            <SelectItem value="paused">paused</SelectItem>
            <SelectItem value="revoked">revoked</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Token ID</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Memo</TableHead>
              <TableHead>Hits</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Created</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.map((t) => (
              <TableRow key={t.id} className="cursor-pointer" onClick={() => setSelected(t.id)}>
                <TableCell className="font-mono text-xs">{t.id}</TableCell>
                <TableCell>
                  <Badge variant="outline">{t.type}</Badge>
                </TableCell>
                <TableCell className="max-w-56 truncate text-muted">{t.memo ?? "—"}</TableCell>
                <TableCell className={t.hitCount ? "font-medium text-accent" : "text-faint"}>
                  {t.hitCount ?? 0}
                </TableCell>
                <TableCell>
                  <StatusBadge status={t.status} />
                </TableCell>
                <TableCell className="text-muted">{new Date(t.createdAt).toLocaleString()}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {filtered.length === 0 && (
          <p className="p-5 text-sm text-faint">
            {(tokens ?? []).length === 0 ? "No tokens yet — create one." : "No tokens match the filter."}
          </p>
        )}
      </Card>

      <CreateTokenDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={() => void reload()}
      />
      <TokenDrawer
        tokenId={selected}
        onClose={() => setSelected(null)}
        onChanged={() => void reload()}
      />
    </section>
  );
}
