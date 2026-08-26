import { Fragment, useEffect, useState } from "react";
import { toast } from "sonner";
import { api, type Incident, type TokenRow } from "../api.js";
import { usePoll } from "@/lib/use-poll";
import { TOKEN_TYPES, tokenFields } from "@/lib/token-types";
import { incidentSummary } from "@/lib/incident";
import { PageHeader } from "@/components/layout/PageHeader";
import { SeverityBadge } from "@/components/SeverityBadge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

const selectClass =
  "h-9 rounded-md border border-border bg-raised px-3 text-sm text-foreground focus-visible:outline-2 focus-visible:outline-accent";

function StatusBadge({ status }: { status: string }) {
  if (status === "active") return <Badge variant="accent">active</Badge>;
  if (status === "paused") return <Badge variant="medium">paused</Badge>;
  return <Badge variant="high">revoked</Badge>;
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
    <div className="space-y-1">
      <p className="text-xs font-medium text-muted">
        {incidents.length} incident(s) for this token
      </p>
      {incidents.map((i) => {
        const { label, sourceIp } = incidentSummary(i);
        return (
          <div key={i.id} className="flex items-center gap-3 text-xs">
            <SeverityBadge severity={i.severity} />
            <span className="flex-1 truncate text-foreground">{label}</span>
            <span className="font-mono text-muted">{sourceIp}</span>
            <span className="text-faint">{new Date(i.seenAt).toLocaleString()}</span>
            {!i.acknowledged && (
              <Button
                variant="outline"
                size="sm"
                onClick={() =>
                  void api.ackIncident(i.id).then(() => {
                    api.tokenIncidents(tokenId).then(setIncidents);
                  })
                }
              >
                ack
              </Button>
            )}
          </div>
        );
      })}
    </div>
  );
}

function CreateTokenForm({ onCreated }: { onCreated: () => void }) {
  const [type, setType] = useState<string>("web_bug");
  const [memo, setMemo] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [decoyPath, setDecoyPath] = useState("");
  const [serverKind, setServerKind] = useState("nginx");
  const [cmdName, setCmdName] = useState("ifconfig");
  const [busy, setBusy] = useState(false);

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
      setMemo("");
      setTargetUrl("");
      toast.success(`Token ${t.id} created`);
      onCreated();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="space-y-3 p-5">
      <h2 className="text-sm font-semibold">Create token</h2>
      <div className="flex flex-wrap items-center gap-3">
        <select value={type} onChange={(e) => setType(e.target.value)} className={`${selectClass} w-72`}>
          {["Network", "Documents", "Cloud Decoys", "Agent"].map((group) => (
            <optgroup key={group} label={group}>
              {TOKEN_TYPES.filter((t) => t.group === group).map((t) => (
                <option key={t.id} value={t.id}>
                  {t.label} — {t.hint}
                </option>
              ))}
            </optgroup>
          ))}
        </select>
        {tokenFields(type).includes("target_url") && (
          <Input
            placeholder="https://target.example.com/"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            className="min-w-56 flex-1"
          />
        )}
        {tokenFields(type).includes("decoy_path") && (
          <Input
            placeholder="Decoy path (e.g. /search.php)"
            value={decoyPath}
            onChange={(e) => setDecoyPath(e.target.value)}
            className="w-56"
          />
        )}
        {tokenFields(type).includes("server_kind") && (
          <select value={serverKind} onChange={(e) => setServerKind(e.target.value)} className={selectClass}>
            <option value="nginx">nginx</option>
            <option value="apache">apache</option>
          </select>
        )}
        {tokenFields(type).includes("cmd_name") && (
          <select value={cmdName} onChange={(e) => setCmdName(e.target.value)} className={selectClass}>
            <option value="ifconfig">ifconfig</option>
            <option value="ipconfig">ipconfig</option>
            <option value="whoami">whoami</option>
            <option value="cat_etc_shadow">cat /etc/shadow</option>
          </select>
        )}
        <Input
          placeholder="memo (optional)"
          value={memo}
          onChange={(e) => setMemo(e.target.value)}
          className="min-w-48 flex-1"
        />
        <Button onClick={() => void create()} disabled={busy}>
          {busy ? "creating…" : "Create"}
        </Button>
      </div>
    </Card>
  );
}

export function TokensPage() {
  const { data: tokens, error, reload } = usePoll<TokenRow[]>(() => api.listTokens());
  const [historyFor, setHistoryFor] = useState<string | null>(null);

  return (
    <section className="space-y-6">
      <PageHeader title="Tokens" description="Create, plant, and manage canarytokens" />
      {error && <p className="text-sm text-danger">{error}</p>}
      <CreateTokenForm onCreated={() => void reload()} />
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
              <TableHead />
            </TableRow>
          </TableHeader>
          <TableBody>
            {(tokens ?? []).map((t) => (
              <Fragment key={t.id}>
                <TableRow>
                  <TableCell className="font-mono text-xs">{t.id}</TableCell>
                  <TableCell>{t.type}</TableCell>
                  <TableCell className="text-muted">{t.memo ?? "—"}</TableCell>
                  <TableCell className={t.hitCount ? "font-medium text-accent" : "text-faint"}>
                    {t.hitCount ?? 0}
                  </TableCell>
                  <TableCell>
                    <StatusBadge status={t.status} />
                  </TableCell>
                  <TableCell className="text-muted">{new Date(t.createdAt).toLocaleString()}</TableCell>
                  <TableCell className="text-right">
                    <Button
                      variant="outline"
                      size="sm"
                      className="mr-2"
                      onClick={() => setHistoryFor(historyFor === t.id ? null : t.id)}
                    >
                      history
                    </Button>
                    {t.status !== "revoked" && (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-danger hover:text-danger"
                        onClick={() =>
                          void api
                            .revokeToken(t.id)
                            .then(() => {
                              toast.success(`Token ${t.id} revoked`);
                              void reload();
                            })
                            .catch((err: unknown) =>
                              toast.error(err instanceof Error ? err.message : String(err)),
                            )
                        }
                      >
                        revoke
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
                {historyFor === t.id && (
                  <TableRow className="hover:bg-transparent">
                    <TableCell colSpan={7} className="bg-background px-4 py-3">
                      <TokenIncidents tokenId={t.id} />
                    </TableCell>
                  </TableRow>
                )}
              </Fragment>
            ))}
          </TableBody>
        </Table>
        {(tokens ?? []).length === 0 && (
          <p className="p-5 text-sm text-faint">No tokens yet — create one above.</p>
        )}
      </Card>
    </section>
  );
}
