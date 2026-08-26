import { useEffect, useMemo, useState } from "react";
import { CheckCheck, Search } from "lucide-react";
import { toast } from "sonner";
import { api, type Incident } from "../api.js";
import { usePoll } from "@/lib/use-poll";
import { geoLabel, geoTitle, incidentSummary } from "@/lib/incident";
import { TOKEN_TYPES } from "@/lib/token-types";
import { PageHeader } from "@/components/layout/PageHeader";
import { SeverityBadge } from "@/components/SeverityBadge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

function NotesEditor({ incident, onSaved }: { incident: Incident; onSaved: () => void }) {
  const [value, setValue] = useState(incident.notes ?? "");
  const [busy, setBusy] = useState(false);
  const dirty = value !== (incident.notes ?? "");
  return (
    <div className="mt-2 space-y-2" onClick={(e) => e.stopPropagation()}>
      <Textarea
        value={value}
        onChange={(e) => setValue(e.target.value)}
        placeholder="triage notes…"
        rows={2}
        className="text-xs"
      />
      {dirty && (
        <Button
          size="sm"
          disabled={busy}
          onClick={() => {
            setBusy(true);
            void api
              .setIncidentNotes(incident.id, value.trim() === "" ? null : value)
              .then(onSaved)
              .then(() => toast.success("Notes saved"))
              .catch((err: unknown) =>
                toast.error(err instanceof Error ? err.message : String(err)),
              )
              .finally(() => setBusy(false));
          }}
        >
          {busy ? "saving…" : "save notes"}
        </Button>
      )}
    </div>
  );
}

export function IncidentsPage() {
  const [severity, setSeverity] = useState("all");
  const [type, setType] = useState("all");
  const [acked, setAcked] = useState("all");
  const [search, setSearch] = useState("");
  const [q, setQ] = useState("");

  // Debounce the free-text filter (server matches raw event JSON).
  useEffect(() => {
    const t = setTimeout(() => setQ(search.trim()), 300);
    return () => clearTimeout(t);
  }, [search]);

  const { data: incidents, error, reload } = usePoll<Incident[]>(() =>
    api.listIncidents({
      severity: severity === "all" ? undefined : severity,
      type: type === "all" ? undefined : type,
      acknowledged: acked === "all" ? undefined : acked,
      q: q || undefined,
    }),
  );

  // Refetch immediately when a filter changes (the 15s interval continues).
  useEffect(() => {
    void reload();
  }, [severity, type, acked, q, reload]);

  const list = useMemo(() => incidents ?? [], [incidents]);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set());

  const selectable = list.filter((i) => !i.acknowledged);
  const allSelected = selectable.length > 0 && selectable.every((i) => selected.has(i.id));

  function toggleAll() {
    setSelected(allSelected ? new Set() : new Set(selectable.map((i) => i.id)));
  }

  function toggleOne(id: string) {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSelected(next);
  }

  async function bulkAck() {
    const ids = [...selected];
    try {
      const r = await api.bulkAckIncidents(ids);
      toast.success(`${r.updated} incident(s) acknowledged`);
      setSelected(new Set());
      void reload();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <section className="space-y-4">
      <PageHeader title="Incidents" description="Trigger events across tokens and sensors">
        {selected.size > 0 && (
          <Button onClick={() => void bulkAck()}>
            <CheckCheck className="h-4 w-4" />
            ack {selected.size} selected
          </Button>
        )}
      </PageHeader>
      {error && <p className="text-sm text-danger">{error}</p>}

      <div className="flex flex-wrap items-center gap-3">
        <div className="relative min-w-56 flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-faint" />
          <Input
            id="page-search"
            placeholder="search raw event (path, UA, DNS name)…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <Select value={severity} onValueChange={setSeverity}>
          <SelectTrigger className="w-36">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">all severities</SelectItem>
            <SelectItem value="high">high</SelectItem>
            <SelectItem value="medium">medium</SelectItem>
            <SelectItem value="low">low</SelectItem>
          </SelectContent>
        </Select>
        <Select value={type} onValueChange={setType}>
          <SelectTrigger className="w-44">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">all types</SelectItem>
            {TOKEN_TYPES.map((t) => (
              <SelectItem key={t.id} value={t.id}>
                {t.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={acked} onValueChange={setAcked}>
          <SelectTrigger className="w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">all states</SelectItem>
            <SelectItem value="false">unacknowledged</SelectItem>
            <SelectItem value="true">acknowledged</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {selectable.length > 0 && (
        <label className="flex items-center gap-2 text-xs text-muted">
          <input
            type="checkbox"
            className="h-3.5 w-3.5 accent-accent"
            checked={allSelected}
            onChange={toggleAll}
          />
          select all visible unacknowledged ({selectable.length})
        </label>
      )}

      {list.length === 0 && (
        <p className="text-sm text-faint">No incidents match the current filters.</p>
      )}
      {list.map((i) => {
        const { label, detail, sourceIp } = incidentSummary(i);
        const geo = geoLabel(i);
        const isOpen = expanded === i.id;
        return (
          <Card
            key={i.id}
            className={cn(
              "flex items-start justify-between gap-4 p-4",
              i.acknowledged && "opacity-55",
            )}
          >
            <div className="flex min-w-0 flex-1 items-start gap-3">
              {!i.acknowledged && (
                <input
                  type="checkbox"
                  className="mt-1 h-3.5 w-3.5 shrink-0 accent-accent"
                  checked={selected.has(i.id)}
                  onChange={() => toggleOne(i.id)}
                />
              )}
              <div className="min-w-0 flex-1 cursor-pointer" onClick={() => setExpanded(isOpen ? null : i.id)}>
                <div className="flex items-center gap-3">
                  <SeverityBadge severity={i.severity} />
                  <Badge variant="outline">{i.tokenType ?? "token"}</Badge>
                  <span className="font-mono text-xs text-faint">{i.tokenId}</span>
                </div>
                <div className="mt-1.5 truncate text-sm text-foreground">{label}</div>
                {detail && <div className="mt-0.5 truncate text-xs text-muted">{detail}</div>}
                {i.notes && !isOpen && (
                  <div className="mt-0.5 truncate text-xs text-warning/80">📝 {i.notes}</div>
                )}
                {isOpen && (
                  <>
                    <pre className="mt-3 overflow-x-auto rounded-md border border-border bg-background p-3 font-mono text-xs text-muted">
                      {JSON.stringify(i.event, null, 2)}
                    </pre>
                    <NotesEditor incident={i} onSaved={() => void reload()} />
                  </>
                )}
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-4 text-xs text-muted">
              <Tooltip>
                <TooltipTrigger asChild>
                  <span className="cursor-default font-mono">
                    {sourceIp}
                    {geo && <span className="text-faint"> · {geo}</span>}
                  </span>
                </TooltipTrigger>
                <TooltipContent>{geoTitle(i)}</TooltipContent>
              </Tooltip>
              <span>{new Date(i.seenAt).toLocaleString()}</span>
              {!i.acknowledged && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() =>
                    void api
                      .ackIncident(i.id)
                      .then(() => void reload())
                      .catch((err: unknown) =>
                        toast.error(err instanceof Error ? err.message : String(err)),
                      )
                  }
                >
                  ack
                </Button>
              )}
            </div>
          </Card>
        );
      })}
    </section>
  );
}
