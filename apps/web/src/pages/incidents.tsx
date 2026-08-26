import { useState } from "react";
import { toast } from "sonner";
import { api, type Incident } from "../api.js";
import { usePoll } from "@/lib/use-poll";
import { geoLabel, geoTitle, incidentSummary } from "@/lib/incident";
import { PageHeader } from "@/components/layout/PageHeader";
import { SeverityBadge } from "@/components/SeverityBadge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
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
  const { data: incidents, error, reload } = usePoll<Incident[]>(() => api.listIncidents());
  const [expanded, setExpanded] = useState<string | null>(null);
  const list = incidents ?? [];

  return (
    <section className="space-y-4">
      <PageHeader title="Incidents" description="Trigger events across tokens and sensors" />
      {error && <p className="text-sm text-danger">{error}</p>}
      {list.length === 0 && <p className="text-sm text-faint">No incidents recorded yet.</p>}
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
