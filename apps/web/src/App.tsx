import { useCallback, useEffect, useState } from "react";
import { api, type Incident, type TokenRow, type AlertChannel, type AgentRow } from "./api.js";

const TOKEN_TYPES = [
  { id: "web_bug", label: "Web Bug", hint: "1x1 pixel URL" },
  { id: "dns", label: "DNS Token", hint: "unique hostname" },
  { id: "qr_code", label: "QR Code", hint: "scan-to-trigger" },
  { id: "fast_redirect", label: "Fast Redirect", hint: "requires target_url" },
  { id: "sensitive_cmd", label: "Sensitive Command", hint: "fake cmd output page" },
] as const;

type Tab = "dashboard" | "tokens" | "incidents" | "agents" | "channels";

export default function App() {
  const [tab, setTab] = useState<Tab>("dashboard");
  const [tokens, setTokens] = useState<TokenRow[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [channels, setChannels] = useState<AlertChannel[]>([]);
  const [agents, setAgents] = useState<AgentRow[]>([]);

  const refresh = useCallback(async () => {
    try {
      const [t, i, c, a] = await Promise.all([
        api.listTokens(),
        api.listIncidents(),
        api.listChannels().catch(() => [] as AlertChannel[]),
        api.listAgents().catch(() => [] as AgentRow[]),
      ]);
      setTokens(t);
      setIncidents(i);
      setChannels(c);
      setAgents(a);
    } catch (err) {
      console.error("failed to load console data:", err);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 15_000);
    return () => clearInterval(timer);
  }, [refresh]);

  return (
    <div className="min-h-screen bg-neutral-950 text-neutral-200">
      <header className="border-b border-neutral-800 px-6 py-4 flex items-center gap-8">
        <h1 className="text-lg font-semibold tracking-tight">
          f0<span className="text-amber-400">_</span>deception
        </h1>
        <nav className="flex gap-1 text-sm">
          {(
            [
              ["dashboard", "Dashboard"],
              ["tokens", "Tokens"],
              ["incidents", `Incidents${unacked(incidents) ? ` (${unacked(incidents)})` : ""}`],
              ["agents", `Agents (${agents.length})`],
              ["channels", "Alert Channels"],
            ] as [Tab, string][]
          ).map(([id, label]) => (
            <button
              key={id}
              onClick={() => setTab(id)}
              className={`px-3 py-1.5 rounded-md transition-colors ${
                tab === id
                  ? "bg-neutral-800 text-white"
                  : "text-neutral-400 hover:text-neutral-200"
              }`}
            >
              {label}
            </button>
          ))}
        </nav>
      </header>
      <main className="p-6 max-w-6xl mx-auto">
        {tab === "dashboard" && <Dashboard tokens={tokens} incidents={incidents} />}
        {tab === "tokens" && <TokensView tokens={tokens} onChange={refresh} />}
        {tab === "incidents" && <IncidentsView incidents={incidents} onChange={refresh} />}
        {tab === "channels" && <ChannelsView channels={channels} onChange={refresh} />}
        {tab === "agents" && <AgentsView agents={agents} onChange={refresh} />}
      </main>
    </div>
  );
}

function unacked(incidents: Incident[]): number {
  return incidents.filter((i) => !i.acknowledged).length;
}

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-5">
      <div className="text-3xl font-semibold">{value}</div>
      <div className="mt-1 text-sm text-neutral-400">{label}</div>
    </div>
  );
}

function Dashboard({ tokens, incidents }: { tokens: TokenRow[]; incidents: Incident[] }) {
  const last24h = incidents.filter(
    (i) => Date.now() - new Date(i.seenAt).getTime() < 86_400_000,
  );
  return (
    <section className="grid grid-cols-1 sm:grid-cols-3 gap-4">
      <Stat label="Active tokens" value={tokens.filter((t) => t.status === "active").length} />
      <Stat label="Incidents (24h)" value={last24h.length} />
      <Stat
        label="Unacknowledged"
        value={unacked(incidents)}
      />
    </section>
  );
}

function TokensView({ tokens, onChange }: { tokens: TokenRow[]; onChange: () => void }) {
  const [type, setType] = useState<string>("web_bug");
  const [memo, setMemo] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function create() {
    setError(null);
    const config: Record<string, unknown> = {};
    if (type === "fast_redirect") config["target_url"] = targetUrl;
    try {
      await api.createToken(type, memo || undefined, config);
      setMemo("");
      setTargetUrl("");
      onChange();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <section className="space-y-6">
      <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-5 space-y-3">
        <h2 className="font-medium">Create token</h2>
        <div className="flex flex-wrap gap-3 items-center">
          <select
            value={type}
            onChange={(e) => setType(e.target.value)}
            className="bg-neutral-800 border border-neutral-700 rounded-md px-3 py-2 text-sm"
          >
            {TOKEN_TYPES.map((t) => (
              <option key={t.id} value={t.id}>
                {t.label} — {t.hint}
              </option>
            ))}
          </select>
          {type === "fast_redirect" && (
            <input
              placeholder="https://target.example.com/"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              className="bg-neutral-800 border border-neutral-700 rounded-md px-3 py-2 text-sm w-72"
            />
          )}
          <input
            placeholder="memo (optional)"
            value={memo}
            onChange={(e) => setMemo(e.target.value)}
            className="bg-neutral-800 border border-neutral-700 rounded-md px-3 py-2 text-sm flex-1 min-w-48"
          />
          <button
            onClick={() => void create()}
            className="bg-amber-500 hover:bg-amber-400 text-black font-medium rounded-md px-4 py-2 text-sm"
          >
            Create
          </button>
        </div>
        {error && <p className="text-sm text-red-400">{error}</p>}
      </div>

      <table className="w-full text-sm">
        <thead className="text-left text-neutral-400 border-b border-neutral-800">
          <tr>
            <th className="py-2">Token ID</th>
            <th>Type</th>
            <th>Memo</th>
            <th>Status</th>
            <th>Created</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {tokens.map((t) => (
            <tr key={t.id} className="border-b border-neutral-900 hover:bg-neutral-900/50">
              <td className="py-2 font-mono text-xs">{t.id}</td>
              <td>{t.type}</td>
              <td className="text-neutral-400">{t.memo ?? "—"}</td>
              <td>
                <span
                  className={
                    t.status === "active"
                      ? "text-green-400"
                      : t.status === "paused"
                        ? "text-yellow-400"
                        : "text-red-400"
                  }
                >
                  {t.status}
                </span>
              </td>
              <td className="text-neutral-400">{new Date(t.createdAt).toLocaleString()}</td>
              <td className="text-right">
                {t.status !== "revoked" && (
                  <button
                    onClick={() => void api.revokeToken(t.id).then(onChange)}
                    className="text-red-400 hover:text-red-300 text-xs"
                  >
                    revoke
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

const SEVERITY_COLOR = {
  high: "text-red-400",
  medium: "text-yellow-400",
  low: "text-neutral-400",
} as const;

function IncidentsView({ incidents, onChange }: { incidents: Incident[]; onChange: () => void }) {
  return (
    <section className="space-y-2">
      {incidents.length === 0 && (
        <p className="text-neutral-500 text-sm">No incidents recorded yet.</p>
      )}
      {incidents.map((i) => (
        <div
          key={i.id}
          className={`rounded-lg border p-4 flex items-center justify-between gap-4 ${
            i.acknowledged
              ? "border-neutral-900 bg-neutral-950 opacity-60"
              : "border-neutral-800 bg-neutral-900"
          }`}
        >
          <div className="min-w-0">
            <div className="flex items-center gap-3">
              <span className={`font-mono text-xs uppercase ${SEVERITY_COLOR[i.severity]}`}>
                {i.severity}
              </span>
              <span className="text-sm font-medium">{i.tokenType ?? "token"}</span>
              <span className="font-mono text-xs text-neutral-500">{i.tokenId}</span>
            </div>
            <div className="mt-1 text-xs text-neutral-400 truncate">
              {i.event.kind === "dns" && i.event.dns
                ? `DNS ${i.event.dns.queryName} (${i.event.dns.queryType})`
                : i.event.http
                  ? `${i.event.http.method} ${i.event.http.host}${i.event.http.path}`
                  : i.event.kind}
            </div>
          </div>
          <div className="flex items-center gap-4 shrink-0 text-xs text-neutral-400">
            <span title={i.event.sourceIp}>{i.event.sourceIp}</span>
            <span>{new Date(i.seenAt).toLocaleString()}</span>
            {!i.acknowledged && (
              <button
                onClick={() => void api.ackIncident(i.id).then(onChange)}
                className="border border-neutral-700 hover:border-neutral-500 rounded px-2 py-1"
              >
                ack
              </button>
            )}
          </div>
        </div>
      ))}
    </section>
  );
}

function AgentsView({ agents, onChange }: { agents: AgentRow[]; onChange: () => void }) {
  const [editing, setEditing] = useState<string | null>(null);

  return (
    <section className="space-y-4">
      {agents.length === 0 && (
        <p className="text-neutral-500 text-sm">
          No agents enrolled. Run the agent with{" "}
          <code className="text-neutral-300">--server &lt;api-url&gt; --enroll &lt;token&gt;</code>.
        </p>
      )}
      {agents.map((a) => {
        const online =
          a.status === "online" &&
          a.lastSeenAt !== null &&
          Date.now() - new Date(a.lastSeenAt).getTime() < 180_000;
        return (
          <div key={a.id} className="rounded-lg border border-neutral-800 bg-neutral-900 p-5 space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <span className="font-medium">{a.hostname}</span>{" "}
                <span
                  className={`ml-2 text-xs ${online ? "text-green-400" : "text-red-400"}`}
                >
                  {online ? "● online" : "● offline"}
                </span>
              </div>
              <span className="text-xs text-neutral-400">
                {a.platform} · v{a.version} · last seen{" "}
                {a.lastSeenAt ? new Date(a.lastSeenAt).toLocaleString() : "never"}
              </span>
            </div>

            <div className="space-y-1">
              {a.sensors.map((s) => (
                <div key={s.id} className="flex items-center gap-3 text-sm text-neutral-300">
                  <span className={s.enabled ? "text-amber-400" : "text-neutral-600"}>
                    {s.enabled ? "▶" : "■"}
                  </span>
                  <span className="font-mono">{s.kind}</span>
                  <span className="font-mono text-xs text-neutral-500">
                    {JSON.stringify(s.config)}
                  </span>
                </div>
              ))}
              {a.sensors.length === 0 && (
                <p className="text-xs text-neutral-500">No sensors configured.</p>
              )}
            </div>

            <button
              onClick={() => setEditing(editing === a.id ? null : a.id)}
              className="text-xs border border-neutral-700 hover:border-neutral-500 rounded px-2 py-1"
            >
              {editing === a.id ? "close editor" : "edit sensors"}
            </button>
            {editing === a.id && (
              <SensorEditor
                agentId={a.id}
                initial={a.sensors}
                onDone={() => {
                  setEditing(null);
                  onChange();
                }}
              />
            )}
          </div>
        );
      })}
    </section>
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

function SensorEditor({
  agentId,
  initial,
  onDone,
}: {
  agentId: string;
  initial: { kind: string; enabled: boolean; config: Record<string, unknown> }[];
  onDone: () => void;
}) {
  const [rows, setRows] = useState(
    initial.map((s) => ({ kind: s.kind, enabled: s.enabled, port: String(s.config["port"] ?? ""), token_id: String(s.config["token_id"] ?? "") })),
  );
  const [error, setError] = useState<string | null>(null);

  function update(i: number, patch: Partial<(typeof rows)[number]>) {
    setRows(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  }

  async function save() {
    setError(null);
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
      onDone();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <div className="border border-neutral-800 rounded-md p-4 space-y-2 bg-neutral-950">
      {rows.map((r, i) => (
        <div key={i} className="flex flex-wrap gap-2 items-center">
          <select
            value={r.kind}
            onChange={(e) => update(i, { kind: e.target.value })}
            className="bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm w-44"
          >
            {SENSOR_KINDS.map((k) => (
              <option key={k.id}>{k.id}</option>
            ))}
          </select>
          {fieldsFor(r.kind).includes("port") && (
            <input placeholder="port" value={r.port} onChange={(e) => update(i, { port: e.target.value })}
              className="bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm w-20" />
          )}
          {fieldsFor(r.kind).includes("path") && (
            <input placeholder="/absolute/path" value={r.path} onChange={(e) => update(i, { path: e.target.value })}
              className="bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm flex-1 min-w-40" />
          )}
          {fieldsFor(r.kind).includes("label") && (
            <input placeholder="label" value={r.label} onChange={(e) => update(i, { label: e.target.value })}
              className="bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm w-32" />
          )}
          {fieldsFor(r.kind).includes("token_id") && (
            <input placeholder="token id" value={r.token_id} onChange={(e) => update(i, { token_id: e.target.value })}
              className="bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm w-36" />
          )}
          <label className="text-xs flex items-center gap-1">
            <input
              type="checkbox"
              checked={r.enabled}
              onChange={(e) => update(i, { enabled: e.target.checked })}
            />
            enabled
          </label>
          <button onClick={() => setRows(rows.filter((_, j) => j !== i))} className="text-red-400 text-xs">
            remove
          </button>
        </div>
      ))}
      <div className="flex gap-2">
        <button
          onClick={() => setRows([...rows, { kind: "http_login", enabled: true, port: "", path: "", label: "", token_id: "" }])}
          className="text-xs border border-neutral-700 hover:border-neutral-500 rounded px-2 py-1"
        >
          + add sensor
        </button>
        <button
          onClick={() => void save()}
          className="bg-amber-500 hover:bg-amber-400 text-black font-medium rounded px-3 py-1 text-xs"
        >
          save &amp; deploy
        </button>
      </div>
      {error && <p className="text-xs text-red-400">{error}</p>}
    </div>
  );
}

function ChannelsView({ channels, onChange }: { channels: AlertChannel[]; onChange: () => void }) {
  const [kind, setKind] = useState("webhook");
  const [url, setUrl] = useState("");
  const [host, setHost] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function create() {
    setError(null);
    const config =
      kind === "webhook"
        ? { url }
        : kind === "syslog"
          ? { host, port: 514 }
          : { url }; // elasticsearch / loki take a url too
    try {
      await api.createChannel(kind, config);
      setUrl("");
      setHost("");
      onChange();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <section className="space-y-6">
      <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-5 space-y-3">
        <h2 className="font-medium">Add alert channel</h2>
        <div className="flex flex-wrap gap-3">
          <select
            value={kind}
            onChange={(e) => setKind(e.target.value)}
            className="bg-neutral-800 border border-neutral-700 rounded-md px-3 py-2 text-sm"
          >
            <option value="webhook">Webhook</option>
            <option value="syslog">Syslog (UDP)</option>
            <option value="elasticsearch">Elasticsearch</option>
            <option value="loki">Grafana Loki</option>
          </select>
          {kind === "syslog" ? (
            <input
              placeholder="siem host"
              value={host}
              onChange={(e) => setHost(e.target.value)}
              className="bg-neutral-800 border border-neutral-700 rounded-md px-3 py-2 text-sm flex-1 min-w-64"
            />
          ) : (
            <input
              placeholder="http(s):// endpoint url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="bg-neutral-800 border border-neutral-700 rounded-md px-3 py-2 text-sm flex-1 min-w-64"
            />
          )}
          <button
            onClick={() => void create()}
            className="bg-amber-500 hover:bg-amber-400 text-black font-medium rounded-md px-4 py-2 text-sm"
          >
            Add
          </button>
        </div>
        {error && <p className="text-sm text-red-400">{error}</p>}
      </div>
      <ul className="space-y-2">
        {channels.map((c) => (
          <li
            key={c.id}
            className="rounded-lg border border-neutral-800 bg-neutral-900 px-4 py-3 flex items-center justify-between"
          >
            <div className="text-sm">
              <span className="font-medium">{c.kind}</span>{" "}
              <span className="font-mono text-xs text-neutral-500">{c.id}</span>
              {c.failureCount > 0 && (
                <span className="ml-2 text-red-400 text-xs">
                  {c.failureCount} failures
                </span>
              )}
            </div>
            <button
              onClick={() => void api.deleteChannel(c.id).then(onChange)}
              className="text-red-400 hover:text-red-300 text-xs"
            >
              delete
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}
