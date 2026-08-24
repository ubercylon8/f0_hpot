import { Fragment, useCallback, useEffect, useState } from "react";
import { api, type Incident, type TokenRow, type AlertChannel, type AgentRow } from "./api.js";

const TOKEN_TYPES = [
  { id: "web_bug", label: "Web Bug", hint: "1x1 pixel URL", fields: [] },
  { id: "dns", label: "DNS Token", hint: "unique hostname", fields: [] },
  { id: "email", label: "Unique Email", hint: "trigger address (needs MX)", fields: [] },
  { id: "qr_code", label: "QR Code", hint: "scan-to-trigger", fields: [] },
  { id: "word_doc", label: "Word Document", hint: "remote-image .docx", fields: [] },
  { id: "excel_doc", label: "Excel Workbook", hint: "hyperlink .xlsx", fields: [] },
  { id: "pdf_doc", label: "PDF Document", hint: "open-action + link", fields: [] },
  { id: "windows_folder", label: "Windows Folder", hint: "DNS-resolving folder name", fields: [] },
  { id: "cloned_website", label: "Cloned Website", hint: "beaconed page clone", fields: ["target_url"] },
  { id: "sql_injection", label: "SQL Injection Canary", hint: "decoy endpoint rules", fields: ["decoy_path", "server_kind"] },
  { id: "sensitive_cmd", label: "Sensitive Command", hint: "fake cmd output page", fields: ["cmd_name"] },
  { id: "fast_redirect", label: "Fast Redirect", hint: "capture + 302", fields: ["target_url"] },
  { id: "aws_keys", label: "AWS Key Decoy", hint: "decoy credentials + wiring", fields: [] },
  { id: "azure_config", label: "Azure SP Decoy", hint: "decoy client-id/secret", fields: [] },
  { id: "honeypot", label: "Honeypot Link", hint: "reference token for agent sensors", fields: [] },
] as const;

type TokenField = "target_url" | "decoy_path" | "server_kind" | "cmd_name";

function tokenFields(type: string): readonly TokenField[] {
  return TOKEN_TYPES.find((t) => t.id === type)?.fields ?? [];
}

type Tab = "dashboard" | "tokens" | "incidents" | "agents" | "channels";

export default function App() {
  const [tab, setTab] = useState<Tab>("dashboard");
  const [tokens, setTokens] = useState<TokenRow[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [channels, setChannels] = useState<AlertChannel[]>([]);
  const [agents, setAgents] = useState<AgentRow[]>([]);

  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [fetchError, setFetchError] = useState<string | null>(null);

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
      setLastUpdated(new Date());
      setFetchError(null);
    } catch (err) {
      setFetchError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 5_000);
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
        <div className="ml-auto flex items-center gap-3 text-xs text-neutral-500">
          {fetchError && (
            <span className="text-red-400">⚠ {fetchError}</span>
          )}
          {lastUpdated && (
            <span>updated {lastUpdated.toLocaleTimeString()}</span>
          )}
          <button
            onClick={() => void refresh()}
            className="border border-neutral-700 hover:border-neutral-500 rounded px-2 py-1"
          >
            refresh
          </button>
        </div>
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

function TokenIncidents({ tokenId }: { tokenId: string }) {
  const [incidents, setIncidents] = useState<Incident[] | null>(null);

  useEffect(() => {
    api
      .tokenIncidents(tokenId)
      .then(setIncidents)
      .catch(() => setIncidents([]));
  }, [tokenId]);

  if (incidents === null) return <p className="text-xs text-neutral-500">loading…</p>;
  if (incidents.length === 0)
    return <p className="text-xs text-neutral-500">No incidents for this token yet.</p>;

  return (
    <div className="space-y-1">
      <p className="text-xs text-neutral-400 font-medium">
        {incidents.length} incident(s) for this token
      </p>
      {incidents.map((i) => {
        const { label, sourceIp } = incidentSummary(i);
        return (
          <div key={i.id} className="flex items-center gap-3 text-xs">
            <span className={`font-mono uppercase ${SEVERITY_COLOR[i.severity]}`}>
              {i.severity}
            </span>
            <span className="text-neutral-300 truncate flex-1">{label}</span>
            <span className="text-neutral-500">{sourceIp}</span>
            <span className="text-neutral-500">{new Date(i.seenAt).toLocaleString()}</span>
            {!i.acknowledged && (
              <button
                onClick={() => void api.ackIncident(i.id).then(() => {
                  api.tokenIncidents(tokenId).then(setIncidents);
                })}
                className="border border-neutral-700 hover:border-neutral-500 rounded px-1.5"
              >
                ack
              </button>
            )}
          </div>
        );
      })}
    </div>
  );
}

function TokensView({ tokens, onChange }: { tokens: TokenRow[]; onChange: () => void }) {
  const [type, setType] = useState<string>("web_bug");
  const [memo, setMemo] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [decoyPath, setDecoyPath] = useState("");
  const [serverKind, setServerKind] = useState("nginx");
  const [cmdName, setCmdName] = useState("ifconfig");
  const [error, setError] = useState<string | null>(null);
  const [historyFor, setHistoryFor] = useState<string | null>(null);

  async function create() {
    setError(null);
    const config: Record<string, unknown> = {};
    if (type === "fast_redirect" || type === "cloned_website") config["target_url"] = targetUrl;
    if (type === "sql_injection") {
      config["path"] = decoyPath || "/search.php";
      config["server_kind"] = serverKind;
    }
    if (type === "sensitive_cmd") config["cmd_name"] = cmdName;
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
          {tokenFields(type).includes("target_url") && (
            <input
              placeholder="https://target.example.com/"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              className="bg-neutral-800 border border-neutral-700 rounded-md px-3 py-2 text-sm flex-1 min-w-56"
            />
          )}
          {tokenFields(type).includes("decoy_path") && (
            <input
              placeholder="Decoy path (e.g. /search.php)"
              value={decoyPath}
              onChange={(e) => setDecoyPath(e.target.value)}
              className="bg-neutral-800 border border-neutral-700 rounded-md px-3 py-2 text-sm w-56"
            />
          )}
          {tokenFields(type).includes("server_kind") && (
            <select
              value={serverKind}
              onChange={(e) => setServerKind(e.target.value)}
              className="bg-neutral-800 border border-neutral-700 rounded-md px-3 py-2 text-sm"
            >
              <option value="nginx">nginx</option>
              <option value="apache">apache</option>
            </select>
          )}
          {tokenFields(type).includes("cmd_name") && (
            <select
              value={cmdName}
              onChange={(e) => setCmdName(e.target.value)}
              className="bg-neutral-800 border border-neutral-700 rounded-md px-3 py-2 text-sm"
            >
              <option value="ifconfig">ifconfig</option>
              <option value="ipconfig">ipconfig</option>
              <option value="whoami">whoami</option>
              <option value="cat_etc_shadow">cat /etc/shadow</option>
            </select>
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
            <th>Hits</th>
            <th>Status</th>
            <th>Created</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {tokens.map((t) => (
            <Fragment key={t.id}>
            <tr className="border-b border-neutral-900 hover:bg-neutral-900/50">
              <td className="py-2 font-mono text-xs">{t.id}</td>
              <td>{t.type}</td>
              <td className="text-neutral-400">{t.memo ?? "—"}</td>
              <td className={t.hitCount ? "text-amber-400 font-medium" : "text-neutral-600"}>
                {t.hitCount ?? 0}
              </td>
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
                <button
                  onClick={() => setHistoryFor(historyFor === t.id ? null : t.id)}
                  className="border border-neutral-700 hover:border-neutral-500 rounded px-2 py-0.5 text-xs mr-2"
                >
                  history
                </button>
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
            {historyFor === t.id && (
              <tr className="border-b border-neutral-900">
                <td colSpan={6} className="py-3 px-2 bg-neutral-950">
                  <TokenIncidents tokenId={t.id} />
                </td>
              </tr>
            )}
            </Fragment>
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

function incidentSummary(i: Incident): { label: string; detail: string; sourceIp: string } {
  const d = (i.event.detail ?? {}) as Record<string, unknown>;
  const str = (k: string) => (typeof d[k] === "string" ? (d[k] as string) : undefined);
  const sourceIp = i.event.sourceIp ?? str("source_ip") ?? "unknown";

  if (i.event.kind === "agent") {
    const sensor = str("sensor") ?? "agent";
    const event = str("event");
    let label: string;
    let extra = "";
    if (event === "ntlm_credentials" || event === "credssp_credentials") {
      label = `${sensor}: CAPTURED credentials ${str("domain") ?? ""}\\${str("username") ?? "?"}`;
      extra = str("hashcat") ?? "";
    } else if (event === "credential_attempt" || str("password") !== undefined) {
      const pw = str("password");
      label = `${sensor}: credential attempt user="${str("user") ?? str("username") ?? "?"}"` +
        (pw ? ` password="${pw}"` : "");
      const cv = str("client_version");
      if (cv) extra = `client: ${cv}`;
    } else if (event === "command_execution" || d["command"] !== undefined) {
      const cmd = d["command"];
      label = `${sensor}: command executed by "${str("user") ?? "?"}": ` +
        (Array.isArray(cmd) ? cmd.join(" ") : String(cmd ?? ""));
    } else if (event === "bait_file_touched" || event === "watched_file_accessed") {
      label = `${sensor}: ${str("label") ?? str("path") ?? event} accessed`;
    } else if (event) {
      label = `${sensor}: ${event}`;
    } else {
      label = sensor;
    }
    return { label, detail: extra, sourceIp };
  }
  if (i.event.kind === "dns" && i.event.dns) {
    return { label: `DNS ${i.event.dns.queryName} (${i.event.dns.queryType})`, detail: "", sourceIp };
  }
  if (i.event.http) {
    const ua = i.event.http.userAgent ? ` · ${i.event.http.userAgent}` : "";
    return {
      label: `${i.event.http.method} ${i.event.http.host}${i.event.http.path}`,
      detail: ua,
      sourceIp,
    };
  }
  return { label: i.event.kind, detail: "", sourceIp };
}

function IncidentsView({ incidents, onChange }: { incidents: Incident[]; onChange: () => void }) {
  const [expanded, setExpanded] = useState<string | null>(null);
  return (
    <section className="space-y-2">
      {incidents.length === 0 && (
        <p className="text-neutral-500 text-sm">No incidents recorded yet.</p>
      )}
      {incidents.map((i) => {
        const { label, detail, sourceIp } = incidentSummary(i);
        const isOpen = expanded === i.id;
        return (
          <div
            key={i.id}
            className={`rounded-lg border p-4 flex items-center justify-between gap-4 ${
              i.acknowledged
                ? "border-neutral-900 bg-neutral-950 opacity-60"
                : "border-neutral-800 bg-neutral-900"
            }`}
          >
            <div className="min-w-0 cursor-pointer" onClick={() => setExpanded(isOpen ? null : i.id)}>
              <div className="flex items-center gap-3">
                <span className={`font-mono text-xs uppercase ${SEVERITY_COLOR[i.severity]}`}>
                  {i.severity}
                </span>
                <span className="text-sm font-medium">{i.tokenType ?? "token"}</span>
                <span className="font-mono text-xs text-neutral-500">{i.tokenId}</span>
              </div>
              <div className="mt-1 text-xs text-neutral-300 truncate">{label}</div>
              {detail && (
                <div className="mt-0.5 text-xs text-neutral-500 truncate">{detail}</div>
              )}
              {isOpen && (
                <pre className="mt-2 text-xs bg-neutral-950 border border-neutral-800 rounded p-3 overflow-x-auto text-neutral-400">
{JSON.stringify(i.event, null, 2)}
                </pre>
              )}
            </div>
            <div className="flex items-center gap-4 shrink-0 text-xs text-neutral-400">
              <span title={sourceIp}>{sourceIp}</span>
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
        );
      })}
    </section>
  );
}

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
    <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-5 space-y-2">
      <h2 className="font-medium">Agent downloads</h2>
      {files.length === 0 ? (
        <p className="text-xs text-neutral-500">
          No release binaries found. Build with{" "}
          <code className="text-neutral-400">cd agent && make release</code> and set{" "}
          <code className="text-neutral-400">F0_AGENT_RELEASE_DIR</code> on the API.
        </p>
      ) : (
        <ul className="space-y-1">
          {files.map((f) => (
            <li key={f.filename} className="flex items-center justify-between text-sm">
              <span className="font-mono text-xs">{f.filename}</span>
              <span className="flex items-center gap-3 text-xs text-neutral-500">
                {(f.size / 1e6).toFixed(1)} MB
                <a
                  href={f.url}
                  download
                  className="border border-neutral-700 hover:border-neutral-500 rounded px-2 py-0.5"
                >
                  download
                </a>
              </span>
            </li>
          ))}
        </ul>
      )}
      {manifest && (
        <p className="text-xs text-green-500">✓ signed release manifest present</p>
      )}
      <p className="text-xs text-neutral-500">
        Install: <code className="text-neutral-400">./f0-deception-agent --server &lt;api-url&gt; --enroll &lt;token&gt; --install</code>
      </p>
    </div>
  );
}

function AgentsView({ agents, onChange }: { agents: AgentRow[]; onChange: () => void }) {
  const [editing, setEditing] = useState<string | null>(null);

  return (
    <section className="space-y-4">
      <ReleasesPanel />

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
