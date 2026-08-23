import { useCallback, useEffect, useState } from "react";
import { api, type Incident, type TokenRow, type AlertChannel } from "./api.js";

const TOKEN_TYPES = [
  { id: "web_bug", label: "Web Bug", hint: "1x1 pixel URL" },
  { id: "dns", label: "DNS Token", hint: "unique hostname" },
  { id: "qr_code", label: "QR Code", hint: "scan-to-trigger" },
  { id: "fast_redirect", label: "Fast Redirect", hint: "requires target_url" },
  { id: "sensitive_cmd", label: "Sensitive Command", hint: "fake cmd output page" },
] as const;

type Tab = "dashboard" | "tokens" | "incidents" | "channels";

export default function App() {
  const [tab, setTab] = useState<Tab>("dashboard");
  const [tokens, setTokens] = useState<TokenRow[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [channels, setChannels] = useState<AlertChannel[]>([]);

  const refresh = useCallback(async () => {
    try {
      const [t, i, c] = await Promise.all([
        api.listTokens(),
        api.listIncidents(),
        api.listChannels(),
      ]);
      setTokens(t);
      setIncidents(i);
      setChannels(c);
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

function ChannelsView({ channels, onChange }: { channels: AlertChannel[]; onChange: () => void }) {
  const [kind, setKind] = useState("webhook");
  const [url, setUrl] = useState("");
  const [host, setHost] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function create() {
    setError(null);
    const config =
      kind === "webhook" ? { url } : kind === "syslog" ? { host, port: 514 } : {};
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
          </select>
          {kind === "webhook" ? (
            <input
              placeholder="https://hooks.example.com/f0"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="bg-neutral-800 border border-neutral-700 rounded-md px-3 py-2 text-sm flex-1 min-w-64"
            />
          ) : (
            <input
              placeholder="siem host"
              value={host}
              onChange={(e) => setHost(e.target.value)}
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
