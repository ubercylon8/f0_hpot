const BASE = "/api/v1";

export interface TokenArtifact {
  kind: "url" | "hostname" | "file_download";
  label: string;
  value: string;
}

export interface TokenRow {
  id: string;
  type: string;
  memo: string | null;
  status: string;
  config: Record<string, unknown>;
  createdAt: string;
  hitCount?: number;
}

export interface Incident {
  id: string;
  tokenId: string;
  tokenType?: string;
  severity: "low" | "medium" | "high";
  acknowledged: boolean;
  event: {
    kind: string;
    sourceIp?: string;
    http?: { method: string; host: string; path: string; userAgent?: string };
    dns?: { queryName: string; queryType: string };
    detail?: Record<string, unknown>;
  };
  seenAt: string;
}

export interface SensorRow {
  id: string;
  agentId?: string;
  kind: string;
  enabled: boolean;
  config: Record<string, unknown>;
}

export interface AgentRow {
  id: string;
  hostname: string;
  platform: string;
  version: string;
  status: string;
  lastSeenAt: string | null;
  sensors: SensorRow[];
}

export interface AlertChannel {
  id: string;
  kind: string;
  enabled: boolean;
  failureCount: number;
  createdAt: string;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "content-type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`${res.status}: ${body}`);
  }
  return (await res.json()) as T;
}

export const api = {
  listTokens: () => request<TokenRow[]>("/tokens"),
  createToken: (type: string, memo?: string, config: object = {}) =>
    request<TokenRow>("/tokens", {
      method: "POST",
      body: JSON.stringify({ type, memo, config }),
    }),
  revokeToken: (id: string) => request(`/tokens/${id}`, { method: "DELETE" }),
  listIncidents: () => request<Incident[]>("/incidents"),
  ackIncident: (id: string) =>
    request(`/incidents/${id}/ack`, { method: "PATCH" }),
  listChannels: () => request<AlertChannel[]>("/alert-channels"),
  listReleases: () =>
    request<{ files: { filename: string; size: number; url: string }[]; manifest: string | null }>(
      "/agent-releases",
    ),
  listAgents: () => request<AgentRow[]>("/agents"),
  setAgentSensors: (id: string, sensors: { kind: string; enabled: boolean; config: object }[]) =>
    request(`/agents/${id}/sensors`, {
      method: "PUT",
      body: JSON.stringify({ sensors }),
    }),
  createChannel: (kind: string, config: object) =>
    request<{ id: string }>("/alert-channels", {
      method: "POST",
      body: JSON.stringify({ kind, config }),
    }),
  deleteChannel: (id: string) =>
    request(`/alert-channels/${id}`, { method: "DELETE" }),
};
