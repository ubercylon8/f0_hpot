const BASE = "/api/v1";
const KEY_STORAGE = "f0_api_key";

export type { DashboardStats } from "@f0/deception-shared";
import type { DashboardStats } from "@f0/deception-shared";

export function getApiKey(): string {
  return localStorage.getItem(KEY_STORAGE) ?? "";
}

export function setApiKey(key: string): void {
  if (key) localStorage.setItem(KEY_STORAGE, key);
  else localStorage.removeItem(KEY_STORAGE);
}

/** Thrown on HTTP 401 so the app can show the login gate. */
export class UnauthorizedError extends Error {
  constructor() {
    super("401: authentication required");
    this.name = "UnauthorizedError";
  }
}

let unauthorizedHandler: (() => void) | null = null;

/** Registered once by the app shell: called whenever the API answers 401. */
export function setUnauthorizedHandler(fn: (() => void) | null): void {
  unauthorizedHandler = fn;
}

/** Drop the stored key and bounce the app to the login gate. */
export function logout(): void {
  setApiKey("");
  unauthorizedHandler?.();
}

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

export interface TokenFileRow {
  idx: number;
  filename: string;
  contentType: string;
}

/** GET /tokens/:id — list row plus display artifacts and stored files. */
export interface TokenDetail extends TokenRow {
  artifacts?: TokenArtifact[];
  files?: TokenFileRow[];
}

export interface GeoInfo {
  country?: string;
  countryName?: string;
  city?: string;
  asn?: number;
  org?: string;
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
  // Populated at ingest (GeoIP enrichment); null when disabled/unmatched.
  sourceIp?: string | null;
  geo?: GeoInfo | null;
  notes?: string | null;
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
  memo?: string | null;
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

export interface ReleaseKeyRow {
  id: string;
  label: string;
  publicKey: string;
  createdAt: string;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const key = getApiKey();
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      "content-type": "application/json",
      ...(key ? { authorization: `Bearer ${key}` } : {}),
    },
  });
  if (res.status === 401) {
    unauthorizedHandler?.();
    throw new UnauthorizedError();
  }
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`${res.status}: ${body}`);
  }
  return (await res.json()) as T;
}

/** Validate a key against the API without storing it. Throws on reject. */
export async function login(key: string): Promise<void> {
  const res = await fetch(`${BASE}/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ key }),
  });
  if (!res.ok) throw new Error(`${res.status}: invalid key`);
}

export const api = {
  listTokens: () => request<TokenRow[]>("/tokens"),
  getStats: () => request<DashboardStats>("/stats"),
  createToken: (type: string, memo?: string, config: object = {}) =>
    request<TokenRow & { artifacts?: TokenArtifact[] }>("/tokens", {
      method: "POST",
      body: JSON.stringify({ type, memo, config }),
    }),
  getToken: (id: string) => request<TokenDetail>(`/tokens/${id}`),
  deleteToken: (id: string, hard = false) =>
    request(`/tokens/${id}${hard ? "?hard=true" : ""}`, { method: "DELETE" }),
  setTokenStatus: (id: string, status: "active" | "paused" | "revoked") =>
    request(`/tokens/${id}/status`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),
  uploadTokenImage: (id: string, image: { data: string; contentType: string; filename?: string }) =>
    request(`/tokens/${id}/image`, { method: "POST", body: JSON.stringify(image) }),
  listIncidents: () => request<Incident[]>("/incidents"),
  getIncident: (id: string) => request<Incident>(`/incidents/${id}`),
  ackIncident: (id: string) =>
    request(`/incidents/${id}/ack`, { method: "PATCH" }),
  setIncidentNotes: (id: string, notes: string | null) =>
    request(`/incidents/${id}/notes`, {
      method: "PATCH",
      body: JSON.stringify({ notes }),
    }),
  tokenIncidents: (tokenId: string) =>
    request<Incident[]>(`/tokens/${tokenId}/incidents`),
  listChannels: () => request<AlertChannel[]>("/alert-channels"),
  listReleases: () =>
    request<{ files: { filename: string; size: number; url: string }[]; manifest: string | null }>(
      "/agent-releases",
    ),
  listAgents: () => request<AgentRow[]>("/agents"),
  getAgentBootstrap: () => request<{ enrollmentToken: string | null }>("/agent-bootstrap"),
  patchAgent: (id: string, memo: string | null) =>
    request(`/agents/${id}`, { method: "PATCH", body: JSON.stringify({ memo }) }),
  deleteAgent: (id: string) => request(`/agents/${id}`, { method: "DELETE" }),
  listReleaseKeys: () => request<ReleaseKeyRow[]>("/release-keys"),
  createReleaseKey: (label: string) =>
    request<ReleaseKeyRow>("/release-keys", {
      method: "POST",
      body: JSON.stringify({ label }),
    }),
  signReleases: (keyId: string, version?: string) =>
    request<{ ok: boolean; version: string; files: string[] }>("/agent-releases/sign", {
      method: "POST",
      body: JSON.stringify(version ? { keyId, version } : { keyId }),
    }),
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
