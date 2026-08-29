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
  /** Present in create responses for file_download artifacts. */
  file?: { filename: string; contentType: string };
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
  config: Record<string, unknown>;
}

export interface AuthKeyRow {
  id: string;
  label: string;
  createdAt: string;
  lastUsedAt: string | null;
}

export interface Capabilities {
  buildReleases: boolean;
  releaseDir: boolean;
  releaseSigning: boolean;
  codeSigning: boolean;
  reasons: Record<string, string>;
}

export interface ServerStatus {
  geoipEnabled: boolean;
  authOpenMode: boolean;
  enrollmentConfigured: boolean;
  alertThrottlePerMinute: number;
  /** Host-dependent actions; absent on older APIs, so treat as available. */
  capabilities?: Capabilities;
}

export interface ReleaseKeyRow {
  id: string;
  label: string;
  publicKey: string;
  createdAt: string;
}

export interface EnrollmentTokenRow {
  id: string;
  label: string;
  expiresAt: string | null;
  lastUsedAt: string | null;
  uses: number;
  createdAt: string;
}

export interface DeploymentRow {
  id: string;
  tokenId: string;
  kind: "file" | "shortcut";
  targetDir: string;
  filename: string;
  url: string | null;
  status: "pending" | "done" | "failed";
  error: string | null;
  createdAt: string;
  completedAt: string | null;
}

export interface CodeSignCertRow {
  id: string;
  label: string;
  subject: string;
  issuer: string;
  notAfter: string;
  createdAt: string;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const key = getApiKey();
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      // Only when a body is present — an empty body with a JSON
      // content-type is a 400 (FST_ERR_CTP_EMPTY_JSON_BODY).
      ...(init?.body ? { "content-type": "application/json" } : {}),
      ...(key ? { authorization: `Bearer ${key}` } : {}),
    },
  });
  if (res.status === 401) {
    unauthorizedHandler?.();
    throw new UnauthorizedError();
  }
  if (!res.ok) {
    const body = await res.text();
    // Fastify error bodies are JSON with a message field — surface that,
    // not the raw blob (e.g. channel test failures).
    let message = body;
    try {
      const parsed = JSON.parse(body) as { message?: string };
      if (parsed.message) message = parsed.message;
    } catch {
      /* not JSON — use the raw body */
    }
    throw new Error(`${res.status}: ${message}`);
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

/**
 * Authenticated file download. Plain <a href download> navigations do NOT
 * send our Bearer key, so they 401 whenever console auth is enforced —
 * fetch as a blob and save via an object URL instead.
 */
export async function downloadFile(path: string, filename: string): Promise<void> {
  const key = getApiKey();
  const res = await fetch(`${BASE}${path}`, {
    headers: key ? { authorization: `Bearer ${key}` } : {},
  });
  if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`);
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/** Same authenticated-fetch pattern for inline <img> sources. */
export async function fetchObjectUrl(path: string): Promise<string> {
  const key = getApiKey();
  const res = await fetch(`${BASE}${path}`, {
    headers: key ? { authorization: `Bearer ${key}` } : {},
  });
  if (!res.ok) throw new Error(`${res.status}`);
  return URL.createObjectURL(await res.blob());
}

export const api = {
  listTokens: () => request<TokenRow[]>("/tokens"),
  getStats: () => request<DashboardStats>("/stats"),
  createToken: (type: string, memo?: string, config: object = {}) =>
    request<TokenRow & { artifacts?: TokenArtifact[]; files?: TokenFileRow[] }>("/tokens", {
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
  patchToken: (id: string, memo: string | null) =>
    request(`/tokens/${id}`, { method: "PATCH", body: JSON.stringify({ memo }) }),
  bulkTokenAction: (ids: string[], action: "revoke" | "delete") =>
    request<{ ok: boolean; updated: number }>("/tokens/bulk", {
      method: "POST",
      body: JSON.stringify({ ids, action }),
    }),
  recloneToken: (id: string) => request(`/tokens/${id}/reclone`, { method: "POST" }),
  uploadTokenImage: (id: string, image: { data: string; contentType: string; filename?: string }) =>
    request(`/tokens/${id}/image`, { method: "POST", body: JSON.stringify(image) }),
  listIncidents: (params: Record<string, string | undefined> = {}) => {
    const qs = new URLSearchParams(
      Object.entries(params).filter((kv): kv is [string, string] => !!kv[1]),
    ).toString();
    return request<Incident[]>(`/incidents${qs ? `?${qs}` : ""}`);
  },
  bulkAckIncidents: (ids: string[]) =>
    request<{ ok: boolean; updated: number }>("/incidents/bulk-ack", {
      method: "POST",
      body: JSON.stringify({ ids }),
    }),
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
  buildReleases: (version: string) =>
    request<{ ok: boolean; version: string; files: { filename: string; size: number }[] }>(
      "/agent-releases/build",
      { method: "POST", body: JSON.stringify({ version }) },
    ),
  deleteRelease: (file: string) =>
    request(`/agent-releases/${encodeURIComponent(file)}`, { method: "DELETE" }),
  listAgents: () => request<AgentRow[]>("/agents"),
  getAgentBootstrap: () => request<{ enrollmentToken: string | null }>("/agent-bootstrap"),
  listEnrollmentTokens: () => request<EnrollmentTokenRow[]>("/enrollment-tokens"),
  createEnrollmentToken: (label: string, expiresInHours?: number) =>
    request<{ id: string; label: string; token: string; expiresAt: string | null }>(
      "/enrollment-tokens",
      {
        method: "POST",
        body: JSON.stringify(
          expiresInHours ? { label, expires_in_hours: expiresInHours } : { label },
        ),
      },
    ),
  deleteEnrollmentToken: (id: string) =>
    request(`/enrollment-tokens/${id}`, { method: "DELETE" }),
  patchAgent: (id: string, memo: string | null) =>
    request(`/agents/${id}`, { method: "PATCH", body: JSON.stringify({ memo }) }),
  deleteAgent: (id: string) => request(`/agents/${id}`, { method: "DELETE" }),
  deployToAgent: (agentId: string, tokenId: string, targetDir: string) =>
    request<{ id: string }>(`/agents/${agentId}/deploy`, {
      method: "POST",
      body: JSON.stringify({ token_id: tokenId, target_dir: targetDir }),
    }),
  listAgentDeployments: (agentId: string) =>
    request<DeploymentRow[]>(`/agents/${agentId}/deployments`),
  listReleaseKeys: () => request<ReleaseKeyRow[]>("/release-keys"),
  createReleaseKey: (label: string) =>
    request<ReleaseKeyRow>("/release-keys", {
      method: "POST",
      body: JSON.stringify({ label }),
    }),
  deleteReleaseKey: (id: string) => request(`/release-keys/${id}`, { method: "DELETE" }),
  signReleases: (keyId: string, version?: string) =>
    request<{ ok: boolean; version: string; files: string[] }>("/agent-releases/sign", {
      method: "POST",
      body: JSON.stringify(version ? { keyId, version } : { keyId }),
    }),
  listCodeSignCerts: () => request<CodeSignCertRow[]>("/codesign-certs"),
  generateCodeSignCert: (label: string, commonName: string, passphrase: string) =>
    request<CodeSignCertRow>("/codesign-certs", {
      method: "POST",
      body: JSON.stringify({ label, generate: true, commonName, passphrase }),
    }),
  uploadCodeSignCert: (label: string, pfx: string, passphrase: string) =>
    request<CodeSignCertRow>("/codesign-certs", {
      method: "POST",
      body: JSON.stringify({ label, pfx, passphrase }),
    }),
  deleteCodeSignCert: (id: string) => request(`/codesign-certs/${id}`, { method: "DELETE" }),
  codeSignRelease: (certId: string) =>
    request<{ ok: boolean; signed: string[]; skipped: string[] }>("/agent-releases/codesign", {
      method: "POST",
      body: JSON.stringify({ certId }),
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
  patchChannel: (id: string, enabled: boolean) =>
    request(`/alert-channels/${id}`, {
      method: "PATCH",
      body: JSON.stringify({ enabled }),
    }),
  testChannel: (id: string) =>
    request(`/alert-channels/${id}/test`, { method: "POST" }),
  deleteChannel: (id: string) =>
    request(`/alert-channels/${id}`, { method: "DELETE" }),
  getStatus: () => request<ServerStatus>("/status"),
  listAuthKeys: () => request<AuthKeyRow[]>("/auth/keys"),
  createAuthKey: (label: string) =>
    request<{ id: string; key: string; label: string }>("/auth/keys", {
      method: "POST",
      body: JSON.stringify({ label }),
    }),
  deleteAuthKey: (id: string) => request(`/auth/keys/${id}`, { method: "DELETE" }),
};
