/**
 * f0_deception MCP server: management + triage tools for LLM clients.
 *
 * Scope is deliberately limited (no destructive operations beyond token
 * revocation): create/list/get/revoke tokens, list/get incidents, list
 * agents, platform stats.
 *
 * Transport: stdio by default; set F0_MCP_HTTP=1 for streamable HTTP on
 * F0_MCP_PORT (default 8444).
 *
 * Auth to the console API via F0_API_BASE_URL + F0_API_TOKEN (Bearer).
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import http from "node:http";

const API_BASE = process.env.F0_API_BASE_URL ?? "http://127.0.0.1:8443";
const API_TOKEN = process.env.F0_API_TOKEN ?? "";

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}/api/v1${path}`, {
    ...init,
    headers: {
      "content-type": "application/json",
      ...(API_TOKEN ? { authorization: `Bearer ${API_TOKEN}` } : {}),
      ...init?.headers,
    },
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`API ${res.status}: ${text.slice(0, 300)}`);
  return (text ? JSON.parse(text) : {}) as T;
}

const server = createServer();

function createServer(): McpServer {
  const s = new McpServer(
    { name: "f0-deception", version: "0.1.0" },
    { instructions:
      "Management and triage tools for the f0_deception canarytoken/deception platform. " +
      "Use create_token to plant canaries, list_incidents/get_incident to triage alerts, " +
      "list_agents for honeypot fleet status." },
  );
  registerTools(s);
  return s;
}

function registerTools(s: McpServer): void {
s.tool(
  "create_token",
  "Create a new canarytoken. Returns the artifacts to deploy (URLs, hostnames, or file downloads).",
  {
    type: z.enum([
      "web_bug",
      "dns",
      "qr_code",
      "email",
      "word_doc",
      "excel_doc",
      "windows_folder",
      "sql_injection",
      "aws_keys",
      "azure_config",
      "honeypot",
      "sensitive_cmd",
      "fast_redirect",
    ]).describe("Token type"),
    memo: z.string().max(500).optional().describe("What this token is for / where it's planted"),
    config: z.record(z.string(), z.unknown()).optional()
      .describe("Type-specific config, e.g. {target_url} for fast_redirect, {cmd_name} for sensitive_cmd"),
  },
  async ({ type, memo, config }) => {
    const out = await api("/tokens", {
      method: "POST",
      body: JSON.stringify({ type, memo, config: config ?? {} }),
    });
    return { content: [{ type: "text", text: JSON.stringify(out, null, 2) }] };
  },
);

s.tool(
  "list_tokens",
  "List all canarytokens with status.",
  {},
  async () => ({
    content: [{ type: "text", text: JSON.stringify(await api("/tokens"), null, 2) }],
  }),
);

s.tool(
  "revoke_token",
  "Revoke a canarytoken (stops alerting; keeps history). Prefer revoking over deleting.",
  { tokenId: z.string().describe("Token id") },
  async ({ tokenId }) => ({
    content: [{
      type: "text",
      text: JSON.stringify(await api(`/tokens/${tokenId}`, { method: "DELETE" })),
    }],
  }),
);

s.tool(
  "list_incidents",
  "List triggered-token incidents, newest first.",
  {
    limit: z.number().int().min(1).max(500).default(50),
    unacknowledged_only: z.boolean().default(false),
  },
  async ({ limit, unacknowledged_only }) => ({
    content: [{
      type: "text",
      text: JSON.stringify(
        await api(`/incidents?limit=${limit}${unacknowledged_only ? "&acknowledged=false" : ""}`),
        null,
        2,
      ),
    }],
  }),
);

s.tool(
  "get_incident_detail",
  "Full evidence for one incident: raw request/DNS data, source IP, geo, notes.",
  { incidentId: z.string() },
  async ({ incidentId }) => ({
    content: [{
      type: "text",
      text: JSON.stringify(await api(`/incidents/${incidentId}`), null, 2),
    }],
  }),
);

s.tool(
  "acknowledge_incident",
  "Mark an incident as acknowledged after triage.",
  { incidentId: z.string() },
  async ({ incidentId }) => ({
    content: [{
      type: "text",
      text: JSON.stringify(await api(`/incidents/${incidentId}/ack`, { method: "PATCH" })),
    }],
  }),
);

s.tool(
  "list_agents",
  "List enrolled endpoint agents (honeypot hosts) with sensor configs.",
  {},
  async () => ({
    content: [{ type: "text", text: JSON.stringify(await api("/agents"), null, 2) }],
  }),
);

s.tool(
  "get_platform_stats",
  "Summary counts: active tokens, recent incidents, agents online.",
  {},
  async () => {
    const [tokens, incidents, agents] = await Promise.all([
      api<{ status: string }[]>("/tokens"),
      api<{ seenAt: string; acknowledged: boolean }[]>("/incidents?limit=500"),
      api<{ status: string; lastSeenAt: string | null }[]>("/agents"),
    ]);
    const now = Date.now();
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          active_tokens: tokens.filter((t) => t.status === "active").length,
          total_tokens: tokens.length,
          incidents_24h: incidents.filter((i) => now - Date.parse(i.seenAt) < 86_400_000).length,
          unacknowledged_incidents: incidents.filter((i) => !i.acknowledged).length,
          agents_online: agents.filter(
            (a) =>
              a.status === "online" &&
              a.lastSeenAt !== null &&
              now - Date.parse(a.lastSeenAt) < 180_000,
          ).length,
          total_agents: agents.length,
        }, null, 2),
      }],
    };
  },
);

}

async function main(): Promise<void> {
  if (process.env.F0_MCP_HTTP === "1") {
    const port = Number(process.env.F0_MCP_PORT ?? 8444);
    const httpServer = http.createServer(async (req, res) => {
      if (req.method !== "POST") {
        res.writeHead(405).end();
        return;
      }
      let body = "";
      for await (const chunk of req) body += chunk;
      let parsed: unknown;
      try {
        parsed = JSON.parse(body);
      } catch {
        res.writeHead(400).end();
        return;
      }
      // Stateless mode: fresh server + transport per request.
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
      });
      res.on("close", () => {
        void transport.close();
      });
      const instance = createServer();
      await instance.connect(transport);
      await transport.handleRequest(
        req,
        res,
        parsed as Parameters<typeof transport.handleRequest>[2],
      );
    });
    httpServer.listen(port, () =>
      console.log(`f0_deception MCP (streamable HTTP) listening on :${port}`),
    );
  } else {
    await server.connect(new StdioServerTransport());
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
