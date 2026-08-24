# f0_deception

Open-source, self-hosted deception platform — an alternative to commercial
canary offerings. Deploy **agentless canarytokens** that reach back when
touched, and/or run an **agent on endpoints** for full-interaction honeypots
and local sensors.

> Status: early development (Phase 1). Web bug / DNS / fast-redirect tokens
> work end-to-end. See `AGENTS.md` roadmap.

## Components

| App | What it does |
|---|---|
| `apps/gateway` | Public trigger catcher: catch-all HTTP + authoritative DNS on your token domain |
| `apps/api` | Token/incident/agent management API (Fastify + SQLite) |
| `apps/web` | Management console *(planned)* |
| `apps/mcp` | MCP server for LLM-based triage *(planned)* |
| `agent/` | Go endpoint agent: honeypot services + local canary sensors *(planned)* |

## Quick start (local smoke test)

```sh
pnpm install && pnpm build

# terminal 1 — API
cd apps/api
F0_DB_PATH=/tmp/f0.db F0_API_PORT=18443 npx tsx src/server.ts

# terminal 2 — gateway
cd apps/gateway
F0_API_BASE_URL=http://127.0.0.1:18443 F0_HTTP_PORT=18080 F0_DNS_PORT=15353 \
  npx tsx src/server.ts

# create a web bug token
curl -s -X POST localhost:18443/api/v1/tokens \
  -H 'content-type: application/json' -d '{"type":"web_bug"}'
```

Production deployment expects a public VPS with ports 80/443/53 and a wildcard
DNS record (`*.tokens.yourdomain.com` → gateway IP).

## Documentation

- [Installation guide](docs/INSTALL.md) — local test setup in minutes, or production VPS deploy
- [User guide](docs/USER-GUIDE.md) — token playbook, honeypot deployment, alerting, MCP triage

## License

Apache-2.0
