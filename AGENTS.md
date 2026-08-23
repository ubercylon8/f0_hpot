# AGENTS.md — f0_deception

Open-source, self-hosted deception platform: agentless canarytokens (reach-back)
plus agent-deployed honeypots/sensors, web console, and MCP server.

## Repo layout

- `apps/api` — Fastify REST API + Drizzle ORM + SQLite (WAL). Source of truth for tokens, incidents, agents, alert channels.
- `apps/gateway` — public trigger catcher: HTTP catch-all (artifacts: pixel gifs, redirects) + authoritative DNS server (dns-packet/UDP).
- `apps/web` — React 19 + Vite + Tailwind console (Phase 1+).
- `apps/mcp` — MCP server (stdio + streamable HTTP) for management/triage.
- `packages/shared` — zod schemas; single source of truth for API validation AND MCP tool definitions.
- `packages/tokens-core` — token type registry. Each token type = `{configSchema, generate(), matchTrigger()}`.
- `agent/` — Go agent (fork of achilles-agent skeleton): enroll → heartbeat → poll → execute sensors → report.
- `deploy/` — docker-compose + Caddy.

## Commands

```sh
pnpm install                 # bootstrap
pnpm build                   # turbo build all
pnpm test                    # turbo test all
pnpm typecheck               # tsc --noEmit everywhere
pnpm dev                     # parallel dev servers

# smoke run (local, no root ports):
F0_DB_PATH=/tmp/f0.db F0_API_PORT=18443 npx tsx src/server.ts   # in apps/api
F0_API_BASE_URL=http://127.0.0.1:18443 F0_HTTP_PORT=18080 F0_DNS_PORT=15353 npx tsx src/server.ts  # in apps/gateway
```

## Conventions & invariants (do not break)

1. **Token IDs are lowercase-only** (`23456789abcdefghjkmnpqrstuvwxyz`). Hostnames/DNS are case-insensitive and get lowercased at the gateway; an uppercase ID would never match.
2. **Token id may sit at ANY label depth** under the base domain (`sub.<id>.tokens.example.com`). The gateway forwards every matching candidate label; the API drops ids that aren't live tokens (404 is benign in gateway logs).
3. All cross-app data shapes live in `packages/shared` zod schemas — never redefine them locally.
4. New token types = one file in `packages/tokens-core/src/` implementing `TokenTypeDefinition` + registration. Trigger rules in `matchTrigger` must mirror artifact paths served by the gateway's `artifactResponder`.
5. The gateway parses attacker-controlled input by definition: cap sizes, never shell out, no dynamic path→filesystem mapping.
6. No secrets in code; config via env (`F0_*`). `.env.example` documents each var.
7. TypeScript strict mode; `noUncheckedIndexedAccess` on — handle undefined explicitly.
8. Apache-2.0; keep license headers on new source files.

## Env vars

| Var | Used by | Default | Purpose |
|---|---|---|---|
| `F0_DB_PATH` | api | `./f0_deception.db` | SQLite file |
| `F0_API_PORT` | api | `8443` | API listen port |
| `F0_TOKEN_DOMAINS` | api, gateway | `tokens.example.com` | comma-separated base domains |
| `F0_GATEWAY_ORIGIN` | api, gateway | derived | public URL of gateway |
| `F0_GATEWAY_IP` | gateway dns | `127.0.0.1` | A-record answer |
| `F0_HTTP_PORT` / `F0_DNS_PORT` | gateway | `8080` / `5353` | listener ports |
| `F0_API_BASE_URL` | gateway | `http://127.0.0.1:8443` | where incidents are forwarded |

## Roadmap snapshot

- P0 ✅ scaffold/schema/shared types · P1 ✅(core) web_bug/dns/fast_redirect e2e
- P2 alerts (email/webhook/syslog) + more token types
- P3 document tokens (Office/PDF/cloned-site/SQLi/desktop.ini)
- P4 Go agent fork + SSH/HTTP honeypots + local sensors
- P5 MCP server · P6 SMB/RDP, Elastic channel, cloud tokens
