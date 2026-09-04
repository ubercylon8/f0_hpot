# AGENTS.md — f0_deception

Open-source, self-hosted deception platform: agentless canarytokens (reach-back)
plus agent-deployed honeypots/sensors, web console, and MCP server.

## Hand-off

- `ARCHITECTURE.md` — component boundaries, the trigger flow, and the reasoning behind the invariants.

## Repo layout

- `apps/api` — Fastify REST API + Drizzle ORM + SQLite (WAL). Source of truth for tokens, incidents, agents, alert channels.
- `apps/gateway` — public trigger catcher: HTTP catch-all (artifacts: pixel gifs, redirects) + authoritative DNS server (dns-packet/UDP).
- `apps/web` — React 19 + Vite + Tailwind console (Phase 1+).
- `apps/mcp` — MCP server (stdio + streamable HTTP) for management/triage.
- `packages/shared` — zod schemas; intended single source of truth for API validation AND MCP tool definitions. `apps/mcp` currently redeclares its shapes by hand instead of depending on this package — see the note under invariant 3.
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
pnpm e2e                     # Playwright UI suite (63 checks across 6 pages) — needs the
                             # demo stack running AND seeded:
                             #   F0_E2E_ADMIN=<F0_ADMIN_TOKEN> F0_DB_PATH=<demo db> \
                             #     node scripts/e2e/seed.mjs      # prints F0_E2E_KEY
                             #   export F0_E2E_KEY=... F0_E2E_ENROLL=<F0_ENROLLMENT_TOKEN>
                             # The suites assume a demo-console key, an enrolled agent and
                             # three alert channels; without the seed they fail in ways that
                             # look like product bugs.

# smoke run (local, no root ports):
F0_DB_PATH=/tmp/f0.db F0_API_PORT=18443 npx tsx src/server.ts   # in apps/api
F0_API_BASE_URL=http://127.0.0.1:18443 F0_HTTP_PORT=18080 F0_DNS_PORT=15353 npx tsx src/server.ts  # in apps/gateway
```

## Conventions & invariants (do not break)

1. **Token IDs are lowercase-only** (`23456789abcdefghjkmnpqrstuvwxyz`). Hostnames/DNS are case-insensitive and get lowercased at the gateway; an uppercase ID would never match.
2. **Token id may sit at ANY label depth** under the base domain (`sub.<id>.tokens.example.com`). The gateway forwards every matching candidate label; the API drops ids that aren't live tokens (404 is benign in gateway logs).
3. All cross-app data shapes should live in `packages/shared` zod schemas — never redefine them locally. `apps/mcp` is the current exception: it has no dependency on `packages/shared` and hand-writes its own shapes (e.g. the token-type enum in `apps/mcp/src/server.ts`), so adding a token type today means updating that file too until it is wired up to depend on `packages/shared` like the other apps.
4. New token types = one file in `packages/tokens-core/src/` implementing `TokenTypeDefinition` + registration. Trigger rules in `matchTrigger` must mirror artifact paths served by the gateway's `artifactResponder`.
5. The gateway parses attacker-controlled input by definition: cap sizes, never shell out, no dynamic path→filesystem mapping. These are design rules the current code upholds, not something a tool checks for you — see `ARCHITECTURE.md` (Components) for why the `.semgrep.yml` rules meant to cover this can't match.
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
| `F0_HTTP_PORT` / `F0_DNS_PORT` / `F0_SMTP_PORT` | gateway | `8080`/`5353`/`2525` | listener ports |
| `F0_MAIL_DOMAINS` | gateway smtp | = token domains | accepted email-token domains |
| `F0_API_BASE_URL` | gateway, mcp | `http://127.0.0.1:8443` | console API location |
| `F0_MAX_ALERTS_PER_MINUTE` | api | `1` | alert throttle per (token, source IP) |
| `F0_GEOIP_DB` | api | unset (disabled) | MaxMind .mmdb path for incident source-IP geo enrichment |
| `F0_ADMIN_TOKEN` | api | unset (open-mode if no keys) | console master key; bootstrap for `POST /api/v1/auth/keys` |
| `F0_INTERNAL_SECRET` | api, gateway | unset | gateway→API shared secret (incident forwarding, internal-config/page) |
| `F0_ENROLLMENT_TOKEN` | api | unset (enroll disabled) | bootstrap token for agent enrollment |
| `F0_AGENT_POLL_INTERVAL` | api | `60` | heartbeat interval served to agents |
| `F0_MCP_HTTP` / `F0_MCP_PORT` | mcp | stdio / `8444` | HTTP transport for MCP |
| `F0_API_TOKEN` | mcp | none | Bearer token sent to API |

## Architecture notes

- **Trigger authority is per-token-type at the API**: the gateway forwards candidate
  events; `POST /api/v1/incidents` runs the token's own `matchTrigger` before recording.
  Severity comes from that match, not the gateway.
- Token ids may be in hostname labels OR the first path segment (apex-hosted
  artifacts like documents embed `https://base.domain/<tokenId>/pixel.gif`).
- Agent sensors reference managed token ids so honeypot hits stay linked to
  revocable, alertable entities.
- Sensor config is fleet-managed (`agent_sensors` table) and delivered via heartbeat.

## Roadmap snapshot

- P0-P2 ✅ scaffold · core tokens · alerts (webhook/email/syslog) + throttling
- P3 ✅ word/excel/windows_folder/sql_injection (+ qr, email, sensitive_cmd)
- P4 ✅ Go agent: enroll, fleet-managed sensors, SSH+HTTP honeypots,
  planted_credential/file_watch local sensors, installers, 5-platform release
- P5 ✅ MCP server (8 tools, stdio+HTTP)
- P6 ✅ PDF/cloned-site tokens, SMB (NTLM capture) + RDP (CredSSP/NLA)
  honeypots, Elastic/Loki channels, AWS/Azure decoys, Ed25519 signed
  self-updates, CI (build/test/semgrep/gitleaks)
- P7 ✅ web console overhaul → f0_hpot (A–G: stats/fleet APIs, dark-SOC
  design system, dashboard, tokens/agents/channels/settings UX)
