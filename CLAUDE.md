# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Read first

- `AGENTS.md` — repo layout, invariants, env var reference, roadmap. The invariants section ("Conventions & invariants") is binding.
- `docs/HANDOFF.md` — project state, architecture-decision rationale, and hard-won gotchas (stale tsx processes, SMB/impacket conformance, DNS zone-cut occlusion, local demo env). Check §5 before debugging anything weird.

## Commands

pnpm monorepo (turbo), Node ≥22, plus a Go agent in `agent/`.

```sh
pnpm install && pnpm build        # bootstrap; build is required before typecheck/test (deps on ^build)
pnpm typecheck                    # tsc --noEmit everywhere
pnpm test                         # vitest across all packages
pnpm dev                          # parallel dev servers (tsx watch / vite)

# single package / single test (vitest):
pnpm --filter @f0/deception-api test          # also -gateway, -shared, -tokens-core, -mcp
cd apps/api && npx vitest run src/auth.test.ts
cd apps/api && npx vitest run -t "name substring"

# Go agent:
cd agent && go test ./... && go vet ./... && gofmt -l .
cd agent && make build            # or `make release` for 5-platform cross-build

# security lint (blocking in CI):
semgrep scan --config .semgrep.yml

# e2e (Playwright, needs the demo stack running + F0_E2E_KEY=<console api key>):
pnpm e2e                          # or run one: node scripts/e2e/tokens-ui.mjs
```

Local smoke run (no root ports): see `AGENTS.md` Commands section and `deploy/local-demo.env`. After editing TS, restart tsx processes — tsx compiles at startup, so edits silently don't run.

## Architecture: how a token trigger flows

The one cross-cutting flow worth knowing before touching any package:

1. **`packages/tokens-core`** defines each token type as one file implementing `TokenTypeDefinition` (`configSchema`, `generate()`, `matchTrigger()`), registered in `registry.ts`. `generate()` produces artifacts (pixel URLs, documents, DNS hostnames); artifacts are DB-backed (`token_files`, base64) — never filesystem paths.
2. **`apps/gateway`** is the public catch-all (HTTP + authoritative DNS + SMTP). It parses attacker-controlled input by design: it lowercases hostnames, extracts every candidate token-id label (ids can sit at any depth, or as the first URL path segment), and forwards candidate events to the API. It never decides whether an event is a real trigger — 404s from the API are benign.
3. **`apps/api`** (`POST /api/v1/incidents`) is the trigger authority: it runs the token's own `matchTrigger` and takes severity from that match. Incidents then fan out to alert channels (`src/alerts/`) with per-(token, source-IP) throttling. Fastify + Drizzle + SQLite (WAL).
4. **`packages/shared`** holds the zod schemas that are the single source of truth for API validation AND MCP tool definitions — never redefine shapes locally.
5. **`agent/`** (Go) enrolls, heartbeats, and runs fleet-managed sensors/honeypots (`agent_sensors` table delivers config — not env vars). Agent-reported incidents reference a managed token id and bypass type rules (`event.detail.sensor` present ⇒ agent event, carries its own severity).
6. **`apps/mcp`** exposes management/triage tools over stdio + streamable HTTP, calling the API.

Adding a token type = one file in `packages/tokens-core/src/` + registration; its `matchTrigger` rules must mirror the artifact paths served by the gateway's `artifactResponder` (`apps/gateway/src/artifacts.ts`).

## Non-negotiables (from AGENTS.md)

- Token IDs are lowercase-only (`23456789abcdefghjkmnpqrstuvwxyz`) — DNS is case-insensitive.
- Gateway: no exec, no request-path→filesystem mapping, size caps on all input (semgrep-enforced).
- TypeScript strict with `noUncheckedIndexedAccess` — handle `undefined` explicitly.
- Config via `F0_*` env vars only (table in `AGENTS.md`); Apache-2.0 license headers on new source files.
