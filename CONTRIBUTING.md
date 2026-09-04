# Contributing to f0_hpot

Thanks for considering a contribution. This document covers the local setup,
the gate list a PR must pass, and a couple of gotchas that cost real time in
this repo.

## Prerequisites

- Node.js ≥ 22 (developed against 25.x)
- pnpm 11.23.0 (pinned via `packageManager` in `package.json`; use `corepack
  enable` to get the exact version)
- Go 1.26.5 for `agent/`
- `semgrep` on your `PATH` for the security lint gate

## Bootstrap

```sh
pnpm install
pnpm build
```

`pnpm build` must run before `pnpm typecheck` or `pnpm test`: turbo tasks
declare `dependsOn: ["^build"]`, so typecheck and test consume the built
output of their workspace dependencies, not just their own source.

## The gate list

Every one of these must pass on a clean tree before a PR is reviewed. This is
the exact sequence CI runs, and it has been verified to pass on this repo as
of this document's last update:

```sh
pnpm build
pnpm typecheck
pnpm test

cd agent
go test ./...
go vet ./...
gofmt -l .
cd ..

semgrep scan --config .semgrep.yml

./scripts/ci/check-identifiers.sh
```

A few notes:

- `pnpm typecheck` is `tsc --noEmit` across every package; `pnpm test` is
  `vitest` across every package. Both can be scoped to one package when
  you're iterating:

  ```sh
  pnpm --filter @f0/deception-api test   # also -gateway, -shared, -tokens-core, -mcp
  cd apps/api && npx vitest run src/auth.test.ts
  cd apps/api && npx vitest run -t "name substring"
  ```

- `gofmt -l .` should print nothing; any listed file is not gofmt-formatted
  and needs `gofmt -w <file>`.

- `semgrep scan --config .semgrep.yml` encodes a handful of project-specific
  invariants (no hardcoded secrets, no string-built SQL, etc.) on top of
  registry rules. It is blocking in CI. Note that two of the rules in
  `.semgrep.yml` — `gateway-no-exec` and `gateway-no-fs-from-request` — are
  written for Go syntax but scoped to `apps/gateway`, which is entirely
  TypeScript, so they can never fire; they do not actually enforce anything
  today. The invariants they were meant to cover (no exec, no
  request-path→filesystem mapping in the gateway) are real and are enforced
  by code review, not by this tool — see `AGENTS.md` and `ARCHITECTURE.md`.

- `./scripts/ci/check-identifiers.sh` fails a tracked file that contains a
  real operational identifier — the point being that deception
  infrastructure only works while an attacker doesn't know which domain and
  console belong to the defender. Its public-IPv4-literal check always runs
  and needs no configuration; that's the part that catches most mistakes
  from a fresh clone. Maintainers additionally export
  `F0_IDENTIFIER_DENYLIST` (a space-separated list of patterns, injected in
  CI from a repository secret) to catch specific real hostnames. A fork
  without that secret still gets the structural IPv4 check — it just won't
  know the maintainers' own denylist, which is by design: publishing the
  denylist would publish the very strings it exists to hide.

## Two workflow gotchas

- **After editing TypeScript, restart any running `tsx` process.** `tsx`
  compiles at startup; a `pnpm dev` server or a manually started
  `npx tsx src/server.ts` will not pick up source edits until you restart it.
  If a change "isn't happening," check this before anything else.

- **`pnpm e2e` needs a seeded stack.** The Playwright suites assume a
  populated console: a demo API key, an enrolled agent, and three alert
  channels in specific states. Against a fresh, unseeded stack they fail in
  ways that read as product bugs rather than as a missing fixture. Seed it
  first:

  ```sh
  F0_E2E_ADMIN=<F0_ADMIN_TOKEN> F0_DB_PATH=<demo db> node scripts/e2e/seed.mjs
  # prints the F0_E2E_KEY to export, then:
  export F0_E2E_KEY=... F0_E2E_ENROLL=<F0_ENROLLMENT_TOKEN>
  pnpm e2e                       # or one suite: node scripts/e2e/tokens-ui.mjs
  ```

## How to add a token type

A token type is one file in `packages/tokens-core/src/` implementing
`TokenTypeDefinition` (`configSchema`, `generate()`, `matchTrigger()`),
registered in `packages/tokens-core/src/registry.ts`. `generate()` produces
the artifacts a defender deploys (pixel URLs, documents, DNS hostnames);
artifacts are DB-backed (`token_files`, base64) rather than files on disk.
`matchTrigger` rules must mirror the artifact paths the gateway actually
serves in `apps/gateway/src/artifacts.ts` — if those two drift, the token
looks like it fires but the API never confirms it (or vice versa).

`apps/mcp` does not currently pull its token-type list from
`packages/tokens-core` or `packages/shared` — it hand-declares its own enum
in `apps/mcp/src/server.ts`. Until that's wired up, adding a token type also
means updating that file so the MCP tool surface stays in sync.

For the full set of repo invariants (token ID format, trigger authority,
gateway hardening rules, env var reference), see `AGENTS.md` — that document
is the authority; this file doesn't duplicate it.

## Commit / PR expectations

- Keep commits focused; explain the *why* in the commit message.
- New source files carry an Apache-2.0 license header (see existing files
  for the exact form).
- Config goes through `F0_*` environment variables, documented in
  `AGENTS.md` — no new hardcoded values, no secrets in code.
- Don't add real hostnames, IPs, or other operational identifiers to
  tracked files; `./scripts/ci/check-identifiers.sh` will catch most of
  this, but it's not a substitute for thinking about it.
