## What changed and why

<!-- Short description. Link an issue if there is one. -->

## How this was verified

<!-- Which of these did you run, and what did they show? -->

- [ ] `pnpm build && pnpm typecheck && pnpm test`
- [ ] `cd agent && go test ./... && go vet ./... && gofmt -l .` (if `agent/` changed)
- [ ] `semgrep scan --config .semgrep.yml`
- [ ] `./scripts/ci/check-identifiers.sh`

## Invariant checklist

- [ ] Token IDs stay lowercase-only (DNS is case-insensitive).
- [ ] Gateway code adds no `exec`/shell-out and no request-path→filesystem mapping.
- [ ] Any new input path in the gateway has a size cap.
- [ ] New/changed cross-app data shapes live in `packages/shared`, not redefined locally.
- [ ] `noUncheckedIndexedAccess` is handled explicitly (no silent `undefined`).
- [ ] New source files carry an Apache-2.0 license header.
- [ ] No real domains, hostnames, or IP addresses added (logs, fixtures, docs, comments).
