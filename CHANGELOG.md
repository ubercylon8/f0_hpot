# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project has not yet been tagged, so this file starts at the first
public release rather than reconstructing a history that predates it.

## [0.1.0]

First public release.

### Added

- **16 token types** (`packages/tokens-core`, enumerated in
  `packages/shared/src/token.ts`'s `tokenTypeSchema`): `web_bug`,
  `custom_image`, `dns`, `email`, `qr_code`, `word_doc`, `excel_doc`,
  `pdf_doc`, `windows_folder`, `sensitive_cmd`, `cloned_website`,
  `sql_injection`, `fast_redirect`, `aws_keys`, `azure_config`, `honeypot`.
  Each is one file implementing `generate()` and `matchTrigger()`,
  registered in `packages/tokens-core/src/registry.ts`.
- **Public gateway** (`apps/gateway`) that catches token reach-back over
  HTTP, authoritative DNS, and SMTP, and forwards candidate trigger events
  to the API. The gateway never decides whether an event is a real
  trigger — that authority lives in the API's per-token-type
  `matchTrigger`, run against `POST /api/v1/incidents`.
- **Management console** (`apps/web`, React 19 + Vite + Tailwind):
  dashboard, tokens, incidents, agents, alert channels, and settings.
- **Go endpoint agent** (`agent/`) with fleet-managed enrollment,
  heartbeat, and configuration (`agent_sensors` table, delivered over
  heartbeat rather than local config) covering six sensor kinds
  (`sensorKindSchema` in `packages/shared/src/agent.ts`): `ssh`,
  `http_login`, `smb_share`, `rdp_banner`, `planted_credential`,
  `file_watch`. Self-update manifests are Ed25519-signed and verified
  against an embedded public key before a release is applied
  (`agent/internal/update/update.go`).
- **Five alert channel kinds** (`alertChannelKindSchema` in
  `packages/shared/src/agent.ts`): `email`, `webhook`, `syslog`,
  `elasticsearch`, `loki`, throttled per `(tokenId, sourceIp)`. `webhook`
  and `syslog` are verified against live sinks; `email` delivery is
  exercised against a local test SMTP sink in the e2e suite and needs an
  SMTP relay you supply for real delivery; `elasticsearch` and `loki` are
  verified at the wire-format level against local mock sinks, not real
  clusters. Slack and Microsoft Teams incoming webhooks reject the
  `webhook` channel's payload as shipped — see `docs/ALERTING.md` before
  pointing one at a chat platform.
- **MCP server** (`apps/mcp`) exposing management and triage tools over
  stdio and streamable HTTP for LLM-driven incident triage. It does not
  yet depend on `packages/shared` and hand-writes its own request/response
  shapes (see `AGENTS.md`, "Conventions & invariants" #3).

### Security

- This release was preceded by a self-audit against a live deployment;
  see `docs/HARDENING-LOG.md` for the full finding-by-finding record and
  the commits that fixed each one.
- The gateway's attacker-facing invariants (no `exec`, no request-path to
  filesystem mapping, size caps on all input) are enforced by design and
  by code review, not by an automated gate: the `.semgrep.yml` rules
  written for them are scoped to Go and the gateway is TypeScript, so
  they never match. See `ARCHITECTURE.md` for why.
