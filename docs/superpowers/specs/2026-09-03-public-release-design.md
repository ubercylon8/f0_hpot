# Design — preparing f0_hpot for public release

**Date:** 2026-09-03
**Status:** approved, pending implementation plan
**Scope:** everything required to publish `ubercylon8/f0_hpot` as a credible
open-source project. No product code changes.

---

## 1. Problem

The repository is private and reads, from the outside, as a much earlier
project than it is. Three things block publication:

1. **The README is materially false.** It describes `apps/web`, `apps/mcp` and
   `agent/` as *planned*, and the project as *"early development (Phase 1)"*
   where *"web bug / DNS / fast-redirect tokens work end-to-end."* In fact all
   16 token types ship, the console is feature-complete, the Go agent runs as a
   Windows service and a systemd unit with signed self-update, and the MCP
   server is live. A reader concludes the project is a stub.
2. **Two docs carry live operational identifiers.** `docs/HANDOFF.md` and
   `docs/TEST-FINDINGS.md` contain the production VPS IP, the real token and
   console domains, lab agent hostnames, and the maintainer's email address —
   in the working tree *and* in git history, which publishes with the repo.
3. **No community or contribution surface exists.** No CONTRIBUTING, SECURITY,
   CODE_OF_CONDUCT, CHANGELOG, issue or PR templates; the repo has no
   description and no topics.

The engineering is further along than anything readable from outside. Most of
this work is making the documentation catch up to code that already shipped.

## 2. Decisions taken

| Decision | Choice | Rationale |
|---|---|---|
| Public name | **`f0_hpot`** | Keeps the existing GitHub URL; no redirect, no broken clone. Package name and docs align to it. |
| Internal workspace scope | **unchanged** (`@f0/deception-*`) | Those packages are `private` and never published; renaming touches every import for no public benefit. |
| Internal docs | **Split** | Durable rationale becomes public `ARCHITECTURE.md` + `docs/HARDENING-LOG.md`; working notes move to gitignored `docs/internal/`. |
| Docs surface | **In-repo Markdown + Mermaid + screenshots** | Renders natively on GitHub, diffs in PRs, no site build to keep green. |
| Vulnerability reporting | **GitHub private vulnerability reporting** | No inbox exposed; provides draft advisories and CVE issuance. |
| Screenshots | **From a local demo stack** | Production console screenshots would leak the very identifiers section 3 removes. |

## 3. Sanitization

### 3.1 What must be removed

| Identifier | Where |
|---|---|
| Production VPS IPv4 address | `docs/HANDOFF.md`, `docs/TEST-FINDINGS.md`, 2 commits |
| Operator's apex domain and its token/console subdomains | `docs/HANDOFF.md`, `docs/TEST-FINDINGS.md`, 3 commits |
| Two lab agent hostnames | `docs/TEST-FINDINGS.md` |
| Maintainer email address | `docs/HANDOFF.md` |

Verified clean: no private keys, certificates or real credentials were ever
committed. The only env files in history are `deploy/.env.example` and
`deploy/local-demo.env`, both containing placeholder values
(`local-demo-secret`, `bootstrap-test-123`) that are correct to publish.

### 3.2 Proportionality

Stated plainly so the effort is not mistaken for alarm: a *token domain*
becoming publicly known is not fatal — Thinkst's free service operates on
`canarytokens.com`, which everyone knows, and any planted artifact reveals its
own domain to whoever finds it. The reasons to scrub are narrower and real:

- the **console IP** is an unnecessary scanning target, and
- the domain in *these* docs identifies *which organisation* runs the
  deception, which is the part an adversary can act on.

Cheap to fix, worth fixing, not an emergency.

### 3.3 Method

Working-tree scrub alone is insufficient: publishing the repo publishes all 135
commits. Sequence:

1. `git rm --cached docs/HANDOFF.md docs/TEST-FINDINGS.md`; move both to
   `docs/internal/`, which is added to `.gitignore`. Note the consequence:
   these files stop being version-controlled. They are working notes, so this
   is acceptable, but the implementation must leave them on disk and say so
   explicitly rather than appearing to delete them — and if their history
   matters, a private repository is the place for it. This is a deliberate
   trade, not an oversight.
2. Rewrite history with `git filter-repo --replace-text`, mapping each
   identifier to a placeholder (`203.0.113.10` from the RFC 5737 documentation
   range, `example.com`, `host-a` / `host-b`, `security@example.com`).
3. **Order matters.** The rewrite changes commit SHAs, and the hardening log's
   entire value is *finding → fix commit*. `filter-repo` writes
   `.git/filter-repo/commit-map`; the public `docs/HARDENING-LOG.md` is authored
   **after** the rewrite, with every referenced SHA remapped through that file.
   Doing the rewrite first turns a broken-reference problem into a non-problem.
4. Verify on a `--mirror` clone and diff before touching the real remote.
5. Force-push. The VPS clone at `/home/jimx/f0_hpot` then needs
   `git fetch origin && git reset --hard origin/master`.

### 3.4 Regression gate

A new blocking CI job, `no-operational-identifiers`, greps tracked files for
public IPv4 addresses outside the documentation ranges, the real domains, and
the lab hostnames. It sits alongside the existing zizmor / semgrep / gitleaks
gates and follows the same principle already established in this repo: a rule
that caught something once must not be able to stop catching it.

## 4. Documentation architecture

```
README.md            hero · screenshot · what it is · quickstart · comparison table
ARCHITECTURE.md      mermaid diagrams · component boundaries · data model
CONTRIBUTING.md      dev setup · invariants · gates · PR expectations
SECURITY.md          disclosure policy · responsible-use scope
CODE_OF_CONDUCT.md   Contributor Covenant 2.1
CHANGELOG.md         Keep a Changelog · opens at 0.1.0
docs/
  INSTALL.md         refresh (exists, 175 lines)
  USER-GUIDE.md      refresh (exists, 220 lines)
  TOKEN-TYPES.md     new — all 16 types
  AGENT-GUIDE.md     new — enrollment, sensors, self-update, service lifecycle
  ALERTING.md        new — 5 channel kinds, throttling, payload shapes
  HARDENING-LOG.md   new — scrubbed 46-finding audit with remapped SHAs
  img/               new — console screenshots from a local demo stack
  internal/          gitignored — HANDOFF.md, TEST-FINDINGS.md
.github/
  ISSUE_TEMPLATE/bug_report.yml, feature_request.yml, config.yml
  PULL_REQUEST_TEMPLATE.md
  workflows/no-identifiers.yml
```

`AGENTS.md` and `CLAUDE.md` remain public. Agent-readable repo docs are now
conventional, and `AGENTS.md`'s "Conventions & invariants" section is the single
best contributor reference in the repository — `CONTRIBUTING.md` links to it
rather than duplicating it.

### 4.1 README

Replaces the false status block. Contents, in order: one-line description; a
console screenshot; what it is and who it is for; a comparison table against
commercial canary offerings and against DIY canarytokens; quickstart (local
demo stack in ~2 minutes); production deploy pointer; documentation index;
responsible-use line; licence. Badges: CI status, licence, Node 22, Go version.

The status paragraph becomes accurate: 16 token types, console, agent fleet,
MCP triage, alerting — pre-1.0 and self-hosted, with a stated stability caveat.

### 4.2 ARCHITECTURE.md

Three Mermaid diagrams, each showing a real mechanism rather than decorating a
box list:

1. **Trigger flow** — gateway (HTTP/DNS/SMTP catch-all, parses attacker input by
   design) → `POST /api/v1/incidents` where the token's own `matchTrigger` is the
   authority → alert fan-out with per-(token, source-IP) throttling. Must make
   visible that the gateway never decides whether an event is a real trigger,
   and that a 404 from the API is a normal outcome.
2. **Component topology** — the four TypeScript apps, the Go agent, SQLite/WAL,
   and which ports face the public internet.
3. **Agent lifecycle** — enrol → heartbeat → fleet-managed sensor config
   delivery → signed self-update → retire (dormancy, deliberately *not* remote
   uninstall).

Prose covers the invariants and the decisions behind them, drawn from
`HANDOFF.md`: lowercase-only token ids (DNS case-insensitivity), token ids at
any label depth, DB-backed artifacts rather than filesystem paths, the
agent-reported incident path that bypasses type rules
(`event.detail.sensor` present), and why retirement is not uninstall.

### 4.3 TOKEN-TYPES.md

One row and one short section per type — artifact produced, what trips it,
severity, and where to plant it — for all 16:
`web_bug`, `custom_image`, `dns`, `email`, `qr_code`, `word_doc`, `excel_doc`,
`pdf_doc`, `windows_folder`, `sensitive_cmd`, `cloned_website`, `sql_injection`,
`fast_redirect`, `aws_keys`, `azure_config`, `honeypot`.

`honeypot` is documented as the exception it is: it plants nothing, can never be
tripped from the internet, and is now provisioned automatically when a sensor is
saved without one.

### 4.4 AGENT-GUIDE.md

Enrollment (managed tokens, one-liners per platform), the six sensor kinds
(`ssh`, `http_login`, `smb`, `rdp`, `planted_credential`, `file_watch`), sensor
config delivery through heartbeat, signed self-update, service lifecycle on
systemd and Windows SCM, and the documented platform limit that NTFS
last-access updates are disabled by default so bait-read detection probes and
reports rather than pretending.

### 4.5 ALERTING.md

The five channel kinds (`email`, `webhook`, `syslog`, `elasticsearch`, `loki`),
their config shapes, the payload schema, per-(token, source-IP) throttling, and
the blank-means-keep secret editing rule. States honestly which integrations are
verified end-to-end and which are wire-format-tested only.

## 5. Community and release engineering

- **SECURITY.md** — GitHub private vulnerability reporting (enabled in repo
  settings), supported-versions statement, and a **responsible-use scope**: this
  software runs honeypots that capture credentials and NTLM hashes; deploy only
  on infrastructure you control; captured credentials are attacker-supplied and
  may belong to third parties; check your jurisdiction. Non-preachy, one short
  section. Its absence in a tool of this category reads as carelessness.
- **CODE_OF_CONDUCT.md** — Contributor Covenant 2.1, unmodified.
- **CONTRIBUTING.md** — prerequisites (Node ≥22, pnpm, Go), `pnpm install && pnpm build`
  before typecheck/test, the full gate list (`pnpm typecheck`, `pnpm test`,
  `go test ./... && go vet ./... && gofmt -l .`, `semgrep scan --config .semgrep.yml`),
  how to add a token type, and a pointer to the invariants in `AGENTS.md`.
- **CHANGELOG.md** — Keep a Changelog format, opening entry `0.1.0`.
- **`v0.1.0` tag** — `release.yml` already cross-compiles five platforms and
  signs an Ed25519 manifest, but nothing has ever been tagged, so agents report
  a commit SHA as their version (the live fleet reports `vd2d18ee`). Tagging
  aligns agent version, release artifacts and changelog.
- **Repo metadata** — description and topics are empty; set both
  (`honeypot`, `canarytokens`, `deception`, `blue-team`, `threat-detection`,
  `self-hosted`).

## 6. Non-goals

- No product code changes. Documentation, metadata and history only.
- No docs site (mkdocs / Docusaurus / GitHub Pages). Premature pre-1.0 and adds
  a CI gate that can rot.
- No renaming of internal `@f0/deception-*` workspace packages.
- No logo or brand design work.
- No container publishing to ghcr.io — the release path today is signed agent
  binaries, and adding image publishing is a separate decision.

## 7. Risks

| Risk | Mitigation |
|---|---|
| History rewrite breaks the VPS clone | Documented reset command; verify on a mirror first |
| Rewrite invalidates SHA references in the hardening log | Author the log *after* the rewrite, remapping via `commit-map` |
| Screenshots leak identifiers | Capture from a local demo stack only, never production |
| Docs drift from code again | The identifier gate is automated; content accuracy is covered by the release checklist in CONTRIBUTING |

## 8. Success criteria

1. `git log -S` finds no operational identifier in any commit.
2. The `no-operational-identifiers` CI job passes and fails correctly when fed a
   deliberate violation.
3. A reader who has never seen the repo can go from landing on the README to a
   triggered token on a local stack without asking a question.
4. Every claim in the README is true of the shipped code.
5. GitHub's community-standards checklist is complete.
