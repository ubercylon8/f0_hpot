# f0_hpot — hardening log

This is a self-audit of a running f0_hpot deployment: every defect found while exercising it
end to end against a real target, each paired with the commit that fixed it. Findings are kept
in full rather than pruned once fixed, so the reasoning behind each change stays readable —
including findings that describe real, sometimes unflattering, defects in this project.

**Date:** 2026-08-29
**Target:** a production deployment (console at `console.example.com`, `203.0.113.10`), token
domain `tokens.example.com`, commit `27e299f`.
**Method:** console click-through (Chrome), live token triggering from a separate VM over the
real internet path, SMTP/DNS from the VPS itself, plus a full code read of the token registry,
console, agent, sensor and alert-channel subsystems. Closed out with the full Playwright e2e
suite (§5).

**Status:** every finding below is fixed and deployed unless explicitly marked otherwise — see §6.

Each finding is tagged with how it was established:

- **LIVE** — reproduced against the running deployment.
- **CODE** — established by reading the source; not yet reproduced live.

---

## 1. What was verified working

This matters as much as the defect list — the core pipeline is sound.

| Area | Result |
|---|---|
| Token creation, all 16 types | 16/16 created via API, correct artifacts returned |
| Gateway HTTP triggers | 12/12 fired, correct content types (gif/png/html/302/json) |
| DNS trigger via real recursive resolution | works — delegation and zone cut are correct |
| SMTP ingest on port 25 | works — full session, incident recorded with from/to/subject |
| Incident recording | 15/15 triggers recorded |
| Severity assignment | matches each token type's `matchTrigger` exactly |
| Webhook alert delivery | 16/16 expected alerts delivered to sink |
| Alert throttling | correct — 3 rapid repeats → 3 incidents, 1 alert (`F0_MAX_ALERTS_PER_MINUTE=1`) |
| `cloned_website` remote clone | succeeded; `/site` serves the cloned page |
| GeoIP enrichment | enabled and populating |
| Agent enroll → heartbeat → re-key | works (Windows), including revoke + re-enroll with a new token |

**Not a platform bug:** SMTP triggering from the Debian VM produced nothing because that VM's
network blocks **outbound** port 25. The same session from the VPS itself succeeded. Test email
tokens from a host with outbound 25, or locally on the server.

---

## 2. Priority 1 — correctness: silently wrong or broken

### P1-1 · Agent `status` never expires; three conflicting definitions of "online" — **LIVE** · ✅ FIXED `e995cbf`

The `agents.status` column is set to `online` at each heartbeat and **nothing ever sets it back**.
There is no sweeper. Meanwhile three different consumers each define liveness differently:

| Consumer | Definition |
|---|---|
| `GET /api/v1/agents` (`status` field) | stored column — **permanently `online` after the first heartbeat** |
| `GET /api/v1/stats` → dashboard KPI | `lastSeenAt` within `2 × F0_AGENT_POLL_INTERVAL` (120 s) |
| Agents page dot + dashboard attention strip | `status === "online" && lastSeenAt < 180 s` |

Evidence: 4.5 minutes after the agent stopped, `GET /agents` still returned `"status": "online"`
while `GET /stats` returned `{"total": 1, "online": 0}`. The dashboard KPI read `0/1` while the
Agents row read `online`.

Impact: any consumer trusting the API's `status` (MCP triage tools, scripts, integrations) sees a
dead agent as healthy — the worst failure mode for a security product. The UI only papers over it
with a client-side clock. The 120 s/180 s split also makes the dashboard contradict itself for
agents last seen in that window.

Fix: derive `status` from `lastSeenAt` at read time in the API, one shared threshold; drop the
stored column or sweep it.

### P1-2 · `windows_folder` token artifact is not resolvable — **LIVE** · ✅ FIXED `e995cbf`

`generate()` emits `<tokenId>@<domain>` (e.g. `3nz5zbzy72cg@tokens.example.com`). The gateway's
zone-ownership test requires `qname === domain || qname.endsWith("." + domain)`, and `@` is not `.`:

```
host 3nz5zbzy72cg@tokens.example.com   → NXDOMAIN     (the artifact as generated)
host 3nz5zbzy72cg.tokens.example.com   → 203.0.113.10, incident fires
```

The operator is handed a string that cannot trigger the token. Fix: either generate the dot form,
or document the exact Windows UNC/folder mechanism that turns the `@` form into a dot-form query —
and label the artifact accordingly.

### P1-3 · `planted_credential` does not detect reads — **CODE** · ✅ FIXED `45baf75`

The sensor's headline use case is "someone opened my fake password file." `statSignature()` returns
**only `ModTime()`** — atime is never consulted, despite the sensor deliberately backdating atime at
plant time. So `cat bait.txt` produces no incident; only writes, touches and deletion do.

Fix: compare atime too (as `file_watch` already does on Linux), or restate the sensor's contract in
the UI as write/delete detection.

### P1-4 · Captured NTLM hashes are uncrackable (zeroed challenge) — **CODE** · ✅ FIXED `e6511e7`

In `smb.go:115`, `smb1.go:295` and `rdp_credssp.go:42`, `BuildChallenge(...)` is destructured as
`challengeMsg, _, err :=` — discarding the 8-byte server challenge. `auth.Challenge` stays all
zeroes, so every emitted `hashcat` line carries `0000000000000000` and cannot be cracked or
correlated. Only the SMB1-legacy path threads a real challenge.

This silently degrades the main value of the SMB/RDP honeypots. Only the credential *metadata*
(username, domain, host) is usable today.

### P1-5 · Sensor config changes never reach a running agent — **CODE** · ✅ FIXED `45baf75`

`specsEqual()` compares only `kind` and `enabled`, not `config`. Changing a port, `token_id`, `path`
or label in the console sensor editor does **not** restart the sensor — the agent keeps the old
config indefinitely, while the console shows the new one as deployed. Worse, when a restart *does*
occur (add/remove/toggle), `sensors.StartAll` has no stop path, so old goroutines keep their
listeners and the new ones die with `bind: address already in use`.

Fix: include config in the comparison and implement sensor shutdown. Until then, restarting the
agent after every sensor change is mandatory — this should be stated in the UI.

### P1-6 · Windows agent self-update is broken — **CODE** · ✅ FIXED `429ec44`

Two independent breaks: the artifact name is built as `f0-deception-agent-<GOOS>-<GOARCH>` with **no
`.exe` suffix**, so the Windows manifest entry is never requested; and `execSelf()` uses
`syscall.Exec`, which returns `EWINDOWS` — the error is discarded, so even a successful update keeps
running the old in-memory binary. Also `Apply` renames from `/tmp`, which fails with `EXDEV`
whenever `/tmp` is a separate mount (typical on Debian).

### P1-7 · Windows agent has no service install (already known) — **CODE** · ✅ FIXED `3d6467f`

`install_windows.go` returns `"windows installer not yet implemented"`; `--install` exits 1. The
agent runs in the foreground only, so it dies with the console session. The UI does say this, but it
makes Windows deployment impractical. **This was already flagged as the next work item.**

### P1-8 · Linux systemd service crash-looped on startup — **LIVE** · ✅ FIXED `f29b5d3`

*Found while testing the P1-7 fix; not in the original sweep.* The documented
Linux deployment path had never worked. systemd starts services with no `HOME`, the unit
set none, and `os.UserHomeDir()` errors outright when `HOME` is unset — so `config.Load()`
hit `log.Fatalf` and `Restart=always` looped it every 10 s:

```
f0-deception-agent[7845]: load state: $HOME is not defined
systemd[1]: f0-deception-agent.service: Main process exited, code=exited, status=1/FAILURE
```

Fixed in two layers: the unit pins `Environment=HOME=<parent of state dir>`, and `stateDir()`
falls back to the passwd home (then `/root` when running as root) rather than failing.
Verified: the service now stays `active` with its sensor listening.

### P1-9 · Code signing could never work as shipped — **LIVE** · ✅ FIXED `3792bfa`, `7075f01`

*Reported from the console, not found in the sweep.* Generating a self-signed
code-signing certificate failed with `400: Error: spawn openssl ENOENT`. Three
compounding problems:

1. **The tools were not in the image.** The API stage ran on `node:22-alpine`, which
   ships neither `openssl` nor `osslsigncode` — and `osslsigncode` is not packaged for
   Alpine at all. The prerequisite belonged in the image, not in the operator's lap.
   The Node stages now use `node:22-slim` (Debian) with both installed. The base had to
   change everywhere rather than just the API stage: `node_modules` is built once and
   copied into each runtime image, and `better-sqlite3` is native, so musl and glibc
   cannot be mixed.
2. **The release directory was mounted read-only.** Signing writes the signed binary
   back, so it failed with `EROFS: read-only file system` — meaning the feature could
   never have worked with the shipped compose file, whatever tooling was present.
3. **The capability gating (P2-4) was wrong here.** Signing a binary needs
   `osslsigncode`, but generating or importing a certificate only needs `openssl`; both
   were gated on the former, so the generate and upload controls stayed enabled on a
   host with neither and failed at the shell.

Verified end to end afterwards: certificate generated, the Windows agent
Authenticode-signed (`subject=CN = f0_hpot Local Code Signing`), signature extractable
from the binary, and the signed binary still downloads. `/status` now reports
`releaseSigning: true, codeSigning: true`.

### P1-10 · Retiring an agent left its honeypots running and unmonitored — **LIVE** · ✅ FIXED `ae92f70`

*Raised as a question — "does deleting an agent stop the service on the endpoint?"* It did not.
`DELETE /api/v1/agents/:id` was purely server-side: it dropped the row and the key, and the endpoint
carried on. The agent logged `heartbeat failed, retrying in 60s` **forever** while its sensors kept
listening and every detection it produced was silently rejected — a host that looks defended and
reports nothing. The console said only that the key stops working, which reads as "the agent is
gone".

The heartbeat now separates retirement from an auth failure: an unknown agent id answers **410 with
`status: "revoked"`**, while a bad key on an agent that still exists stays 401 (it may be an orphaned
process superseded by a re-enrollment, and must keep retrying). On revocation the agent stops its
sensors, prints the uninstall and re-enroll commands, and goes dormant.

**Deliberately not a remote uninstall.** Giving the console that power would let anyone who
compromised it wipe the fleet and destroy evidence, and an API restored from an older backup would
tell healthy agents they are unknown. Dormancy is recoverable; self-deletion is not. Exiting was
rejected too — the service manager would restart into the same state and bury the message.

Verified on the Debian VM: retire in the console → next heartbeat →

```
[smb] stopped
this agent was retired from the console: agent revoked
sensors stopped. To remove the service from this host, run: ... --uninstall
```

…with `:10445` genuinely released, the service still `active` rather than crash-looping, and
`--uninstall` then removing the unit cleanly.

### P1-11 · systemd hardening silently disabled the file-based sensors — **LIVE** · ✅ FIXED `2c8430d`, `ad14ec1`

*Found restoring sensors on the Debian host: `planted_credential` never fired, and nothing said why.*

The generated unit used `ProtectSystem=strict` with `ReadWritePaths=<state dir>`, which makes the
**entire filesystem read-only** to the service except the agent's own state directory. Under the
recommended systemd deployment that silently disabled two headline features: planting and re-arming
bait credentials, and landing console token deployments on disk. Both failed with no error an
operator would ever see. Confirmed directly:

```
touch /opt/backup/probe → Read-only file system
```

The e2e suite missed it because its deployment test runs the agent as a bare process, not as the
service — worth remembering when a test and a deployment disagree about privileges.

`ProtectSystem=full` keeps `/usr`, `/boot` and `/etc` read-only, which is the part that matters
since the agent has no business editing system binaries, while leaving `/opt`, `/srv`, `/var` and
homes writable for bait. `ProtectHome` and `PrivateTmp` are dropped deliberately:
`~/.aws/credentials` and `~/.ssh` are prime bait locations, and a private `/tmp` would hide deployed
tokens from the intruder they exist to attract. Arming failures are now logged rather than
swallowed, because an unarmed trap is indistinguishable from a quiet one.

### P1-12 · The planted-credential trap was never armed, and was one-shot — **LIVE** · ✅ FIXED `2c8430d`, `ad14ec1`

Two related gaps in the same sensor, both meaning reads went undetected:

1. It backdated atime only when it **planted** a file. A bait file that already existed — left by a
   previous run, or placed by the operator — was never armed, and under `relatime` (the Linux
   default) the kernel refreshes atime only when it is already older than mtime. Reproduced: atime
   two days newer than mtime, `cat` raised nothing.
2. Even for files it did plant, the trap was **one-shot**. After the first detected read, atime sits
   newer than mtime again, so nothing fires for up to 24 hours.

The sensor now arms on startup regardless of who created the file, and re-arms after each detected
read, preserving mtime exactly — moving it would look like tampering and flip the read-vs-modified
classification. Verified end to end: two consecutive reads produced two `bait_file_read` incidents.

### P2-13 · The console showed stale agent versions — **LIVE** · ✅ FIXED `2c8430d`, `ad14ec1`

The agent reported its version only at enrollment, so the console kept showing whatever first
enrolled. Confirmed on the Windows host: it displayed a two-week-old version while running the
current binary (proved by comparing SHA-256 against what the console serves). For "which hosts are
on the patched build?" that is actively misleading. The heartbeat now carries the running version
and the API refreshes it, keeping the previous value when an older agent reports none.

### P1-13 · Bait reads were undetectable on Windows — **LIVE** · ✅ FIXED `c5822e5`

`atime_windows.go` returned `""` unconditionally, on the stated premise that Go does not expose
access time portably on Windows. It does: `FileInfo.Sys()` carries a
`*syscall.Win32FileAttributeData` with `LastAccessTime`. The stub quietly reduced
`planted_credential` and `file_watch` to write/delete detection on Windows — the read case, which is
the entire point of a bait credential, never fired.

Exposing atime is not sufficient by itself: NTFS last-access updates are disabled by default on
modern Windows, and Linux hosts can be mounted `noatime`. Either way the sensor keeps catching
writes while being blind to reads. Rather than infer that from `GOOS`, the sensor now **probes the
filesystem at startup** — arm, read, look — and warns with the platform's remedy when reads will not
register. An empirical answer holds for any mount option on any platform.

Verified on the Windows VM (which reports `Last Access Time Updates ENABLED`): reading
`C:\Backups\passwords.txt` produced `bait_file_read`. Nothing fired there before.

### P1-14 · Self-update could not write under the systemd unit — **LIVE** · ✅ FIXED `42210f7`

*Found by finally exercising self-update against a real hosted manifest — it had been unit-tested,
including openssl↔Go interop, but never run end to end.* The agent fetched and verified correctly,
then failed:

```
self-update: open /usr/local/bin/f0-update-...: read-only file system
```

`ProtectSystem=full` protects `/usr`, where the binary lives, so staging and replacing the
executable were both impossible. No update mechanism can work while the binary's own directory is
read-only, so the unit now lists it alongside the state dir in `ReadWritePaths`.

Verified end to end afterwards: a signed manifest advertising a newer build produced
`updated to selfupd-v2; restarting`, the on-disk SHA-256 matched the published artifact, and the
console showed the new version — which also exercises the heartbeat version reporting (P2-13).

---

### P1-15 · A sensor could be saved with no reporting token, and would then detect into a void — **CODE** · ✅ FIXED `4e7ac4d`

*Found by asking where in the console a sensor's `token_id` gets set — the honest answer exposed
the gap.* Every sensor reports its triggers against a token id. A sensor saved without one emits
`TokenID: ""`, which `POST /api/v1/incidents` rejects at the schema (`tokenId: z.string().min(1)`).
The sensor still binds its port, still logs the connection locally, and is never heard from.

Nothing prevented this. The `token id` box was a bare free-text input, fourth in a wrapping row,
behind an `edit sensors` button, in a section whose read-only view rendered
`JSON.stringify(s.config)` — so it read as debug output rather than settings. Saving a blank or
typo'd id succeeded and the toast said *"Sensor config deployed"*, which was true and useless.
**Our own e2e suite had the bug**: it pasted a hardcoded `whwmhnd54y5b` that no fixture ever
created, and asserted success.

Two-part fix:

- `PUT /agents/:id/sensors` now resolves the token before persisting. A row without one gets a
  `honeypot` token provisioned in the same transaction (memo `<host> · <kind>`, config
  `{sensor, host}` — the type's own long-unused config keys). A row naming a missing or non-active
  token is a **400 for the whole save**, so the agent keeps its previous config rather than
  half-applying a broken one.
- The console drops `token_id` from the always-visible controls and shows `▸ token: auto` per row,
  expanding to the override for the case where several sensors share one token. The read-only list
  renders real fields plus `→ <token>` instead of a JSON dump.

Creating a honeypot token by hand is now an advanced action, not step one of two. Six API tests
cover provisioning, per-sensor uniqueness, idempotent re-save, explicit-token passthrough, and both
rejection paths.

**Deliberate non-goal:** removing a sensor leaves its auto-created token behind. Deleting it would
take the incident history with it, and a token that has fired is evidence.

---

## 3. Priority 2 — the console misleads the operator

### P2-1 · Agent drawer renders stale data after every mutation — **CODE** · ✅ FIXED `4ad3d5f`

`AgentDrawer` receives a row object from the list; `onChanged()` reloads the list but the drawer
keeps the **stale object**. After `save & deploy`, the sensor badges do not change. After saving a
memo, the `save` button stays enabled. The operator cannot tell whether the write landed. (The token
drawer refetches correctly — this is an inconsistency, not a platform-wide pattern.)

### P2-2 · Incidents cap at 200 rows with no indication and no pagination — **CODE** · ✅ FIXED `4ad3d5f`

Server default `limit=200` (max 500); the UI never sends `limit` and offers no pagination or "load
more". Past 200 incidents the list silently truncates. For an alerting product this is a data-loss
illusion — the operator believes they are looking at everything.

### P2-3 · Nine destructive controls have no confirmation — **CODE** · ✅ FIXED `4ad3d5f`, `c6be5e8`

Single-click, no confirm, no undo: alert-channel delete, API-key revoke, enrollment-token delete,
release-signing-key delete, release-file delete (row **and** one-step bulk), codesign-cert delete,
and saving a sensor set with zero rows (wipes all sensors).

Related footgun: **the API key currently in use can be revoked** from Settings — nothing marks
which row is the operator's own session key, and doing so drops them to the login gate on the
next poll.

### P2-4 · Environment-gated buttons are indistinguishable from working ones — **CODE** · ✅ FIXED `a8d40a1`

`build binaries` shells out to `make` + the Go toolchain on the API host; `sign release dir`,
`sign binaries` and the cert generate/upload need `F0_AGENT_RELEASE_DIR`, `openssl` and
`osslsigncode`. In a slim container deployment these all fail as opaque `400` toasts. The UI should
disable them with a reason (the API already knows).

### P2-5 · Incident filters never sync to the URL — **CODE** · ✅ FIXED `c6be5e8`

Filters are read from the URL at mount but never written back (except clearing the IP chip). Copying
the address bar after changing a dropdown reproduces the *old* filter set, and a refresh silently
resets the view. Deep links from the dashboard work; anything after that diverges.

### P2-6 · False empty states on first load — **CODE** · ✅ FIXED `c6be5e8`

`usePoll` exposes `loading`, but only the dashboard uses it. Tokens, Incidents, Agents and Channels
all render their "nothing here" copy during the first fetch — "No incidents match the current
filters" flashes before data arrives, which reads as "the product isn't detecting anything."

### P2-7 · `syslog` test button proves nothing — **CODE** · ✅ FIXED `c6be5e8`

The sender is UDP fire-and-forget with a 2 s timer that resolves regardless of delivery. "test alert
delivered via syslog" is emitted even if nothing is listening. Either say "sent (unverified)" or
switch to TCP syslog for a real result.

### P2-8 · Loki placeholder produces a 404 — **CODE** · ✅ FIXED `c6be5e8`

The sender appends `/loki/api/v1/push`, but the console placeholder for the field is
`http://loki:3100/loki/api/v1/push`. Following the placeholder yields
`…/loki/api/v1/push/loki/api/v1/push`. Change the placeholder to the base URL.

### P2-9 · Alert channels cannot be edited — **CODE** · ✅ FIXED `c6be5e8`, `da274f4`

No edit affordance anywhere: a typo'd webhook URL requires delete + recreate, and secrets are masked
so they cannot be recovered for the replacement.

Fixed: `PATCH /alert-channels/:id` takes a config update validated against the channel's kind
schema, and the console's dialog does double duty for add and edit. Secrets need care — the
client only ever sees a mask, so a field left blank keeps the stored value while a new value
replaces it. Kind is fixed once created (a different kind is a different config shape).
Clearing a secret outright still means delete and recreate.

**Follow-up caught by driving the console rather than the API** (`9047887`): the first
implementation dropped the secret on *every* edit — the next delivery arrived with no
`x-f0-signature` header at all. The merge iterated over the **incoming** config keys, so it only
restored a secret that arrived present-but-masked; the form omits blank fields entirely, so the
key never arrived, the loop never saw it, and the stored credential was lost. The API test missed
it because it sent the mask explicitly — the one thing the real client never does. The merge is
now driven off the stored keys, with a regression test that omits the field exactly as the form
does. Re-verified in the browser: after editing the URL, the delivery hit the new path carrying
the original secret.

### P2-10 · `ssh` sensor source IP includes the port — **CODE** · ✅ FIXED `c6be5e8`

Unlike every other sensor, the ssh honeypot records `RemoteAddr().String()` (`1.2.3.4:53422`). This
breaks the `?source_ip=` exact-match filter and gives every connection its own throttle bucket, so an
ssh brute-force floods the alert channels instead of being throttled.

### P2-11 · RDP emits duplicate incidents — **CODE** · ✅ FIXED `c6be5e8`

A non-NLA connection produces two incidents with identical detail (medium at `rdp.go:109`, high at
`rdp.go:126`). Alert throttling usually hides the second, but both rows land in the incident list.

### P2-12 · The gateway warned about broken credentials on every correct start — **LIVE** · ✅ FIXED `031eff9`

*Found while standing up the demo stack for the e2e run.* A correctly configured gateway printed:

```
WARNING: API answered 401 for the gateway credentials.
Incident forwarding and internal artifact lookups will be REJECTED.
```

…while forwarding worked perfectly (verified by triggering a token and watching the incident land).
The startup self-check probed `/api/v1/status`, which is **console scope** — and the internal secret
is deliberately not accepted there. So the check fired on every properly configured start.

A warning that always cries wolf is worse than no warning: it trains operators to ignore the one
that matters. The probe now hits an internal route, where a nonexistent token id answers 404 with
good credentials and 401/403 with bad ones. Verified both ways — silent when correct, still warning
with a wrong secret.

---

## 4. Priority 3 — polish, dead code, docs

| # | Finding | Tag | Status |
|---|---|---|---|
| P3-1 | Dashboard "Incident origins" always says *"set F0_GEOIP_DB on the API to enable"* even when GeoIP **is** enabled (`/status` → `geoipEnabled: true`) — tells the operator to fix something already done | LIVE | ✅ `d18a211` |
| P3-2 | `alertChannelKindSchema` in `packages/shared` is **never imported anywhere** and has diverged (4 kinds vs the API's 5 — missing `loki`). Violates the AGENTS.md invariant "never redefine shapes locally" | LIVE | ✅ `d18a211` |
| P3-3 | `docs/INSTALL.md` self-update recipe is wrong twice: `-X update.UpdatePublicKey=` needs the full import path, and `base64 -w0 release.pub` base64s the PEM rather than the raw key. Both fail **silently** — the updater becomes a no-op | CODE | ✅ `429ec44` |
| P3-4 | Add-agent dialog hardcodes "Run this on the honeypot host (linux/amd64)" directly above an OS selector | CODE | ✅ `3d6467f` |
| P3-5 | Keyboard shortcuts `1`–`6` fire while a Radix dialog is open (its trigger is a `<button>`, not `<select>`), navigating away and unmounting the dialog mid-edit | CODE | ✅ `596eab4` |
| P3-6 | Token drawer shows the **previous** token's data while loading the next one | CODE | ✅ `596eab4` |
| P3-7 | `sensitive_cmd`: `/<id>/cmd` without a trailing slash is *served* (defaults to ifconfig output) but does **not** match — a plausible attacker path produces no incident | CODE | ✅ `d18a211` |
| P3-8 | `email` token accepts `mail_domain` in config but the empty zod schema strips it — the address is always `<id>@<baseDomain>` | CODE | ✅ `d18a211` |
| P3-9 | `cloned_website`: `strip_assets` is accepted, stored, and never read — dead config presented as a real option | CODE | ✅ `d18a211` |
| P3-10 | `qr_code`: the gateway re-renders the QR encoding the request **path** rather than the URL (`QRCode.toBuffer(path)`) — cosmetic, doesn't affect triggering | CODE | ✅ `d18a211` |
| P3-11 | Enrollment-token "expires in hours" silently drops non-numeric input (`Number("abc")` → NaN → falsy) and creates a **non-expiring** token | CODE | ✅ `d18a211` |
| P3-12 | `api.getIncident` is exported and never used — dead code | CODE | ✅ `d18a211` |
| P3-13 | Bulk token delete reports `updated: ids.length` regardless of what existed, so the toast can overstate what happened | CODE | ✅ `d18a211` |
| P3-14 | Deployment rows only refresh on manual click — they sit at `pending` forever even after the agent finishes | CODE | ✅ `d18a211` |
| P3-15 | The API does not serve the SPA (no static handler/fallback); deep links depend entirely on Caddy's `try_files` | CODE | won't fix — Caddy owns this by design |
| P3-16 | `honeypot`-type tokens generate a bogus artifact (`token_id=<id>`) that the deploy flow will happily push as a nonsense `.url` shortcut instead of rejecting | CODE | ✅ `596eab4` |
| P3-17 | The e2e suite assumed a populated console (a `demo-console` key, an enrolled agent, three channels in set states) that **nothing in the repo created** — against a clean database it failed in ways that read as product bugs | LIVE | ✅ `dcf3484` (`scripts/e2e/seed.mjs` + AGENTS.md) |
| P3-18 | The settings suite counted "never" across the whole API-keys card, so any unrelated never-used key failed a check about `demo-console` | LIVE | ✅ `dcf3484` |

---

## 5. Regression run — full e2e suite (2026-08-29, after every fix)

Run against a local demo stack, not production, so the live deployment was untouched.

| Suite | Result |
|---|---|
| Dashboard | 6/6 |
| Tokens (all 16 types: create → configure → download → trigger) | 16/16 |
| Incidents | 11/11 |
| Agents (incl. release signing, Authenticode, live deploy loop) | 14/14 |
| Alert channels (webhook, elasticsearch, loki, syslog, email) | 9/9 |
| Settings | 7/7 |
| **Total** | **63/63** |

Reproduced from an empty database via `scripts/e2e/seed.mjs`, so the run is repeatable rather than
dependent on a hand-built environment.

**The first run failed 8 checks. None were regressions**, which is worth recording because the
distinction is the whole value of the exercise:

- **Stale expectations (5).** The suite encoded behaviour that changed deliberately. The clearest:
  it asserted the Windows one-liner *must not* contain `--install`, commented "service stub" — true
  that morning, exactly backwards once P1-7 landed. Likewise four destructive controls became
  two-step confirms (P2-3) and the syslog toast stopped promising unverifiable delivery (P2-7).
- **A missing fixture (2).** See P3-17 — the suite could not run from a clean database at all.
- **An over-broad assertion (1).** See P3-18.

One genuine product bug surfaced during setup: **P2-12**, the gateway's false credential warning.

## 6. Status

Every finding is closed. P1-1 through P1-14, P2-1 through P2-13, and P3-1 through P3-18 are fixed and
deployed, with two deliberate exceptions recorded in place:

- **P3-15** — the API not serving the SPA. Caddy owns that by design; won't fix.
- **Clearing** an alert-channel secret still requires delete-and-recreate (blank means "keep", so
  there is no way to express "set to empty"). The safer default: blank-means-erase would silently
  drop credentials on a careless save.

Test coverage grew from 40 unit tests at the start of the day to 150, plus the 63 e2e checks. Each
fix carries a regression test named for the behaviour it protects.

## 7. Test scaffolding

None left running. The webhook sink, its alert channel, the test tokens and the code-signing
certificate created during this campaign were all removed; the local demo stack was torn down. The
only lasting additions are `scripts/e2e/seed.mjs` and the e2e run instructions in `AGENTS.md`.
