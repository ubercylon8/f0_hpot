# Token Types

f0_hpot ships 16 token types. Each one is a small artifact — a URL, a
document, a hostname, a set of fake credentials — that does something
innocuous-looking but alerts the moment someone (or something) touches it.
This page is the reference for what each type actually plants, what trips
it, how severe that trip is scored, and where it's worth deploying.

Every type is defined in `packages/tokens-core/src/` as a single
`TokenTypeDefinition` implementing `generate()` (produces the artifact) and
`matchTrigger()` (decides whether an incoming gateway event is a real hit,
and at what severity). Related types are grouped a few to a file —
`network-tokens.ts`, `document-tokens.ts`, `pdf-clone-tokens.ts`,
`cloud-tokens.ts` — and all of them are listed in `registry.ts`. The gateway
(`apps/gateway`) only recognizes the token id in
attacker-controlled input and forwards a candidate event; the API
(`apps/api`) is what actually runs `matchTrigger` and creates the incident.

## Summary

| Type | Artifact you plant | What trips it | Severity | Group |
|---|---|---|---|---|
| `web_bug` | 1×1 pixel URL | any HTTP fetch of the pixel | medium | Network |
| `custom_image` | operator-uploaded image URL | any HTTP fetch of the image | medium | Network |
| `dns` | unique hostname | any DNS resolution of the name | high | Network |
| `email` | unique trigger address | inbound mail to the address (needs MX + inbound :25) | high | Network |
| `windows_folder` | folder containing `desktop.ini` | Explorer resolving the icon's UNC path → DNS | high | Network |
| `sensitive_cmd` | fake command-output page | HTTP fetch of the decoy page | high | Network |
| `fast_redirect` | link that 302s onward | the click — captured, then redirected | medium | Network |
| `sql_injection` | decoy endpoint rules | a request matching the injection decoy | high | Network |
| `qr_code` | printable QR PNG | scanning it (fetches the encoded URL) | high | Documents |
| `word_doc` | `.docx` with a remote image | opening it in Word | high | Documents |
| `excel_doc` | `.xlsx` with a hyperlink | opening / following the link | high | Documents |
| `pdf_doc` | PDF with an open-action | opening it in a reader that honours the action | high | Documents |
| `cloned_website` | beaconed clone of a real page | loading the clone | high | Documents |
| `aws_keys` | decoy AWS credentials | your CloudTrail wiring reporting their use | high | Cloud decoys |
| `azure_config` | decoy client id / secret | your Azure audit wiring reporting their use | high | Cloud decoys |
| `honeypot` | *nothing* — a reference token | an agent sensor reporting against it | n/a — never matches | Agent |

All 16 rows come straight from `tokenTypeSchema` in
`packages/shared/src/token.ts` — that enum is the authoritative list. If a
type isn't in this table, it isn't a real token type.

---

## Network tokens

These are served directly by the gateway. The token id is embedded in a
hostname label or the first URL path segment; the gateway lowercases and
extracts it before ever asking the API whether it's real.

### `web_bug`

**Artifact:** a URL — `<gateway>/<tokenId>/pixel.gif` — serving a static 1×1
transparent GIF. No config.

**Trigger:** any HTTP GET of that path. Severity: **medium**.

**Plant it:** emails, wikis, internal bookmark pages, anywhere an HTML
`<img>` tag or link preview will fetch it automatically.

### `custom_image`

**Artifact:** a URL — `<gateway>/<tokenId>/image` — serving an image you
upload after creation (`POST /api/v1/tokens/:id/image`; ≤4 MiB, common
raster formats). Until you upload one, the URL has nothing behind it.

**Trigger:** any HTTP GET of that path. Severity: **medium**.

**Plant it:** anywhere a web bug would go, when you want the bait to look
like your own logo, screenshot, or document thumbnail instead of a blank
pixel.

### `dns`

**Artifact:** a unique hostname, `<tokenId>.<baseDomain>`. No config.

**Trigger:** any DNS query naming that hostname (as the query name or one of
its labels). Severity: **high** — a DNS lookup for a name that exists only
in one config file or one attacker's notes is rarely accidental.

**Plant it:** `/etc/hosts` entries, tool configs, internal documentation,
anywhere that gets read rather than executed. Requires your zone delegated
to (or served by) the gateway's authoritative DNS.

### `email`

**Artifact:** a unique address, `<tokenId>@<mailDomain>` (defaults to the
base domain; `mail_domain` config overrides it per-token).

**Trigger:** inbound SMTP `RCPT TO`/delivery naming that address. Severity:
**high**. Requires MX records pointing at the gateway and inbound `:25`
actually reaching it — without that wiring the address is a dead end that
looks planted but never fires.

**Plant it:** breach-filler credential dumps, retired resumes, "contact"
fields in decoy config files.

### `windows_folder`

**Artifact:** a `desktop.ini` file (plus a readme) whose `IconResource`
points at a UNC path on the token's hostname — `\\<tokenId>.<baseDomain>\share\folder.ico`.
No config.

**Trigger:** Windows Explorer resolving that UNC path to render the folder
icon sends a DNS query for the hostname; that query is what actually fires
the alert (a `dns`-shaped match, severity **high**). Browsing the folder is
enough — nothing needs to be opened.

**Plant it:** drop `desktop.ini` into a folder an intruder would browse
(e.g. `Finance\Payroll Exports`), then mark the folder and file `system`/
`hidden` so Explorer reads it (`attrib +s`/`attrib +h`). Explorer caches
folder icons, so test from a machine that hasn't opened the folder before.

### `sensitive_cmd`

**Artifact:** a URL — `<gateway>/<tokenId>/cmd/<cmd_name>` — serving a
realistic fake output page. `cmd_name` config picks the flavor: `ifconfig`
(default), `ipconfig`, `whoami`, or `cat_etc_shadow`.

**Trigger:** any HTTP fetch of `/<tokenId>/cmd` or `/<tokenId>/cmd/...`.
Severity: **high**.

**Plant it:** behind a bookmarklet, shell alias, or "helpful" documentation
link — something that looks like it *runs* a command but actually just
fetches a page. Someone triggering "the wrong" planted command from a bait
doc is exactly the signal this is for.

### `fast_redirect`

**Artifact:** a URL — `<gateway>/<tokenId>/r` — that 302-redirects to a
`target_url` you configure (required).

**Trigger:** any HTTP fetch of that path — the visitor is captured (source
IP, UA, etc.) *before* the redirect fires. Severity: **medium**.

**Plant it:** link-tracking inside documents, shortened URLs, anywhere you
want a working link that also tells you who clicked it.

### `sql_injection`

**Artifact:** a config snippet (nginx `location` block or Apache
`Redirect`) that 302s a decoy path (`path`, default `/search.php`) on
**your own** web server to `<gateway>/<tokenId>/sqli`. `server_kind` picks
nginx or apache.

**Trigger:** any HTTP fetch of `/<tokenId>/sqli` — i.e., a scanner or
attacker hitting your decoy "vulnerable" endpoint and getting redirected
into the tracker. Severity: **high**.

**Plant it:** deploy the generated rule on a real, internet-facing web
server. This is the one network type whose artifact lives outside f0_hpot
entirely — the gateway only ever sees the resulting redirect.

---

## Document tokens

### `qr_code`

**Artifact:** a printable PNG QR code encoding `<gateway>/<tokenId>/qr`,
plus the URL itself. Optional `filename`.

**Trigger:** scanning the code (or otherwise fetching the encoded URL).
Severity: **high**.

**Plant it:** printed and stuck somewhere physical, or embedded in a slide
deck / PDF / poster — anything a phone camera might scan.

### `word_doc`

**Artifact:** a `.docx` (default `quarterly_report.docx`, or your
`filename`) containing an image relationship marked
`TargetMode="External"`, pointing at `<gateway>/<tokenId>/pixel.gif`.

**Trigger:** Word resolving that external image when the document is
opened (and remote content isn't blocked). Severity: **high**.

**Plant it:** shared drives, intranets, bait email attachments. Pick a
`filename` that blends into the share it lands in — the generated default
is a placeholder, not camouflage.

### `excel_doc`

**Artifact:** an `.xlsx` (default `figures.xlsx`) with one hyperlinked
cell, external relationship targeting `<gateway>/<tokenId>/pixel.gif`.

**Trigger:** clicking the hyperlink from within Excel. Severity: **high**.

**Plant it:** same bait locations as `word_doc` — this one needs the click,
not just the open.

### `pdf_doc`

**Artifact:** a hand-built PDF (default `confidential_report.pdf`) whose
`/OpenAction` fires a URI action at `<gateway>/<tokenId>/pixel.gif`, with a
link annotation over the visible text pointing at the same URL.

**Trigger:** either the open-action firing when the document is opened, or
the link being clicked — both resolve the same tracking URL. Severity:
**high**. Detection depends on the reader actually honoring open-actions
and remote URI fetches; some viewers strip or sandbox both, so treat this
as the least reliable of the document types.

**Plant it:** anywhere a Word/Excel bait file would go, when a PDF fits the
pretext better.

### `cloned_website`

**Artifact:** a copy of a page you point it at (`target_url`, required),
fetched and stored at creation time, served from
`<gateway>/<tokenId>/site` with an invisible beacon injected into the
markup (the markup itself is left otherwise unmodified).

**Trigger:** loading the cloned page — either the `/site` path itself or a
beaconed request that hits `/pixel.gif` inside it. Severity: **high**.

**Plant it:** phish-test your own users, or watch for link-scrapers picking
up a lookalike of your VPN/SSO portal. The token detail view shows clone
status — re-clone if the source page changed or the fetch failed.

---

## Cloud decoys

**`aws_keys` and `azure_config` are inert without one-time cloud wiring.**
Both types generate believable, unprivileged credential material *and* a
readme with the exact steps to route your own tenant's audit log to this
platform's ingest URL. Until that one-time wiring is done, planting the
credentials produces nothing when they're used — no incident, no alert,
just silence. That is expected, not a bug: the token can't see credential
use on its own, only your cloud provider's audit trail can, and only once
you've told it to forward there. Do the wiring step in the generated
readme before you plant either type, or you will conclude — wrongly —
that the product doesn't work.

### `aws_keys`

**Artifact:** a decoy access key id (`AKIA...`) and secret key, a
`credentials` file in AWS CLI format, and a readme with the CloudTrail →
EventBridge → `<gateway>/<tokenId>/aws` wiring instructions and the steps
to create a matching, permission-less IAM user. No config.

**Trigger:** any HTTP POST your CloudTrail/EventBridge wiring makes to the
ingest URL once the decoy key is used. Severity: **high**.

**Plant it:** as an IAM user with *no* permissions attached — any use of it
is inherently suspicious. Drop the `credentials` file where a compromised
host or repo scan would find it.

### `azure_config`

**Artifact:** a decoy client id (UUID) and client secret, an `.env` file
(`AZURE_TENANT_ID`/`AZURE_CLIENT_ID`/`AZURE_CLIENT_SECRET`), and a readme
with the Azure Monitor diagnostic-setting → Event Grid/Logic App →
`<gateway>/<tokenId>/azure` wiring instructions plus the `az ad sp
create-for-rbac` command to create the matching, role-less service
principal. No config.

**Trigger:** any HTTP POST your sign-in-log wiring makes to the ingest URL
once the decoy secret is used to sign in. Severity: **high**.

**Plant it:** same idea as `aws_keys` — a service principal with no role
assignments, credentials planted somewhere a lateral-movement attempt would
look.

---

## Agent

### `honeypot`

**`honeypot` is the odd one out.** It plants no artifact a network
attacker could ever reach: `matchTrigger` returns `{ matched: false }`
unconditionally, so no gateway HTTP/DNS/SMTP event can trip it — full
stop. Its only purpose is to give an agent-run honeypot sensor (SSH, SMB,
RDP, HTTP login, planted-credential, file-watch — see the agent's own
sensor kinds) a managed, revocable token id to report detections against.
Agent-reported incidents carry their own severity and bypass the type's
`matchTrigger` entirely (`event.detail.sensor` present ⇒ agent event).

**You will almost never create one by hand.** Since the sensor-provisioning
fix, saving a sensor in the Agents console tab without a `token_id`
automatically creates a `honeypot` token for it — named `<hostname> ·
<sensor kind>` (e.g. `dmz-01 · ssh`), with `sensor`/`host` config populated
so the artifact label reflects it. Create one manually only when you want
several sensors across different agents to share a single revocable token —
then paste that token's id into the `token_id` field behind each sensor
row.

**Config:** `sensor` (label) and `host` (label) — cosmetic only, they
render into the artifact's display label and are otherwise unused by
`matchTrigger`.

> **One SSH session can legitimately produce two incidents.** The SSH
> sensor deliberately reports a **credential attempt** (the password
> captured at auth time) and, separately, a **command execution** (what the
> attacker ran after logging in) as two distinct incidents against the
> same honeypot token — they're labeled by their `event` field and are
> separate evidence, not a duplicate-alert bug. Expect that shape from any
> honeypot type that captures both a login and post-login activity.

---

## Where the trigger rules live

Every `matchTrigger` above mirrors a path the gateway actually serves in
`apps/gateway/src/artifacts.ts` (`pixel.gif`, `image`, `r`, `qr`,
`cmd/:name`, `site`, `sqli`, `azure`, `aws`) or an event kind it forwards
(`dns`, `smtp`). If you add a new token type, its `matchTrigger` rules and
the gateway's `artifactResponder` need to move together — a type that
matches a path the gateway never serves can never trigger, and one where
the gateway serves a path nothing matches leaks a working artifact with no
alert behind it.
