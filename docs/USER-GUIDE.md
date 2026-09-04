# User Guide

How to use f0_deception day-to-day: plant tokens, read alerts, run honeypots.

---

## 1. Concepts

| Term | Meaning |
|---|---|
| **Token** | a deception artifact (URL, file, hostname, credentials…) tied to an alert |
| **Incident** | one recorded trigger of a token, with evidence (IP, headers, DNS query…) |
| **Gateway** | public listener that catches token triggers (HTTP / DNS / SMTP) |
| **Agent** | endpoint software running honeypot sensors + local canary detectors |
| **Sensor** | one deception component on an agent (SSH, SMB, planted credential…) |

**Golden rule:** every sensor references a *managed token id*, so all
detections — network or agent-side — appear in the same incident feed and can
be revoked/alerted centrally.

## 2. Console tour

Open `http://<console-host>` and log in with an API key (create one with
`POST /api/v1/auth/keys` or use `F0_ADMIN_TOKEN`). The console has a
sidebar with six pages; press `?` anywhere for keyboard shortcuts
(`1–6` jump between pages, `/` focuses the search box).

- **Dashboard** – posture at a glance: unacknowledged/24h/7d counters,
  active tokens, agents online, 30-day incident timeline, severity mix,
  incidents by token type, top source IPs and countries, token
  leaderboard, and a live recent-incidents feed.
- **Tokens** – searchable/filterable table. **New token** opens a dialog
  (type picker + per-type config) that hands you the artifacts to plant.
  Click any row for the detail drawer: artifacts (copy/download),
  custom-image upload, pause/resume/revoke/delete, incident history.
- **Incidents** – filter by severity, token type, ack state, or free-text
  search over the raw event. Select multiple unacknowledged incidents and
  **ack selected** in one shot; click a row for the raw event JSON and
  triage notes. Severity colors: red = high, amber = medium, blue = low.
- **Agents** – fleet table (status, sensors, last seen). **Add agent**
  gives a copy-paste install one-liner. Click a row for the drawer: memo,
  sensor editor (*save & deploy* lands on the next heartbeat), retire.
  Retiring is server-side dormancy, not uninstall: the agent's key stops
  working immediately (its past incidents are kept), and on its next
  heartbeat it learns it was retired and shuts its sensors down — but the
  service stays installed on the host until you run its binary with
  `--uninstall` there yourself. Release binaries and Ed25519 signing keys
  live here too.
- **Alert Channels** – webhook / email / syslog / Elasticsearch / Loki.
  Every channel has **edit**, a **test** button, and an enable switch
  (disabling resets the failure counter); failing channels show a failure
  badge. Editing re-shows a masked `•••` in place of any stored secret —
  leave it as the mask (or blank) to keep the stored value, or type a new
  one to replace it; the mask is never written back as a literal secret.
- **Settings** – API keys (create → shown once, revoke), server status
  (GeoIP, enrollment, throttle), and an open-mode warning when the API
  is running unauthenticated.

## 3. Token playbook

### Web bug (URL pixel)
Create `web_bug` → copy the pixel URL into emails, wikis, bookmark pages,
HTML documents. Fires when anything fetches it.

### Custom image
Create `custom_image`, then upload your own image (logo, document
screenshot, bait picture) — max 4 MiB, common raster formats (no svg):

```sh
curl -X POST $CONSOLE/api/v1/tokens/<id>/image \
  -H 'content-type: application/json' \
  -d "{\"data\":\"$(base64 -w0 bait.png)\",\"contentType\":\"image/png\",\"filename\":\"bait.png\"}"
```

Plant the `/<id>/image` URL like a web bug; the gateway serves your image
and any fetch fires a medium alert. Re-upload replaces the image.

### DNS token
Create `dns` → you get `<id>.tokens.example.com`. Any lookup of it or its
subdomains alerts. Plant in: `hosts` files, documentation, tool configs.

> Requires your token domain delegated to (or served by) the gateway's
> authoritative DNS — see `docs/INSTALL.md` § DNS delegation.

### Unique email address
Create `email` → `<id>@tokens.example.com`. Plant in breach-filler accounts,
old resumes, config comments. Requires MX records.

### QR code
Create `qr_code` → download the PNG. Print/stick anywhere physical or digital;
scanning fires a high-severity hit.

### Word/Excel/PDF documents
Download the generated file and plant it in shared folders, intranets, or as
bait attachments. Word fetches its embedded remote image on open; Excel fires
when the hyperlink is clicked. PDF uses open-action/link (viewer dependent).
Set a custom bait filename at creation — default names like
`quarterly_report.docx` are fine, but something that blends into *your*
share drive is better.

### Cloned website
Give it a URL to clone (e.g. your VPN portal). You get a lookalike page on
your infrastructure with an invisible beacon. Phish-test your users or watch
for link-scrapers. Any visit = high severity. The token's detail drawer
shows the clone status — if the fetch failed or the target page changed,
fix the target and hit **re-clone now** there.

### Windows folder
Create `windows_folder` → download the generated `desktop.ini` (plus a
readme). Drop `desktop.ini` into a folder an intruder would browse (e.g.
`Finance\Payroll Exports`), then mark the folder and file `system`/`hidden`
(`attrib +s`/`attrib +h`) so Explorer actually reads it. Its `IconResource`
points at a UNC path on the token's hostname; browsing the folder makes
Explorer resolve that hostname to fetch the icon, which is what fires the
alert — nothing needs to be opened. Explorer caches folder icons, so test
from a machine that hasn't browsed the folder before. See
`docs/TOKEN-TYPES.md` for the full mechanism.

### SQL injection canary
Generates an nginx/Apache snippet redirecting a decoy path (default
`/search.php`) to our tracker. Deploy the rule on your real web server;
scanners probing for injection get flagged.

### Sensitive command
Serves a realistic fake output page (`ifconfig`, `whoami`, …). Wrap it behind
an alias/bookmark/tool shortcut — if someone runs "the wrong" command from a
planted doc, you'll know.

### AWS key decoy / Azure service principal decoy
Generates believable credentials + instructions wiring YOUR cloud tenant's
audit logs to this platform's ingest URL. Without cloud wiring they are inert
decorations — do the one-time wiring step in the readme.

### Honeypot link
Reference token for agent-side sensors — it plants nothing and can never be
tripped from the public internet; it exists so a sensor's detections have a
revocable entity to hang off.

**You normally never create one by hand.** Add a sensor in the Agents tab and
save: the console provisions a honeypot token for it named `<host> · <kind>`
(e.g. `dmz-01 · ssh`). Create one here only when you want several sensors to
report against a *shared* token — then paste its id into the `token:` field
behind each sensor row's disclosure.

> One SSH session produces TWO incidents by design: a **credential attempt**
> (password captured) and a **command execution** (what they ran). They are
> separate evidence, labeled by their `event` field.

### Fast redirect
302s visitors to any target while capturing them. Use for link-tracking in
documents or shortened URLs.

## 4. Honeypots (agents)

| Sensor | Port | What it captures |
|---|---|---|
| ssh | 22-ish | usernames, passwords, post-login commands |
| http_login | 8080-ish | login POST creds (user + pass length) |
| smb | 445 | negotiate probes, **NTLM user/domain/hash** (hashcat format) |
| rdp | 3389 | connection probes incl. requested security; **CredSSP/NLA creds** |
| planted_credential | — | bait file reads/tampering/deletion |
| file_watch | — | access/modification of real sensitive files |

Deployment tips:

- Put agents on juicy subnets (DC-adjacent, user VLANs, DMZ)
- Name sensors' tokens clearly (`memo: "DC-adjacent SMB"` etc.)
- For `file_watch`, good targets: `/etc/shadow`, browser cookie stores,
  KeePass databases
- For `planted_credential`, use believable names: `passwords.txt`,
  `.env.prod`, `servicenow_creds.txt` — content ships with plausible defaults

## 5. Alerting

Configure channels under **Alert Channels**, then test with the API:

```sh
curl -X POST $F0/api/v1/alert-channels/<id>/test
```

Throttling: max 1 alert per unique (token, source IP) per minute by default
(`F0_MAX_ALERTS_PER_MINUTE`). Incidents are ALWAYS recorded even when alerts
are throttled.

Channel notes:
- **webhook**: JSON POST of the whole alert; `secret` goes in `x-f0-signature`
- **syslog**: UDP RFC5424, severity-mapped (high→critical)
- **elasticsearch**: indexes to `<url>/<index>/_doc`
- **loki**: pushes log lines with labels `{app="f0_deception", severity=…}`

## 6. MCP server (LLM triage)

```jsonc
// claude_desktop_config.json / opencode config
{
  "mcpServers": {
    "f0_deception": {
      "command": "node",
      "args": ["/path/to/apps/mcp/dist/server.js"],
      "env": { "F0_API_BASE_URL": "http://localhost:18443" }
    }
  }
}
```

Tools available to the LLM: create/list/revoke tokens, list incidents +
detail/acknowledge, list agents, platform stats. No destructive operations.

## 7. Triage workflow

1. Incident appears (console / SIEM / LLM ping)
2. Open detail: source IP, UA, exact request/DNS query
3. Assess: internal IP → possible compromise walk-back; external → likely scan
4. Ack the incident; escalate via your normal IR process if warranted

## 8. Legal & safety

- Only deploy honeypots/cloned sites on systems and networks you own or are
  authorized to test
- Cloned-site tokens impersonate pages — use your own properties
- Credential material captured by honeypots is attacker-supplied; handle per
  your evidence procedures
- The platform itself is internet-exposed attack surface: keep it patched,
  restrict console access (VPN/reverse proxy auth), monitor the monitor

## 9. Troubleshooting

| Symptom | Fix |
|---|---|
| No incidents but curl works | gateway's `F0_API_BASE_URL` must point at the API |
| DNS token silent | check :53/:15353 listener + NS/A records; test with `dig -p PORT @host name` |
| Agent shows offline | heartbeat every 60s — check `~/.f0-deception/agent.yaml` server URL matches |
| "sensor not available in this build" | rebuild the agent binary |
| Email token silent | MX record + the gateway's actual SMTP ingest port (`F0_SMTP_PORT`, default `2525` — not 25 unless you chose that) reachable from the sender; spam filters may block first |
| Word doc doesn't alert | viewer blocked external content; PDF viewers vary — prefer web bugs for reliability |
