# Installation Guide

Two paths: **local testing** (no root, no public domain — runs in minutes)
and **production** (public VPS with real DNS).

---

## Option A: Local test installation (recommended first)

Everything runs on high ports; token triggers work from the same machine or
your LAN. DNS and email tokens need extra steps noted below.

### Prerequisites

- Node.js ≥ 22 + pnpm (`npm i -g pnpm`)
- Go ≥ 1.26.5 (only for the agent; the version `agent/go.mod` declares)

### 1. Build

```sh
git clone <repo> f0_deception && cd f0_deception
pnpm install
pnpm build            # builds api, gateway, web, mcp
(cd agent && go build -o /tmp/f0-deception-agent .)
```

### 2. Start the platform

Use distinct shells, or append `&`:

```sh
# Terminal 1 — API (console backend) on :18443
pnpm --filter @f0/deception-api dev

# Terminal 2 — Gateway on :18080 (HTTP triggers) + :15353/udp (DNS)
F0_API_BASE_URL=http://localhost:18443 \
F0_HTTP_PORT=18080 F0_DNS_PORT=15353 \
pnpm --filter @f0/deception-gateway dev

# Console UI: open apps/web/index.html via any static server, e.g.
npx serve apps/web   # then open http://localhost:3000
```

> The gateway needs `F0_API_BASE_URL` pointing at the API so it can forward
> trigger events.

### 3. Enroll an agent + deploy honeypots

```sh
export F0=http://localhost:18443
curl -s $F0/api/v1/agents   # empty until you enroll

# enroll (one-shot; saves identity to ~/.f0-deception/)
/tmp/f0-deception-agent --server $F0 --enroll bootstrap-test-123

# deploy sensors via the console (Agents tab → sensor editor),
# or via API:
AID=$(curl -s $F0/api/v1/agents | python3 -c 'import json,sys;print(json.load(sys.stdin)[0]["id"])')
TID=$(curl -s -X POST $F0/api/v1/tokens -H 'content-type: application/json' \
      -d '{"type":"web_bug","memo":"honeypot link"}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')

curl -s -X PUT $F0/api/v1/agents/$AID/sensors -H 'content-type: application/json' -d '{
  "sensors": [
    {"kind":"ssh","enabled":true,"config":{"port":12222,"token_id":"'"$TID"'"}},
    {"kind":"http_login","enabled":true,"config":{"port":18081,"token_id":"'"$TID"'"}},
    {"kind":"smb","enabled":true,"config":{"port":1445,"token_id":"'"$TID"'"}},
    {"kind":"rdp","enabled":true,"config":{"port":13389,"token_id":"'"$TID"'"}}
  ]}'

/tmp/f0-deception-agent    # run the agent (foreground)
```

### 4. Fire a test attack

```sh
# SSH honeypot
ssh -p 12222 admin@127.0.0.1          # any password → captured

# HTTP login honeypot
curl -s "http://127.0.0.1:18081/?user=admin&pass=hunter2"

# SMB / RDP: use any scanner against 127.0.0.1:1445 / :13389
```

Open the console → **Incidents** appear within seconds.

### Notes per token type (local mode)

| Token | Works locally? | Notes |
|---|---|---|
| http_login, ssh, smb, rdp honeypots | ✅ | fully functional on high ports |
| cloned_website | ✅ | clone any page reachable from the gateway |
| pdf_doc, aws_keys, azure_config | ✅ | decoys generate fine; cloud detection needs cloud wiring |
| dns | ⚠️ | gateway listens on :15353/udp — test with `dig -p 15353 @127.0.0.1 <id>.tokens.example.com` |
| email | ❌ | needs production MX |

---

## Option B: Production VPS

### Prerequisites

- A public domain (e.g. `tokens.example.com`) — delegated by NS record to
  the gateway, not just an A record inside your existing DNS (see
  "DNS: delegation, not a record in your existing zone" below)
- Ports: the **gateway** owns `:80/tcp` (HTTP token reach-backs — needs
  raw source IPs, so it can't sit behind a proxy) and `:53/udp` (DNS
  tokens), plus an SMTP ingest port for email tokens (default `2525`,
  configurable — see "Mail-server coexistence" below). The **console**
  is `:443` only (or loopback `:8080` in private mode) — see
  `deploy/docker-compose.yml`.
- Docker + Docker Compose (the installer drives this), OR Node 22 + Go
  directly for a bare-metal install

### Automated install (recommended)

```sh
git clone <repo> f0_deception && cd f0_deception
node deploy/install.mjs
```

This is a zero-dependency TUI (`deploy/install.mjs`) that drives the whole
deployment in phases:

1. **Preflight** — checks for `docker`, the compose plugin, `git`,
   `openssl`, `curl`, `dig` (offers to `apt-get install` anything missing
   on Debian/Ubuntu), then verifies **docker daemon access**, not just
   that the binary exists: if the daemon isn't running it offers
   `systemctl enable --now docker`; if your user can't reach the socket
   (not root, not in the `docker` group) it offers to add you to the
   group (effective next login) and runs the rest of *this* install
   through `sudo` either way.
2. **Questions** — public IP (auto-detected), token base domain, console
   exposure (`private`: loopback + `ssh -L`, or `public`: ACME TLS),
   email-token (MX) domain, token-surface TLS mode (`http` default /
   import a wildcard cert / on-demand per-hostname certs), SMTP ingest
   port (default `2525`), whether to download the GeoIP city database,
   and whether to cross-compile agent binaries for all 5 platforms.
3. **Secrets & config** — generates `F0_ADMIN_TOKEN`, `F0_INTERNAL_SECRET`,
   `F0_ENROLLMENT_TOKEN` into `deploy/.env` (mode 600, preserved across
   re-runs unless `--reconfigure`), and renders `deploy/Caddyfile` from
   `deploy/Caddyfile.template`.
4. **DNS records** — prints the exact records to create and then verifies
   them by querying the *parent* zone's authoritative nameserver directly
   (not a recursive resolver, and not 8.8.8.8) — a recursive lookup would
   follow the delegation to a gateway that isn't running yet and fail
   spuriously. Retries until the records are visible, or lets you skip.
5. **Binaries & GeoIP** — cross-compiles agent binaries and/or fetches the
   DB-IP city-lite database, if you asked for them.
6. **Launch & health checks** — `docker compose up -d --build`, then
   confirms the API answers through the console proxy, the gateway serves
   HTTP on the public IP, and the gateway's DNS actually answers
   authoritatively for the token zone.
7. **Done** — prints the console URL, the one-time admin token, and a
   ready-to-paste command to install your first agent.

Flags: `--dry-run` (writes `.env` + `Caddyfile`, stops before `compose up`)
and `--reconfigure` (re-asks every question; existing secrets are kept).

### TLS: shipped, not something you add

The production compose (`deploy/docker-compose.yml`) already runs Caddy
with ACME for the console — you do not need to put your own reverse proxy
in front of it. The compose file states the reasoning directly: *"No :80
publish — the gateway owns public :80 for token reach-backs (source IPs
must arrive unproxied); the console cert uses the TLS-ALPN-01 challenge,
which needs only :443."* The installer renders Caddy's config for you
(`deploy/Caddyfile`, from `deploy/Caddyfile.template`) based on your
console-exposure and token-TLS answers; don't hand-edit it, re-run the
installer instead.

If you skip Docker Compose entirely (bare metal, below), there's no Caddy
container — put a reverse proxy (Caddy/Nginx) in front of the API/console
yourself for TLS.

### Bare metal

Same as local, but run services under systemd with the standard ports,
`F0_TOKEN_DOMAINS` set to your domain, and your own reverse proxy + TLS in
front of the console/API (see above — this path doesn't get Caddy for
free).

### Mail-server coexistence

Internet SMTP senders always deliver to port 25, no matter what the MX
record says (RFC 5321) — so a host that will actually receive real
`email` token triggers from the Internet needs port 25 free. The
installer defaults the gateway's SMTP ingest port to `2525` precisely
because a VPS often already runs a mail stack (Postfix, Mail-in-a-Box,
etc.) bound to `:25`, and colliding with it would break both. If you want
`email` tokens to fire from real Internet mail, you have two options:
stop/move the existing MTA and answer `25` at the installer's SMTP-port
prompt (`F0_SMTP_PORT`, also the `docker-compose.yml` port mapping), or
accept that at the default `2525` the address only works for senders you
point at that port directly (manual testing, not real inbound mail).

### DNS: delegation, not a record in your existing zone

The token domain must be **delegated** to the gateway by an `NS` record —
adding the token domain as a plain record inside your existing DNS zone
does not work, because the gateway needs to be *authoritative* for every
name under it (it answers arbitrary token-id subdomains it has never seen
before). Concretely:

```
NS <token-domain>     → ns1.<token-domain>      # the delegation itself
A  ns1.<token-domain> → <gateway-ip>             # glue: the NS needs an address
```

NS values must be hostnames, not IPs (some DNS panels reject an IP there
with "Invalid value"). No wildcard `A` record is needed or wanted — the
gateway's own DNS server answers every name under the delegated zone, so
adding one at the parent would just be occluded by the delegation anyway.
Once the zone is delegated, any other record you might add at or below
that name in the *parent* zone (wildcard `A`, `MX`) is invisible to
resolvers — the parent answers with a referral, not the record, and the
child (gateway) answers instead.

### Production checklist

- [ ] Set `F0_TOKEN_DOMAINS` and `F0_GATEWAY_ORIGIN` consistently
- [ ] Delegate the token zone as described above; verify it resolves
  (the installer's DNS phase does this against the parent's authoritative
  nameserver, so it doesn't need to wait for propagation)
- [ ] Email tokens: if the mail domain is the (delegated) token domain, no
  MX record is needed — senders fall back to the gateway's A answer
  (implicit MX). Set `MX <mail-domain> → ns1.<token-domain>` only for a
  mail domain outside the token zone. Decide port 25 vs 2525 per the
  mail-server coexistence note above
- [ ] TLS is handled by the shipped Caddy service when using Docker
  Compose; bare-metal installs need their own reverse proxy + TLS
- [ ] Enroll agents with the *production* API URL
- [ ] Configure alert channels (SIEM tab) before planting decoys
- [ ] Review `docs/USER-GUIDE.md` § Legal before deploying honeypots

---

## Upgrading the agent fleet

Agents self-update when built with an embedded Ed25519 public key:

```sh
# operator side: sign a release
openssl genpkey -algorithm ed25519 -out release.key
openssl pkey -in release.key -pubout -out release.pub

cd agent && RELEASE_PRIVKEY=../release.key make release
# upload bin/ + bin/release-manifest.json to a URL, then:
export F0_UPDATE_MANIFEST_URL=https://your.cdn/release-manifest.json
# embed pub key into future agent builds.
#
# Two things this line gets wrong if you shorten it:
#   * -X needs the FULL import path, not "update.…", or the symbol is
#     silently not matched and the updater is a permanent no-op.
#   * the key must be the RAW 32 bytes, not the PEM. base64-ing release.pub
#     directly yields "public key has wrong size" at runtime.
PUB=$(openssl pkey -in release.key -pubout -outform DER | tail -c 32 | base64 -w0)
go build -ldflags "-X github.com/f0rt1ka/f0-deception-agent/internal/update.UpdatePublicKey=$PUB" .
```

Running agents fetch, verify, swap and restart themselves once per poll
interval (default 60s — not hourly).

Note the manifest cannot be served from the console API: `GET
/api/v1/agent-releases/:file` only matches `f0-deception-agent-*`, so
`release-manifest.json` returns 400. Host it on any static server.
