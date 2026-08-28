# Installation Guide

Two paths: **local testing** (no root, no public domain — runs in minutes)
and **production** (public VPS with real DNS).

---

## Option A: Local test installation (recommended first)

Everything runs on high ports; token triggers work from the same machine or
your LAN. DNS and email tokens need extra steps noted below.

### Prerequisites

- Node.js ≥ 22 + pnpm (`npm i -g pnpm`)
- Go ≥ 1.25 (only for the agent)

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

- A public domain (e.g. `tokens.example.com`) with A record to your VPS
- Ports 80/443 (console), 53 (DNS tokens), 25 (email tokens) as desired
- Docker + Docker Compose, OR Node 22 + Go directly

### Docker Compose (simplest)

```sh
git clone <repo> f0_deception && cd f0_deception
docker compose up -d --build     # see compose file; set env below
```

Environment for the gateway/API containers:

```yaml
environment:
  F0_TOKEN_DOMAINS: tokens.example.com
  F0_GATEWAY_ORIGIN: https://tokens.example.com
  F0_UPDATE_MANIFEST_URL: ""        # optional signed self-update feed
```

Put a reverse proxy (Caddy/Nginx) in front of the API/console for TLS.

### Bare metal

Same as local, but run services under systemd with the standard ports and
`F0_TOKEN_DOMAINS` set to your domain.

### Production checklist

- [ ] Set `F0_TOKEN_DOMAINS` and `F0_GATEWAY_ORIGIN` consistently
- [ ] Delegate the token zone to the gateway: `NS <token-domain> → ns1.<token-domain>`
  plus glue `A ns1.<token-domain> → <gateway-ip>`. NS values must be hostnames,
  not IPs. No wildcard A needed — the gateway DNS answers every name under the zone.
- [ ] Email tokens: if the mail domain is the (delegated) token domain, no MX
  record is needed — senders fall back to the gateway's A answer (implicit MX).
  Set `MX <mail-domain> → ns1.<token-domain>` only for a mail domain outside
  the token zone. Internet senders always deliver on port 25.
- [ ] Reverse proxy + TLS for console/API
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
# embed pub key into future agent builds:
go build -ldflags "-X update.UpdatePublicKey=$(base64 -w0 release.pub)" .
```

Running agents fetch, verify, swap, and restart themselves hourly.
