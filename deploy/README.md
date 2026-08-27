# f0_hpot — production deployment (single host)

## One command

```sh
node deploy/install.mjs
```

A zero-dependency TUI (Node ≥ 20, nothing to install first) that walks the
whole deployment: preflight → questions → secrets → DNS records
(verified) → binaries/GeoIP → `docker compose up` → health checks →
first-run card with your console URL and admin token.

Flags: `--reconfigure` (re-ask everything, secrets preserved),
`--dry-run` (write `.env` + `Caddyfile`, stop before compose up).

## What the installer asks

| Question | Used for |
|---|---|
| Public IP (auto-detected) | `GATEWAY_PUBLISH_IP`, `F0_GATEWAY_IP` (A-record answers) |
| Token base domain | attacker-facing token URLs + the DNS zone the gateway answers |
| Console exposure | `private` (loopback, `ssh -L`) or `public` (ACME TLS, needs FQDN + email) |
| Email-token domain | `F0_MAIL_DOMAINS` (MX target) |
| Token-surface TLS | `http` (default) / `import` your wildcard cert / `on_demand` |
| SMTP port | email-token ingest (default 2525; 25 if no MTA) |
| GeoIP download | DB-IP city-lite (~62MB, optional, enables the world map) |
| Binary build | cross-compile all 5 agent platforms with Go (optional) |

Secrets (`F0_ADMIN_TOKEN`, `F0_INTERNAL_SECRET`, `F0_ENROLLMENT_TOKEN`)
are generated for you and written to `deploy/.env` (mode 600). The admin
token is shown **once** on the final card — the console runs in open mode
until you create the first API key with it (Settings), so store it.

## DNS records (the installer prints and verifies these)

```text
A    ns1.<token-domain>    → <your-ip>        # gateway nameserver identity
NS   <token-domain>        → ns1.<token-domain>
A    *.<token-domain>      → <your-ip>        # wildcard → host (HTTP URLs)
MX   <mail-domain>         → ns1.<token-domain>  (priority 10)
A    <console-domain>      → <your-ip>        # only for public console
```

Verification runs `dig` against 8.8.8.8 per record with retry/skip/abort.

## Topology

| Surface | Exposure | Ports |
|---|---|---|
| Gateway (attacker reach-back) | public IP | 80/tcp (HTTP triggers), 53/udp (DNS), SMTP |
| Token TLS (import/on-demand) | public IP | 443/tcp |
| Console + API proxy | loopback (default) or public | 8080 (private) / 80+443 (public) |
| API | internal only | — |

Private console access: `ssh -L 8080:127.0.0.1:8080 <user>@<host>` →
`http://localhost:8080`.

## Operations

```sh
docker compose -f deploy/docker-compose.yml logs -f     # follow logs
docker compose -f deploy/docker-compose.yml up -d --build  # rebuild after upgrades
# backup the incident/token DB (SQLite volume):
docker run --rm -v f0-deception_api-data:/data -v $(pwd):/backup alpine \
  tar czf /backup/api-data-$(date +%F).tar.gz -C /data .
```

Generated artifacts (`deploy/.env`, `Caddyfile`, `certs/`, `data/`,
`release-bin/`, `install.log`) are gitignored.
