# f0_hpot — production deployment (single host)

## One command

```sh
node deploy/install.mjs
```

A zero-dependency TUI (Node ≥ 20, nothing to install first) that walks the
whole deployment: preflight (with **automatic dependency installation**
on Debian/Ubuntu — it offers the exact `apt-get` command before running
it) → questions → secrets → DNS records (verified) → binaries/GeoIP →
`docker compose up` → health checks → first-run card with your console
URL and admin token.

Flags: `--reconfigure` (re-ask everything, secrets preserved),
`--dry-run` (write `.env` + `Caddyfile`, stop before compose up).

Runs as root or as a regular user with sudo. Preflight verifies docker
*daemon access* (not just the binary): if your user can't reach the
socket it offers to add you to the docker group (effective next login)
and finishes the current run through sudo; if the daemon isn't running
it offers `systemctl enable --now docker`.

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
A    ns1.<token-domain>    → <your-ip>        # glue: gateway nameserver address
NS   <token-domain>        → ns1.<token-domain>  # delegates the token zone to the gateway
MX   <mail-domain>         → ns1.<token-domain>  (priority 10)  # only when mail-domain sits outside the token zone
A    <console-domain>      → <your-ip>        # only for public console
```

No wildcard `A` record — once the `NS` record is live the gateway's own DNS
server answers every name under the delegated zone itself, so a wildcard at
the parent would just be occluded by the delegation and do nothing. NS
values must be hostnames, not IPs. See `docs/INSTALL.md` § "DNS: delegation,
not a record in your existing zone" for the full explanation of why a plain
record in an existing zone can't work here.

Verification queries the parent zone's authoritative nameserver directly,
not a recursive resolver: 8.8.8.8 is used only to find *which* nameserver
is authoritative for the parent zone, then every record check goes straight
to it — a recursive lookup would instead follow the (not-yet-live)
delegation to the gateway and fail. Retries with retry/skip/abort.

## Signing prerequisites

The API image ships `openssl` and `osslsigncode`, so release-manifest signing
and Authenticode code signing work on a fresh install — nothing to install by
hand. `GET /api/v1/status` reports which host-dependent actions are available
(`capabilities`), and the console disables the ones that are not, with the
reason. `build binaries` stays unavailable in the container image by design:
it needs the Go toolchain and the agent source, which the runtime image does
not carry — build releases on a host checkout instead.

## Topology

| Surface | Exposure | Ports |
|---|---|---|
| Gateway (attacker reach-back) | public IP | 80/tcp (HTTP triggers), 53/udp (DNS), SMTP |
| Token TLS (import/on-demand) | public IP | 443/tcp |
| Console + API proxy | loopback (default) or public | 8080 (private) / 443 (public; TLS-ALPN ACME — the gateway owns :80, so use `https://` explicitly) |
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
