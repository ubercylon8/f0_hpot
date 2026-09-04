# Alerting Guide

When the API confirms a real trigger (`POST /api/v1/incidents`, driven by
the token type's own `matchTrigger`), the incident fans out to every
enabled alert channel, subject to per-source throttling
(`apps/api/src/alerts/dispatcher.ts`). This guide covers the five channel
kinds, the payload they receive, throttling, and how channel secrets are
edited — and is deliberately blunt about which integrations are proven end
to end versus asserted-but-unverified.

## Integration status — read this before you pick a channel

| Channel | Status |
|---|---|
| `webhook` | **Verified live.** |
| `syslog` | **Verified live.** |
| `email` | Config validation and delivery are exercised against a local test SMTP sink in the e2e suite. Sending a real alert needs an SMTP relay you supply — host, port, and (usually) credentials; nothing is bundled. |
| `elasticsearch` | Wire format only — method, path, request body, and the Basic-auth header have been asserted against a local mock sink, not against a real Elasticsearch cluster. Expect to work through index-mapping conflicts on the dynamic `event` object and any TLS/auth specifics of your deployment. |
| `loki` | Wire format only, same caveat as `elasticsearch` — asserted against a local mock sink (push endpoint, labels, the `X-Scope-OrgID` tenant header), not a real Loki instance. Expect label-cardinality tuning on a real deployment. |

**Slack and Microsoft Teams incoming webhooks will reject this payload as
shipped.** The `webhook` channel POSTs the raw `AlertPayload` object as
`application/json` (`apps/api/src/alerts/webhook.ts`) — it is not Slack's
Block Kit format and not a Teams `MessageCard`/Adaptive Card. Pointing a
Slack or Teams webhook URL at this channel gets you an HTTP 400 from
Slack/Teams, not a delivered message. If you want alerts in Slack or
Teams today, put a small transformer in front (a relay that accepts this
JSON shape and re-posts it in the format that platform expects) rather
than wiring the URL in directly.

## Channel kinds and config shapes

Config shapes are enforced server-side by zod schemas
(`apps/api/src/routes/alerts.ts`); the `kind` itself comes from
`alertChannelKindSchema` in `packages/shared/src/agent.ts`.

- **`email`** — `{ smtp_host, smtp_port?, smtp_user?, smtp_pass?, from, to, subject_prefix? }`.
  Plain SMTP via `nodemailer`, STARTTLS when the server offers it, default
  port `587` (`apps/api/src/alerts/email.ts`).
- **`webhook`** — `{ url, secret? }`. POSTs the alert JSON to `url`; if
  `secret` is set it's sent verbatim as an `X-F0-Signature` header (a
  shared-secret check, not an HMAC signature — that's a stated future
  hardening step, not a bug) (`apps/api/src/alerts/webhook.ts`).
- **`syslog`** — `{ host, port?, app_name? }`. Sends one RFC 5424 message
  over UDP per alert, default port `514`, severity mapped from the
  incident's `low`/`medium`/`high` to syslog's informational/warning/critical
  (`apps/api/src/alerts/syslog.ts`).
- **`elasticsearch`** — `{ url, index?, username?, password? }`. Indexes
  one document per alert at `<url>/<index>/_doc` (default index
  `f0_deception`), Basic auth if both `username` and `password` are set
  (`apps/api/src/alerts/siem.ts`).
- **`loki`** — `{ url, labels?, tenant_id? }`. Pushes one log line per
  alert to `<url>/loki/api/v1/push`; `tenant_id`, if set, is sent as
  `X-Scope-OrgID` (`apps/api/src/alerts/siem.ts`).

## Alert payload

Every sender receives the same `AlertPayload`
(`apps/api/src/alerts/types.ts`):

```ts
interface AlertPayload {
  tokenId: string;
  tokenType: string;
  severity: string;      // "low" | "medium" | "high"
  incidentId: string;
  event: TriggerEvent;    // kind, tokenHint, timestamp, sourceIp, plus an
                          // optional http/dns/smtp block matching what
                          // triggered
  seenAt: string;         // ISO 8601
}
```

`TriggerEvent` is defined in `packages/shared/src/incident.ts`, which is the
intended single source of truth for shapes crossing app boundaries: the API,
the gateway, and the token registry all import it from there, and no alert
channel redefines it. The MCP server is the current exception — `apps/mcp`
declares no dependency on `packages/shared` and hand-writes its own tool
shapes in `apps/mcp/src/server.ts`.

## Throttling

Alerts are throttled per `(tokenId, sourceIp)` pair, independent of which
channels are enabled: `AlertDispatcher.shouldAlert` opens a rolling
60-second window per pair and allows at most `F0_MAX_ALERTS_PER_MINUTE`
alerts through it (default `1` if unset), dropping the rest for that
window without dropping the underlying incident record
(`apps/api/src/alerts/dispatcher.ts`). Set
`F0_MAX_ALERTS_PER_MINUTE` higher if you'd rather be paged on every hit
from a noisy, repeatedly-probed token; the current value is also exposed
read-only at `GET /api/v1/status` as `alertThrottlePerMinute`.

A channel that fails five times in a row is disabled automatically (a
circuit breaker, `MAX_FAILURES` in `apps/api/src/alerts/dispatcher.ts`); a
successful delivery, or any edit to the channel's config, resets that
failure count. `POST /api/v1/alert-channels/:id/test` sends one synthetic
alert through a channel on demand, useful for confirming a new config
before it has to prove itself on a real trigger.

## Editing channel secrets: blank means keep, not clear

`GET /api/v1/alert-channels` never returns real secret values — any config
key whose name matches `pass|secret|token|key` (case-insensitive) comes
back masked as `•••` (`SECRET_MASK` in `apps/api/src/routes/alerts.ts`).
Because of that, `PATCH /api/v1/alert-channels/:id` treats a secret field
in the submitted config as **unchanged** if it is omitted, empty, or still
the mask string — only a genuinely new, non-empty value overwrites what's
stored. This is deliberate: an edit form that shows the mask (or a UI that
only sends the fields the user touched) must not be able to overwrite a
real secret with an empty string just because the user didn't retype it.

The consequence: there is no way to set a secret field to *empty* through
this endpoint — "blank" always means "leave it alone." If you genuinely
need to clear a stored secret, delete the channel and recreate it.
Changing a channel's `kind` isn't supported either, for the same
config-shape reason: a different kind is a different config schema, so
that's a delete-and-recreate too, not an edit.
