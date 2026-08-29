import { startHttpServer } from "./http.js";
import { startDnsServer, extractTokenHints } from "./dns.js";
import { startSmtpServer } from "./smtp.js";
import { extractTokenHints as extractHostHints } from "./http.js";
import { artifactResponder } from "./artifacts.js";
import { matchEventToType } from "@f0/deception-tokens-core";

const baseDomains = (process.env.F0_TOKEN_DOMAINS ?? "tokens.example.com")
  .split(",")
  .map((d) => d.trim().toLowerCase())
  .filter(Boolean);
const gatewayIp = process.env.F0_GATEWAY_IP ?? "127.0.0.1";
const gatewayOrigin =
  process.env.F0_GATEWAY_ORIGIN ?? `http://${baseDomains[0]}:${process.env.F0_HTTP_PORT ?? 8080}`;
const apiBaseUrl = process.env.F0_API_BASE_URL ?? "http://127.0.0.1:8443";
const apiInternalSecret = process.env.F0_INTERNAL_SECRET;

async function forwardIncident(body: unknown): Promise<void> {
  try {
    const res = await fetch(`${apiBaseUrl}/api/v1/incidents`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(apiInternalSecret
          ? { authorization: `Bearer ${apiInternalSecret}` }
          : {}),
      },
      body: JSON.stringify(body),
    });
    // 404 = forwarded candidate isn't a live token id: expected, benign.
    if (!res.ok && res.status !== 404) {
      console.error("incident forward failed:", res.status, await res.text());
    }
  } catch (err) {
    console.error("incident forward error:", err);
  }
}

function onEvent(event: Parameters<typeof matchEventToType>[0]): void {
  // The token id can sit at any label depth under the base domain, or in
  // the first path segment for apex-hosted artifacts (docs embed
  // https://base.domain/<tokenId>/pixel.gif). Forward every plausible
  // candidate; the API confirms against each token's actual type rules.
  const candidates = new Set<string>();
  if (event.kind === "dns") {
    for (const c of extractTokenHints(event.dns?.queryName ?? "", baseDomains)) candidates.add(c);
  } else if (event.kind === "http" && event.http) {
    for (const c of extractHostHints(event.http.host, baseDomains)) candidates.add(c);
    // Apex-hosted artifact: /<tokenId>/...
    const firstSegment = event.http.path.split("?")[0]!.split("/").filter(Boolean)[0];
    if (firstSegment && isOnBaseDomain(event.http.host)) candidates.add(firstSegment);
  } else if (event.kind === "smtp") {
    candidates.add(event.smtp?.to.split("@")[0] ?? "");
  }
  candidates.delete("");
  for (const tokenId of candidates) {
    const def = matchEventToType(event, tokenId);
    if (!def) continue;
    const match = def.matchTrigger(event, tokenId);
    if (!match.matched) continue;
    void forwardIncident({ tokenId, severity: match.severity, event });
  }
}

function isOnBaseDomain(host: string): boolean {
  return baseDomains.includes(host);
}

const httpPort = Number(process.env.F0_HTTP_PORT ?? 8080);
const dnsPort = Number(process.env.F0_DNS_PORT ?? 5353);

startHttpServer({
  port: httpPort,
  baseDomains,
  onEvent,
  respond: artifactResponder({ gatewayOrigin, apiBaseUrl, apiInternalSecret }),
}).listen(httpPort, () => console.log(`gateway HTTP listening on :${httpPort}`));

startDnsServer({
  port: dnsPort,
  host: gatewayIp,
  baseDomains,
  onEvent,
});
console.log(`gateway DNS listening on udp/:${dnsPort}`);

const smtpPort = Number(process.env.F0_SMTP_PORT ?? 2525);
startSmtpServer({
  port: smtpPort,
  mailDomains: (process.env.F0_MAIL_DOMAINS ?? baseDomains.join(","))
    .split(",")
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean),
  onEvent,
});

// Startup self-check: if the API enforces auth and our secret is wrong or
// missing, incident forwarding and artifact lookups will be rejected —
// say so loudly instead of silently dropping triggers. The API may not be
// up yet, so only a definitive 401/403 warns; anything else is ignored.
{
  // Probe an INTERNAL route, not /status. The internal secret is
  // deliberately not accepted on console routes, so probing /status warned
  // on every correctly-configured start — training operators to ignore the
  // one message that matters. A nonexistent token id answers 404 when the
  // credentials are good and 401/403 when they are not.
  const res = await fetch(
    `${apiBaseUrl}/api/v1/tokens/000000000000/internal-config`,
    {
      signal: AbortSignal.timeout(3000),
      headers: apiInternalSecret ? { authorization: `Bearer ${apiInternalSecret}` } : {},
    },
  ).catch(() => null);
  if (res && (res.status === 401 || res.status === 403)) {
    console.error(
      `WARNING: API answered ${res.status} for the gateway credentials. ` +
        "Incident forwarding and internal artifact lookups will be REJECTED. " +
        "Set F0_INTERNAL_SECRET on both the API and the gateway.",
    );
  }
}
console.log(`gateway SMTP listening on :${smtpPort}`);
