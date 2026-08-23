import { startHttpServer } from "./http.js";
import { startDnsServer, extractTokenHints } from "./dns.js";
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

async function forwardIncident(body: unknown): Promise<void> {
  try {
    const res = await fetch(`${apiBaseUrl}/api/v1/incidents`, {
      method: "POST",
      headers: { "content-type": "application/json" },
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
  // The token id can sit at any label depth under the base domain. Labels
  // like "sub" may spuriously satisfy trigger rules, so forward every
  // matching candidate; the API drops ids that aren't live tokens.
  const candidates =
    event.kind === "dns"
      ? extractTokenHints(event.dns?.queryName ?? "", baseDomains)
      : event.kind === "http"
        ? extractHostHints(event.http?.host ?? "", baseDomains)
        : [];
  const seen = new Set<string>();
  for (const tokenId of candidates) {
    if (!tokenId || seen.has(tokenId)) continue;
    seen.add(tokenId);
    const def = matchEventToType(event, tokenId);
    if (!def) continue;
    const match = def.matchTrigger(event, tokenId);
    if (!match.matched) continue;
    void forwardIncident({ tokenId, severity: match.severity, event });
  }
}

const httpPort = Number(process.env.F0_HTTP_PORT ?? 8080);
const dnsPort = Number(process.env.F0_DNS_PORT ?? 5353);

startHttpServer({
  port: httpPort,
  baseDomains,
  onEvent,
  respond: artifactResponder({ gatewayOrigin }),
}).listen(httpPort, () => console.log(`gateway HTTP listening on :${httpPort}`));

startDnsServer({
  port: dnsPort,
  host: gatewayIp,
  baseDomains,
  onEvent,
});
console.log(`gateway DNS listening on udp/:${dnsPort}`);
