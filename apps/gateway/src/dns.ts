import dgram from "node:dgram";
import packet from "dns-packet";
import type { TriggerEvent } from "@f0/deception-shared";

export interface DnsServerOptions {
  port: number;
  host: string;
  /** Domains this gateway is authoritative for, e.g. ["tokens.example.com"]. */
  baseDomains: string[];
  onEvent(event: TriggerEvent): void;
}

/**
 * Minimal authoritative DNS server: answers every query for the configured
 * base domains (and subdomains) with a fixed A record, and emits a
 * TriggerEvent so token rules can match on the query name.
 *
 * Queries outside our domains get REFUSED — we are not a resolver.
 */
export function startDnsServer(opts: DnsServerOptions): dgram.Socket {
  const sock = dgram.createSocket("udp4");

  sock.on("message", (msg, rinfo) => {
    let query: packet.Packet;
    try {
      query = packet.decode(msg);
    } catch {
      return;
    }
    const question = query.questions?.[0];
    if (!question) return;

    const qname = question.name.toLowerCase().replace(/\.$/, "");
    const isOurs = opts.baseDomains.some(
      (d) => qname === d || qname.endsWith(`.${d}`),
    );

    if (isOurs) {
      opts.onEvent({
        kind: "dns",
        // Candidate token ids; tokens-core does label-aware matching.
        tokenHint: extractTokenHints(qname, opts.baseDomains)[0] ?? "",
        timestamp: new Date().toISOString(),
        sourceIp: rinfo.address,
        sourcePort: rinfo.port,
        dns: { queryName: qname, queryType: String(question.type).toUpperCase() },
      });
    }

    const response: packet.Packet = {
      id: query.id,
      type: "response",
      // 0x0005 = RCODE REFUSED, 0x0080 = RD
      flags: isOurs ? 0x0080 : 0x0005,
      questions: query.questions,
      answers:
        isOurs && question.type === "A"
          ? [
              {
                name: question.name,
                type: "A",
                class: "IN",
                ttl: 60,
                data: opts.host,
              },
            ]
          : [],
    };
    const buf = packet.encode(response);
    sock.send(buf, rinfo.port, rinfo.address);
  });

  sock.on("error", (err) => {
    throw err;
  });

  sock.bind(opts.port, "0.0.0.0");
  return sock;
}

/**
 * `abc123.sub.tokens.example.com` -> candidate token ids: every label
 * before the base domain, since a DNS token may sit at any depth.
 */
export function extractTokenHints(
  qname: string,
  baseDomains: string[],
): string[] {
  for (const domain of baseDomains) {
    if (qname === domain) continue;
    if (qname.endsWith(`.${domain}`)) {
      return qname.slice(0, -(domain.length + 1)).split(".");
    }
  }
  return [];
}
