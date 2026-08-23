import http from "node:http";
import type { TriggerEvent } from "@f0/deception-shared";

export interface HttpServerOptions {
  port: number;
  baseDomains: string[];
  /** Called for every request that belongs to one of our token domains. */
  onEvent(event: TriggerEvent): void;
  /**
   * Serves the actual artifact response (pixel gif, redirect, document...).
   * Return false if the request should be answered with a generic 404.
   */
  respond(req: http.IncomingMessage, res: http.ServerResponse): boolean;
}

/**
 * Catch-all HTTP listener for token trigger URLs. Every request under a
 * configured base domain is normalized into a TriggerEvent and then handed
 * to `respond` for artifact delivery.
 *
 * Hardening: strict size caps, no proxy trust, no dynamic file access.
 */
export function startHttpServer(opts: HttpServerOptions): http.Server {
  const server = http.createServer((req, res) => {
    const host = (req.headers.host ?? "").toLowerCase().split(":")[0] ?? "";
    const isOurs = opts.baseDomains.some(
      (d) => host === d || host.endsWith(`.${d}`),
    );

    if (!isOurs) {
      res.writeHead(421, { "content-type": "text/plain" });
      res.end("misdirected request");
      return;
    }

    const event: TriggerEvent = {
      kind: "http",
      tokenHint:
        extractTokenHints(host, opts.baseDomains)[0] ?? "",
      timestamp: new Date().toISOString(),
      sourceIp: req.socket.remoteAddress ?? "0.0.0.0",
      sourcePort: req.socket.remotePort,
      http: {
        method: req.method ?? "?",
        host,
        path: (req.url ?? "/").slice(0, 2048),
        userAgent: req.headers["user-agent"],
        referer: req.headers.referer,
        acceptLanguage: req.headers["accept-language"],
        headers: req.headers as Record<string, string>,
      },
    };
    opts.onEvent(event);

    let served = false;
    try {
      served = opts.respond(req, res);
    } catch {
      served = false;
    }
    if (!served && !res.writableEnded) {
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("not found");
    }
  });

  server.maxHeadersCount = 32;
  server.on("clientError", (_err, socket) => {
    socket.destroy();
  });
  return server;
}

/** `abc123.tokens.example.com` -> candidate token ids (any label depth). */
export function extractTokenHints(
  host: string,
  baseDomains: string[],
): string[] {
  for (const domain of baseDomains) {
    if (host === domain) continue;
    if (host.endsWith(`.${domain}`)) {
      return host.slice(0, -(domain.length + 1)).split(".");
    }
  }
  return [];
}
