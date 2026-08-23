import net from "node:net";
import type { TriggerEvent } from "@f0/deception-shared";

export interface SmtpServerOptions {
  port: number;
  /** Domains we accept mail for, e.g. ["tokens.example.com"]. */
  mailDomains: string[];
  onEvent(event: TriggerEvent): void;
}

const MAX_MESSAGE_BYTES = 1024 * 1024; // 1 MiB
const MAX_RCPT = 8;
const SESSION_TIMEOUT_MS = 30_000;

/**
 * Minimal SMTP ingest for unique-email canarytokens.
 *
 * Accepts unauthenticated mail on a dedicated port (front with Postfix/
 * Caddy L4 or publish :25 directly), parses the envelope + basic headers,
 * and emits one TriggerEvent per accepted RCPT TO that belongs to our
 * mail domains. It never relays: all messages terminate here.
 *
 * Hardening: session timeout, message size cap, recipient count cap,
 * no filesystem access, no shell-outs, responses are fixed strings.
 */
export function startSmtpServer(opts: SmtpServerOptions): net.Server {
  const server = net.createServer((socket) => {
    let buffer = "";
    let inData = false;
    let dataBytes = 0;
    let dataLines: string[] = [];
    let rcptTo: string[] = [];
    let mailFrom = "";
    let rcptCount = 0;

    socket.setTimeout(SESSION_TIMEOUT_MS);

    const reset = () => {
      inData = false;
      dataBytes = 0;
      dataLines = [];
      rcptTo = [];
      mailFrom = "";
      // keep rcptCount cumulative per RFC 5321 (max recipients per message)
    };

    const reply = (line: string) => socket.write(`${line}\r\n`);

    const finishMessage = () => {
      const subjectLine = dataLines.find((l) =>
        /^subject:/i.test(l),
      );
      for (const to of rcptTo) {
        if (!belongsToOurDomains(to, opts.mailDomains)) continue;
        opts.onEvent({
          kind: "smtp",
          tokenHint: localPart(to),
          timestamp: new Date().toISOString(),
          sourceIp: socket.remoteAddress ?? "0.0.0.0",
          sourcePort: socket.remotePort,
          smtp: {
            from: mailFrom,
            to,
            subject: subjectLine?.slice(8).trim().slice(0, 200),
          },
        });
      }
      reset();
      reply("250 OK");
    };

    reply(`220 ${opts.mailDomains[0] ?? "localhost"} f0_deception SMTP ready`);

    socket.on("timeout", () => socket.destroy());

    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      if (buffer.length > MAX_MESSAGE_BYTES) {
        socket.destroy();
        return;
      }

      while (true) {
        const idx = buffer.indexOf("\r\n");
        if (idx === -1) break;
        const line = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 2);

        if (inData) {
          if (line === ".") {
            finishMessage();
            continue;
          }
          dataBytes += line.length + 2;
          if (dataBytes > MAX_MESSAGE_BYTES) {
            reply("552 Message too large");
            socket.destroy();
            return;
          }
          // dot-unstuffing per RFC 5321
          dataLines.push(line.startsWith("..") ? line.slice(1) : line);
          continue;
        }

        const verb = line.slice(0, 4).toUpperCase();
        if (verb === "HELO" || verb === "EHLO") {
          reply(
            verb === "EHLO"
              ? `250-${opts.mailDomains[0] ?? "localhost"}\r\n250 SIZE ${MAX_MESSAGE_BYTES}`
              : "250 OK",
          );
        } else if (verb === "MAIL") {
          if (!/^MAIL FROM:\s*<([^>]*)>/i.test(line)) {
            reply("501 Syntax error");
            continue;
          }
          if (mailFrom || rcptTo.length > 0) {
            reply("503 Nested MAIL command");
            continue;
          }
          mailFrom = line.replace(/^MAIL FROM:\s*<([^>]*)>.*$/i, "$1");
          rcptTo = [];
          reply("250 OK");
        } else if (verb === "RCPT") {
          const m = line.match(/^RCPT TO:\s*<([^>]*)>/i);
          if (!m) {
            reply("501 Syntax error");
            continue;
          }
          rcptCount += 1;
          if (rcptCount > MAX_RCPT) {
            reply("452 Too many recipients");
            continue;
          }
          const addr = m[1]!.toLowerCase();
          if (!belongsToOurDomains(addr, opts.mailDomains)) {
            // Don't reveal whether the address exists; accept then drop.
            reply("250 OK");
            continue;
          }
          rcptTo.push(addr);
          reply("250 OK");
        } else if (verb === "DATA") {
          if (rcptTo.length === 0) {
            reply("554 No valid recipients");
            continue;
          }
          inData = true;
          reply("354 End data with <CR><LF>.<CR><LF>");
        } else if (verb === "RSET") {
          reset();
          reply("250 OK");
        } else if (verb === "NOOP") {
          reply("250 OK");
        } else if (verb === "QUIT") {
          reply("221 Bye");
          socket.end();
        } else {
          reply("502 Command not implemented");
        }
      }
    });

    socket.on("error", () => socket.destroy());
  });

  server.listen(opts.port, "0.0.0.0");
  return server;
}

function belongsToOurDomains(addr: string, domains: string[]): boolean {
  return domains.some((d) => addr.endsWith(`@${d}`));
}

/** `abc123.tokens.example.com`-style local part extraction. */
function localPart(addr: string): string {
  return addr.split("@")[0] ?? "";
}
