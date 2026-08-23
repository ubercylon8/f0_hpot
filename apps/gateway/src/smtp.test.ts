import { describe, it, expect, afterAll } from "vitest";
import net from "node:net";
import { startSmtpServer } from "./smtp.js";
import type { TriggerEvent } from "@f0/deception-shared";
import { extractTokenHints } from "./dns.js";

const events: TriggerEvent[] = [];
const server = startSmtpServer({
  port: 0, // ephemeral
  mailDomains: ["tokens.example.com"],
  onEvent: (e) => events.push(e),
});

afterAll(() => {
  server.close();
});

function smtpConversation(lines: string[]): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const port = (server.address() as net.AddressInfo).port;
    const sock = net.connect(port, "127.0.0.1");
    const replies: string[] = [];
    let buf = "";
    sock.on("data", (d) => {
      buf += d.toString();
      let idx;
      while ((idx = buf.indexOf("\r\n")) !== -1) {
        const line = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        replies.push(line);
      }
      if (replies.some((r) => r.startsWith("221"))) {
        sock.end();
        resolve(replies);
      }
    });
    sock.on("error", reject);
    // Fire the whole conversation; the server parses the stream sequentially.
    sock.write(lines.map((l) => `${l}\r\n`).join(""));
  });
}

describe("smtp ingest", () => {
  it("extracts token hints at any label depth", () => {
    expect(extractTokenHints("sub.tok123.tokens.example.com", ["tokens.example.com"])).toEqual([
      "sub",
      "tok123",
    ]);
    expect(extractTokenHints("tokens.example.com", ["tokens.example.com"])).toEqual([]);
    expect(extractTokenHints("other.example.net", ["tokens.example.com"])).toEqual([]);
  });

  it("accepts a message for our domain and emits an event", async () => {
    const replies = await smtpConversation([
      "HELO tester",
      "MAIL FROM:<attacker@evil.example>",
      "RCPT TO:<tokabc123@tokens.example.com>",
      "DATA",
      "Subject: hello",
      ".",
      "QUIT",
    ]);
    expect(replies[0]).toMatch(/^220/);
    expect(replies.some((r) => r === "250 OK")).toBe(true);
    await new Promise((r) => setTimeout(r, 50));
    const evt = events.find((e) => e.kind === "smtp");
    expect(evt).toBeDefined();
    expect(evt!.tokenHint).toBe("tokabc123");
    expect(evt!.smtp?.from).toBe("attacker@evil.example");
    expect(evt!.smtp?.subject).toBe("hello");
  });

  it("silently drops recipients outside our domains", async () => {
    const before = events.length;
    const replies = await smtpConversation([
      "HELO tester",
      "MAIL FROM:<x@y.example>",
      "RCPT TO:<victim@gmail.com>",
      "DATA",
      "Subject: nope",
      ".",
      "QUIT",
    ]);
    expect(replies.filter((r) => r === "250 OK").length).toBeGreaterThanOrEqual(3);
    await new Promise((r) => setTimeout(r, 50));
    expect(events.length).toBe(before);
  });
});
