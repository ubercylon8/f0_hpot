import { describe, it, expect, vi } from "vitest";
import { AlertDispatcher } from "./dispatcher.js";
import type { AlertPayload } from "./types.js";

function makeAlert(sourceIp: string, tokenId = "tok1"): AlertPayload {
  return {
    tokenId,
    tokenType: "web_bug",
    severity: "medium",
    incidentId: `inc_${Math.random().toString(36).slice(2)}`,
    seenAt: new Date().toISOString(),
    event: {
      kind: "http",
      tokenHint: tokenId,
      timestamp: new Date().toISOString(),
      sourceIp,
      http: { method: "GET", host: `${tokenId}.t.example.com`, path: `/${tokenId}/pixel.gif` },
    },
  };
}

describe("AlertDispatcher.shouldAlert", () => {
  it("allows the first alert per (token, ip) then throttles", () => {
    let now = 1_000_000;
    const d = new AlertDispatcher({} as never, { now: () => now });
    expect(d.shouldAlert("tok1", "1.2.3.4")).toBe(true);
    expect(d.shouldAlert("tok1", "1.2.3.4")).toBe(false);
    expect(d.shouldAlert("tok1", "5.6.7.8")).toBe(true); // different ip
    expect(d.shouldAlert("tok2", "1.2.3.4")).toBe(true); // different token
    // window expiry resets the counter
    now += 61_000;
    expect(d.shouldAlert("tok1", "1.2.3.4")).toBe(true);
  });

  it("honors maxAlertsPerMinute > 1", () => {
    const d = new AlertDispatcher({} as never, { maxAlertsPerMinute: 2 });
    expect(d.shouldAlert("tok1", "1.2.3.4")).toBe(true);
    expect(d.shouldAlert("tok1", "1.2.3.4")).toBe(true);
    expect(d.shouldAlert("tok1", "1.2.3.4")).toBe(false);
  });
});

describe("senders registry", () => {
  it("webhook sender rejects non-http urls", async () => {
    const { webhookSender } = await import("./webhook.js");
    await expect(
      webhookSender.send({ url: "ftp://nope" }, makeAlert("1.1.1.1")),
    ).rejects.toThrow(/http\(s\) url/);
  });

  it("syslog sender rejects missing host", async () => {
    const { syslogSender } = await import("./syslog.js");
    await expect(syslogSender.send({}, makeAlert("1.1.1.1"))).rejects.toThrow(/host/);
  });

  it("email sender rejects incomplete config", async () => {
    const { emailSender } = await import("./email.js");
    await expect(emailSender.send({ smtp_host: "x" }, makeAlert("1.1.1.1"))).rejects.toThrow(
      /requires/,
    );
  });

  it("dispatch is a graceful no-op with unknown channel kinds", async () => {
    const { AlertDispatcher: D } = await import("./dispatcher.js");
    const rows = [
      { id: "chan_x", kind: "carrier_pigeon", config: {}, enabled: true, failureCount: 0, createdAt: "" },
    ];
    const fakeDb = {
      select() {
        return {
          from: () => ({
            where: () => ({ all: () => rows, get: () => rows[0] }),
          }),
        };
      },
      update() {
        return { set: () => ({ where: () => ({ run: () => ({ changes: 1 }) }) }) };
      },
    } as never;
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const d = new D(fakeDb);
    await expect(d.dispatch(makeAlert("9.9.9.9"))).resolves.toBeUndefined();
    errSpy.mockRestore();
  });
});
