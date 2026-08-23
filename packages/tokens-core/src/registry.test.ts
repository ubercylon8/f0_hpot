import { describe, it, expect } from "vitest";
import { listTokenTypes, getTokenType, matchEventToType } from "./registry.js";
import type { TriggerEvent } from "@f0/deception-shared";

function httpEvent(overrides: Partial<TriggerEvent> = {}): TriggerEvent {
  return {
    kind: "http",
    tokenHint: "tok123",
    timestamp: new Date().toISOString(),
    sourceIp: "203.0.113.9",
    http: { method: "GET", host: "tok123.tokens.example.com", path: "/" },
    ...overrides,
  };
}

describe("registry", () => {
  it("lists v1 network tokens", () => {
    const ids = listTokenTypes().map((d) => d.id);
    expect(ids).toContain("web_bug");
    expect(ids).toContain("dns");
    expect(ids).toContain("fast_redirect");
  });

  it("web_bug matches pixel path fetch", () => {
    const def = getTokenType("web_bug")!;
    const ev = httpEvent({
      http: { method: "GET", host: "tok123.tokens.example.com", path: "/tok123/pixel.gif" },
    });
    expect(def.matchTrigger(ev, "tok123").matched).toBe(true);
  });

  it("web_bug does not match unrelated path", () => {
    const def = getTokenType("web_bug")!;
    expect(def.matchTrigger(httpEvent(), "tok123").matched).toBe(false);
  });

  it("dns token matches dns queries", () => {
    const def = getTokenType("dns")!;
    const ev = httpEvent({
      kind: "dns",
      dns: { queryName: "sub.tok123.tokens.example.com", queryType: "A" },
    });
    expect(matchEventToType(ev, "tok123")?.id).toBe("dns");
  });

  it("fast_redirect requires /r suffix and valid config", () => {
    const def = getTokenType("fast_redirect")!;
    expect(
      def.configSchema.safeParse({ target_url: "not a url" }).success,
    ).toBe(false);
    expect(
      def.configSchema.safeParse({ target_url: "https://corp.example.com/" })
        .success,
    ).toBe(true);
    const ev = httpEvent({
      http: { method: "GET", host: "tok123.tokens.example.com", path: "/tok123/r" },
    });
    expect(def.matchTrigger(ev, "tok123").matched).toBe(true);
  });

  it("qr_code token matches /qr path with high severity", () => {
    const def = getTokenType("qr_code")!;
    expect(def).toBeDefined();
    const ev = httpEvent({
      http: { method: "GET", host: "tok123.tokens.example.com", path: "/tok123/qr" },
    });
    const match = def.matchTrigger(ev, "tok123");
    expect(match.matched).toBe(true);
    if (match.matched) expect(match.severity).toBe("high");
  });

  it("sensitive_cmd matches /cmd/* paths and defaults cmd_name", () => {
    const def = getTokenType("sensitive_cmd")!;
    expect(def.configSchema.parse({})).toEqual({ cmd_name: "ifconfig" });
    const ev = httpEvent({
      http: { method: "GET", host: "tok123.tokens.example.com", path: "/tok123/cmd/ipconfig" },
    });
    const match = def.matchTrigger(ev, "tok123");
    expect(match.matched).toBe(true);
  });

  it("web_bug does not swallow qr or redirect paths of same token id", () => {
    const webBug = getTokenType("web_bug")!;
    const ev = httpEvent({
      http: { method: "GET", host: "tok123.tokens.example.com", path: "/tok123/qr" },
    });
    // web_bug requires the pixel path specifically
    expect(webBug.matchTrigger(ev, "tok123").matched).toBe(false);
    expect(matchEventToType(ev, "tok123")?.id).toBe("qr_code");
  });
});
