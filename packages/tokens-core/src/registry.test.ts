import { describe, it, expect } from "vitest";
import { listTokenTypes, getTokenType, matchEventToType } from "./registry.js";
import { tokenTypeSchema, type TriggerEvent } from "@f0/deception-shared";

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
  // packages/shared is meant to be the single source of truth for token
  // types, but nothing checked that its enum still matched what the
  // registry actually registers. It had already drifted somewhere else:
  // the MCP server hand-wrote its own 14-entry copy and silently lost
  // pdf_doc and cloned_website, so neither could be created through it
  // while every document promised 16. This guards the pair that every
  // other consumer derives from.
  it("tokenTypeSchema matches the registered types exactly", () => {
    const registered = listTokenTypes().map((d) => d.id).sort();
    const declared = [...tokenTypeSchema.options].sort();
    expect(declared).toEqual(registered);
  });

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

  it("custom_image matches /image path fetch", () => {
    const def = getTokenType("custom_image")!;
    const ev = httpEvent({
      http: { method: "GET", host: "tok123.tokens.example.com", path: "/tok123/image" },
    });
    const match = def.matchTrigger(ev, "tok123");
    expect(match.matched).toBe(true);
    if (match.matched) expect(match.severity).toBe("medium");
  });

  it("custom_image and web_bug do not match each other's paths", () => {
    const customImage = getTokenType("custom_image")!;
    const webBug = getTokenType("web_bug")!;
    const pixel = httpEvent({
      http: { method: "GET", host: "tok123.tokens.example.com", path: "/tok123/pixel.gif" },
    });
    const image = httpEvent({
      http: { method: "GET", host: "tok123.tokens.example.com", path: "/tok123/image" },
    });
    expect(customImage.matchTrigger(pixel, "tok123").matched).toBe(false);
    expect(webBug.matchTrigger(image, "tok123").matched).toBe(false);
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

describe("P3 matcher and config corrections", () => {
  it("sensitive_cmd matches the bare /cmd path it already serves", () => {
    const def = getTokenType("sensitive_cmd")!;
    const ev = (path: string): TriggerEvent => ({
      kind: "http",
      tokenHint: "tok123",
      timestamp: new Date().toISOString(),
      sourceIp: "203.0.113.5",
      http: { method: "GET", path, host: "tokens.example.com", headers: {} },
    });
    // The gateway serves this (default command output), so it must alert.
    expect(def.matchTrigger(ev("/tok123/cmd"), "tok123").matched).toBe(true);
    expect(def.matchTrigger(ev("/tok123/cmd/whoami"), "tok123").matched).toBe(true);
    expect(def.matchTrigger(ev("/tok123/cmdother"), "tok123").matched).toBe(false);
  });

  it("email token honours a configured mail_domain", () => {
    const def = getTokenType("email")!;
    const cfg = def.configSchema.parse({ mail_domain: "mail.example.net" }) as Record<string, unknown>;
    // Previously the empty schema stripped this and the address was always
    // <id>@<baseDomain>.
    expect(cfg["mail_domain"]).toBe("mail.example.net");
    const [artifact] = def.generate({
      tokenId: "tok123",
      baseDomain: "tokens.example.com",
      gatewayOrigin: "https://tokens.example.com",
      config: cfg,
    });
    expect(artifact?.value).toBe("tok123@mail.example.net");
  });

  it("cloned_website no longer advertises the dead strip_assets option", () => {
    const def = getTokenType("cloned_website")!;
    const cfg = def.configSchema.parse({
      target_url: "https://example.com/",
      strip_assets: true,
    }) as Record<string, unknown>;
    expect(cfg["strip_assets"]).toBeUndefined();
  });
});
