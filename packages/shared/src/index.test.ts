import { describe, it, expect } from "vitest";
import {
  triggerEventSchema,
  incidentCreateInputSchema,
  tokenCreateInputSchema,
} from "./index.js";

describe("triggerEventSchema", () => {
  it("accepts a valid http event", () => {
    const result = triggerEventSchema.safeParse({
      kind: "http",
      tokenHint: "abc123",
      timestamp: new Date().toISOString(),
      sourceIp: "203.0.113.9",
      http: { method: "GET", host: "abc123.t.example.com", path: "/" },
    });
    expect(result.success).toBe(true);
  });

  it("rejects an unknown kind", () => {
    const result = triggerEventSchema.safeParse({
      kind: "gopher",
      tokenHint: "x",
      timestamp: new Date().toISOString(),
      sourceIp: "203.0.113.9",
    });
    expect(result.success).toBe(false);
  });
});

describe("tokenCreateInputSchema", () => {
  it("defaults config to empty object", () => {
    const parsed = tokenCreateInputSchema.parse({ type: "dns" });
    expect(parsed.config).toEqual({});
  });

  it("rejects memo over 500 chars", () => {
    const result = tokenCreateInputSchema.safeParse({
      type: "web_bug",
      memo: "a".repeat(501),
    });
    expect(result.success).toBe(false);
  });
});
