import { describe, it, expect } from "vitest";
import { getTokenType } from "./registry.js";
import { buildOoxmlWithExternalImage, buildXlsxWithHyperlink } from "./document-tokens.js";
import type { TriggerEvent } from "@f0/deception-shared";

function httpEvent(path: string): TriggerEvent {
  return {
    kind: "http",
    tokenHint: "tok123",
    timestamp: new Date().toISOString(),
    sourceIp: "203.0.113.9",
    http: { method: "GET", host: "tokens.example.com", path },
  };
}

describe("document tokens", () => {
  it("word_doc matches its pixel fetch with high severity", () => {
    const def = getTokenType("word_doc")!;
    const match = def.matchTrigger(httpEvent("/tok123/pixel.gif"), "tok123");
    expect(match).toEqual({ matched: true, severity: "high" });
    expect(def.matchTrigger(httpEvent("/other"), "tok123").matched).toBe(false);
  });

  it("windows_folder matches dns lookups", () => {
    const def = getTokenType("windows_folder")!;
    const ev: TriggerEvent = {
      kind: "dns",
      tokenHint: "tok123",
      timestamp: new Date().toISOString(),
      sourceIp: "203.0.113.9",
      dns: { queryName: "tok123.tokens.example.com", queryType: "A" },
    };
    expect(def.matchTrigger(ev, "tok123").matched).toBe(true);
  });

  it("sql_injection matches /sqli decoy hits", () => {
    const def = getTokenType("sql_injection")!;
    expect(
      def.configSchema.parse({}) as unknown,
    ).toMatchObject({ path: "/search.php", server_kind: "nginx" });
    const match = def.matchTrigger(httpEvent("/tok123/sqli"), "tok123");
    expect(match).toEqual({ matched: true, severity: "high" });
  });

  it("builds a structurally valid minimal docx zip", () => {
    // PK magic + EOCD magic at the end; entries present in raw bytes.
    const buf = buildOoxmlWithExternalImage({
      appName: "Microsoft Word",
      headingText: "T",
      bodyText: "B",
      pixelUrl: "https://tokens.example.com/tok123/pixel.gif",
    });
    expect(buf.subarray(0, 2).toString()).toBe("PK");
    // EOCD record ends the file; its signature is at (len - 22).
    expect(buf.subarray(buf.length - 22).readUInt32LE(0)).toBe(0x06054b50);
    expect(buf.includes("word/document.xml")).toBe(true);
    expect(buf.includes('TargetMode="External"')).toBe(true);
  });

  it("builds an xlsx with external hyperlink rel", () => {
    const buf = buildXlsxWithHyperlink({
      sheetName: "S",
      cellLabel: "L",
      url: "https://tokens.example.com/tok123/pixel.gif",
    });
    expect(buf.subarray(0, 2).toString()).toBe("PK");
    expect(buf.includes('TargetMode="External"')).toBe(true);
  });

  it("sql_injection generates nginx and apache snippets", () => {
    const def = getTokenType("sql_injection")!;
    for (const kind of ["nginx", "apache"] as const) {
      const artifacts = def.generate({
        tokenId: "tok123",
        baseDomain: "tokens.example.com",
        gatewayOrigin: "https://tokens.example.com",
        config: { server_kind: kind, path: "/admin/search" },
      });
      const fileArtifact = artifacts.find((a) => a.file)!;
      const content = Buffer.from(fileArtifact.file!.bodyBase64, "base64").toString();
      if (kind === "nginx") expect(content).toContain("location = /admin/search");
      else expect(content).toContain("Redirect 302 /admin/search");
      expect(content).toContain("/tok123/sqli");
    }
  });
});
