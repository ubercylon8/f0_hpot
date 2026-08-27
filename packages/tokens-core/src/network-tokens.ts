import { z } from "zod";
import type { TriggerEvent } from "@f0/deception-shared";
import type { TokenTypeDefinition, MatchResult, GenerateContext } from "./types.js";

function defaultHostname(ctx: GenerateContext): string {
  return `${ctx.tokenId}.${ctx.baseDomain}`;
}

/**
 * A trigger matches a token when the token id appears in the event:
 * as a hostname/query-name label, or as the first URL path segment
 * (artifacts hosted on the base domain itself).
 */
export function eventMentionsToken(event: TriggerEvent, tokenId: string): boolean {
  if (event.tokenHint === tokenId) return true;
  if (event.dns?.queryName.split(".").includes(tokenId)) return true;
  const http = event.kind === "http" ? event.http : undefined;
  if (http) {
    if (http.host.split(".").includes(tokenId)) return true;
    if (http.path.split("?")[0]!.split("/").includes(tokenId)) return true;
  }
  return false;
}

function httpOf(event: TriggerEvent) {
  return event.kind === "http" ? event.http : undefined;
}

const emptyConfig = z.object({});

export const webBugToken: TokenTypeDefinition = {
  id: "web_bug",
  label: "Web Bug",
  description:
    "A unique URL returning a 1x1 tracking pixel. Any fetch of the URL triggers an alert.",
  group: "network",
  configSchema: emptyConfig,
  generate(ctx) {
    const url = `${ctx.gatewayOrigin}/${ctx.tokenId}/pixel.gif`;
    return [{ kind: "url", label: "Tracking pixel URL", value: url }];
  },
  matchTrigger(event, tokenId) {
    const http = httpOf(event);
    if (!http || !eventMentionsToken(event, tokenId)) return { matched: false };
    if (!http.path.startsWith(`/${tokenId}/pixel.gif`)) return { matched: false };
    return { matched: true, severity: "medium" };
  },
};

export const customImageToken: TokenTypeDefinition = {
  id: "custom_image",
  label: "Custom Image",
  description:
    "A unique URL serving an operator-uploaded image (POST the image to /api/v1/tokens/:id/image after creation). Any fetch of the URL triggers an alert.",
  group: "network",
  configSchema: emptyConfig,
  generate(ctx) {
    const url = `${ctx.gatewayOrigin}/${ctx.tokenId}/image`;
    return [{ kind: "url", label: "Custom image URL", value: url }];
  },
  matchTrigger(event, tokenId) {
    const http = httpOf(event);
    if (!http || !eventMentionsToken(event, tokenId)) return { matched: false };
    if (!http.path.startsWith(`/${tokenId}/image`)) return { matched: false };
    return { matched: true, severity: "medium" };
  },
};

export const dnsToken: TokenTypeDefinition = {
  id: "dns",
  label: "DNS Token",
  description:
    "A unique hostname. Any DNS lookup for it or its subdomains triggers an alert.",
  group: "network",
  configSchema: emptyConfig,
  hostnameFor: defaultHostname,
  generate(ctx) {
    return [
      {
        kind: "hostname",
        label: "Trigger hostname",
        value: defaultHostname(ctx),
      },
    ];
  },
  matchTrigger(event, tokenId) {
    if (event.kind !== "dns") return { matched: false };
    if (!eventMentionsToken(event, tokenId)) return { matched: false };
    return { matched: true, severity: "high" };
  },
};

export const fastRedirectToken: TokenTypeDefinition = {
  id: "fast_redirect",
  label: "Fast Redirect",
  description:
    "A URL that 302-redirects to a target of your choice while capturing the visitor.",
  group: "network",
  configSchema: z.object({
    target_url: z.string().url(),
  }),
  generate(ctx) {
    const target = String(ctx.config["target_url"] ?? "");
    return [
      {
        kind: "url",
        label: `Redirect URL${target ? ` -> ${target}` : ""}`,
        value: `${ctx.gatewayOrigin}/${ctx.tokenId}/r`,
      },
    ];
  },
  matchTrigger(event, tokenId) {
    const http = httpOf(event);
    if (!http || !eventMentionsToken(event, tokenId)) return { matched: false };
    if (!http.path.startsWith(`/${tokenId}/r`)) return { matched: false };
    return { matched: true, severity: "medium" };
  },
};

export const qrCodeToken: TokenTypeDefinition = {
  id: "qr_code",
  label: "QR Code",
  description:
    "A unique QR code. Scanning it (or fetching the encoded URL) triggers an alert.",
  group: "document",
  configSchema: emptyConfig,
  generate(ctx) {
    const targetUrl = `${ctx.gatewayOrigin}/${ctx.tokenId}/qr`;
    return [
      {
        kind: "url",
        label: "Encoded trigger URL",
        value: targetUrl,
      },
      {
        kind: "file_download",
        label: "QR code image",
        // The API renders the PNG at creation and stores it in token_files.
        value: `/api/v1/tokens/${ctx.tokenId}/files/0`,
      },
    ];
  },
  matchTrigger(event, tokenId) {
    const http = httpOf(event);
    if (!http || !eventMentionsToken(event, tokenId)) return { matched: false };
    if (!http.path.startsWith(`/${tokenId}/qr`)) return { matched: false };
    return { matched: true, severity: "high" };
  },
};

export const emailToken: TokenTypeDefinition = {
  id: "email",
  label: "Unique Email Address",
  description:
    "A unique email address. Any mail sent to it triggers an alert (requires MX records pointing at the gateway).",
  group: "network",
  configSchema: emptyConfig,
  generate(ctx) {
    const mailDomain = ctx.config["mail_domain"]
      ? String(ctx.config["mail_domain"])
      : ctx.baseDomain;
    return [
      {
        kind: "url",
        label: "Trigger email address",
        value: `${ctx.tokenId}@${mailDomain}`,
      },
    ];
  },
  matchTrigger(event, tokenId) {
    if (event.kind !== "smtp") return { matched: false };
    if (!eventMentionsToken(event, tokenId)) return { matched: false };
    if (!event.smtp) return { matched: false };
    if (!event.smtp.to.split("@")[0]?.includes(tokenId)) return { matched: false };
    return { matched: true, severity: "high" };
  },
};

export const sensitiveCmdToken: TokenTypeDefinition = {
  id: "sensitive_cmd",
  label: "Sensitive Command",
  description:
    "Serves a fake command output page. Triggered when someone executes or fetches the planted command URL (e.g. a bookmarklet, alias, or documentation link).",
  group: "network",
  configSchema: z.object({
    cmd_name: z
      .enum(["ifconfig", "ipconfig", "whoami", "cat_etc_shadow"])
      .default("ifconfig"),
  }),
  generate(ctx) {
    const cmd = String(ctx.config["cmd_name"] ?? "ifconfig");
    return [
      {
        kind: "url",
        label: `${cmd} trigger URL`,
        value: `${ctx.gatewayOrigin}/${ctx.tokenId}/cmd/${cmd}`,
      },
    ];
  },
  matchTrigger(event, tokenId) {
    const http = httpOf(event);
    if (!http || !eventMentionsToken(event, tokenId)) return { matched: false };
    if (!http.path.startsWith(`/${tokenId}/cmd/`)) return { matched: false };
    return { matched: true, severity: "high" };
  },
};
