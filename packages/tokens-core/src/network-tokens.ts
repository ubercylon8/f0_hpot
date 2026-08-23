import { z } from "zod";
import type { TriggerEvent } from "@f0/deception-shared";
import type { TokenTypeDefinition, MatchResult, GenerateContext } from "./types.js";

const emptyConfig = z.object({});

function defaultHostname(ctx: GenerateContext): string {
  return `${ctx.tokenId}.${ctx.baseDomain}`;
}

/**
 * A trigger matches a token when the token hint appears in the event
 * (as a hostname/query-name label, or a URL path segment).
 */
export function eventMentionsToken(event: TriggerEvent, tokenId: string): boolean {
  if (event.tokenHint === tokenId) return true;
  if (event.dns?.queryName.split(".").includes(tokenId)) return true;
  if (event.http?.host.split(".").includes(tokenId)) return true;
  return false;
}

export function matchByTokenHint(
  event: TriggerEvent,
  tokenId: string,
): MatchResult {
  if (eventMentionsToken(event, tokenId)) {
    return { matched: true, severity: "medium" };
  }
  return { matched: false };
}

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
    const http = event.kind === "http" ? event.http : undefined;
    if (!http || !eventMentionsToken(event, tokenId)) return { matched: false };
    if (!http.path.includes(tokenId)) return { matched: false };
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
    const http = event.kind === "http" ? event.http : undefined;
    if (!http || !eventMentionsToken(event, tokenId)) return { matched: false };
    if (!http.path.startsWith(`/${tokenId}/r`)) return { matched: false };
    return { matched: true, severity: "medium" };
  },
};
