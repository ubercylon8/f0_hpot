import type { TokenType } from "@f0/deception-shared";
import {
  webBugToken,
  dnsToken,
  fastRedirectToken,
  qrCodeToken,
  emailToken,
  sensitiveCmdToken,
} from "./network-tokens.js";
import type { TokenTypeDefinition, GenerateContext, TokenArtifactSpec, MatchResult } from "./types.js";

export type {
  TokenTypeDefinition,
  GenerateContext,
  TokenArtifactSpec,
  MatchResult,
};

const definitions: TokenTypeDefinition[] = [
  webBugToken,
  dnsToken,
  fastRedirectToken,
  qrCodeToken,
  emailToken,
  sensitiveCmdToken,
];

const registry = new Map<string, TokenTypeDefinition>(
  definitions.map((d) => [d.id, d]),
);

export function listTokenTypes(): TokenTypeDefinition[] {
  return definitions;
}

export function getTokenType(type: TokenType): TokenTypeDefinition | undefined {
  return registry.get(type);
}

export function registerTokenType(definition: TokenTypeDefinition): void {
  if (registry.has(definition.id)) {
    throw new Error(`token type already registered: ${definition.id}`);
  }
  registry.set(definition.id, definition);
  definitions.push(definition);
}

/**
 * Find the token definition whose trigger rules match this event for a given
 * tokenId. Returns the first matching definition.
 */
export function matchEventToType(
  event: Parameters<TokenTypeDefinition["matchTrigger"]>[0],
  tokenId: string,
): TokenTypeDefinition | null {
  for (const def of definitions) {
    if (def.matchTrigger(event, tokenId).matched) return def;
  }
  return null;
}
