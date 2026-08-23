import type { ZodType } from "zod";
import type { TriggerEvent } from "@f0/deception-shared";

export interface TokenArtifactSpec {
  kind: "url" | "hostname" | "file_download";
  label: string;
  value: string;
}

export interface GenerateContext {
  tokenId: string;
  /** Base domain under which token hostnames are served, e.g. tokens.example.com */
  baseDomain: string;
  /** Public origin of the gateway, e.g. https://tokens.example.com */
  gatewayOrigin: string;
  config: Record<string, unknown>;
}

export type MatchResult =
  | { matched: false }
  | {
      matched: true;
      severity: "low" | "medium" | "high";
    };

export interface TokenTypeDefinition<C = Record<string, unknown>> {
  id: string;
  label: string;
  description: string;
  group: "network" | "document" | "agent";

  /** Creation-time config validation. */
  configSchema: ZodType<C>;

  /**
   * Hostname prefix used for DNS/HTTP matching. The full trigger hostname is
   * `<tokenId>.<baseDomain>` unless the definition overrides `hostnameFor`.
   */
  hostnameFor?(ctx: GenerateContext): string;

  /** User-facing artifacts (URL to plant, file to download, ...). */
  generate(ctx: GenerateContext): TokenArtifactSpec[];

  /** Decide whether an inbound trigger event belongs to this token. */
  matchTrigger(event: TriggerEvent, tokenId: string): MatchResult;
}
