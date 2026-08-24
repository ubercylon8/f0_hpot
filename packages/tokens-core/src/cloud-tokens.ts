import { z } from "zod";
import crypto from "node:crypto";

const emptyAzConfig = z.object({});
import { randomBytes } from "node:crypto";
import type { TriggerEvent } from "@f0/deception-shared";
import { eventMentionsToken } from "./network-tokens.js";
import type { TokenTypeDefinition, MatchResult } from "./types.js";

/**
 * Azure service principal decoy.
 *
 * Self-hosted reality: detection of secret use requires the operator's
 * tenant to stream Sign-in/Audit logs to this platform (Azure Monitor ->
 * Event Grid / Logic App -> ingest endpoint). We generate the decoy
 * credential material and the wiring instructions.
 */
export const azureConfigToken: TokenTypeDefinition = {
  id: "azure_config",
  label: "Azure Service Principal Decoy",
  description:
    "Decoy Azure client-id/secret pair plus wiring instructions so sign-ins with it trigger an alert.",
  group: "cloud",
  configSchema: emptyAzConfig,
  generate(ctx) {
    const clientId = crypto.randomUUID();
    const secret = base64url(randomBytes(24)) + "~"; // ~ suffix mimics real secrets
    const tenantHint = "REPLACE-WITH-TENANT-ID";
    const ingestUrl = `${ctx.gatewayOrigin}/${ctx.tokenId}/azure`;

    const envFile =
      `AZURE_TENANT_ID=${tenantHint}\n` +
      `AZURE_CLIENT_ID=${clientId}\n` +
      `AZURE_CLIENT_SECRET=${secret}\n`;
    const readme = `# Azure Service Principal Decoy

1. Create a service principal with client-id ${clientId}
   and the secret below, with NO roles (any use is suspicious).
2. Stream its sign-in logs to this platform:
   - Azure Monitor -> Diagnostic setting on the tenant:
     route SignInLogs to Event Grid / Logic App
   - POST matching events to: ${ingestUrl}
     (any HTTP request to that path records a high-severity incident)
3. Plant the env file where an attacker will find it.

## .env file
${envFile}

## az cli equivalent for creating the SP
az ad sp create-for-rbac --name "f0-decoy-${ctx.tokenId}" \\
  --years 1 --skip-assignment  # then rotate-in the secret below
`;
    return [
      { kind: "url", label: "Ingest endpoint", value: ingestUrl },
      {
        kind: "file_download",
        label: "azure_decoy_readme.txt",
        value: `/api/v1/tokens/${ctx.tokenId}/files/0`,
        file: {
          filename: "azure_decoy_readme.txt",
          contentType: "text/plain",
          bodyBase64: Buffer.from(readme).toString("base64"),
        },
      },
      {
        kind: "file_download",
        label: ".env (plant me)",
        value: `/api/v1/tokens/${ctx.tokenId}/files/1`,
        file: {
          filename: ".env.azure",
          contentType: "text/plain",
          bodyBase64: Buffer.from(envFile).toString("base64"),
        },
      },
    ];
  },
  matchTrigger(event, tokenId): MatchResult {
    const http = event.kind === "http" ? event.http : undefined;
    if (!http || !eventMentionsToken(event, tokenId)) return { matched: false };
    if (!http.path.startsWith(`/${tokenId}/azure`)) return { matched: false };
    return { matched: true, severity: "high" };
  },
};


function base64url(buf: Buffer): string {
  return buf.toString("base64url");
}

/**
 * AWS key decoy. See the self-hosted note: detection of use requires the
 * operator's CloudTrail wired to /<tokenId>/aws.
 */
export const awsKeysToken: TokenTypeDefinition = {
  id: "aws_keys",
  label: "AWS Key Decoy",
  description:
    "Decoy AWS credentials plus a Terraform snippet wiring your CloudTrail to this platform so key use triggers an alert.",
  group: "cloud",
  configSchema: z.object({}),
  generate(ctx) {
    const accessKeyId = `AKIA${base32(randomBytes(8)).slice(0, 16).toUpperCase()}`;
    const secretAccessKey = randomBytes(30).toString("base64").replace(/[^A-Za-z0-9+/]/g, "").slice(0, 40);
    const ingestUrl = `${ctx.gatewayOrigin}/${ctx.tokenId}/aws`;
    const credentialsFile =
      `[default]\naws_access_key_id = ${accessKeyId}\naws_secret_access_key = ${secretAccessKey}\n`;
    const readme = `# AWS Key Decoy — ${accessKeyId}

1. Create an IAM user with ONLY this access key and no permissions.
2. Wire CloudTrail -> EventBridge -> ${ingestUrl}
3. Plant the credentials file.

## credentials file
${credentialsFile}
`;
    return [
      { kind: "url", label: "Ingest endpoint", value: ingestUrl },
      {
        kind: "file_download",
        label: "aws_decoy_readme.txt",
        value: `/api/v1/tokens/${ctx.tokenId}/files/0`,
        file: {
          filename: "aws_decoy_readme.txt",
          contentType: "text/plain",
          bodyBase64: Buffer.from(readme).toString("base64"),
        },
      },
      {
        kind: "file_download",
        label: "credentials (plant me)",
        value: `/api/v1/tokens/${ctx.tokenId}/files/1`,
        file: {
          filename: "credentials",
          contentType: "text/plain",
          bodyBase64: Buffer.from(credentialsFile).toString("base64"),
        },
      },
    ];
  },
  matchTrigger(event, tokenId): MatchResult {
    const http = event.kind === "http" ? event.http : undefined;
    if (!http || !eventMentionsToken(event, tokenId)) return { matched: false };
    if (!http.path.startsWith(`/${tokenId}/aws`)) return { matched: false };
    return { matched: true, severity: "high" };
  },
};

function base32(buf: Buffer): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return out;
}


// node:crypto randomUUID re-exported for clarity

/**
 * Honeypot placeholder token: the managed token a sensor references so
 * agent-side detections are linked to something revocable/alertable.
 * It never triggers from the gateway — only agent reports hit it.
 */
export const honeypotToken: TokenTypeDefinition = {
  id: "honeypot",
  label: "Honeypot Link",
  description:
    "Reference token for agent-side honeypot sensors. Create one per honeypot deployment and point the sensor's token_id at it.",
  group: "agent",
  configSchema: z.object({
    sensor: z.string().optional(),
    host: z.string().optional(),
  }),
  generate(ctx) {
    const sensor = ctx.config["sensor"] ? String(ctx.config["sensor"]) : "any";
    const host = ctx.config["host"] ? String(ctx.config["host"]) : "";
    return [
      {
        kind: "url",
        label: `Sensor reference (${sensor}${host ? ` on ${host}` : ""})`,
        value: `token_id=${ctx.tokenId}`,
      },
    ];
  },
  matchTrigger(_event, _tokenId): MatchResult {
    return { matched: false }; // gateway events never trigger honeypot links
  },
};
