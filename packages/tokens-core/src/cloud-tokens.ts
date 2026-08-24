import { z } from "zod";

const emptyConfig = z.object({});
import { randomBytes } from "node:crypto";
import type { TriggerEvent } from "@f0/deception-shared";
import { eventMentionsToken } from "./network-tokens.js";
import type { TokenTypeDefinition, MatchResult } from "./types.js";

/**
 * AWS key decoy.
 *
 * IMPORTANT (self-hosted reality): upstream services detect AWS key use via
 * THEIR cloud account infrastructure. Self-hosted f0_deception generates
 * decoy credentials and gives you a Terraform snippet to wire YOUR
 * CloudTrail -> EventBridge -> this platform's ingest endpoint. Without that
 * wiring the key is inert decoration.
 */
export const awsKeysToken: TokenTypeDefinition = {
  id: "aws_keys",
  label: "AWS Key Decoy",
  description:
    "Decoy AWS credentials plus a Terraform snippet wiring your CloudTrail to this platform so key use triggers an alert.",
  group: "cloud",
  configSchema: emptyConfig,
  generate(ctx) {
    const accessKeyId = `AKIA${base32(randomBytes(8)).slice(0, 16).toUpperCase()}`;
    const secretAccessKey = randomBytes(30).toString("base64").replace(/[^A-Za-z0-9+/]/g, "").slice(0, 40);
    const ingestUrl = `${ctx.gatewayOrigin}/${ctx.tokenId}/aws`;
    const credentialsFile =
      `[default]\naws_access_key_id = ${accessKeyId}\naws_secret_access_key = ${secretAccessKey}\n`;
    const terraform = `# f0_deception AWS key decoy wiring (run once in the account to protect)
# Forwards CloudTrail management events for this key's IAM user to ${ingestUrl}

resource "aws_cloudtrail_event_data_store" "f0" {
  name = "f0-deception"
}

# Simpler alternative: CloudTrail -> SNS/EventBridge rule -> HTTP target
resource "aws_cloudwatch_event_rule" "f0_iam_usage" {
  name        = "f0-deception-iam-${ctx.tokenId}"
  description = "Forward IAM activity for decoy key ${accessKeyId}"
  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      userIdentity = { accessedApiKey = [{ exists = true }] }
    }
  })
}

resource "aws_cloudwatch_event_target" "f0_forward" {
  rule = aws_cloudwatch_event_rule.f0_iam_usage.name
  arn  = "arn:aws:sqs:REPLACE" # queue consumed by a small forwarder, or use
                               # api-destination pointed at:
                               # ${ingestUrl}
}
`;
    const readme = `# AWS Key Decoy — ${accessKeyId}

1. Create an IAM user with ONLY this access key and no permissions
   (any use is therefore suspicious).
2. Deploy the Terraform snippet below in the same account so any API call
   made with this key is forwarded to: ${ingestUrl}
3. Plant the credentials file where an attacker will find it.

## credentials file
${credentialsFile}

## terraform snippet
${terraform}
`;
    return [
      {
        kind: "url",
        label: "Ingest endpoint (wire your CloudTrail here)",
        value: ingestUrl,
      },
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

// Crockford-ish base32 for AWS-style ids.
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
