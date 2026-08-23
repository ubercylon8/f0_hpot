import { z } from "zod";
import { tokenStatusSchema, tokenTypeSchema } from "./token.js";

export const triggerEventSchema = z.object({
  kind: z.enum(["http", "dns", "smtp"]),
  tokenHint: z.string().min(1),
  timestamp: z.string().datetime(),
  sourceIp: z.string(),
  sourcePort: z.number().int().optional(),
  http: z
    .object({
      method: z.string(),
      host: z.string(),
      path: z.string(),
      userAgent: z.string().optional(),
      referer: z.string().optional(),
      acceptLanguage: z.string().optional(),
      headers: z.record(z.string(), z.string()).optional(),
    })
    .optional(),
  dns: z
    .object({
      queryName: z.string(),
      queryType: z.string(),
    })
    .optional(),
  smtp: z
    .object({
      from: z.string().optional(),
      to: z.string(),
      subject: z.string().optional(),
    })
    .optional(),
});
export type TriggerEvent = z.infer<typeof triggerEventSchema>;

export const incidentSeveritySchema = z.enum(["low", "medium", "high"]);
export type IncidentSeverity = z.infer<typeof incidentSeveritySchema>;

export const incidentSchema = z.object({
  id: z.string(),
  tokenId: z.string(),
  tokenType: tokenTypeSchema,
  severity: incidentSeveritySchema,
  acknowledged: z.boolean(),
  event: triggerEventSchema,
  seenAt: z.string().datetime(),
});
export type Incident = z.infer<typeof incidentSchema>;

export const incidentCreateInputSchema = z.object({
  tokenId: z.string().min(1),
  severity: incidentSeveritySchema.default("medium"),
  event: triggerEventSchema,
});

export const tokenResponseSchema = z.object({
  id: z.string(),
  type: tokenTypeSchema,
  memo: z.string().nullable(),
  status: tokenStatusSchema,
  config: z.record(z.string(), z.unknown()),
  artifacts: z.array(
    z.object({
      kind: z.enum(["url", "hostname", "file_download"]),
      label: z.string(),
      value: z.string(),
    }),
  ),
  createdAt: z.string().datetime(),
  hitCount: z.number().int().nonnegative(),
});
export type TokenResponse = z.infer<typeof tokenResponseSchema>;

export const tokenCreateInputSchema = z.object({
  type: tokenTypeSchema,
  memo: z.string().max(500).optional(),
  config: z.record(z.string(), z.unknown()).default({}),
});
