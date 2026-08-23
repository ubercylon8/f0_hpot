import { z } from "zod";

/**
 * Token types supported by f0_deception.
 * v1 core set; cloud/agent tokens land in later phases.
 */
export const tokenTypeSchema = z.enum([
  "web_bug",
  "custom_image",
  "dns",
  "email",
  "qr_code",
  "word_doc",
  "excel_doc",
  "pdf_doc",
  "windows_folder",
  "sensitive_cmd",
  "cloned_website",
  "sql_injection",
  "fast_redirect",
]);
export type TokenType = z.infer<typeof tokenTypeSchema>;

export const tokenStatusSchema = z.enum(["active", "paused", "revoked"]);
export type TokenStatus = z.infer<typeof tokenStatusSchema>;

export const tokenArtifactSchema = z.object({
  kind: z.enum(["url", "hostname", "file_download"]),
  label: z.string(),
  value: z.string(),
});
export type TokenArtifact = z.infer<typeof tokenArtifactSchema>;
