/** Token type catalog for the create form (mirrors the tokens-core registry). */
export const TOKEN_TYPES = [
  { id: "web_bug", label: "Web Bug", hint: "1x1 pixel URL", fields: [], group: "Network" },
  { id: "custom_image", label: "Custom Image", hint: "operator-uploaded image URL", fields: [], group: "Network" },
  { id: "dns", label: "DNS Token", hint: "unique hostname", fields: [], group: "Network" },
  { id: "email", label: "Unique Email", hint: "trigger address (needs MX)", fields: [], group: "Network" },
  { id: "qr_code", label: "QR Code", hint: "scan-to-trigger", fields: ["filename"], group: "Documents" },
  { id: "word_doc", label: "Word Document", hint: "remote-image .docx", fields: ["filename"], group: "Documents" },
  { id: "excel_doc", label: "Excel Workbook", hint: "hyperlink .xlsx", fields: ["filename"], group: "Documents" },
  { id: "pdf_doc", label: "PDF Document", hint: "open-action + link", fields: ["filename"], group: "Documents" },
  { id: "windows_folder", label: "Windows Folder", hint: "DNS-resolving folder name", fields: [], group: "Network" },
  { id: "cloned_website", label: "Cloned Website", hint: "beaconed page clone", fields: ["target_url"], group: "Documents" },
  { id: "sql_injection", label: "SQL Injection Canary", hint: "decoy endpoint rules", fields: ["decoy_path", "server_kind", "filename"], group: "Network" },
  { id: "sensitive_cmd", label: "Sensitive Command", hint: "fake cmd output page", fields: ["cmd_name"], group: "Network" },
  { id: "fast_redirect", label: "Fast Redirect", hint: "capture + 302", fields: ["target_url"], group: "Network" },
  { id: "aws_keys", label: "AWS Key Decoy", hint: "decoy credentials + wiring", fields: [], group: "Cloud Decoys" },
  { id: "azure_config", label: "Azure SP Decoy", hint: "decoy client-id/secret", fields: [], group: "Cloud Decoys" },
  { id: "honeypot", label: "Honeypot Link", hint: "reference token for agent sensors", fields: [], group: "Agent" },
] as const;

export type TokenField = "target_url" | "decoy_path" | "server_kind" | "cmd_name" | "filename";

export function tokenFields(type: string): readonly TokenField[] {
  return TOKEN_TYPES.find((t) => t.id === type)?.fields ?? [];
}
