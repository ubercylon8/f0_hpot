import nodemailer from "nodemailer";
import type { AlertPayload, AlertSender } from "./types.js";

interface EmailConfig {
  smtp_host: string;
  smtp_port?: number;
  smtp_user?: string;
  smtp_pass?: string;
  from: string;
  to: string;
  subject_prefix?: string;
}

function isEmailConfig(
  config: Record<string, unknown>,
): config is Record<string, unknown> & EmailConfig {
  return (
    typeof config["smtp_host"] === "string" &&
    typeof config["from"] === "string" &&
    typeof config["to"] === "string"
  );
}

/** Plain SMTP email channel (STARTTLS when offered). */
export const emailSender: AlertSender = {
  async send(config, alert) {
    if (!isEmailConfig(config)) {
      throw new Error("email channel requires smtp_host, from, to");
    }
    const transport = nodemailer.createTransport({
      host: config.smtp_host,
      port: config.smtp_port ?? 587,
      secure: false,
      auth:
        config.smtp_user && config.smtp_pass
          ? { user: config.smtp_user, pass: config.smtp_pass }
          : undefined,
      connectionTimeout: 10_000,
    });
    const subject = `${config.subject_prefix ?? "[f0_deception]"} canary triggered: ${alert.tokenType} (${alert.tokenId})`;
    await transport.sendMail({
      from: config.from,
      to: config.to,
      subject,
      text: renderText(alert),
    });
  },
};

export function renderText(alert: AlertPayload): string {
  const e = alert.event;
  const lines = [
    `A canarytoken was triggered.`,
    ``,
    `Token:   ${alert.tokenType} (${alert.tokenId})`,
    `Severity: ${alert.severity}`,
    `Seen at:  ${alert.seenAt}`,
    `Source IP: ${e.sourceIp}`,
  ];
  if (e.http) {
    lines.push(`HTTP: ${e.http.method} ${e.http.host}${e.http.path}`);
    if (e.http.userAgent) lines.push(`User-Agent: ${e.http.userAgent}`);
    if (e.http.referer) lines.push(`Referer: ${e.http.referer}`);
  }
  if (e.dns) {
    lines.push(`DNS query: ${e.dns.queryName} (${e.dns.queryType})`);
  }
  return lines.join("\n");
}
