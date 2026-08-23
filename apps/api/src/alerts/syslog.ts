import dgram from "node:dgram";
import type { AlertPayload, AlertSender } from "./types.js";

const FACILITY_USER = 1; // RFC5424 facility 1 = user-level
const SEVERITY_MAP: Record<string, number> = {
  low: 6, // informational
  medium: 4, // warning
  high: 2, // critical
};

/**
 * Syslog channel: UDP RFC5424 messages.
 * Config: { host, port?, app_name? }
 */
export const syslogSender: AlertSender = {
  async send(config, alert) {
    const host = config["host"];
    if (typeof host !== "string") throw new Error("syslog config requires host");
    const port = typeof config["port"] === "number" ? config["port"] : 514;
    const appName = typeof config["app_name"] === "string" ? config["app_name"] : "f0_deception";

    const pri = FACILITY_USER * 8 + (SEVERITY_MAP[alert.severity] ?? 4);
    const msgId = "canary";
    const sd = `[f0_deception@61836 token_id="${alert.tokenId}" token_type="${alert.tokenType}" source_ip="${alert.event.sourceIp}"]`;
    const message =
      `<${pri}>1 ${new Date().toISOString()} ${appName} - ${msgId} ${sd} ` +
      `Canarytoken ${alert.tokenType} (${alert.tokenId}) triggered from ${alert.event.sourceIp}`;

    await new Promise<void>((resolve, reject) => {
      const sock = dgram.createSocket("udp4");
      const buf = Buffer.from(message, "utf8");
      sock.send(buf, port, host, (err) => {
        sock.close();
        if (err) reject(err);
        else resolve();
      });
      // UDP is fire-and-forget; don't hang the dispatcher.
      setTimeout(() => {
        try {
          sock.close();
        } catch {
          /* already closed */
        }
        resolve();
      }, 2000).unref();
    });
  },
};
