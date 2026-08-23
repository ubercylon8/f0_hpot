import type { AlertPayload, AlertSender } from "./types.js";

/**
 * Generic webhook channel. POSTs the alert JSON to a user-configured URL.
 * Config: { url, secret? } — secret is sent as X-F0-Signature (HMAC-less
 * shared secret header for v1; HMAC signing is a later hardening step).
 */
export const webhookSender: AlertSender = {
  async send(config, alert: AlertPayload) {
    const url = config["url"];
    if (typeof url !== "string" || !/^https?:\/\//.test(url)) {
      throw new Error("webhook config requires an http(s) url");
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10_000);
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(typeof config["secret"] === "string"
            ? { "x-f0-signature": config["secret"] }
            : {}),
        },
        body: JSON.stringify(alert),
        signal: controller.signal,
      });
      if (!res.ok) {
        throw new Error(`webhook responded ${res.status}`);
      }
    } finally {
      clearTimeout(timer);
    }
  },
};
