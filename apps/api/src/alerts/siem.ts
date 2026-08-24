import type { AlertPayload, AlertSender } from "./types.js";

interface ElasticConfig {
  url: string; // e.g. https://elastic.internal:9200
  index?: string;
  username?: string;
  password?: string;
}

/** Elasticsearch channel: indexes each alert as a document. */
export const elasticsearchSender: AlertSender = {
  async send(config, alert) {
    const cfg = config as unknown as ElasticConfig;
    if (typeof cfg.url !== "string" || !/^https?:\/\//.test(cfg.url)) {
      throw new Error("elasticsearch config requires an http(s) url");
    }
    const index = typeof cfg.index === "string" && cfg.index ? cfg.index : "f0_deception";
    const auth =
      cfg.username && cfg.password
        ? `Basic ${Buffer.from(`${cfg.username}:${cfg.password}`).toString("base64")}`
        : undefined;

    const res = await fetch(`${cfg.url}/${index}/_doc`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(auth ? { authorization: auth } : {}),
      },
      body: JSON.stringify({
        "@timestamp": alert.seenAt,
        token_id: alert.tokenId,
        token_type: alert.tokenType,
        severity: alert.severity,
        incident_id: alert.incidentId,
        source_ip: alert.event.sourceIp,
        event: alert.event,
      }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) {
      throw new Error(`elasticsearch responded ${res.status}: ${(await res.text()).slice(0, 200)}`);
    }
  },
};

interface LokiConfig {
  url: string; // e.g. https://loki.internal:3100
  labels?: Record<string, string>;
  tenant_id?: string;
}

/** Grafana Loki channel: pushes a log line per alert via /loki/api/v1/push. */
export const lokiSender: AlertSender = {
  async send(config, alert) {
    const cfg = config as unknown as LokiConfig;
    if (typeof cfg.url !== "string" || !/^https?:\/\//.test(cfg.url)) {
      throw new Error("loki config requires an http(s) url");
    }
    const line =
      `canary_triggered token=${alert.tokenId} type=${alert.tokenType} ` +
      `severity=${alert.severity} source=${alert.event.sourceIp} ` +
      `incident=${alert.incidentId}`;
    const payload = {
      streams: [
        {
          stream: { app: "f0_deception", severity: alert.severity, ...(cfg.labels ?? {}) },
          values: [[String(Date.now() * 1e6), line]],
        },
      ],
    };
    const res = await fetch(`${cfg.url.replace(/\/$/, "")}/loki/api/v1/push`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(cfg.tenant_id ? { "x-scope-orgid": cfg.tenant_id } : {}),
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) {
      throw new Error(`loki responded ${res.status}: ${(await res.text()).slice(0, 200)}`);
    }
  },
};
