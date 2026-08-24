import type { Db } from "../db/index.js";
import { alertChannels } from "../db/schema.js";
import { eq } from "drizzle-orm";
import type { AlertPayload, AlertSender } from "./types.js";
import { webhookSender } from "./webhook.js";
import { emailSender } from "./email.js";
import { syslogSender } from "./syslog.js";
import { elasticsearchSender, lokiSender } from "./siem.js";

const senders: Record<string, AlertSender> = {
  webhook: webhookSender,
  email: emailSender,
  syslog: syslogSender,
  elasticsearch: elasticsearchSender,
  loki: lokiSender,
};

const MAX_FAILURES = 5;

interface ThrottleEntry {
  count: number;
  windowStart: number;
}

/**
 * Dispatches incidents to enabled alert channels with per-(token,sourceIp)
 * throttling (mirrors upstream canarytokens behavior: at most one alert per
 * unique source per minute; hits are still recorded).
 */
export class AlertDispatcher {
  private throttle = new Map<string, ThrottleEntry>();

  constructor(
    private db: Db,
    private opts: { maxAlertsPerMinute?: number; now?: () => number } = {},
  ) {}

  /** Returns true if the alert is allowed through the throttle window. */
  shouldAlert(tokenId: string, sourceIp: string): boolean {
    const now = (this.opts.now ?? Date.now)();
    const key = `${tokenId}|${sourceIp}`;
    const max = this.opts.maxAlertsPerMinute ?? 1;
    const entry = this.throttle.get(key);
    if (!entry || now - entry.windowStart >= 60_000) {
      this.throttle.set(key, { count: 1, windowStart: now });
      return true;
    }
    if (entry.count < max) {
      entry.count += 1;
      return true;
    }
    return false;
  }

  async dispatch(alert: AlertPayload): Promise<void> {
    if (!this.shouldAlert(alert.tokenId, alert.event.sourceIp)) return;

    const channels = this.db
      .select()
      .from(alertChannels)
      .where(eq(alertChannels.enabled, true))
      .all();

    await Promise.allSettled(
      channels.map(async (channel) => {
        const sender = senders[channel.kind];
        if (!sender) return;
        try {
          await sender.send(channel.config as Record<string, unknown>, alert);
          if (channel.failureCount > 0) {
            this.db
              .update(alertChannels)
              .set({ failureCount: 0 })
              .where(eq(alertChannels.id, channel.id))
              .run();
          }
        } catch (err) {
          const failures = channel.failureCount + 1;
          this.db
            .update(alertChannels)
            .set({
              failureCount: failures,
              // Circuit breaker: disable after repeated failures.
              enabled: failures < MAX_FAILURES ? true : false,
            })
            .where(eq(alertChannels.id, channel.id))
            .run();
          console.error(
            `alert channel ${channel.kind}/${channel.id} failed (${failures}):`,
            err instanceof Error ? err.message : err,
          );
        }
      }),
    );
  }

  async testChannel(channelId: string): Promise<void> {
    const channel = this.db
      .select()
      .from(alertChannels)
      .where(eq(alertChannels.id, channelId))
      .get();
    if (!channel) throw new Error("channel not found");
    const sender = senders[channel.kind];
    if (!sender) throw new Error(`unknown channel kind: ${channel.kind}`);
    await sender.send(channel.config as Record<string, unknown>, {
      tokenId: "test00000000",
      tokenType: "test",
      severity: "low",
      incidentId: "test",
      seenAt: new Date().toISOString(),
      event: {
        kind: "http",
        tokenHint: "test00000000",
        timestamp: new Date().toISOString(),
        sourceIp: "127.0.0.1",
        http: { method: "GET", host: "test.tokens.invalid", path: "/test" },
      },
    });
  }
}
