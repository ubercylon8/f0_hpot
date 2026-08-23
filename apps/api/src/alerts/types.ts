import type { TriggerEvent } from "@f0/deception-shared";

export interface AlertPayload {
  tokenId: string;
  tokenType: string;
  severity: string;
  incidentId: string;
  event: TriggerEvent;
  seenAt: string;
}

export interface AlertSender {
  /** Deliver the alert. Throws on failure. */
  send(config: Record<string, unknown>, alert: AlertPayload): Promise<void>;
}
