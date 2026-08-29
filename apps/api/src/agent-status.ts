/**
 * Agent liveness — one definition, shared by every consumer.
 *
 * An agent is online if it heartbeat within `2 x F0_AGENT_POLL_INTERVAL`
 * (one missed beat plus slack). The `agents.status` column records only what
 * the agent last *said*; it is never swept, so it must not be read as
 * liveness. Derive it here at read time instead — otherwise the API reports a
 * dead agent as online forever, and the console's own clock disagrees with it.
 */

export const DEFAULT_POLL_INTERVAL_SECONDS = 60;

export function pollIntervalSeconds(): number {
  const raw = Number(process.env.F0_AGENT_POLL_INTERVAL ?? DEFAULT_POLL_INTERVAL_SECONDS);
  return Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_POLL_INTERVAL_SECONDS;
}

/** Milliseconds an agent may stay silent before it counts as offline. */
export function onlineWindowMs(): number {
  return 2 * pollIntervalSeconds() * 1000;
}

/** ISO cutoff; lastSeenAt is ISO-8601 so string comparison is chronological. */
export function onlineCutoffIso(now: number = Date.now()): string {
  return new Date(now - onlineWindowMs()).toISOString();
}

export function isOnline(lastSeenAt: string | null, now: number = Date.now()): boolean {
  return lastSeenAt !== null && lastSeenAt >= onlineCutoffIso(now);
}

export function agentStatus(lastSeenAt: string | null, now?: number): "online" | "offline" {
  return isOnline(lastSeenAt, now) ? "online" : "offline";
}
