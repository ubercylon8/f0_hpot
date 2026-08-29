import { describe, it, expect, afterEach } from "vitest";
import { agentStatus, isOnline, onlineWindowMs, pollIntervalSeconds } from "./agent-status.js";

const saved = process.env.F0_AGENT_POLL_INTERVAL;

function ago(ms: number): string {
  return new Date(Date.now() - ms).toISOString();
}

describe("agent liveness", () => {
  afterEach(() => {
    if (saved === undefined) delete process.env.F0_AGENT_POLL_INTERVAL;
    else process.env.F0_AGENT_POLL_INTERVAL = saved;
  });

  it("treats an agent as offline once it misses two poll intervals", () => {
    delete process.env.F0_AGENT_POLL_INTERVAL;
    expect(pollIntervalSeconds()).toBe(60);
    expect(onlineWindowMs()).toBe(120_000);

    expect(agentStatus(ago(30_000))).toBe("online");
    expect(agentStatus(ago(119_000))).toBe("online");
    // The regression this guards: a stale row previously reported "online"
    // indefinitely because the stored column was never swept.
    expect(agentStatus(ago(121_000))).toBe("offline");
    expect(agentStatus(ago(86_400_000))).toBe("offline");
  });

  it("never reports an agent that has never checked in as online", () => {
    expect(isOnline(null)).toBe(false);
    expect(agentStatus(null)).toBe("offline");
  });

  it("scales the window with the configured poll interval", () => {
    process.env.F0_AGENT_POLL_INTERVAL = "3";
    expect(onlineWindowMs()).toBe(6_000);
    expect(agentStatus(ago(4_000))).toBe("online");
    expect(agentStatus(ago(8_000))).toBe("offline");
  });

  it("falls back to the default for unusable interval values", () => {
    for (const bad of ["", "abc", "0", "-5"]) {
      process.env.F0_AGENT_POLL_INTERVAL = bad;
      expect(pollIntervalSeconds()).toBe(60);
    }
  });
});
