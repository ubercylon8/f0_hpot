import { describe, it, expect, afterEach } from "vitest";
import { capabilities } from "./capabilities.js";

const ENV = ["F0_AGENT_RELEASE_DIR", "F0_AGENT_SOURCE_DIR"] as const;
const saved: Record<string, string | undefined> = {};
for (const v of ENV) saved[v] = process.env[v];

describe("host capabilities", () => {
  afterEach(() => {
    for (const v of ENV) {
      if (saved[v] === undefined) delete process.env[v];
      else process.env[v] = saved[v];
    }
  });

  it("reports the release dir as unavailable when it is unset or missing", () => {
    delete process.env["F0_AGENT_RELEASE_DIR"];
    expect(capabilities().releaseDir).toBe(false);

    process.env["F0_AGENT_RELEASE_DIR"] = "/definitely/not/a/real/dir";
    expect(capabilities().releaseDir).toBe(false);

    // An existing directory flips it without a restart.
    process.env["F0_AGENT_RELEASE_DIR"] = "/tmp";
    expect(capabilities().releaseDir).toBe(true);
  });

  it("cannot build releases without the agent source", () => {
    process.env["F0_AGENT_SOURCE_DIR"] = "/definitely/not/a/real/dir";
    const caps = capabilities();
    expect(caps.buildReleases).toBe(false);
    // The console shows this verbatim, so it must explain the fix.
    expect(caps.reasons["buildReleases"]).toMatch(/source|F0_AGENT_SOURCE_DIR/i);
  });

  it("always explains an unavailable capability", () => {
    process.env["F0_AGENT_SOURCE_DIR"] = "/definitely/not/a/real/dir";
    delete process.env["F0_AGENT_RELEASE_DIR"];
    const caps = capabilities();
    for (const key of ["buildReleases", "releaseDir", "releaseSigning", "codeSigning"] as const) {
      if (!caps[key]) {
        expect(caps.reasons[key], `${key} is unavailable with no reason`).toBeTruthy();
      }
    }
  });
});
