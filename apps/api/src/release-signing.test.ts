import { describe, it, expect } from "vitest";
import { canonicalManifestBytes } from "./release-signing.js";

// Golden bytes shared with the Go verifier's TestCanonicalManifestGolden
// (agent/internal/update/update_test.go). If either side drifts, release
// signatures stop verifying — all signers (this module, sign_release.sh)
// MUST produce the agent's exact canonical form.
describe("canonicalManifestBytes", () => {
  it("matches the Go verifier golden bytes", () => {
    const got = canonicalManifestBytes("v1.2.3", {
      "f0-deception-agent-linux-amd64": { sha256: "aaaa", size: 123 },
      "f0-deception-agent-windows-amd64.exe": { sha256: "bbbb", size: 456 },
    });
    expect(got).toBe(
      `{"version":"v1.2.3","files":{` +
        `"f0-deception-agent-linux-amd64":{"sha256":"aaaa","size":123},` +
        `"f0-deception-agent-windows-amd64.exe":{"sha256":"bbbb","size":456}` +
        `},"signature":""}`,
    );
  });

  it("escapes HTML chars and U+2028/U+2029 like Go's json.Marshal", () => {
    const got = canonicalManifestBytes("v1<>&\u2028\u2029", {
      "a<b>c": { sha256: "x&y", size: 1 },
    });
    expect(got).toBe(
      `{"version":"v1\\u003c\\u003e\\u0026\\u2028\\u2029","files":{` +
        `"a\\u003cb\\u003ec":{"sha256":"x\\u0026y","size":1}` +
        `},"signature":""}`,
    );
  });
});
