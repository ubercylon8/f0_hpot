import { execFileSync } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

/**
 * Which host-dependent console actions can actually succeed here.
 *
 * The Agents page offers "build binaries", release signing and code signing
 * unconditionally, but each needs tooling or a directory that a slim
 * container deployment does not have. Without this the buttons look
 * identical to working ones and fail as opaque 400 toasts, so the console
 * can now disable them and say why.
 *
 * Resolved per request: an operator can mount a release dir or install a
 * tool without restarting the API.
 */

export interface Capabilities {
  /** POST /agent-releases/build — needs the Go module, `make` and `go`. */
  buildReleases: boolean;
  /** Release listing/signing — needs F0_AGENT_RELEASE_DIR to exist. */
  releaseDir: boolean;
  /** Ed25519 manifest signing + cert handling — needs openssl. */
  releaseSigning: boolean;
  /** Authenticode signing of the Windows agent — needs osslsigncode. */
  codeSigning: boolean;
  /** Human-readable reason per unavailable capability. */
  reasons: Record<string, string>;
}

function onPath(tool: string): boolean {
  const override = process.env[`F0_${tool.toUpperCase()}`];
  if (override) return existsSync(override);
  try {
    return !!execFileSync("which", [tool], { encoding: "utf8" }).trim();
  } catch {
    return false;
  }
}

function isDir(p: string): boolean {
  try {
    return !!p && existsSync(p) && statSync(p).isDirectory();
  } catch {
    return false;
  }
}

function agentSourceDir(): string {
  return (
    process.env.F0_AGENT_SOURCE_DIR ??
    fileURLToPath(new URL("../../../agent", import.meta.url))
  );
}

export function capabilities(): Capabilities {
  const srcDir = agentSourceDir();
  const hasSource = isDir(srcDir) && existsSync(path.join(srcDir, "go.mod"));
  const hasGo = onPath("go");
  const hasMake = onPath("make");
  const releaseDir = isDir(process.env.F0_AGENT_RELEASE_DIR ?? "");
  const hasOpenssl = onPath("openssl");
  const hasOsslsigncode = onPath("osslsigncode");

  const reasons: Record<string, string> = {};
  if (!hasSource) reasons["buildReleases"] = "agent source not present (set F0_AGENT_SOURCE_DIR)";
  else if (!hasGo) reasons["buildReleases"] = "the Go toolchain is not installed on the API host";
  else if (!hasMake) reasons["buildReleases"] = "make is not installed on the API host";
  if (!releaseDir) reasons["releaseDir"] = "F0_AGENT_RELEASE_DIR is not set or does not exist";
  if (!hasOpenssl) reasons["releaseSigning"] = "openssl is not installed on the API host";
  if (!hasOsslsigncode) reasons["codeSigning"] = "osslsigncode is not installed on the API host";

  return {
    buildReleases: hasSource && hasGo && hasMake,
    releaseDir,
    releaseSigning: hasOpenssl,
    codeSigning: hasOsslsigncode,
    reasons,
  };
}
