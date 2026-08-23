import type http from "node:http";
import QRCode from "qrcode";

const PIXEL_GIF = Buffer.from(
  "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7",
  "base64",
);

export interface ArtifactResponderOptions {
  gatewayOrigin: string;
  /** Base URL of the API, for internal token-config lookups. */
  apiBaseUrl: string;
}

interface CachedConfig {
  type: string;
  config: Record<string, unknown>;
  expiresAt: number;
}

const CONFIG_TTL_MS = 60_000;

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

const FAKE_CMD_OUTPUTS: Record<string, (ip: string) => string> = {
  ifconfig: (ip) => `eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255
lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
# request from ${ip}
`,
  ipconfig: (ip) => `Ethernet adapter Ethernet0:

   IPv4 Address. . . . . . . . . . . : 192.168.1.50
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
<!-- request from ${ip} -->
`,
  whoami: (ip) => `svc_backup
<!-- request from ${ip} -->
`,
  cat_etc_shadow: (ip) => `root:*:19700:0:99999:7:::
daemon:*:19700:0:99999:7:::
svc_backup:$6$rounds=...:19724:0:99999:7:::
<!-- request from ${ip} -->
`,
};

/**
 * Serves token artifacts for matched requests. Mirrors the trigger rules in
 * tokens-core: `/tok/pixel.gif`, `/tok/r` (redirect), `/tok/qr`, `/tok/cmd/:name`.
 */
export function artifactResponder(opts: ArtifactResponderOptions) {
  const configCache = new Map<string, CachedConfig>();

  async function lookupToken(
    tokenId: string,
  ): Promise<CachedConfig | null> {
    const hit = configCache.get(tokenId);
    if (hit && hit.expiresAt > Date.now()) return hit;
    try {
      const res = await fetch(
        `${opts.apiBaseUrl}/api/v1/tokens/${encodeURIComponent(tokenId)}/internal-config`,
        { signal: AbortSignal.timeout(3000) },
      );
      if (!res.ok) return null;
      const data = (await res.json()) as CachedConfig;
      const entry = { ...data, expiresAt: Date.now() + CONFIG_TTL_MS };
      configCache.set(tokenId, entry);
      return entry;
    } catch {
      return null;
    }
  }

  return async function respond(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<boolean> {
    const path = (req.url ?? "/").split("?")[0]!;
    const segments = path.split("/").filter(Boolean);
    if (segments.length < 2) return false;

    const [tokenId, action] = segments as [string, string];
    const sourceIp = req.socket.remoteAddress ?? "unknown";

    if (action === "pixel.gif") {
      res.writeHead(200, {
        "content-type": "image/gif",
        "cache-control": "no-store",
      });
      res.end(PIXEL_GIF);
      return true;
    }

    if (action === "r") {
      // Redirect to the configured target; fall back to a neutral page.
      const info = await lookupToken(tokenId);
      const target =
        info?.type === "fast_redirect" &&
        typeof info.config["target_url"] === "string"
          ? String(info.config["target_url"])
          : `${opts.gatewayOrigin}/landed`;
      res.writeHead(302, { location: target, "cache-control": "no-store" });
      res.end();
      return true;
    }

    if (action === "qr") {
      const png = await QRCode.toBuffer(path, {
        width: 512,
        margin: 1,
        errorCorrectionLevel: "L",
      });
      res.writeHead(200, {
        "content-type": "image/png",
        "cache-control": "no-store",
      });
      res.end(png);
      return true;
    }

    if (action === "cmd") {
      const cmdName = segments[2] ?? "ifconfig";
      const render = FAKE_CMD_OUTPUTS[cmdName];
      const body =
        render !== undefined
          ? `<html><body><pre>${escapeHtml(render(sourceIp))}</pre></body></html>`
          : "<html><body><pre>command not found</pre></body></html>";
      res.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        "x-robots-tag": "noindex",
      });
      res.end(body);
      return true;
    }

    void tokenId;
    return false;
  };
}
