import type http from "node:http";

const PIXEL_GIF = Buffer.from(
  "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7",
  "base64",
);

export interface ArtifactResponderOptions {
  gatewayOrigin: string;
}

/**
 * Serves token artifacts for matched requests. Mirrors the trigger rules in
 * tokens-core: `/tok123/pixel.gif` for web bugs, `/tok123/r` for redirects.
 */
export function artifactResponder(opts: ArtifactResponderOptions) {
  return function respond(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): boolean {
    const path = (req.url ?? "/").split("?")[0]!;
    const segments = path.split("/").filter(Boolean);
    if (segments.length < 2) return false;

    const [tokenId, action] = segments;

    if (action === "pixel.gif") {
      res.writeHead(200, {
        "content-type": "image/gif",
        "cache-control": "no-store",
      });
      res.end(PIXEL_GIF);
      return true;
    }

    if (action === "r") {
      // Fast redirect: capture then bounce to configured target (or a
      // neutral landing page when none is set).
      res.writeHead(302, { location: `${opts.gatewayOrigin}/landed` });
      res.end();
      return true;
    }

    void tokenId;
    return false;
  };
}
