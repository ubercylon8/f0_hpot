import { z } from "zod";
import type { TriggerEvent } from "@f0/deception-shared";
import { eventMentionsToken } from "./network-tokens.js";
import type { TokenTypeDefinition, MatchResult } from "./types.js";

const emptyPdfConfig = z.object({
  filename: z.string().min(1).max(120).optional(),
});

/**
 * Cloned website token: fetches a target page, injects our beacon, and
 * serves the clone from the gateway. Any visit triggers an alert.
 * The page itself is fetched and stored by the API at creation time
 * (see apps/api routes/tokens.ts post-generation hook).
 */
export const clonedWebsiteToken: TokenTypeDefinition = {
  id: "cloned_website",
  label: "Cloned Website",
  description:
    "A copy of a page you choose, served from our infrastructure with an invisible beacon. Anyone browsing the clone triggers an alert.",
  group: "document",
  configSchema: z.object({
    target_url: z.string().url(),
    strip_assets: z.boolean().default(true),
  }),
  generate(ctx) {
    return [
      {
        kind: "url",
        label: "Cloned page URL (share with targets)",
        value: `${ctx.gatewayOrigin}/${ctx.tokenId}/site`,
      },
    ];
  },
  matchTrigger(event, tokenId): MatchResult {
    const http = event.kind === "http" ? event.http : undefined;
    if (!http || !eventMentionsToken(event, tokenId)) return { matched: false };
    if (
      !http.path.startsWith(`/${tokenId}/site`) &&
      !http.path.startsWith(`/${tokenId}/pixel.gif`)
    ) {
      return { matched: false };
    }
    return { matched: true, severity: "high" };
  },
};

/** Minimal hand-rolled PDF with an OpenAction URI + visible link annotation. */
export const pdfDocToken: TokenTypeDefinition = {
  id: "pdf_doc",
  label: "PDF Document",
  description:
    "A PDF whose open-action and embedded link hit our tracker. Detection depends on the viewer honoring remote actions/links.",
  group: "document",
  configSchema: emptyPdfConfig,
  generate(ctx) {
    const url = `${ctx.gatewayOrigin}/${ctx.tokenId}/pixel.gif`;
    const filename = String(ctx.config["filename"] ?? "confidential_report.pdf");
    const body = buildTrackingPdf({
      title: "Confidential Report",
      bodyText: "This document is confidential. Unauthorized distribution is prohibited.",
      trackingUrl: url,
    });
    return [
      { kind: "url", label: "Tracking URL embedded in PDF", value: url },
      {
        kind: "file_download",
        label: filename,
        value: `/api/v1/tokens/${ctx.tokenId}/files/0`,
        file: {
          filename,
          contentType: "application/pdf",
          bodyBase64: body.toString("base64"),
        },
      },
    ];
  },
  matchTrigger(event, tokenId): MatchResult {
    const http = event.kind === "http" ? event.http : undefined;
    if (!http || !eventMentionsToken(event, tokenId)) return { matched: false };
    if (!http.path.startsWith(`/${tokenId}/pixel.gif`)) return { matched: false };
    return { matched: true, severity: "high" };
  },
};



interface PdfOpts {
  title: string;
  bodyText: string;
  trackingUrl: string;
}

/**
 * Builds a small single-page PDF:
 *  - /OpenAction -> URI action (some viewers fire on open)
 *  - link annotation over the whole text area (click fires everywhere)
 */
export function buildTrackingPdf(opts: PdfOpts): Buffer {
  const esc = (s: string) => s.replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
  const stream =
    `BT /F1 20 Tf 60 740 Td (${esc(opts.title)}) Tj ET\n` +
    `BT /F1 11 Tf 60 700 Td (${esc(opts.bodyText)}) Tj ET\n`;

  // Objects (1-indexed):
  // 1 catalog, 2 pages, 3 page, 4 contents, 5 font,
  // 6 openaction uri, 7 annot
  const objects = [
    `<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>`,
    `<< /Type /Pages /Kids [3 0 R] /Count 1 >>`,
    `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] ` +
      `/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> ` +
      `/Annots [7 0 R] >>`,
    `<< /Length ${stream.length} >>\nstream\n${stream}endstream`,
    `<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>`,
    `<< /Type /Action /S /URI /URI (${esc(opts.trackingUrl)}) >>`,
    `<< /Type /Annot /Subtype /Link /Rect [50 690 562 720] ` +
      `/Border [0 0 0] /A << /Type /Action /S /URI /URI (${esc(opts.trackingUrl)}) >> >>`,
  ];

  let out = "%PDF-1.4\n";
  const offsets: number[] = [];
  objects.forEach((body, i) => {
    offsets.push(out.length);
    out += `${i + 1} 0 obj\n${body}\nendobj\n`;
  });
  const xrefStart = out.length;
  out += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const off of offsets) {
    out += `${off.toString().padStart(10, "0")} 00000 n \n`;
  }
  out += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF`;
  return Buffer.from(out, "latin1");
}
