import { z } from "zod";
import type { TriggerEvent } from "@f0/deception-shared";
import { eventMentionsToken } from "./network-tokens.js";
import type { TokenTypeDefinition, GenerateContext, TokenArtifactSpec, MatchResult } from "./types.js";

const emptyConfig = z.object({});

/**
 * Word document token: a .docx whose embedded image is an EXTERNAL
 * relationship pointing at our tracking pixel. When the document is opened
 * (and external content is allowed), Word fetches the pixel -> alert.
 */
export const wordDocToken: TokenTypeDefinition = {
  id: "word_doc",
  label: "Word Document",
  description:
    "A .docx file with a remote tracking image. Opening it in Word fetches the image and triggers an alert.",
  group: "document",
  configSchema: emptyConfig,
  generate(ctx) {
    const pixelUrl = `${ctx.gatewayOrigin}/${ctx.tokenId}/pixel.gif`;
    const body = buildOoxmlWithExternalImage({
      appName: "Microsoft Word",
      headingText: "Quarterly Report",
      bodyText:
        "Please find the summary of Q3 figures below. This document is best viewed in Microsoft Word.",
      pixelUrl,
    });
    return [
      {
        kind: "url",
        label: "Tracking URL embedded in document",
        value: pixelUrl,
      },
      {
        kind: "file_download",
        label: "quarterly_report.docx",
        value: `/api/v1/tokens/${ctx.tokenId}/files/0`,
        file: {
          filename: "quarterly_report.docx",
          contentType:
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
          bodyBase64: body.toString("base64"),
        },
      },
    ];
  },
  matchTrigger(event, tokenId) {
    return matchPixelPath(event, tokenId);
  },
};

/**
 * Excel workbook token: hyperlinked cell pointing at our tracker. Fires
 * when the link is clicked from within Excel.
 */
export const excelDocToken: TokenTypeDefinition = {
  id: "excel_doc",
  label: "Excel Workbook",
  description:
    "An .xlsx workbook whose hyperlink targets our tracker. Clicking the link triggers an alert.",
  group: "document",
  configSchema: emptyConfig,
  generate(ctx) {
    const url = `${ctx.gatewayOrigin}/${ctx.tokenId}/pixel.gif`;
    const body = buildXlsxWithHyperlink({
      sheetName: "Figures",
      cellLabel: "Open detailed figures",
      url,
    });
    return [
      { kind: "url", label: "Tracking URL embedded in workbook", value: url },
      {
        kind: "file_download",
        label: "figures.xlsx",
        value: `/api/v1/tokens/${ctx.tokenId}/files/0`,
        file: {
          filename: "figures.xlsx",
          contentType:
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
          bodyBase64: body.toString("base64"),
        },
      },
    ];
  },
  matchTrigger(event, tokenId) {
    return matchPixelPath(event, tokenId);
  },
};

/**
 * Windows folder token: create a folder named `<tokenId>@<baseDomain>`.
 * Browsing it makes Windows resolve that name via DNS -> alert.
 */
export const windowsFolderToken: TokenTypeDefinition = {
  id: "windows_folder",
  label: "Windows Folder",
  description:
    "Create a folder with this special name; Windows resolves it over DNS when browsed, triggering an alert.",
  group: "network",
  configSchema: emptyConfig,
  generate(ctx) {
    const name = `${ctx.tokenId}@${ctx.baseDomain}`;
    return [
      {
        kind: "hostname",
        label: "Folder name to create",
        value: name,
      },
    ];
  },
  matchTrigger(event, tokenId) {
    if (event.kind !== "dns") return { matched: false };
    if (!event.dns?.queryName.split(".").includes(tokenId)) return { matched: false };
    return { matched: true, severity: "high" };
  },
};

/**
 * SQL injection token: generates rewrite rules that turn a chosen URL into
 * a canary. Any request matching the rule (i.e., someone probing for the
 * fake vulnerable endpoint) hits the gateway.
 */
export const sqlInjectionToken: TokenTypeDefinition = {
  id: "sql_injection",
  label: "SQL Injection Canary",
  description:
    "Deploy generated nginx/Apache rules on your real web server so scans hitting a decoy 'vulnerable' page hit our tracker instead.",
  group: "network",
  configSchema: z.object({
    path: z.string().default("/search.php"),
    server_kind: z.enum(["nginx", "apache"]).default("nginx"),
  }),
  generate(ctx) {
    const decoyPath = String(ctx.config["path"] ?? "/search.php");
    const serverKind = String(ctx.config["server_kind"] ?? "nginx");
    const url = `${ctx.gatewayOrigin}/${ctx.tokenId}/sqli`;
    const rule =
      serverKind === "nginx"
        ? `# f0_deception SQLi canary\nlocation = ${decoyPath} {\n    return 302 ${url};\n}\n`
        : `# f0_deception SQLi canary\nRedirect 302 ${decoyPath} ${url}\n`;
    return [
      { kind: "url", label: "Canary target", value: url },
      {
        kind: "file_download",
        label: `${serverKind}_snippet.conf`,
        value: `/api/v1/tokens/${ctx.tokenId}/files/0`,
        file: {
          filename: `${serverKind}_snippet.conf`,
          contentType: "text/plain",
          bodyBase64: Buffer.from(rule).toString("base64"),
        },
      },
    ];
  },
  matchTrigger(event, tokenId) {
    const http = event.kind === "http" ? event.http : undefined;
    if (!http || !eventMentionsToken(event, tokenId)) return { matched: false };
    if (!http.path.startsWith(`/${tokenId}/sqli`)) return { matched: false };
    return { matched: true, severity: "high" };
  },
};

function matchPixelPath(event: TriggerEvent, tokenId: string): MatchResult {
  const http = event.kind === "http" ? event.http : undefined;
  if (!http || !eventMentionsToken(event, tokenId)) return { matched: false };
  if (!http.path.startsWith(`/${tokenId}/pixel.gif`)) return { matched: false };
  return { matched: true, severity: "high" };
}

type GenerateResult = TokenArtifactSpec[];
export type { GenerateContext, TokenArtifactSpec, TokenTypeDefinition, GenerateResult };

interface OoxmlOpts {
  appName: string;
  headingText: string;
  bodyText: string;
  pixelUrl: string;
}

/**
 * Minimal OOXML .docx containing one paragraph and an <a:blip r:embed>
 * drawing whose relationship is TargetMode="External" pointing at pixelUrl.
 * Word downloads the remote image when rendering.
 */
export function buildOoxmlWithExternalImage(opts: OoxmlOpts): Buffer {
  void opts.appName;
  const rels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`;

  const docRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rIdPix" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="${escapeXml(opts.pixelUrl)}" TargetMode="External"/>
</Relationships>`;

  const document = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
            xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
            xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
            xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
            xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">
<w:body>
<w:p><w:r><w:rPr><w:b/><w:sz w:val="32"/></w:rPr><w:t>${escapeXml(opts.headingText)}</w:t></w:r></w:p>
<w:p><w:r><w:t>${escapeXml(opts.bodyText)}</w:t></w:r></w:p>
<w:p><w:r><w:drawing>
<wp:inline distT="0" distB="0" distL="0" distR="0">
<wp:extent cx="9525" cy="9525"/><wp:docPr id="1" name="Figure1"/>
<a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">
<pic:pic><pic:nvPicPr><pic:cNvPr id="1" name="figure"/><pic:cNvPicPr/></pic:nvPicPr>
<pic:blipFill><a:blip r:embed="rIdPix"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>
<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="9525" cy="9525"/></a:xfrm>
<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>
</pic:pic></a:graphicData></a:graphic></wp:inline>
</w:drawing></w:r></w:p>
</w:body></w:document>`;

  const contentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`;

  // Minimal ZIP (stored, no compression) — hand-rolled to avoid a dependency
  // here; sizes/CRC computed below.
  return buildZip([
    ["[Content_Types].xml", contentTypes],
    ["_rels/.rels", rels],
    ["word/_rels/document.xml.rels", docRels],
    ["word/document.xml", document],
  ]);
}

/** Minimal .xlsx with a hyperlinked cell (external relationship). */
export function buildXlsxWithHyperlink(opts: {
  sheetName: string;
  cellLabel: string;
  url: string;
}): Buffer {
  const rels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>`;

  const workbook = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="${escapeXml(opts.sheetName)}" sheetId="1" r:id="rId1"/></sheets></workbook>`;

  const wbRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>`;

  const sheetRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rIdLink" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="${escapeXml(opts.url)}" TargetMode="External"/>
</Relationships>`;

  const sheet = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
           xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>${escapeXml(opts.cellLabel)}</t></is></c></row></sheetData>
<hyperlinks><hyperlink ref="A1" r:id="rIdLink"/></hyperlinks></worksheet>`;

  const contentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>`;

  return buildZip([
    ["[Content_Types].xml", contentTypes],
    ["_rels/.rels", rels],
    ["xl/workbook.xml", workbook],
    ["xl/_rels/workbook.xml.rels", wbRels],
    ["xl/worksheets/sheet1.xml", sheet],
    ["xl/worksheets/_rels/sheet1.xml.rels", sheetRels],
  ]);
}

function escapeXml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/** Hand-rolled STORE-only zip writer (no compression deps). */
function buildZip(entries: [string, string][]): Buffer {
  const chunks: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;

  for (const [name, content] of entries) {
    const nameBuf = Buffer.from(name, "utf8");
    const data = Buffer.from(content, "utf8");
    const crc = crc32(data);

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(0x0800, 6); // UTF-8 flag
    local.writeUInt16LE(0, 8); // stored
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);

    chunks.push(local, nameBuf, data);

    const cen = Buffer.alloc(46);
    cen.writeUInt32LE(0x02014b50, 0);
    cen.writeUInt16LE(20, 4);
    cen.writeUInt16LE(20, 6);
    cen.writeUInt16LE(0x0800, 8);
    cen.writeUInt16LE(0, 10);
    cen.writeUInt32LE(crc, 16);
    cen.writeUInt32LE(data.length, 20);
    cen.writeUInt32LE(data.length, 24);
    cen.writeUInt16LE(nameBuf.length, 28);
    cen.writeUInt32LE(offset, 42);
    central.push(cen, nameBuf);

    offset += local.length + nameBuf.length + data.length;
  }

  const centralBuf = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralBuf.length, 12);
  end.writeUInt32LE(offset, 16);

  return Buffer.concat([...chunks, centralBuf, end]);
}

let crcTable: Uint32Array | null = null;
function crc32(buf: Buffer): number {
  if (!crcTable) {
    crcTable = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      crcTable[n] = c >>> 0;
    }
  }
  let crc = 0xffffffff;
  for (const b of buf) crc = crcTable![(crc ^ b) & 0xff]! ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}
