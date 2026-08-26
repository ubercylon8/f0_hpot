import type { Incident } from "../api.js";

export interface IncidentSummary {
  label: string;
  detail: string;
  sourceIp: string;
}

/** Human one-liner for an incident, shared by the incidents and tokens pages. */
export function incidentSummary(i: Incident): IncidentSummary {
  const d = (i.event.detail ?? {}) as Record<string, unknown>;
  const str = (k: string) => (typeof d[k] === "string" ? (d[k] as string) : undefined);
  const sourceIp = i.sourceIp ?? i.event.sourceIp ?? str("source_ip") ?? "unknown";

  if (i.event.kind === "agent") {
    const sensor = str("sensor") ?? "agent";
    const event = str("event");
    let label: string;
    let extra = "";
    if (event === "ntlm_credentials" || event === "credssp_credentials") {
      label = `${sensor}: CAPTURED credentials ${str("domain") ?? ""}\\${str("username") ?? "?"}`;
      extra = str("hashcat") ?? "";
    } else if (event === "credential_attempt" || str("password") !== undefined) {
      const pw = str("password");
      label = `${sensor}: credential attempt user="${str("user") ?? str("username") ?? "?"}"` +
        (pw ? ` password="${pw}"` : "");
      const cv = str("client_version");
      if (cv) extra = `client: ${cv}`;
    } else if (event === "command_execution" || d["command"] !== undefined) {
      const cmd = d["command"];
      label = `${sensor}: command executed by "${str("user") ?? "?"}": ` +
        (Array.isArray(cmd) ? cmd.join(" ") : String(cmd ?? ""));
    } else if (event === "bait_file_touched" || event === "watched_file_accessed") {
      label = `${sensor}: ${str("label") ?? str("path") ?? event} accessed`;
    } else if (event) {
      label = `${sensor}: ${event}`;
    } else {
      label = sensor;
    }
    return { label, detail: extra, sourceIp };
  }
  if (i.event.kind === "dns" && i.event.dns) {
    return { label: `DNS ${i.event.dns.queryName} (${i.event.dns.queryType})`, detail: "", sourceIp };
  }
  if (i.event.http) {
    const ua = i.event.http.userAgent ? ` · ${i.event.http.userAgent}` : "";
    return {
      label: `${i.event.http.method} ${i.event.http.host}${i.event.http.path}`,
      detail: ua,
      sourceIp,
    };
  }
  return { label: i.event.kind, detail: "", sourceIp };
}

/** Compact geo label for an incident row: "DE · Berlin" / "Germany" / "" */
export function geoLabel(i: Incident): string {
  const g = i.geo;
  if (!g) return "";
  const place = [g.country, g.city].filter(Boolean).join(" · ");
  return place || g.countryName || (g.org ? g.org : "");
}

/** Full geo tooltip: country, city, ASN, org. */
export function geoTitle(i: Incident): string {
  const g = i.geo;
  if (!g) return i.sourceIp ?? "";
  return [
    g.countryName ?? g.country,
    g.city,
    g.asn ? `AS${g.asn}` : undefined,
    g.org,
  ]
    .filter(Boolean)
    .join(" · ");
}
