import { readFileSync } from "node:fs";
import { Reader, type CityResponse } from "mmdb-lib";

/**
 * GeoIP enrichment for incident source IPs.
 *
 * Enabled by pointing F0_GEOIP_DB at a MaxMind-format .mmdb file
 * (GeoLite2-City/Country or a compatible DB). When unset or unloadable the
 * lookup degrades to nulls — incidents are still recorded with the raw
 * source IP.
 */

export interface GeoInfo {
  country?: string;
  countryName?: string;
  city?: string;
  asn?: number;
  org?: string;
  /** Present when the .mmdb provides them (GeoLite2-City / DB-IP city). */
  lat?: number;
  lon?: number;
}

export interface GeoLookup {
  /** false when running without an .mmdb (null lookup). */
  readonly enabled: boolean;
  lookup(ip: string): GeoInfo | null;
}

const NULL_LOOKUP: GeoLookup = { enabled: false, lookup: () => null };

export function createGeoLookup(
  dbPath: string | undefined,
  log: { warn: (msg: string) => void } = console,
): GeoLookup {
  if (!dbPath) return NULL_LOOKUP;
  try {
    const reader = new Reader<CityResponse>(readFileSync(dbPath));
    return {
      enabled: true,
      lookup(ip: string): GeoInfo | null {
        try {
          const r = reader.get(ip);
          if (!r) return null;
          const country = r.country ?? r.registered_country;
          const geo: GeoInfo = {};
          if (country?.iso_code) geo.country = country.iso_code;
          if (country?.names?.en) geo.countryName = country.names.en;
          if (r.city?.names?.en) geo.city = r.city.names.en;
          if (r.traits?.autonomous_system_number) {
            geo.asn = r.traits.autonomous_system_number;
          }
          if (r.traits?.autonomous_system_organization) {
            geo.org = r.traits.autonomous_system_organization;
          }
          if (typeof r.location?.latitude === "number") geo.lat = r.location.latitude;
          if (typeof r.location?.longitude === "number") geo.lon = r.location.longitude;
          return Object.keys(geo).length > 0 ? geo : null;
        } catch {
          return null; // malformed IP or reader hiccup — never break ingest
        }
      },
    };
  } catch (err) {
    log.warn(
      `geoip: failed to load ${dbPath} (${err instanceof Error ? err.message : err}); enrichment disabled`,
    );
    return NULL_LOOKUP;
  }
}

/**
 * Best-effort source IP extraction from a trigger/agent event.
 * Gateway events carry `sourceIp`; agent-reported detections carry
 * `detail.source_ip` (and occasionally `detail.ip`).
 */
export function extractSourceIp(event: Record<string, unknown>): string | undefined {
  const top = event["sourceIp"];
  if (typeof top === "string" && top && top !== "unknown") return top;
  const detail = event["detail"] as Record<string, unknown> | undefined;
  for (const k of ["source_ip", "ip", "client_ip"]) {
    const v = detail?.[k];
    if (typeof v === "string" && v && v !== "unknown") return v;
  }
  return undefined;
}
