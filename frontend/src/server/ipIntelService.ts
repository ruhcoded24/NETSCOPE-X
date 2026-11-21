import { isPrivateIp } from '../core/protocolClassifier.ts';
import type { IpIntelResult } from '../core/types.ts';

interface CacheEntry {
  expiresAt: number;
  data: IpIntelResult;
}

const CACHE_TTL_MS = 15 * 60 * 1000;
const intelCache = new Map<string, CacheEntry>();

function isValidIpFormat(ip: string): boolean {
  const clean = ip.trim();
  // IPv4 or IPv6 basic validation
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6 = /^[0-9a-fA-F:]+$/;
  if (ipv4.test(clean)) {
    return clean.split('.').every((octet) => Number(octet) >= 0 && Number(octet) <= 255);
  }
  return clean.includes(':') && ipv6.test(clean);
}

export async function lookupIpIntelligence(rawIp: string): Promise<IpIntelResult> {
  const ip = rawIp.trim();
  const now = Date.now();

  if (!isValidIpFormat(ip)) {
    return {
      ip,
      isPrivate: true,
      country: null,
      region: null,
      city: null,
      asn: null,
      org: null,
      reputationStatus: 'Invalid Format',
      reputationNote: 'Provide a valid IPv4 or IPv6 address.',
      sourceLabel: 'Local Validation',
      cached: false,
      lookedUpAt: new Date(now).toISOString(),
      error: 'Invalid IP address format.',
    };
  }

  if (isPrivateIp(ip)) {
    return {
      ip,
      isPrivate: true,
      country: null,
      region: null,
      city: null,
      asn: null,
      org: 'Private / RFC1918 / Loopback / Reserved Scope',
      reputationStatus: 'Internal Address',
      reputationNote: 'Private and loopback addresses are never sent to external geolocation providers.',
      sourceLabel: 'RFC1918 / Local Policy Guard',
      cached: false,
      lookedUpAt: new Date(now).toISOString(),
    };
  }

  const cached = intelCache.get(ip);
  if (cached && cached.expiresAt > now) {
    return { ...cached.data, cached: true };
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4500);
    const resp = await fetch(
      `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,country,regionName,city,isp,org,as`,
      { signal: controller.signal },
    );
    clearTimeout(timer);

    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status} from external lookup service`);
    }

    const json = (await resp.json()) as {
      status?: string;
      message?: string;
      country?: string;
      regionName?: string;
      city?: string;
      isp?: string;
      org?: string;
      as?: string;
    };

    if (json.status !== 'success') {
      throw new Error(json.message || 'Lookup returned non-success status');
    }

    const result: IpIntelResult = {
      ip,
      isPrivate: false,
      country: json.country ?? null,
      region: json.regionName ?? null,
      city: json.city ?? null,
      asn: json.as ?? null,
      org: json.org || json.isp || null,
      reputationStatus: 'External ASN & Geo Only (No Malicious Feed Configured)',
      reputationNote:
        'Geolocation and ASN indicate network ownership only. Never treat geographic location as proof of malicious activity.',
      sourceLabel: 'ip-api.com (External Lookup · Cached 15m)',
      cached: false,
      lookedUpAt: new Date(now).toISOString(),
    };

    intelCache.set(ip, { expiresAt: now + CACHE_TTL_MS, data: result });
    return result;
  } catch (err) {
    return {
      ip,
      isPrivate: false,
      country: null,
      region: null,
      city: null,
      asn: null,
      org: null,
      reputationStatus: 'External Lookup Unavailable',
      reputationNote:
        'External IP intelligence service could not be reached from this environment. No fabricated reputation score was generated.',
      sourceLabel: 'Service Unavailable',
      cached: false,
      lookedUpAt: new Date(now).toISOString(),
      error: err instanceof Error ? err.message : 'External lookup failed',
    };
  }
}
