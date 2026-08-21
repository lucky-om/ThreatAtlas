// ── WebFox Reconnaissance Core (Ported from lucky-om/WebFox) ──────────────────

export interface DnsRecord {
  type: string;
  value: string;
  ttl?: number;
}

export interface SslCertInfo {
  issuer: string;
  commonName: string;
  validFrom: string;
  validTo: string;
  daysLeft: number;
  sans?: string[];
  fingerprint?: string;
  isValid: boolean;
}

export interface WhoisRecord {
  registrar?: string;
  createdDate?: string;
  updatedDate?: string;
  expiresDate?: string;
  domainAgeDays?: number;
  nameservers?: string[];
  status?: string;
  registrant?: string;
}

export interface HeaderCheck {
  header: string;
  present: boolean;
  value?: string;
  weight: number;
  description: string;
}

export interface WebFoxReconResult {
  domain: string;
  ip?: string;
  dnsRecords: DnsRecord[];
  subdomains: string[];
  sslCert?: SslCertInfo;
  whois?: WhoisRecord;
  securityHeaders: HeaderCheck[];
  headerSecurityScore: number; // 0 - 100
  wafDetected?: string;
  serverBanner?: string;
  httpStatus?: number;
  latencyMs?: number;
}

// ── DNS Type ID Mapping ────────────────────────────────────────────────────────
const DNS_TYPES: Record<number, string> = {
  1: 'A',
  28: 'AAAA',
  15: 'MX',
  16: 'TXT',
  2: 'NS',
  5: 'CNAME',
  6: 'SOA',
};

// ── DoH DNS Resolver ───────────────────────────────────────────────────────────
export async function resolveDnsRecords(domain: string): Promise<DnsRecord[]> {
  const records: DnsRecord[] = [];
  const typesToQuery = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME'];

  await Promise.allSettled(
    typesToQuery.map(async (t) => {
      try {
        const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${t}`, {
          headers: { 'Accept': 'application/dns-json' },
          signal: AbortSignal.timeout(4000),
        });
        if (res.ok) {
          const json = await res.json();
          if (json.Answer) {
            for (const ans of json.Answer) {
              records.push({
                type: DNS_TYPES[ans.type] || t,
                value: ans.data,
                ttl: ans.TTL,
              });
            }
          }
        }
      } catch {
        // Fallback or ignore timeout
      }
    })
  );

  return records;
}

// ── crt.sh Subdomain Discovery ─────────────────────────────────────────────────
export async function discoverSubdomains(domain: string): Promise<string[]> {
  const cleanDomain = domain.replace(/^www\./, '').toLowerCase();
  try {
    const res = await fetch(`https://crt.sh/?q=%.${encodeURIComponent(cleanDomain)}&output=json`, {
      signal: AbortSignal.timeout(6000),
    });
    if (res.ok) {
      const data = await res.json();
      const subSet = new Set<string>();
      if (Array.isArray(data)) {
        for (const item of data.slice(0, 30)) {
          const nameVal: string = item.name_value || '';
          nameVal.split('\n').forEach(sub => {
            const cleanSub = sub.trim().toLowerCase();
            if (cleanSub.endsWith(cleanDomain) && !cleanSub.includes('*') && cleanSub !== cleanDomain) {
              subSet.add(cleanSub);
            }
          });
        }
      }
      return Array.from(subSet).slice(0, 15);
    }
  } catch {
    // Return empty if blocked by CORS or rate limited
  }
  return [];
}

// ── RDAP WHOIS Lookup ──────────────────────────────────────────────────────────
export async function lookupWhois(domain: string): Promise<WhoisRecord | undefined> {
  const cleanDomain = domain.replace(/^www\./, '').toLowerCase();
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(cleanDomain)}`, {
      signal: AbortSignal.timeout(5000),
    });
    if (res.ok) {
      const data = await res.json();
      let registrar = 'Unknown';
      if (data.entities) {
        for (const ent of data.entities) {
          if (ent.roles?.includes('registrar')) {
            registrar = ent.vcardArray?.[1]?.find((f: any) => f[0] === 'fn')?.[3] || ent.handle || registrar;
          }
        }
      }

      let createdDate: string | undefined;
      let expiresDate: string | undefined;
      let updatedDate: string | undefined;

      if (data.events) {
        for (const ev of data.events) {
          if (ev.eventAction === 'registration') createdDate = ev.eventDate;
          if (ev.eventAction === 'expiration') expiresDate = ev.eventDate;
          if (ev.eventAction === 'last changed') updatedDate = ev.eventDate;
        }
      }

      let domainAgeDays: number | undefined;
      if (createdDate) {
        const ageMs = Date.now() - new Date(createdDate).getTime();
        domainAgeDays = Math.max(0, Math.floor(ageMs / (1000 * 60 * 60 * 24)));
      }

      const nameservers = data.nameservers?.map((ns: any) => ns.ldhName || ns.handle).filter(Boolean);

      return {
        registrar,
        createdDate,
        expiresDate,
        updatedDate,
        domainAgeDays,
        nameservers,
        status: data.status?.[0] || 'active',
      };
    }
  } catch {
    // Ignore fallback
  }
  return undefined;
}

// ── Security Headers Scorer ────────────────────────────────────────────────────
export function auditSecurityHeaders(headers: Record<string, string>): { checks: HeaderCheck[]; score: number; waf?: string; server?: string } {
  const checks: Array<{ header: string; weight: number; description: string }> = [
    { header: 'strict-transport-security', weight: 25, description: 'Enforces HTTPS encryption (HSTS)' },
    { header: 'content-security-policy', weight: 25, description: 'Mitigates XSS, CSRF, and data injection' },
    { header: 'x-frame-options', weight: 15, description: 'Prevents Clickjacking UI redressing' },
    { header: 'x-content-type-options', weight: 15, description: 'Prevents MIME-type sniffing' },
    { header: 'referrer-policy', weight: 10, description: 'Controls referrer data leakage' },
    { header: 'permissions-policy', weight: 10, description: 'Restricts camera/mic browser APIs' },
  ];

  const norm: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    norm[k.toLowerCase()] = v;
  }

  let totalWeight = 0;
  let earned = 0;

  const evaluatedChecks = checks.map(c => {
    totalWeight += c.weight;
    const isPresent = c.header in norm;
    if (isPresent) earned += c.weight;
    return {
      ...c,
      present: isPresent,
      value: norm[c.header],
    };
  });

  const score = Math.round((earned / totalWeight) * 100);

  // WAF Detection
  let waf: string | undefined;
  if (norm['cf-ray'] || norm['cf-cache-status'] || norm['server']?.toLowerCase().includes('cloudflare')) {
    waf = 'Cloudflare Edge Protection';
  } else if (norm['x-amz-cf-id'] || norm['x-amz-id-2']) {
    waf = 'AWS CloudFront / AWS WAF';
  } else if (norm['x-akamai-transformed']) {
    waf = 'Akamai Intelligent Edge';
  } else if (norm['x-sucuri-id']) {
    waf = 'Sucuri CloudProxy';
  }

  return {
    checks: evaluatedChecks,
    score,
    waf,
    server: norm['server'],
  };
}

// ── Full WebFox Recon Orchestrator ─────────────────────────────────────────────
export async function runWebFoxRecon(targetUrlOrDomain: string): Promise<WebFoxReconResult> {
  const cleanDomain = targetUrlOrDomain
    .replace(/^https?:\/\//i, '')
    .split('/')[0]
    .split(':')[0]
    .toLowerCase();

  const start = Date.now();

  const [dnsRecords, subdomains, whois] = await Promise.all([
    resolveDnsRecords(cleanDomain),
    discoverSubdomains(cleanDomain),
    lookupWhois(cleanDomain),
  ]);

  const latencyMs = Date.now() - start;

  // Extract primary A record IP
  const aRecord = dnsRecords.find(r => r.type === 'A');
  const ip = aRecord?.value;

  // Default security headers audit
  const defaultHeaderAudit = auditSecurityHeaders({});

  return {
    domain: cleanDomain,
    ip,
    dnsRecords,
    subdomains,
    whois,
    securityHeaders: defaultHeaderAudit.checks,
    headerSecurityScore: defaultHeaderAudit.score,
    wafDetected: defaultHeaderAudit.waf,
    latencyMs,
  };
}
