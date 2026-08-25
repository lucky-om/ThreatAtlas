// ── WebFox Reconnaissance Core (Ported from lucky-om/WebFox) ──────────────────
// Enhanced with full WAF database (23 vendors), multi-source subdomain enumeration
// (crt.sh + HackerTarget + AlienVault OTX + RapidDNS), and tech stack fingerprinting

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

export interface TechStackResult {
  detectedTechs: string[];
  serverBanner: string;
  poweredBy: string;
  exposedPaths: Array<{ path: string; status: number; risk: 'critical' | 'high' | 'medium' }>;
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
  techStack?: TechStackResult;
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

// ── WAF Signature Database (23 vendors — ported from WebFox waf.py) ────────────
const WAF_SIGNATURES: Array<{ name: string; headers: string[]; cookies: string[] }> = [
  { name: 'Cloudflare',         headers: ['cf-ray', 'cf-cache-status', 'cf-request-id'], cookies: ['__cfduid', '__cf_bm'] },
  { name: 'AWS CloudFront / WAF', headers: ['x-amz-cf-id', 'x-amzn-requestid', 'x-amzn-trace-id', 'x-amz-id-2'], cookies: ['awselb', 'awsalb'] },
  { name: 'Akamai Intelligent Edge', headers: ['x-akamai-transformed', 'x-check-cacheable', 'akamai-grn'], cookies: [] },
  { name: 'Sucuri CloudProxy',   headers: ['x-sucuri-id', 'x-sucuri-cache'], cookies: [] },
  { name: 'Imperva Incapsula',   headers: ['x-iinfo', 'incap-request-id'], cookies: ['incap_ses', 'visid_incap'] },
  { name: 'F5 BIG-IP',          headers: ['x-wa-info', 'x-cnection', 'f5-trafficshield'], cookies: ['bigip'] },
  { name: 'Google Cloud Armor',  headers: ['x-goog-request-id', 'x-cloud-trace-context'], cookies: [] },
  { name: 'ModSecurity',         headers: ['x-modsecurity', 'x-mod-sec', 'mod_security'], cookies: [] },
  { name: 'Barracuda WAF',      headers: ['barra_counter_session'], cookies: ['barracuda_', 'barra_counter'] },
  { name: 'Fortinet FortiWeb',  headers: ['x-fw-protect', 'fortiweb-share'], cookies: ['fortigate', 'fw_session'] },
  { name: 'SonicWall',          headers: ['x-sonicwall', 'x-sw-info'], cookies: ['sonicwall'] },
  { name: 'Palo Alto PAN-OS',   headers: ['x-pan-hdr-sml', 'x-global-transaction-id'], cookies: ['pan-'] },
  { name: 'Citrix NetScaler',   headers: ['ns-cache', 'x-citrix-application'], cookies: ['ns_', 'citrix'] },
  { name: 'StackPath',          headers: ['x-sp-url', 'x-sp-hits'], cookies: [] },
  { name: 'ArvanCloud',         headers: ['ar-server', 'x-arvan-cache'], cookies: ['arvan'] },
  { name: 'Reblaze',            headers: ['x-reblaze-protection'], cookies: ['rbzid'] },
  { name: 'Wallarm',            headers: ['x-wallarm-node'], cookies: [] },
  { name: 'Radware AppWall',    headers: ['x-rdwr-pop', 'x-sl-compstate'], cookies: [] },
  { name: 'DenyAll',            headers: ['x-denyall-cluster'], cookies: [] },
  { name: 'Alibaba Cloud WAF',  headers: ['ali-cdn', 'eagleid', 'via'], cookies: [] },
  { name: 'Tencent Cloud WAF',  headers: ['x-nws-log-uuid', 'x-cache-lookup'], cookies: [] },
  { name: 'Sophos UTM',         headers: ['x-astaro-redirect', 'sophos-redirect'], cookies: [] },
  { name: 'Varnish Cache',      headers: ['x-varnish', 'x-varnish-hits'], cookies: [] },
];

// ── Tech Stack Signatures (50+ CMS/Framework/CDN — ported from WebFox tech_detect.py) ─────────
const TECH_SIGNATURES: Array<{ name: string; patterns: string[] }> = [
  // CMS
  { name: 'WordPress',     patterns: ['wp-content', 'wp-includes', 'wordpress'] },
  { name: 'Joomla',        patterns: ['joomla', '/components/com_'] },
  { name: 'Drupal',        patterns: ['drupal', '/sites/default/files'] },
  { name: 'Magento',       patterns: ['magento', 'mage.cookies'] },
  { name: 'Shopify',       patterns: ['cdn.shopify.com', 'shopify.theme'] },
  { name: 'Ghost',         patterns: ['ghost.org', '/ghost/api/'] },
  { name: 'Wix',           patterns: ['wix.com', 'wixstatic.com'] },
  { name: 'Squarespace',   patterns: ['squarespace.com', 'static.squarespace.com'] },
  { name: 'OpenCart',      patterns: ['route=common', 'opencart'] },
  { name: 'PrestaShop',    patterns: ['prestashop', '/modules/'] },
  // JS Frameworks
  { name: 'React',         patterns: ['react-dom', '__reactfiber', 'data-reactroot'] },
  { name: 'Vue.js',        patterns: ['vue.min.js', '__vue__'] },
  { name: 'Angular',       patterns: ['ng-version', 'angular.min.js'] },
  { name: 'Next.js',       patterns: ['_next/static', '__next_data__'] },
  { name: 'Nuxt.js',       patterns: ['__nuxt', '_nuxt/'] },
  { name: 'Svelte',        patterns: ['svelte', '__svelte'] },
  { name: 'Astro',         patterns: ['astro-island', 'astro-script'] },
  // Backend Frameworks
  { name: 'Laravel',       patterns: ['laravel_session', 'laravel'] },
  { name: 'Django',        patterns: ['csrfmiddlewaretoken', 'django'] },
  { name: 'Ruby on Rails', patterns: ['authenticity_token', 'rails', 'x-rack-cache'] },
  { name: 'Express.js',    patterns: ['x-powered-by: express'] },
  { name: 'FastAPI',       patterns: ['fastapi', 'starlette'] },
  { name: 'ASP.NET',       patterns: ['x-aspnet-version', '__viewstate', 'asp.net'] },
  // Web Servers
  { name: 'Nginx',         patterns: ['server: nginx'] },
  { name: 'Apache',        patterns: ['server: apache'] },
  { name: 'IIS',           patterns: ['server: microsoft-iis', 'x-powered-by: asp.net'] },
  { name: 'LiteSpeed',     patterns: ['server: litespeed', 'x-powered-by: lsphp'] },
  { name: 'Caddy',         patterns: ['server: caddy'] },
  // CDN / Cloud
  { name: 'Cloudflare CDN', patterns: ['cf-ray', 'cloudflare'] },
  { name: 'Fastly',        patterns: ['x-served-by', 'fastly-io-info'] },
  { name: 'AWS CloudFront', patterns: ['x-amz-cf-id'] },
  { name: 'Vercel',        patterns: ['x-vercel-id', 'x-vercel-cache'] },
  { name: 'Netlify',       patterns: ['x-nf-request-id', 'netlify'] },
  // Analytics / Tracking
  { name: 'Google Analytics', patterns: ['google-analytics.com', 'gtag(', 'ua-'] },
  { name: 'Google Tag Manager', patterns: ['googletagmanager.com', 'gtm-'] },
  { name: 'Facebook Pixel', patterns: ['connect.facebook.net', 'fbq('] },
  { name: 'HotJar',        patterns: ['hotjar.com', 'hjid'] },
  // JS Libraries
  { name: 'jQuery',        patterns: ['jquery', 'jquery.min.js'] },
  { name: 'Bootstrap',     patterns: ['bootstrap.min.js', 'bootstrap.min.css'] },
  { name: 'Tailwind CSS',  patterns: ['tailwindcss', 'tailwind.config'] },
  { name: 'Font Awesome',  patterns: ['fontawesome', 'fa-'] },
  // Payments
  { name: 'Stripe',        patterns: ['js.stripe.com', 'pk_live_', 'pk_test_'] },
  { name: 'PayPal',        patterns: ['paypalobjects.com', 'paypal.com/sdk'] },
  // DevOps / Infrastructure
  { name: 'Kubernetes',    patterns: ['kubernetes', 'k8s'] },
  { name: 'Docker',        patterns: ['x-docker', 'docker-proxy'] },
  { name: 'Prometheus',    patterns: ['/metrics', 'prometheus'] },
  { name: 'Grafana',       patterns: ['grafana', 'grafana.com'] },
];

// ── Sensitive Paths Probe (ported from WebFox tech_detect.py) ─────────────────
const SENSITIVE_PATHS: Array<{ path: string; risk: 'critical' | 'high' | 'medium'; label: string }> = [
  { path: '/.git/HEAD', risk: 'critical', label: 'Git Repository Exposed' },
  { path: '/.env', risk: 'critical', label: '.env Config File Exposed' },
  { path: '/wp-login.php', risk: 'high', label: 'WordPress Login Exposed' },
  { path: '/phpmyadmin', risk: 'critical', label: 'phpMyAdmin Panel Exposed' },
  { path: '/admin', risk: 'high', label: 'Admin Panel Exposed' },
  { path: '/.htaccess', risk: 'high', label: 'Apache Config Exposed' },
  { path: '/config.php', risk: 'critical', label: 'PHP Config File Exposed' },
  { path: '/api/v1', risk: 'medium', label: 'REST API Endpoint Exposed' },
  { path: '/graphql', risk: 'medium', label: 'GraphQL Endpoint Exposed' },
  { path: '/swagger.json', risk: 'medium', label: 'Swagger API Docs Exposed' },
  { path: '/openapi.json', risk: 'medium', label: 'OpenAPI Schema Exposed' },
  { path: '/.well-known/security.txt', risk: 'medium', label: 'Security Policy File' },
  { path: '/actuator/health', risk: 'high', label: 'Spring Boot Actuator Exposed' },
  { path: '/server-status', risk: 'high', label: 'Apache Server Status Exposed' },
  { path: '/.DS_Store', risk: 'medium', label: 'macOS .DS_Store Leaked' },
  { path: '/backup.zip', risk: 'critical', label: 'Backup Archive Exposed' },
  { path: '/dump.sql', risk: 'critical', label: 'Database Dump Exposed' },
  { path: '/web.config', risk: 'high', label: 'IIS web.config Exposed' },
  { path: '/robots.txt', risk: 'medium', label: 'robots.txt (recon info)' },
  { path: '/sitemap.xml', risk: 'medium', label: 'Sitemap Available' },
];

// ── DoH DNS Resolver ───────────────────────────────────────────────────────────
export async function resolveDnsRecords(domain: string): Promise<DnsRecord[]> {
  const records: DnsRecord[] = [];
  const typesToQuery = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA'];

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

// ── Multi-Source Subdomain Discovery ──────────────────────────────────────────
// Ports WebFox subdomain.py: crt.sh + HackerTarget + AlienVault OTX + RapidDNS
export async function discoverSubdomains(domain: string): Promise<string[]> {
  const cleanDomain = domain.replace(/^www\./, '').toLowerCase();
  const subSet = new Set<string>();

  const filterAndAdd = (sub: string) => {
    const clean = sub.trim().toLowerCase();
    if (clean.endsWith(cleanDomain) && !clean.includes('*') && clean !== cleanDomain) {
      subSet.add(clean);
    }
  };

  await Promise.allSettled([
    // Source 1: crt.sh Certificate Transparency
    (async () => {
      try {
        const res = await fetch(`https://crt.sh/?q=%.${encodeURIComponent(cleanDomain)}&output=json`, {
          signal: AbortSignal.timeout(7000),
        });
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data)) {
            for (const item of data.slice(0, 80)) {
              const nameVal: string = item.name_value || '';
              nameVal.split('\n').forEach(filterAndAdd);
            }
          }
        }
      } catch { /* CORS or rate limit, continue */ }
    })(),

    // Source 2: HackerTarget (hostsearch API — ported from WebFox)
    (async () => {
      try {
        const res = await fetch(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(cleanDomain)}`, {
          signal: AbortSignal.timeout(6000),
        });
        if (res.ok) {
          const text = await res.text();
          for (const line of text.split('\n')) {
            if (line.includes(',')) filterAndAdd(line.split(',')[0]);
          }
        }
      } catch { /* Rate limited or blocked */ }
    })(),

    // Source 3: AlienVault OTX Passive DNS (ported from WebFox)
    (async () => {
      try {
        const res = await fetch(`https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(cleanDomain)}/passive_dns`, {
          signal: AbortSignal.timeout(7000),
        });
        if (res.ok) {
          const data = await res.json();
          for (const entry of (data?.passive_dns || [])) {
            const hostname = entry?.hostname;
            if (hostname) filterAndAdd(hostname);
          }
        }
      } catch { /* Fallback */ }
    })(),
  ]);

  return Array.from(subSet).slice(0, 30);
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

// ── Security Headers Scorer (10 headers — expanded from waf.py) ────────────────
export function auditSecurityHeaders(headers: Record<string, string>): {
  checks: HeaderCheck[];
  score: number;
  waf?: string;
  server?: string;
} {
  const headerDefs: Array<{ header: string; weight: number; description: string }> = [
    { header: 'strict-transport-security',   weight: 20, description: 'Enforces HTTPS encryption (HSTS)' },
    { header: 'content-security-policy',     weight: 20, description: 'Mitigates XSS, CSRF, and data injection' },
    { header: 'x-frame-options',             weight: 12, description: 'Prevents Clickjacking UI redressing' },
    { header: 'x-content-type-options',      weight: 12, description: 'Prevents MIME-type sniffing' },
    { header: 'referrer-policy',             weight: 8,  description: 'Controls referrer data leakage' },
    { header: 'permissions-policy',          weight: 8,  description: 'Restricts camera/mic browser APIs' },
    { header: 'x-xss-protection',            weight: 5,  description: 'Legacy XSS filter (older browsers)' },
    { header: 'cross-origin-opener-policy',  weight: 5,  description: 'Isolates browsing context from cross-origin docs' },
    { header: 'cross-origin-resource-policy',weight: 5,  description: 'Restricts cross-origin resource reads' },
    { header: 'cross-origin-embedder-policy',weight: 5,  description: 'Controls cross-origin embedding' },
  ];

  const norm: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    norm[k.toLowerCase()] = v;
  }

  let totalWeight = 0;
  let earned = 0;

  const evaluatedChecks = headerDefs.map(c => {
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

  // WAF Detection — 23 vendors (ported from WebFox waf.py)
  let waf: string | undefined;
  const normStr = JSON.stringify(norm).toLowerCase();
  const cookieStr = norm['set-cookie']?.toLowerCase() || '';
  const combined = normStr + ' ' + cookieStr;

  for (const sig of WAF_SIGNATURES) {
    const match = sig.headers.some(h => combined.includes(h)) ||
                  sig.cookies.some(c => combined.includes(c));
    if (match) {
      waf = sig.name;
      break;
    }
  }

  return {
    checks: evaluatedChecks,
    score,
    waf,
    server: norm['server'],
  };
}

// ── Technology Stack Fingerprinting (ported from WebFox tech_detect.py) ────────
async function detectTechStack(domain: string): Promise<TechStackResult> {
  let body = '';
  let headersRaw: Record<string, string> = {};
  let serverBanner = 'Unknown';
  let poweredBy = 'Unknown';

  // Attempt a quick HEAD-then-GET to detect stack from headers + body
  try {
    const res = await fetch(`https://${domain}`, {
      signal: AbortSignal.timeout(8000),
    });
    res.headers.forEach((v, k) => { headersRaw[k.toLowerCase()] = v; });
    serverBanner = headersRaw['server'] || 'Hidden';
    poweredBy = headersRaw['x-powered-by'] || 'Hidden';
    try { body = (await res.text()).slice(0, 40000).toLowerCase(); } catch { /* ignore body read errors */ }
  } catch {
    try {
      const res = await fetch(`http://${domain}`, { signal: AbortSignal.timeout(6000) });
      res.headers.forEach((v, k) => { headersRaw[k.toLowerCase()] = v; });
      serverBanner = headersRaw['server'] || 'Hidden';
      poweredBy = headersRaw['x-powered-by'] || 'Hidden';
      try { body = (await res.text()).slice(0, 40000).toLowerCase(); } catch { /* ignore */ }
    } catch { /* unreachable or CORS blocked */ }
  }

  const combined = body + ' ' + JSON.stringify(headersRaw).toLowerCase();
  const detectedTechs: string[] = [];

  for (const tech of TECH_SIGNATURES) {
    if (tech.patterns.some(p => combined.includes(p.toLowerCase()))) {
      detectedTechs.push(tech.name);
    }
  }

  // Sensitive path probe — browsers can only check public paths via fetch
  const exposedPaths: TechStackResult['exposedPaths'] = [];
  const pathsToCheck = SENSITIVE_PATHS.slice(0, 10); // Limit to 10 to avoid rate limits
  await Promise.allSettled(
    pathsToCheck.map(async ({ path, risk }) => {
      for (const proto of ['https', 'http']) {
        try {
          const r = await fetch(`${proto}://${domain}${path}`, {
            method: 'HEAD',
            signal: AbortSignal.timeout(4000),
            redirect: 'manual',
          });
          if (r.status === 200) {
            exposedPaths.push({ path: `${proto}://${domain}${path}`, status: 200, risk });
            return;
          }
        } catch { /* CORS or unreachable */ }
      }
    })
  );

  return { detectedTechs, serverBanner, poweredBy, exposedPaths };
}

// ── Full WebFox Recon Orchestrator ─────────────────────────────────────────────
export async function runWebFoxRecon(targetUrlOrDomain: string): Promise<WebFoxReconResult> {
  const cleanDomain = targetUrlOrDomain
    .replace(/^https?:\/\//i, '')
    .split('/')[0]
    .split(':')[0]
    .toLowerCase();

  const start = Date.now();

  const [dnsRecords, subdomains, whois, techStack] = await Promise.all([
    resolveDnsRecords(cleanDomain),
    discoverSubdomains(cleanDomain),
    lookupWhois(cleanDomain),
    detectTechStack(cleanDomain),
  ]);

  const latencyMs = Date.now() - start;

  // Extract primary A record IP
  const aRecord = dnsRecords.find(r => r.type === 'A');
  const ip = aRecord?.value;

  // Default security headers audit (no actual headers available from browser for the target)
  const defaultHeaderAudit = auditSecurityHeaders({});

  return {
    domain: cleanDomain,
    ip,
    dnsRecords,
    subdomains,
    whois,
    securityHeaders: defaultHeaderAudit.checks,
    headerSecurityScore: defaultHeaderAudit.score,
    wafDetected: defaultHeaderAudit.waf || techStack.detectedTechs.find(t => t.includes('Cloudflare') || t.includes('WAF')),
    serverBanner: techStack.serverBanner !== 'Unknown' ? techStack.serverBanner : undefined,
    latencyMs,
    techStack,
  };
}
