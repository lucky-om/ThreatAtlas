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
  openPorts?: number[];
  cves?: string[];
  cpes?: string[];
  techStack?: TechStackResult;
  crawl?: WebFoxCrawlResult;
}

export interface WebFoxCrawlResult {
  robots: { found: boolean; disallowed: string[]; flagged: string[]; raw?: string };
  sitemap: { found: boolean; urls: string[]; source?: string };
  jsSecrets: Array<{ type: string; value: string; file: string }>;
  jsEndpoints: string[];
}


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

  try {
    const res = await fetch(`/api/webfox/dns?domain=${encodeURIComponent(domain)}`, {
      signal: AbortSignal.timeout(8000)
    });
    if (res.ok) {
      const data = await res.json();
      for (const [type, recs] of Object.entries(data)) {
        if (Array.isArray(recs)) {
          for (const rec of recs) {
            records.push({
              type: type,
              value: typeof rec === 'string' ? rec : (rec.address || rec.value || JSON.stringify(rec)),
            });
          }
        }
      }
    }
  } catch (err) {
    if (import.meta.env.DEV) console.error('[WebFox] DNS lookup failed', err);
  }

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
        const targetUrl = `https://crt.sh/?q=%.${encodeURIComponent(cleanDomain)}&output=json`;
        const res = await fetch(`https://corsproxy.io/?url=${encodeURIComponent(targetUrl)}`, {
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
        const targetUrl = `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(cleanDomain)}`;
        const res = await fetch(`https://corsproxy.io/?url=${encodeURIComponent(targetUrl)}`, {
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

    // Source 4: CertSpotter API
    (async () => {
      try {
        const targetUrl = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(cleanDomain)}&include_subdomains=true&expand=dns_names`;
        const res = await fetch(`https://corsproxy.io/?url=${encodeURIComponent(targetUrl)}`, {
          signal: AbortSignal.timeout(6000),
        });
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data)) {
            for (const item of data) {
              if (Array.isArray(item.dns_names)) {
                item.dns_names.forEach(filterAndAdd);
              }
            }
          }
        }
      } catch { /* Fallback */ }
    })(),

    // Source 5: Anubis (jldc.me)
    (async () => {
      try {
        const targetUrl = `https://jldc.me/anubis/subdomains/${encodeURIComponent(cleanDomain)}`;
        const res = await fetch(`https://corsproxy.io/?url=${encodeURIComponent(targetUrl)}`, {
          signal: AbortSignal.timeout(6000),
        });
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data)) {
            data.forEach(filterAndAdd);
          }
        }
      } catch { /* Fallback */ }
    })(),

    // Source 6: ThreatMiner
    (async () => {
      try {
        const targetUrl = `https://api.threatminer.org/v2/domain.php?q=${encodeURIComponent(cleanDomain)}&rt=5`;
        const res = await fetch(`https://corsproxy.io/?url=${encodeURIComponent(targetUrl)}`, {
          signal: AbortSignal.timeout(6000),
        });
        if (res.ok) {
          const data = await res.json();
          if (data && Array.isArray(data.results)) {
            data.results.forEach(filterAndAdd);
          }
        }
      } catch { /* Fallback */ }
    })(),
  ]);

  return Array.from(subSet).slice(0, 80);
}

// ── RDAP WHOIS Lookup ──────────────────────────────────────────────────────────
export async function lookupWhois(domain: string): Promise<WhoisRecord | undefined> {
  const cleanDomain = domain.replace(/^www\./, '').toLowerCase();
  try {
    const res = await fetch(`/api/webfox/whois?query=${encodeURIComponent(cleanDomain)}`, {
      signal: AbortSignal.timeout(10000),
    });
    if (res.ok) {
      const data = await res.json();
      
      // Parse the standard whois-json format
      const registrar = data.registrar || data.Registrar || 'Unknown';
      const createdDate = data.creationDate || data.CreationDate || data.created;
      const expiresDate = data.registrarRegistrationExpirationDate || data.ExpiryDate || data.expires;
      const updatedDate = data.updatedDate || data.UpdatedDate || data.updated;
      
      let domainAgeDays: number | undefined;
      if (createdDate) {
        const ageMs = Date.now() - new Date(createdDate).getTime();
        if (!isNaN(ageMs)) {
          domainAgeDays = Math.max(0, Math.floor(ageMs / (1000 * 60 * 60 * 24)));
        }
      }

      // Convert name server string to array
      let nameservers: string[] = [];
      const nsRaw = data.nameServer || data.NameServer;
      if (typeof nsRaw === 'string') {
        nameservers = nsRaw.split('\n').map(n => n.trim()).filter(Boolean);
      }

      return {
        registrar,
        createdDate,
        expiresDate,
        updatedDate,
        domainAgeDays,
        nameservers,
        status: data.domainStatus || data.DomainStatus || 'active',
        registrant: data.registrantOrganization || data.RegistrantOrganization || 'Redacted'
      };
    }
  } catch (err) {
    if (import.meta.env.DEV) console.error('[WebFox] WHOIS lookup failed', err);
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
  const headersRaw: Record<string, string> = {};
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

  const [dnsRecords, subdomains, whois, techStack, tlsCert] = await Promise.all([
    resolveDnsRecords(cleanDomain),
    discoverSubdomains(cleanDomain),
    lookupWhois(cleanDomain),
    detectTechStack(cleanDomain),
    fetch(`/api/webfox/tls?host=${encodeURIComponent(cleanDomain)}`).then(r => r.ok ? r.json() : undefined).catch(() => undefined),
  ]);

  const latencyMs = Date.now() - start;

  // Extract primary A record IP
  const aRecord = dnsRecords.find(r => r.type === 'A');
  const ip = aRecord?.value;

  // Default security headers audit (no actual headers available from browser for the target)
  const defaultHeaderAudit = auditSecurityHeaders({});
    
  // 6. WebFox Crawl (Robots, Sitemap, JS Analysis)
  const crawl = await runWebFoxCrawl(cleanDomain);

  // 7. Shodan InternetDB lookup for IP
  let openPorts: number[] = [];
  let cves: string[] = [];
  let cpes: string[] = [];
  if (ip) {
    try {
      const shodanRes = await fetch(`https://internetdb.shodan.io/${ip}`, { signal: AbortSignal.timeout(6000) });
      if (shodanRes.ok) {
        const shodanData = await shodanRes.json();
        if (Array.isArray(shodanData.ports)) openPorts = shodanData.ports;
        if (Array.isArray(shodanData.vulns)) cves = shodanData.vulns;
        if (Array.isArray(shodanData.cpes)) cpes = shodanData.cpes;
      }
    } catch { /* Ignore if it fails */ }
  }

  let sslCert: SslCertInfo | undefined;
  if (tlsCert && !tlsCert.error) {
    sslCert = {
      issuer: tlsCert.issuer?.O || tlsCert.issuer?.CN || 'Unknown',
      commonName: tlsCert.subject?.CN || cleanDomain,
      validFrom: tlsCert.valid_from,
      validTo: tlsCert.valid_to,
      daysLeft: Math.max(0, Math.floor((new Date(tlsCert.valid_to).getTime() - Date.now()) / (1000 * 60 * 60 * 24))),
      fingerprint: tlsCert.fingerprint,
      isValid: new Date(tlsCert.valid_to).getTime() > Date.now()
    };
  }

  return {
    domain: cleanDomain,
    ip,
    dnsRecords,
    subdomains,
    whois,
    sslCert,
    securityHeaders: defaultHeaderAudit.checks,
    headerSecurityScore: defaultHeaderAudit.score,
    wafDetected: defaultHeaderAudit.waf || techStack.detectedTechs.find(t => t.includes('Cloudflare') || t.includes('WAF')),
    serverBanner: techStack.serverBanner !== 'Unknown' ? techStack.serverBanner : undefined,
    latencyMs,
    techStack,
    crawl,
    openPorts: openPorts.length > 0 ? openPorts : undefined,
    cves: cves.length > 0 ? cves : undefined,
    cpes: cpes.length > 0 ? cpes : undefined
  };
}

// ── WebFox Crawl (Robots, Sitemap, JS Scanning) ────────────────────────────────

async function runWebFoxCrawl(domain: string): Promise<WebFoxCrawlResult> {
  const result: WebFoxCrawlResult = {
    robots: { found: false, disallowed: [], flagged: [] },
    sitemap: { found: false, urls: [] },
    jsSecrets: [],
    jsEndpoints: []
  };

  try {
    // We proxy through corsproxy.io to avoid CORS limitations on text fetching
    const fetchProxy = async (url: string) => {
      const res = await fetch(`https://corsproxy.io/?url=${encodeURIComponent(url)}`);
      if (!res.ok) throw new Error('Proxy fetch failed');
      return await res.text();
    };

    // 1. Robots.txt Analysis
    try {
      const robotsTxt = await fetchProxy(`https://${domain}/robots.txt`);
      result.robots.found = true;
      result.robots.raw = robotsTxt.substring(0, 5000); // cap size
      
      const lines = robotsTxt.split('\n');
      for (const line of lines) {
        const stripped = line.trim();
        if (stripped.toLowerCase().startsWith('disallow:')) {
          const path = stripped.substring(9).trim();
          if (path) {
            result.robots.disallowed.push(path);
            const riskKeywords = ['/admin', '/wp-admin', '/phpmyadmin', '/login', '/backup', '/private', '/secret', '/db', '/api'];
            if (riskKeywords.some(rk => path.toLowerCase().includes(rk))) {
              result.robots.flagged.push(path);
            }
          }
        }
      }
    } catch { /* robots.txt fetch failed */ }

    // 2. Sitemap Discovery
    try {
      // First try robots.txt for sitemap location
      let sitemapUrl = `https://${domain}/sitemap.xml`;
      if (result.robots.raw) {
        const smMatch = result.robots.raw.match(/Sitemap:\s*(https?:\/\/[^\s]+)/i);
        if (smMatch && smMatch[1]) sitemapUrl = smMatch[1];
      }

      const sitemapTxt = await fetchProxy(sitemapUrl);
      result.sitemap.found = true;
      result.sitemap.source = sitemapUrl;
      
      // Extract <loc> tags
      const locRegex = /<loc>(.*?)<\/loc>/gi;
      let match;
      let count = 0;
      while ((match = locRegex.exec(sitemapTxt)) !== null && count < 200) {
        if (match[1]) result.sitemap.urls.push(match[1].trim());
        count++;
      }
    } catch { /* sitemap fetch failed */ }

    // 3. JavaScript Secret Scanning (Inline & External)
    try {
      const homeHtml = await fetchProxy(`https://${domain}/`);
      
      const jsUrls = new Set<string>();
      // Find scripts in HTML
      const scriptRegex = /src=["'](.*?.js.*?)["']/gi;
      let match;
      while ((match = scriptRegex.exec(homeHtml)) !== null) {
        let jsUrl = match[1];
        if (jsUrl.startsWith('//')) jsUrl = 'https:' + jsUrl;
        else if (jsUrl.startsWith('/')) jsUrl = `https://${domain}${jsUrl}`;
        else if (!jsUrl.startsWith('http')) jsUrl = `https://${domain}/${jsUrl}`;
        jsUrls.add(jsUrl);
      }
      
      // Check common chunk paths if none found
      if (jsUrls.size === 0) {
        jsUrls.add(`https://${domain}/static/js/main.js`);
        jsUrls.add(`https://${domain}/app.js`);
      }

      const SECRET_PATTERNS = {
        "Google API Key": /AIza[0-9A-Za-z\-_]{35}/g,
        "AWS Access Key ID": /AKIA[0-9A-Z]{16}/g,
        "Stripe Live Key": /sk_live_[0-9a-zA-Z]{24,}/g,
        "GitHub Token": /ghp_[a-zA-Z0-9]{36}/g,
        "Slack Bot Token": /xoxb-[0-9]+-[a-zA-Z0-9]+/g,
        "JWT Token": /eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*/g,
        "Firebase Config": /firebaseapp\.com/g,
        "Mailgun API": /key-[a-zA-Z0-9]{32}/g,
        "Twilio Auth Token": /twilio.{0,20}["']([a-f0-9]{32})["']/gi
      };

      const ENDPOINT_PATTERNS = [
        /(?:"|'|`)\/((?:api|v\d|graphql|admin|user|auth|login)[^"'`<>]{0,100})(?:"|'|`)/gi,
        /fetch\(["']([^"']{5,})["']/gi,
        /axios\.(get|post)\(["']([^"']{5,})["']/gi
      ];

      // Scan up to 5 JS files to save time
      const urlsToScan = Array.from(jsUrls).slice(0, 5);
      
      await Promise.allSettled(urlsToScan.map(async (jsUrl) => {
        try {
          const jsContent = await fetchProxy(jsUrl);
          const srcName = jsUrl.split('/').pop()?.substring(0, 30) || 'unknown.js';
          
          for (const [name, pattern] of Object.entries(SECRET_PATTERNS)) {
            let m;
            while ((m = pattern.exec(jsContent)) !== null) {
              const val = m[0].substring(0, 80);
              // Avoid duplicates
              if (!result.jsSecrets.find(s => s.value === val)) {
                result.jsSecrets.push({ type: name, value: val, file: srcName });
              }
            }
          }

          for (const pattern of ENDPOINT_PATTERNS) {
            let m;
            while ((m = pattern.exec(jsContent)) !== null) {
              const ep = m[1] || m[0];
              const clean = ep.replace(/["'`]/g, '');
              if (clean && clean.length > 2 && !clean.endsWith('.js') && !clean.endsWith('.css')) {
                if (!result.jsEndpoints.includes(clean)) {
                  result.jsEndpoints.push(clean.substring(0, 100));
                }
              }
            }
          }
        } catch { /* individual JS file scan failed */ }
      }));
      
    } catch { /* JS crawl failed — skip */ }

  } catch (err) {
    if (import.meta.env.DEV) console.error('[WebFox Crawl] Error:', err);
  }

  return result;
}
