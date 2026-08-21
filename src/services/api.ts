// VirusTotal API Service & Data Normalizers
import { normalizeUrlForScan, sanitizeUrl } from '../utils/sanitize';

export interface EngineResult {
  engine: string;
  category?: string;
  result: string | null;
  method?: string;
  detected: boolean;
}

export interface ScanStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  timeout?: number;
  total?: number;
}

export interface DnsRecord {
  type: string;
  value: string;
  ttl?: number;
}

export interface MitreAttackTechnique {
  id: string;
  signature_description: string;
  tactic: string;
}

export interface CommunityComment {
  id: string;
  date: number;
  author: string;
  text: string;
  votes: { positive: number; negative: number; abuse: number };
}

export interface CrowdsourcedYaraRule {
  rule_name: string;
  ruleset_name?: string;
  author?: string;
  description?: string;
  source?: string;
  match_data?: any;
}

export interface ExtendedDetails {
  categories?: Record<string, string>;
  history?: {
    firstSubmission?: number;
    lastSubmission?: number;
    lastAnalysis?: number;
  };
  ssdeep?: string;
  tlsh?: string;
  vhash?: string;
  magika?: string;
  crowdsourcedYara?: CrowdsourcedYaraRule[];
  sigmaAnalysis?: any[];
  redirectionChain?: string[];
  httpResponse?: {
    finalUrl?: string;
    servingIp?: string;
    statusCode?: number;
    bodyLength?: number;
    headers?: Record<string, string>;
  };
  htmlInfo?: {
    title?: string;
    meta?: Record<string, string>;
  };
  favicon?: { raw_md5?: string; dhash?: string };
  outgoingLinks?: string[];
  javascriptVariables?: any;
  networkRequests?: any[];
  magic?: string;
  trid?: Array<{ file_type: string; probability: number }>;
  exiftool?: Record<string, any>;
  signatureInfo?: Record<string, any>;
  peInfo?: {
    imphash?: string;
    entry_point?: number;
    machine_type?: string;
    sections?: Array<{ name: string; entropy: number; virtual_size: number; raw_size: number }>;
    import_list?: Array<{ library_name: string; imported_functions: string[] }>;
  };
  packers?: Record<string, string>;
  mitreAttack?: MitreAttackTechnique[];
  pdfInfo?: Record<string, any>;
  officeInfo?: Record<string, any>;
  bundleInfo?: Record<string, any>;
}

export interface EntityRelations {
  resolutions?: Array<{ ip: string; date: number; stats?: ScanStats }>;
  subdomains?: Array<{ id: string; stats?: ScanStats }>;
  historicalWhois?: Array<{ date: number; registrar?: string; registrant?: string }>;
  historicalSsl?: Array<{ date: number; subject?: string; thumbprint?: string }>;
  communicatingFiles?: Array<{ id: string; name?: string; type?: string; stats?: ScanStats }>;
  downloadedFiles?: Array<{ id: string; name?: string; type?: string; stats?: ScanStats }>;
  contactedIps?: Array<{ ip: string; country?: string; stats?: ScanStats }>;
  contactedDomains?: Array<{ domain: string; categories?: Record<string, string>; stats?: ScanStats }>;
  contactedUrls?: Array<{ url: string; stats?: ScanStats }>;
}

export interface NormalizedAnalysis {
  id: string;
  status: string;
  date: number | null;
  threatScore: number;
  verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  stats: ScanStats;
  engines: EngineResult[];
  fileName?: string;
  fileSize?: number;
  url?: string;
  hash?: string;
  extended?: ExtendedDetails;
  relations?: EntityRelations;
  comments?: CommunityComment[];
}

export interface NormalizedFile {
  id: string;
  sha256: string;
  sha1: string;
  md5: string;
  name: string;
  names: string[];
  size: number;
  type: string;
  mimeType: string;
  firstSeen: number;
  lastSeen: number;
  timesSubmitted: number;
  verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  stats: ScanStats;
  tags: string[];
  engines: EngineResult[];
  extended?: ExtendedDetails;
  relations?: EntityRelations;
  comments?: CommunityComment[];
}

export interface NormalizedIp {
  id: string;
  ip: string;
  asn: number | null;
  asOwner: string;
  country: string;
  network: string;
  verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  stats: ScanStats;
  reputation: number;
  tags: string[];
  engines: EngineResult[];
  lastSeen: number;
  relations?: EntityRelations;
  dnsRecords?: DnsRecord[];
  comments?: CommunityComment[];
}

export interface NormalizedDomain {
  id: string;
  domain: string;
  registrar: string;
  creation: number;
  expiration: number;
  reputation: number;
  verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  stats: ScanStats;
  tags: string[];
  categories: Record<string, string>;
  engines: EngineResult[];
  lastSeen: number;
  relations?: EntityRelations;
  dnsRecords?: DnsRecord[];
  comments?: CommunityComment[];
}

export class ApiError extends Error {
  status?: number;
  code?: string;

  constructor(message: string, status?: number, code?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

// ── In-Memory Fast Cache ───────────────────────────────────────────────────
const cache = new Map<string, { data: any; timestamp: number }>();
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

function getCached<T>(key: string): T | null {
  const item = cache.get(key);
  if (!item) return null;
  if (Date.now() - item.timestamp > CACHE_TTL_MS) {
    cache.delete(key);
    return null;
  }
  return item.data as T;
}

function setCache<T>(key: string, data: T): T {
  cache.set(key, { data, timestamp: Date.now() });
  return data;
}

// Low-level fetch wrapper with error handling
async function vtFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const cacheKey = `${options?.method || 'GET'}:${path}`;
  if (!options?.method || options.method === 'GET') {
    const cached = getCached<T>(cacheKey);
    if (cached) return cached;
  }

  const url = `/api/vt${path}`;
  const res = await fetch(url, options);

  if (!res.ok) {
    let errMsg = `VirusTotal API error (${res.status})`;
    let code: string | undefined;

    try {
      const data = await res.json();
      if (data?.error?.message) {
        errMsg = data.error.message;
        code = data.error.code;
      }
    } catch (_) {}

    if (res.status === 401) throw new ApiError('VirusTotal API key is not configured. Please add a valid VT key in server config. Get a free key at virustotal.com', 401, code);
    if (res.status === 404) throw new ApiError('Resource not found in threat database.', 404, code);
    if (res.status === 429) throw new ApiError('API rate limit exceeded. Please wait a minute.', 429, code);
    if (res.status === 400) throw new ApiError('Bad Request: ' + errMsg, 400, code);

    throw new ApiError(errMsg, res.status, code);
  }

  const contentType = res.headers.get('content-type') || '';
  let result: any;
  if (contentType.includes('application/json')) {
    result = await res.json();
  } else {
    result = await res.text();
  }

  if (!options?.method || options.method === 'GET') {
    setCache(cacheKey, result);
  }
  return result as T;
}

// ── Relations & Extra Extractors ───────────────────────────────────────────
export async function fetchEntityRelations(type: 'domains' | 'ip_addresses' | 'files' | 'urls', id: string): Promise<EntityRelations> {
  const relations: EntityRelations = {};

  const safeFetch = async (rel: string) => {
    try {
      return await vtFetch<any>(`/${type}/${encodeURIComponent(id)}/${rel}?limit=10`);
    } catch (e) {
      return null;
    }
  };

  if (type === 'domains' || type === 'ip_addresses') {
    const [res, sub, whois, ssl, commFiles, downFiles] = await Promise.all([
      safeFetch('resolutions'),
      type === 'domains' ? safeFetch('subdomains') : Promise.resolve(null),
      safeFetch('historical_whois'),
      safeFetch('historical_ssl_certificates'),
      safeFetch('communicating_files'),
      safeFetch('downloaded_files')
    ]);

    if (res?.data) {
      relations.resolutions = res.data.map((r: any) => ({
        ip: r.attributes?.ip_address,
        date: r.attributes?.date,
        stats: r.attributes?.last_analysis_stats
      }));
    }
    if (sub?.data) {
      relations.subdomains = sub.data.map((r: any) => ({
        id: r.id,
        stats: r.attributes?.last_analysis_stats
      }));
    }
    if (whois?.data) {
      relations.historicalWhois = whois.data.map((r: any) => ({
        date: r.attributes?.last_updated || r.attributes?.first_seen_date,
        registrar: r.attributes?.registrar_name || r.attributes?.whois_map?.Registrar,
        registrant: r.attributes?.whois_map?.['Registrant Name'] || r.attributes?.whois_map?.['Registrant'] || '-',
      }));
    }
    if (ssl?.data) {
      relations.historicalSsl = ssl.data.map((r: any) => ({
        date: typeof r.attributes?.validity?.not_before === 'string' ? new Date(r.attributes.validity.not_before).getTime() / 1000 : r.attributes?.first_seen_date,
        subject: r.attributes?.subject?.CN,
        thumbprint: r.attributes?.thumbprint
      }));
    }
    if (commFiles?.data) {
      relations.communicatingFiles = commFiles.data.map((r: any) => ({
        id: r.id,
        name: r.attributes?.meaningful_name || r.attributes?.names?.[0],
        type: r.attributes?.type_description,
        stats: r.attributes?.last_analysis_stats
      }));
    }
    if (downFiles?.data) {
      relations.downloadedFiles = downFiles.data.map((r: any) => ({
        id: r.id,
        name: r.attributes?.meaningful_name || r.attributes?.names?.[0],
        type: r.attributes?.type_description,
        stats: r.attributes?.last_analysis_stats
      }));
    }
  } else if (type === 'files') {
    const [cIps, cDomains, cUrls] = await Promise.all([
      safeFetch('contacted_ips'),
      safeFetch('contacted_domains'),
      safeFetch('contacted_urls')
    ]);

    if (cIps?.data) {
      relations.contactedIps = cIps.data.map((r: any) => ({
        ip: r.id,
        country: r.attributes?.country,
        stats: r.attributes?.last_analysis_stats
      }));
    }
    if (cDomains?.data) {
      relations.contactedDomains = cDomains.data.map((r: any) => ({
        domain: r.id,
        categories: r.attributes?.categories,
        stats: r.attributes?.last_analysis_stats
      }));
    }
    if (cUrls?.data) {
      relations.contactedUrls = cUrls.data.map((r: any) => ({
        url: r.attributes?.url || r.id,
        stats: r.attributes?.last_analysis_stats
      }));
    }
  }

  return relations;
}

export async function fetchComments(type: 'domains' | 'ip_addresses' | 'files' | 'urls', id: string): Promise<CommunityComment[]> {
  try {
    const res = await vtFetch<any>(`/${type}/${encodeURIComponent(id)}/comments?limit=10`);
    if (!res?.data) return [];
    return res.data.map((item: any) => ({
      id: item.id,
      date: item.attributes?.date || 0,
      author: item.attributes?.author?.username || 'Community Member',
      text: item.attributes?.text || '',
      votes: item.attributes?.votes || { positive: 0, negative: 0, abuse: 0 }
    }));
  } catch (_) {
    return [];
  }
}

// ── Public API Methods ─────────────────────────────────────────────────────

// Check IP geolocation and VT scan
export async function lookupIpGeo(query: string): Promise<NormalizedIp & { vtAvailable: boolean }> {
  const clean = query.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  if (!clean) throw new ApiError('Invalid input.', 400);

  const isIp = isValidIp(clean);

  // Call geo-ip proxy
  const res = await fetch(`/geo-ip/${encodeURIComponent(clean)}`);
  if (!res.ok) throw new ApiError('Failed to fetch geolocation data.', res.status);
  const geo = await res.json();

  if (geo.status === 'fail') {
    throw new ApiError(geo.message || 'Lookup failed. Try a plain IP address like 8.8.8.8.', 400);
  }

  // VirusTotal scan results
  const endpoint = isIp ? `/ip_addresses/${encodeURIComponent(geo.query || clean)}` : `/domains/${encodeURIComponent(clean)}`;
  const vtData = await vtFetch<any>(endpoint);
  
  // Fetch relations and comments concurrently
  const [relations, comments] = await Promise.all([
    fetchEntityRelations(isIp ? 'ip_addresses' : 'domains', geo.query || clean),
    fetchComments(isIp ? 'ip_addresses' : 'domains', geo.query || clean)
  ]);

  const vtAvailable = true;
  const normalized = isIp ? normalizeIpData(vtData, geo) : (normalizeDomainData(vtData) as any);
  normalized.relations = relations;
  normalized.comments = comments;

  if (vtData?.data?.attributes?.last_dns_records) {
    normalized.dnsRecords = parseDnsRecords(vtData.data.attributes.last_dns_records);
  }

  return { ...normalized, vtAvailable } as any;
}

// Convert a URL to VirusTotal base64url identifier
export function urlToBase64Id(url: string): string {
  const normalized = normalizeUrlForScan(url);
  try {
    return btoa(unescape(encodeURIComponent(normalized)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  } catch (_) {
    return btoa(normalized).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
}

// Fetch direct cached report for a URL via VirusTotal API
export async function getUrlReport(urlOrId: string): Promise<NormalizedAnalysis> {
  const isPlainUrl = urlOrId.startsWith('http') || (urlOrId.includes('.') && !urlOrId.startsWith('u-'));
  const id = isPlainUrl ? urlToBase64Id(urlOrId) : urlOrId;
  const raw = await vtFetch<any>(`/urls/${id}`);
  const normalized = normalizeAnalysis(raw);

  // Fetch relations and comments concurrently
  try {
    const [relations, comments] = await Promise.all([
      fetchEntityRelations('urls', id),
      fetchComments('urls', id)
    ]);
    normalized.relations = relations;
    normalized.comments = comments;
  } catch (_) {}

  return normalized;
}

// Submit a URL for scanning
export async function scanUrl(url: string): Promise<{ data: { id: string } }> {
  const normalized = normalizeUrlForScan(url);
  const form = new URLSearchParams();
  form.append('url', normalized);
  return vtFetch<{ data: { id: string } }>('/urls', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form.toString()
  });
}

// Submit a file for scanning
export async function scanFile(file: File): Promise<{ data: { id: string } }> {
  if (file.size > 32 * 1024 * 1024) {
    throw new ApiError('File exceeds 32MB limit for the public API.', 413);
  }
  const form = new FormData();
  form.append('file', file, file.name);
  return vtFetch<{ data: { id: string } }>('/files', { method: 'POST', body: form });
}

// Poll analysis progress with fast responsive intervals
export async function pollAnalysis(
  analysisId: string,
  onProgress?: (data: NormalizedAnalysis) => void
): Promise<NormalizedAnalysis> {
  let attempts = 0;
  const maxAttempts = 10;
  const interval = 2500; // 2.5s responsive polling

  let latestData: NormalizedAnalysis | null = null;

  while (attempts < maxAttempts) {
    attempts++;

    try {
      const res = await vtFetch<any>(`/analyses/${analysisId}`);
      const status = res?.data?.attributes?.status || 'queued';
      const normalizedData = normalizeAnalysis(res);
      latestData = normalizedData;

      if (onProgress) {
        onProgress(normalizedData);
      }

      if (status === 'completed') {
        // Fetch comments concurrently if URL / File
        if (normalizedData.hash) {
          try {
            const comments = await fetchComments('files', normalizedData.hash);
            normalizedData.comments = comments;
          } catch (_) {}
        }
        return normalizedData;
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) {
        await new Promise((resolve) => setTimeout(resolve, 3000));
        continue;
      }
      if (latestData) return latestData;
      throw err;
    }

    await new Promise((resolve) => setTimeout(resolve, interval));
  }

  if (latestData) {
    return latestData;
  }

  throw new ApiError('Analysis is queued in the global pipeline. Results will update shortly.', 408);
}

// Lookup hashes directly
export async function lookupHash(hash: string): Promise<NormalizedFile> {
  const clean = hash.trim().toLowerCase();
  if (!isValidHash(clean)) {
    throw new ApiError('Invalid hash format. Must be MD5, SHA1 or SHA256.', 400);
  }
  const raw = await vtFetch<any>(`/files/${clean}`);
  const normalized = normalizeFileData(raw);

  // Fetch relations and comments concurrently
  const [relations, comments] = await Promise.all([
    fetchEntityRelations('files', clean),
    fetchComments('files', clean)
  ]);

  normalized.relations = relations;
  normalized.comments = comments;

  return normalized;
}

// Lookup domains directly
export async function lookupDomain(domain: string): Promise<NormalizedDomain> {
  const clean = domain.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  if (!clean) throw new ApiError('Invalid domain format.', 400);
  const raw = await vtFetch<any>(`/domains/${encodeURIComponent(clean)}`);
  
  const [relations, comments] = await Promise.all([
    fetchEntityRelations('domains', clean),
    fetchComments('domains', clean)
  ]);

  const normalized = normalizeDomainData(raw);
  normalized.relations = relations;
  normalized.comments = comments;

  if (raw?.data?.attributes?.last_dns_records) {
    normalized.dnsRecords = parseDnsRecords(raw.data.attributes.last_dns_records);
  }

  return normalized;
}

// ── Validation Helpers ──────────────────────────────────────────────────────
export function isValidHash(hash: string): boolean {
  const clean = hash.trim();
  return /^[0-9a-fA-F]{32}$/.test(clean) ||
         /^[0-9a-fA-F]{40}$/.test(clean) ||
         /^[0-9a-fA-F]{64}$/.test(clean);
}

export function isValidIp(ip: string): boolean {
  const clean = ip.trim();
  const v4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(clean) &&
    clean.split('.').every(n => parseInt(n) <= 255);
  const v6 = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/.test(clean);
  return v4 || v6;
}

export function detectInputType(input: string): 'hash' | 'ip' | 'domain' | 'url' | 'unknown' {
  const clean = sanitizeUrl(input).toLowerCase();
  if (!clean) return 'unknown';
  if (isValidHash(clean)) return 'hash';
  if (isValidIp(clean)) return 'ip';

  // Explicit protocol or path / parameters -> URL
  if (/^https?:\/\//i.test(clean) || clean.includes('/') || clean.includes('?')) {
    return 'url';
  }

  // Pure domain (e.g. google.com, luckyverse.tech)
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(clean)) {
    return 'domain';
  }

  return 'unknown';
}

function parseDnsRecords(records: any[]): DnsRecord[] {
  if (!Array.isArray(records)) return [];
  return records.map(r => ({
    type: r.type || 'A',
    value: r.value || r.target || r.rdata || JSON.stringify(r),
    ttl: r.ttl
  }));
}

function calcVerdictFromStats(stats: ScanStats): 'malicious' | 'suspicious' | 'clean' | 'unknown' {
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  if (malicious > 0) return 'malicious';
  if (suspicious > 0) return 'suspicious';
  return 'clean';
}

// ── Normalizers ─────────────────────────────────────────────────────────────
export function normalizeAnalysis(data: any): NormalizedAnalysis {
  const attrs = data?.data?.attributes || {};
  const stats = attrs.stats || {};
  const results = attrs.results || {};

  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const harmless = stats.harmless || 0;
  const undetected = stats.undetected || 0;
  const total = malicious + suspicious + harmless + undetected;

  const threatScore = total > 0 ? Math.round(((malicious + suspicious) / total) * 100) : 0;
  const verdict = malicious > 0
    ? 'malicious'
    : suspicious > 0
    ? 'suspicious'
    : 'clean';

  const engines = Object.entries(results).map(([engine, res]: [string, any]) => ({
    engine,
    category: res.category,
    result: res.result || null,
    method: res.method,
    detected: res.category === 'malicious' || res.category === 'suspicious',
  }));

  const extended: ExtendedDetails = {
    categories: attrs.categories || {},
    history: {
      firstSubmission: attrs.first_submission_date,
      lastSubmission: attrs.last_submission_date,
      lastAnalysis: attrs.last_analysis_date || attrs.date,
    },
    redirectionChain: attrs.redirection_chain ? attrs.redirection_chain.map((r: any) => typeof r === 'string' ? r : r.url || r.final_url || '') : undefined,
    httpResponse: attrs.last_http_response_code ? {
      finalUrl: attrs.last_final_url,
      servingIp: attrs.last_http_response_serving_ip,
      statusCode: attrs.last_http_response_code,
      bodyLength: attrs.last_http_response_content_length,
      headers: attrs.last_http_response_headers,
    } : undefined,
    htmlInfo: (attrs.title || attrs.html_meta) ? {
      title: attrs.title,
      meta: attrs.html_meta
    } : undefined,
    favicon: attrs.favicon,
    outgoingLinks: attrs.outgoing_links,
    javascriptVariables: attrs.javascript_variables,
    networkRequests: attrs.network_requests || attrs.last_http_response_requests,
  };

  return {
    id: data?.data?.id || '',
    status: attrs.status || 'completed',
    date: attrs.date || null,
    threatScore,
    verdict,
    stats: { malicious, suspicious, harmless, undetected, total },
    engines,
    url: attrs.url || data?.meta?.url_info?.url,
    // Robust extraction across all VirusTotal response topologies
    hash: data?.meta?.file_info?.sha256
      || data?.data?.meta?.file_info?.sha256
      || attrs.sha256
      || data?.data?.attributes?.sha256
      || data?.meta?.file_info?.md5
      || data?.meta?.file_info?.sha1
      || (data?.data?.links?.item ? data.data.links.item.split('/').pop() : undefined),
    fileName: data?.meta?.file_info?.name || attrs.meaningful_name || (attrs.names ? attrs.names[0] : undefined),
    fileSize: data?.meta?.file_info?.size || attrs.size,
    extended
  };
}

export function normalizeFileData(data: any): NormalizedFile {
  const id = data?.data?.id || '';
  const attrs = data?.data?.attributes || {};
  const stats = attrs.last_analysis_stats || {};
  const results = attrs.last_analysis_results || {};

  const engines = Object.entries(results).map(([engine, res]: [string, any]) => ({
    engine,
    category: res.category,
    result: res.result || null,
    detected: res.category === 'malicious' || res.category === 'suspicious',
  }));

  const extended: ExtendedDetails = {
    categories: attrs.categories || {},
    history: {
      firstSubmission: attrs.first_submission_date,
      lastSubmission: attrs.last_submission_date,
      lastAnalysis: attrs.last_analysis_date,
    },
    ssdeep: attrs.ssdeep,
    tlsh: attrs.tlsh,
    vhash: attrs.vhash,
    magika: attrs.magika,
    crowdsourcedYara: attrs.crowdsourced_yara_results ? attrs.crowdsourced_yara_results.map((y: any) => ({
      rule_name: y.rule_name || y.ruleset_name || 'Generic_Rule',
      ruleset_name: y.ruleset_name,
      author: y.author,
      description: y.description,
      source: y.source,
      match_data: y.match_data,
    })) : undefined,
    sigmaAnalysis: attrs.sigma_analysis_results,
    magic: attrs.magic,
    trid: attrs.trid,
    exiftool: attrs.exiftool,
    signatureInfo: attrs.signature_info,
    peInfo: attrs.pe_info,
    packers: attrs.packers,
    mitreAttack: attrs.mitre_attack_techniques ? attrs.mitre_attack_techniques.map((m: any) => ({
      id: m.id || m.technique_id,
      signature_description: m.signature_description || m.technique_name,
      tactic: m.tactic || m.tactic_name
    })) : undefined,
    pdfInfo: attrs.pdf_info,
    officeInfo: attrs.office_info || attrs.vba_info,
    bundleInfo: attrs.bundle_info || attrs.archive_info || attrs.zip_info
  };

  return {
    id,
    sha256: attrs.sha256 || '',
    sha1: attrs.sha1 || '',
    md5: attrs.md5 || '',
    name: (attrs.names || [])[0] || attrs.meaningful_name || 'Unknown File',
    names: attrs.names || [],
    size: attrs.size || 0,
    type: attrs.type_description || 'Unknown Type',
    mimeType: attrs.type_tag || '',
    firstSeen: attrs.first_submission_date || 0,
    lastSeen: attrs.last_analysis_date || 0,
    timesSubmitted: attrs.times_submitted || 0,
    verdict: calcVerdictFromStats(stats),
    stats,
    tags: attrs.tags || [],
    engines,
    extended
  };
}

export function normalizeIpData(data: any, geo: any): NormalizedIp {
  const id = data?.data?.id || geo.query || '';
  const attrs = data?.data?.attributes || {};
  const stats = attrs.last_analysis_stats || {};
  const results = attrs.last_analysis_results || {};

  const engines = Object.entries(results).map(([engine, res]: [string, any]) => ({
    engine,
    category: res.category,
    result: res.result || null,
    detected: res.category === 'malicious' || res.category === 'suspicious',
  }));

  const asnMatch = (geo.as || '').match(/AS(\d+)/i);
  const asn = asnMatch ? parseInt(asnMatch[1]) : null;

  return {
    id,
    ip: id,
    asn,
    asOwner: geo.org || geo.isp || geo.as || '—',
    country: geo.countryCode || '—',
    network: geo.as ? geo.as.split(' ')[0] : '—',
    verdict: calcVerdictFromStats(stats),
    stats,
    reputation: attrs.reputation || 0,
    tags: attrs.tags || [],
    engines,
    lastSeen: attrs.last_analysis_date || 0
  };
}

export function normalizeDomainData(data: any): NormalizedDomain {
  const id = data?.data?.id || '';
  const attrs = data?.data?.attributes || {};
  const stats = attrs.last_analysis_stats || {};
  const results = attrs.last_analysis_results || {};

  const engines = Object.entries(results).map(([engine, res]: [string, any]) => ({
    engine,
    category: res.category,
    result: res.result || null,
    detected: res.category === 'malicious' || res.category === 'suspicious',
  }));

  return {
    id,
    domain: id,
    registrar: attrs.registrar || '—',
    creation: attrs.creation_date || 0,
    expiration: attrs.expiration_date || 0,
    reputation: attrs.reputation || 0,
    verdict: calcVerdictFromStats(stats),
    stats,
    tags: attrs.tags || [],
    categories: attrs.categories || {},
    engines,
    lastSeen: attrs.last_analysis_date || 0
  };
}
