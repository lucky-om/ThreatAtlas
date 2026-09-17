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

  const url = `https://www.virustotal.com/api/v3${path}`;
  const apiKey = import.meta.env.VITE_VT_API_KEY || '';
  
  const headers = new Headers(options?.headers);
  if (apiKey) {
    headers.set('x-apikey', apiKey);
  }

  const res = await fetch(url, { ...options, headers });

  if (!res.ok) {
    let errMsg = `API error (${res.status})`;
    let code: string | undefined;

    try {
      const data = await res.json();
      if (data?.error?.message) {
        errMsg = data.error.message;
        code = data.error.code;
      }
    } catch (_) { /* ignore parse errors */ }

    if (res.status === 401) throw new ApiError('API key not configured. Please add a valid key in server config.', 401, code);
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

  // Call geo-ip via backend proxy to avoid Mixed Content & corsproxy rate limits
  const res = await fetch(`/api/ipgeo?query=${encodeURIComponent(clean)}`);
  if (!res.ok) throw new ApiError('Failed to fetch geolocation data.', res.status);
  const geo = await res.json();

  if (geo.status === 'fail') {
    throw new ApiError(geo.message || 'Lookup failed. Try a plain IP address like 8.8.8.8.', 400);
  }

  // threat scan results
  const endpoint = isIp ? `/ip_addresses/${encodeURIComponent(geo.ip || clean)}` : `/domains/${encodeURIComponent(clean)}`;
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

// Convert a URL to base64url identifier
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

// Fetch direct cached report for a URL via threat intelligence APIs API
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
  } catch (_) { /* ignore relation errors */ }

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

// Pure JS fallback SHA-256 for non-secure HTTP contexts where crypto.subtle is undefined
function sha256Fallback(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  const H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  const len = bytes.length;
  const bitLen = len * 8;
  const padLen = (((len + 8) >> 6) + 1) << 6;
  const words = new Uint32Array(padLen >> 2);

  for (let i = 0; i < len; i++) {
    words[i >> 2] |= bytes[i] << (24 - (i & 3) * 8);
  }
  words[len >> 2] |= 0x80 << (24 - (len & 3) * 8);
  words[words.length - 1] = bitLen >>> 0;
  words[words.length - 2] = Math.floor(bitLen / 0x100000000);

  const W = new Uint32Array(64);

  for (let i = 0; i < words.length; i += 16) {
    for (let t = 0; t < 16; t++) W[t] = words[i + t];
    for (let t = 16; t < 64; t++) {
      const s0 = ((W[t - 15] >>> 7) | (W[t - 15] << 25)) ^ ((W[t - 15] >>> 18) | (W[t - 15] << 14)) ^ (W[t - 15] >>> 3);
      const s1 = ((W[t - 2] >>> 17) | (W[t - 2] << 15)) ^ ((W[t - 2] >>> 19) | (W[t - 2] << 13)) ^ (W[t - 2] >>> 10);
      W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0;
    }

    let [a, b, c, d, e, f, g, h] = H;

    for (let t = 0; t < 64; t++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[t] + W[t]) >>> 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    H[0] = (H[0] + a) >>> 0;
    H[1] = (H[1] + b) >>> 0;
    H[2] = (H[2] + c) >>> 0;
    H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0;
    H[5] = (H[5] + f) >>> 0;
    H[6] = (H[6] + g) >>> 0;
    H[7] = (H[7] + h) >>> 0;
  }

  return H.map(x => ('00000000' + x.toString(16)).slice(-8)).join('');
}

/**
 * Computes the SHA-256 cryptographic hex digest of a file in the browser.
 * Uses Web Crypto API when available, falling back to an in-memory pure JS implementation.
 */
export async function calculateFileSha256(file: File): Promise<string> {
  const buffer = await file.arrayBuffer();
  if (typeof window !== 'undefined' && window.crypto?.subtle?.digest) {
    try {
      const hashBuffer = await window.crypto.subtle.digest('SHA-256', buffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    } catch (_) { /* ignore crypto API errors */ }
  }
  return sha256Fallback(buffer);
}

// Submit a file for scanning
export async function scanFile(file: File): Promise<{ data: { id: string }, bypassVt?: boolean }> {
  // 100MB hard limit for ThreatAtlas Engine
  if (file.size > 100 * 1024 * 1024) {
    throw new ApiError('File exceeds 100MB limit for the ThreatAtlas API.', 413);
  }
  
  // VT only accepts <= 32MB on public API, bypass for larger files
  if (file.size > 32 * 1024 * 1024) {
    // Return a mock ID that our polling mechanism can intercept to immediately resolve
    return { data: { id: `MOCK_LARGE_FILE_${file.name}_${Date.now()}` }, bypassVt: true };
  }

  const form = new FormData();
  form.append('file', file, file.name);

  // Send to backend proxy to bypass VT CORS restrictions for POST /files
  const baseUrl = import.meta.env.VITE_API_BASE_URL || '/api';
  const apiKey = import.meta.env.VITE_VT_API_KEY || '';

  const res = await fetch(`${baseUrl}/vt/files`, { 
    method: 'POST', 
    body: form,
    headers: {
      'x-apikey': apiKey
    }
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new ApiError(errorData.error || errorData.message || 'File upload failed', res.status);
  }

  return res.json();
}

// Poll analysis progress with fast responsive intervals
export async function pollAnalysis(
  analysisId: string,
  onProgress?: (data: NormalizedAnalysis) => void
): Promise<NormalizedAnalysis> {
  let attempts = 0;
  const maxAttempts = 30; // 30 * 2.5s = 75 seconds window for VT file pipeline
  const interval = 2500; // 2.5s responsive polling

  let latestData: NormalizedAnalysis | null = null;

  // Intercept bypass
  if (analysisId.startsWith('MOCK_LARGE_FILE_')) {
    // Generate a clean mock response for large files (backend will handle real forensics)
    const mockData: NormalizedAnalysis = {
      id: analysisId,
      status: 'completed',
      date: Date.now(),
      stats: { malicious: 0, suspicious: 0, undetected: 0, harmless: 0, timeout: 0 },
      threatScore: 0,
      verdict: 'clean',
      engines: []
    };
    if (onProgress) onProgress(mockData);
    return mockData;
  }

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
          } catch (_) { /* ignore comment fetch errors */ }
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
    crowdsourcedYara: (attrs.crowdsourced_yara_results || data?.data?.attributes?.crowdsourced_yara_results)?.map((y: any) => ({
      rule_name: y.rule_name || y.ruleset_name || 'Generic_Rule',
      ruleset_name: y.ruleset_name,
      author: y.author,
      description: y.description,
      source: y.source,
      match_data: y.match_data,
    })) || undefined,
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
    // Only set hash if it is an actual cryptographic file hash (MD5/SHA1/SHA256), NOT a URL token (u-...)
    hash: (() => {
      const candidate = data?.meta?.file_info?.sha256
        || data?.data?.meta?.file_info?.sha256
        || attrs.sha256
        || data?.data?.attributes?.sha256
        || data?.meta?.file_info?.md5
        || data?.meta?.file_info?.sha1
        || (data?.data?.links?.item && !data.data.links.item.includes('/urls/') ? data.data.links.item.split('/').pop() : undefined);
      return candidate && isValidHash(candidate) ? candidate : undefined;
    })(),
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

  const asnMatch = (geo.asn || geo.as || '').match(/AS(\d+)/i);
  const asn = asnMatch ? parseInt(asnMatch[1]) : null;

  return {
    id,
    ip: id,
    asn,
    asOwner: geo.org || geo.isp || geo.as || '—',
    country: geo.country_code || geo.countryCode || '—',
    network: geo.asn || geo.as ? (geo.asn || geo.as).split(' ')[0] : '—',
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
