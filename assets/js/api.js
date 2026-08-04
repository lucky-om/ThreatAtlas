/**
 * ThreatAtlas — VirusTotal API Client
 * threatatlas.luckyverse.tech
 *
 * This file provides the client-side API abstraction layer.
 * To avoid browser CORS restrictions, it routes all API requests
 * through the local Express server proxy (at /api).
 * Geolocation requests are routed through the local /geo-ip proxy.
 */

// ── Config ─────────────────────────────────────────────────────────────────
const VT_BASE = '/api';

// Rate limiting settings (public key = 4 req/min, 500/day)
const RATE = {
  queue:       [],
  maxPerMin:   4,
  tokens:      4,
  lastRefill:  Date.now(),
  pollInterval: 4000, // ms between polling
  maxPolls:    15,
};

// ── Rate Limiter ────────────────────────────────────────────────────────────
function refillTokens() {
  const now  = Date.now();
  const diff = (now - RATE.lastRefill) / 60000;
  const add  = Math.floor(diff * RATE.maxPerMin);
  if (add > 0) {
    RATE.tokens    = Math.min(RATE.maxPerMin, RATE.tokens + add);
    RATE.lastRefill = now;
  }
}

async function withRateLimit(fn) {
  refillTokens();
  if (RATE.tokens <= 0) {
    const wait = Math.ceil((60000 - (Date.now() - RATE.lastRefill)) / 1000);
    throw new ApiError(`Rate limit reached. Please wait ${wait}s before retrying.`, 429);
  }
  RATE.tokens--;
  return fn();
}

// ── Error Class ─────────────────────────────────────────────────────────────
class ApiError extends Error {
  constructor(message, status = 0, code = '') {
    super(message);
    this.name   = 'ApiError';
    this.status = status;
    this.code   = code;
  }
}

// ── Core Fetch Wrapper ──────────────────────────────────────────────────────
async function vtFetch(endpoint, options = {}) {
  const url = `${VT_BASE}${endpoint}`;
  const headers = {
    ...options.headers,
  };

  if (!(options.body instanceof FormData)) {
    headers['Accept'] = 'application/json';
  }

  const res = await fetch(url, { ...options, headers });

  if (!res.ok) {
    let errMsg = `HTTP ${res.status}`;
    let code   = '';
    try {
      const json = await res.json();
      errMsg = json?.error?.message || errMsg;
      code   = json?.error?.code || '';
    } catch (_) {}

    if (res.status === 401) throw new ApiError('Invalid API key or Unauthorized. Please check your config.', 401, code);
    if (res.status === 404) throw new ApiError('Resource not found in the database.', 404, code);
    if (res.status === 429) throw new ApiError('API rate limit exceeded. Please wait a minute.', 429, code);
    if (res.status === 400) throw new ApiError('Bad request: ' + errMsg, 400, code);

    throw new ApiError(errMsg, res.status, code);
  }

  const contentType = res.headers.get('content-type') || '';
  if (contentType.includes('application/json')) return res.json();
  return res.text();
}

// ── Analysis Poller ─────────────────────────────────────────────────────────
async function pollAnalysis(analysisId, onProgress) {
  let attempts = 0;

  while (attempts < RATE.maxPolls) {
    await sleep(RATE.pollInterval);
    attempts++;

    let data;
    try {
      data = await withRateLimit(() => vtFetch(`/analyses/${analysisId}`));
    } catch (e) {
      if (e.status === 429) {
        await sleep(15000);
        continue;
      }
      throw e;
    }

    const status = data?.data?.attributes?.status;
    if (onProgress) onProgress({ status, attempt: attempts, maxAttempts: RATE.maxPolls });

    if (status === 'completed') return data;
    if (status === 'queued' || status === 'in-progress') continue;

    return data;
  }

  throw new ApiError('Analysis timed out. The request may still be queued — try searching the hash directly.', 408);
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ── Public API Functions ────────────────────────────────────────────────────

/**
 * Scan a URL for threats.
 */
async function scanUrl(url) {
  return withRateLimit(async () => {
    const form = new FormData();
    form.append('url', url);
    return vtFetch('/urls', { method: 'POST', body: form });
  });
}

/**
 * Scan a file for threats.
 */
async function scanFile(file) {
  if (file.size > 32 * 1024 * 1024) {
    throw new ApiError('File exceeds 32MB limit for the public API.', 413);
  }

  return withRateLimit(async () => {
    const form = new FormData();
    form.append('file', file, file.name);
    return vtFetch('/files', { method: 'POST', body: form });
  });
}

/**
 * Get analysis result by analysis ID.
 */
async function getAnalysis(analysisId, onProgress) {
  return pollAnalysis(analysisId, onProgress);
}

/**
 * Look up a file by hash (SHA256, SHA1, or MD5).
 */
async function lookupHash(hash) {
  const clean = hash.trim().toLowerCase();
  if (!isValidHash(clean)) {
    throw new ApiError('Invalid hash format. Supported: SHA256, SHA1, MD5.', 400);
  }
  return withRateLimit(() => vtFetch(`/files/${clean}`));
}

/**
 * Look up an IP address using ip-api.com via local Express proxy.
 */
async function lookupIp(ip) {
  const clean = ip.trim();
  if (!isValidIp(clean)) {
    throw new ApiError('Invalid IP address format.', 400);
  }

  // Fetch geolocation data from local geo-ip proxy (connecting to ip-api.com)
  const res = await fetch(`/geo-ip/${encodeURIComponent(clean)}`);
  if (!res.ok) {
    throw new ApiError('Failed to fetch geolocation data.', res.status);
  }
  const geo = await res.json();

  if (geo.status === 'fail') {
    throw new ApiError(geo.message || 'IP lookup failed.', 400);
  }

  // For threat scanner part on IP lookup, fetch analysis from VirusTotal
  let vtData = {};
  try {
    vtData = await withRateLimit(() => vtFetch(`/ip_addresses/${encodeURIComponent(clean)}`));
  } catch (err) {
    console.warn('[ThreatAtlas API] VirusTotal IP scanning failed. Overlaying geo data only.', err);
    // If VirusTotal returns error (like 401 Unauthorized for bad API Key), we still return the geo data
    // with empty threat stats so the page works.
    vtData = {
      data: {
        id: clean,
        attributes: {
          last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 },
          last_analysis_results: {}
        }
      }
    };
  }

  // Merge ip-api.com geolocation data with VirusTotal scan results
  const asnMatch = (geo.as || '').match(/AS(\d+)/i);
  const asn = asnMatch ? parseInt(asnMatch[1]) : null;

  const merged = {
    data: {
      id: clean,
      type: 'ip_address',
      attributes: {
        asn: asn,
        as_owner: geo.org || geo.isp || geo.as || '—',
        country: geo.countryCode || '—',
        continent: '—',
        network: geo.as ? geo.as.split(' ')[0] : '—',
        last_analysis_stats: vtData?.data?.attributes?.last_analysis_stats || { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 },
        last_analysis_results: vtData?.data?.attributes?.last_analysis_results || {},
        reputation: vtData?.data?.attributes?.reputation || 0,
        tags: vtData?.data?.attributes?.tags || [],
        last_analysis_date: vtData?.data?.attributes?.last_analysis_date || Math.floor(Date.now() / 1000)
      }
    }
  };

  return merged;
}

/**
 * Look up a domain.
 */
async function lookupDomain(domain) {
  const clean = domain.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  if (!clean) throw new ApiError('Invalid domain format.', 400);
  return withRateLimit(() => vtFetch(`/domains/${encodeURIComponent(clean)}`));
}

/**
 * Look up a URL by its VT identifier (base64url of the URL).
 */
async function lookupUrl(url) {
  const id = btoa(url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return withRateLimit(() => vtFetch(`/urls/${id}`));
}

/**
 * Get URL analysis.
 */
async function getUrlAnalysis(analysisId, onProgress) {
  return pollAnalysis(analysisId, onProgress);
}

// ── Validation Helpers ──────────────────────────────────────────────────────
function isValidHash(hash) {
  return /^[0-9a-f]{32}$/.test(hash) ||
         /^[0-9a-f]{40}$/.test(hash) ||
         /^[0-9a-f]{64}$/.test(hash);
}

function isValidIp(ip) {
  const v4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) &&
    ip.split('.').every(n => parseInt(n) <= 255);
  const v6 = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/.test(ip);
  return v4 || v6;
}

function detectInputType(input) {
  const clean = input.trim();

  if (isValidHash(clean)) return 'hash';
  if (isValidIp(clean)) return 'ip';

  try {
    const url = new URL(clean.startsWith('http') ? clean : `https://${clean}`);
    if (url.pathname !== '/' || clean.includes('/')) return 'url';
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(clean)) return 'domain';
    return 'url';
  } catch (_) {}

  return 'unknown';
}

// ── Data Normalizers ────────────────────────────────────────────────────────
function normalizeAnalysis(data) {
  const attrs  = data?.data?.attributes || {};
  const stats  = attrs.stats || {};
  const results = attrs.results || {};

  const malicious   = stats.malicious   || 0;
  const suspicious  = stats.suspicious  || 0;
  const harmless    = stats.harmless    || 0;
  const undetected  = stats.undetected  || 0;
  const total       = malicious + suspicious + harmless + undetected;

  const threatScore = total > 0 ? Math.round(((malicious + suspicious) / total) * 100) : 0;
  const verdict = malicious > 0
    ? 'malicious'
    : suspicious > 0
    ? 'suspicious'
    : total > 0
    ? 'clean'
    : 'unknown';

  const engines = Object.entries(results).map(([engine, res]) => ({
    engine,
    category:  res.category,
    result:    res.result,
    method:    res.method,
    detected:  res.category === 'malicious' || res.category === 'suspicious',
  }));

  return {
    id:          data?.data?.id,
    status:      attrs.status,
    date:        attrs.date,
    threatScore,
    verdict,
    stats: { malicious, suspicious, harmless, undetected, total },
    engines,
    meta: attrs.meta || {},
  };
}

function normalizeFileData(data) {
  const attrs = data?.data?.attributes || {};
  return {
    id:           data?.data?.id,
    sha256:       attrs.sha256,
    sha1:         attrs.sha1,
    md5:          attrs.md5,
    name:         (attrs.names || [])[0] || attrs.meaningful_name || 'Unknown',
    names:        attrs.names || [],
    size:         attrs.size,
    type:         attrs.type_description || attrs.magic || 'Unknown',
    mimeType:     attrs.type_tag,
    firstSeen:    attrs.first_submission_date,
    lastSeen:     attrs.last_analysis_date,
    timesSubmitted: attrs.times_submitted,
    verdict:      calcVerdictFromStats(attrs.last_analysis_stats),
    stats:        attrs.last_analysis_stats || {},
    tags:         attrs.tags || [],
    engines:      Object.entries(attrs.last_analysis_results || {}).map(([engine, res]) => ({
      engine,
      category: res.category,
      result:   res.result,
      detected: res.category === 'malicious' || res.category === 'suspicious',
    })),
  };
}

function normalizeIpData(data) {
  const attrs = data?.data?.attributes || {};
  return {
    id:         data?.data?.id,
    ip:         data?.data?.id,
    asn:        attrs.asn,
    asOwner:    attrs.as_owner,
    country:    attrs.country,
    network:    attrs.network,
    verdict:    calcVerdictFromStats(attrs.last_analysis_stats),
    stats:      attrs.last_analysis_stats || {},
    reputation: attrs.reputation,
    tags:       attrs.tags || [],
    engines:    Object.entries(attrs.last_analysis_results || {}).map(([engine, res]) => ({
      engine,
      category: res.category,
      result:   res.result,
      detected: res.category === 'malicious' || res.category === 'suspicious',
    })),
    lastSeen: attrs.last_analysis_date,
  };
}

function normalizeDomainData(data) {
  const attrs = data?.data?.attributes || {};
  return {
    id:         data?.data?.id,
    domain:     data?.data?.id,
    registrar:  attrs.registrar,
    creation:   attrs.creation_date,
    expiration: attrs.last_dns_records_date,
    reputation: attrs.reputation,
    verdict:    calcVerdictFromStats(attrs.last_analysis_stats),
    stats:      attrs.last_analysis_stats || {},
    tags:       attrs.tags || [],
    categories: attrs.categories || {},
    engines:    Object.entries(attrs.last_analysis_results || {}).map(([engine, res]) => ({
      engine,
      category: res.category,
      result:   res.result,
      detected: res.category === 'malicious' || res.category === 'suspicious',
    })),
    lastSeen: attrs.last_analysis_date,
  };
}

function calcVerdictFromStats(stats) {
  if (!stats) return 'unknown';
  if ((stats.malicious || 0) > 0) return 'malicious';
  if ((stats.suspicious || 0) > 0) return 'suspicious';
  if ((stats.harmless || 0) + (stats.undetected || 0) > 0) return 'clean';
  return 'unknown';
}

// ── Export (ES Module style for compatibility) ──────────────────────────────
window.ThreatAtlasAPI = {
  scanUrl,
  scanFile,
  getAnalysis,
  lookupHash,
  lookupIp,
  lookupDomain,
  lookupUrl,
  getUrlAnalysis,
  detectInputType,
  normalizeAnalysis,
  normalizeFileData,
  normalizeIpData,
  normalizeDomainData,
  ApiError,
  isValidHash,
  isValidIp,
};
