/**
 * sanitize.ts — ThreatAtlas Input Sanitization & URL Normalization Engine
 * Handles XSS filtering, control character removal, lowercase domain normalization,
 * and automatic HTTP / HTTPS protocol detection for bare domains.
 */

const MAX_INPUT_LENGTH = 2048;

/**
 * Sanitizes a generic text input (strips script injection, HTML tags, control chars).
 */
export function sanitizeInput(input: string): string {
  if (typeof input !== 'string') return '';
  return input
    .trim()
    .slice(0, MAX_INPUT_LENGTH)
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<[^>]*>/g, '')
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '');
}

/**
 * Sanitizes a URL / domain input:
 * - Strips script tags, HTML tags, control chars, null bytes
 * - Blocks dangerous schemes (javascript:, data:, vbscript:)
 */
export function sanitizeUrl(input: string): string {
  if (typeof input !== 'string') return '';
  let clean = input.trim().slice(0, MAX_INPUT_LENGTH);
  clean = clean.replace(/<script[\s\S]*?<\/script>/gi, '');
  clean = clean.replace(/<[^>]*>/g, '');
  clean = clean.replace(/^(javascript|data|vbscript):/i, '');
  clean = clean.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '');
  return clean;
}

/**
 * Normalizes a URL / domain input for scanning:
 * - Sanitizes raw input
 * - Lowercases domain name
 * - Auto-detects HTTP vs HTTPS:
 *   - If explicit http:// or https:// is provided, preserves and normalizes scheme.
 *   - If user typed a bare domain (e.g. "google.com", "luckyverse.tech", "phishing.test/login"), automatically attaches "https://".
 */
export function normalizeUrlForScan(input: string): string {
  const sanitized = sanitizeUrl(input);
  if (!sanitized) return '';

  // Case 1: Explicit http:// or https://
  const protocolMatch = sanitized.match(/^(https?:\/\/)(.*)$/i);
  if (protocolMatch) {
    const protocol = protocolMatch[1].toLowerCase();
    const rest = protocolMatch[2];
    // Split into host and path/query
    const slashIdx = rest.indexOf('/');
    if (slashIdx === -1) {
      return `${protocol}${rest.toLowerCase()}`;
    }
    const host = rest.substring(0, slashIdx).toLowerCase();
    const path = rest.substring(slashIdx);
    return `${protocol}${host}${path}`;
  }

  // Case 2: Bare domain or domain with path (e.g. google.com or luckyverse.tech/about)
  const slashIdx = sanitized.indexOf('/');
  if (slashIdx === -1) {
    return `https://${sanitized.toLowerCase()}`;
  }
  const host = sanitized.substring(0, slashIdx).toLowerCase();
  const path = sanitized.substring(slashIdx);
  return `https://${host}${path}`;
}

/**
 * Detects if an organization / ISP / ASN name belongs to a Telecom, Mobile Carrier, or Residential Broadband provider.
 * (e.g. Jio, Vi / Vodafone Idea, Airtel, BSNL, AT&T, Verizon, T-Mobile, Comcast, Orange, etc.)
 * When true, website-specific heuristic scans (PhishGuard/WebFox HTML crawler) are bypassed.
 */
export function isTelecomCarrier(orgOrIsp?: string, asOwner?: string): boolean {
  if (!orgOrIsp && !asOwner) return false;
  const combined = `${orgOrIsp || ''} ${asOwner || ''}`.toLowerCase();

  const telecomKeywords = [
    'jio', 'reliance jio', 'infocomm',
    'vodafone', 'vi ', 'idea cellular', 'vodafone idea',
    'airtel', 'bharti airtel', 'bharti',
    'bsnl', 'bharat sanchar', 'mtnl', 'mahanagar telephone',
    'tata teleservices', 'tata communications', 'act fibernet', 'hathway', 'you broadband',
    'verizon', 'at&t', 'att wireless', 't-mobile', 'tmobile', 'sprint',
    'comcast', 'xfinity', 'charter', 'spectrum', 'cox communications',
    'centurylink', 'lumen', 'frontier communications',
    'orange', 'deutsche telekom', 'telekom', 'telefonica', 'o2 ', 'ee limited', 'bt group', 'british telecom',
    'telecom italia', 'tim brasil', 'singtel', 'telstra', 'optus', 'starhub',
    'ntt docomo', 'softbank', 'kddi', 'china mobile', 'china telecom', 'china unicom',
    'claro', 'movistar', 'rogers', 'bell canada', 'telus', 'shaw',
    'mtn', 'etisalat', 'stc', 'saudi telecom', 'ooredoo', 'zain', 'telecom'
  ];

  return telecomKeywords.some(k => combined.includes(k));
}

/**
 * Formats a Unix timestamp (in seconds or ms) or ISO string into a human-readable relative time (e.g., "16 days ago", "2 hours ago", "just now").
 */
export function formatRelativeTime(timestamp?: number | string | null): string {
  if (!timestamp) return 'N/A';
  let dateMs: number;
  if (typeof timestamp === 'string') {
    dateMs = new Date(timestamp).getTime();
  } else {
    // If timestamp is in Unix seconds (< 100 billion), convert to ms
    dateMs = timestamp < 100000000000 ? timestamp * 1000 : timestamp;
  }

  if (isNaN(dateMs) || dateMs <= 0) return 'N/A';

  const diffMs = Date.now() - dateMs;
  if (diffMs < 0) return 'just now';

  const sec = Math.floor(diffMs / 1000);
  if (sec < 60) return `${sec}s ago`;

  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;

  const hours = Math.floor(min / 60);
  if (hours < 24) return `${hours} hour${hours > 1 ? 's' : ''} ago`;

  const days = Math.floor(hours / 24);
  if (days < 30) return `${days} day${days > 1 ? 's' : ''} ago`;

  const months = Math.floor(days / 30);
  if (months < 12) return `${months} month${months > 1 ? 's' : ''} ago`;

  const years = Math.floor(days / 365);
  return `${years} year${years > 1 ? 's' : ''} ago`;
}

/**
 * Formats byte size into human-readable string with byte count, e.g. "17.08 KB (17496 bytes)"
 */
export function formatBytes(bytes?: number): string {
  if (bytes === undefined || bytes === null || isNaN(bytes)) return '0 B';
  if (bytes === 0) return '0 B (0 bytes)';

  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  const formatted = (bytes / Math.pow(1024, i)).toFixed(2);
  const unit = units[i] || 'B';

  return `${formatted} ${unit} (${bytes.toLocaleString()} bytes)`;
}

