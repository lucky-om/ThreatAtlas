// ── PhishGuard Heuristic Engine v4.0.0 (Ported from lucky-om/PhishGuard) ──────────────

export interface PhishGuardFlag {
  type: 'critical' | 'warning' | 'info' | 'safe';
  message: string;
  category: string;
}

export interface PhishGuardResult {
  riskScore: number; // 0 - 10
  riskLevel: 'Critical' | 'High' | 'Medium' | 'Low' | 'Safe';
  flags: PhishGuardFlag[];
  decodedDetails: Array<{ label: string; value: string; danger?: boolean }>;
  entropy: number;
  isHomograph: boolean;
  impersonatedBrand: string | null;
  baseDomain: string;
  tld: string;
}

// ── Target Brand Impersonation Patterns ─────────────────────────────────────────
const BRANDS: Array<{ name: string; patterns: RegExp[] }> = [
  { name: 'Microsoft', patterns: [/rnicrosoft/, /micros0ft/, /mircosoft/, /microsoft-verify/, /ms-security/, /office-365-/, /login\.microsoft/i] },
  { name: 'Google', patterns: [/g00gle/, /google-verify/, /gmail-security/, /google-account-/, /g0ogle/, /gogle\./, /accounts\.google/i] },
  { name: 'Amazon', patterns: [/amazon-billing/, /amzn-/, /shopplng-amazon/, /amazon-update/, /arnazon/, /aws-billing/] },
  { name: 'Netflix', patterns: [/netfIix/, /netflix-billing/, /nfx-login/, /netflix-update/, /net-flix/] },
  { name: 'PayPal', patterns: [/paypa1/, /paypal-secure/, /paypal-update/, /paypal-billing/, /paypai/, /pay-pal/] },
  { name: 'Apple', patterns: [/apple-id-verify/, /icloud-security/, /apple-support-/, /appie\./, /app1e/, /appl3/] },
  { name: 'Facebook / Meta', patterns: [/faceb00k/, /facebook-security/, /fb-verify/, /meta-security/, /facebok/, /faceboook/] },
  { name: 'Instagram', patterns: [/lnstagram/, /instagrarn/, /instagram-verify/, /ig-security/] },
  { name: 'Twitter / X', patterns: [/twltter/, /twitter-verify/, /x-security-login/] },
  { name: 'Steam', patterns: [/stearncommunity/, /steamconmunity/, /steamcomnunity/, /steampowered-login/] },
  { name: 'Binance', patterns: [/blnance/, /binance-verify/, /binance-security/, /binance-wallet/] },
  { name: 'Coinbase', patterns: [/colnbase/, /coinbase-verify/, /coinbase-support/, /coinbase-wallet/] },
  { name: 'Chase Bank', patterns: [/chase-verify/, /chase-online-/, /chase-security/] },
  { name: 'Wells Fargo', patterns: [/wellsfargo-verify/, /wells-security/] },
  { name: 'Bank of America', patterns: [/bofa-verify/, /bankofamerica-login/] },
  { name: 'Telegram', patterns: [/telegraam/, /telegram-web-login/, /t-me-login/] },
  { name: 'Discord', patterns: [/dlscord/, /discord-nitro-gift/, /discord-app-gift/, /discorcl/] },
];

// ── Suspicious High-Risk TLDs ──────────────────────────────────────────────────
const SUSPICIOUS_TLDS = [
  'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'club', 'work', 'click',
  'link', 'sur', 'tokyo', 'space', 'site', 'loan', 'buzz', 'fit', 'rest',
  'shop', 'surf', 'support', 'live', 'download', 'stream', 'racing',
  'win', 'bid', 'review', 'country', 'kim', 'science', 'party', 'trade', 'date'
];

// ── Suspicious Keyword List ───────────────────────────────────────────────────
const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'sign-in', 'verify', 'verification', 'secure', 'account',
  'banking', 'update', 'free', 'bonus', 'wallet', 'support', 'checkpoint',
  'confirm', 'recover', 'billing', 'authenticate', 'mfa', 'oauth', 'token',
  'session', 'portal', 'cpanel', 'webmail', 'invoice', 'document', 'password',
  'credential', 'unlock', 'suspended', 're-activate'
];

// ── Phishing Path Keywords ────────────────────────────────────────────────────
const PHISHING_PATH_KEYWORDS = [
  'login', 'signin', 'auth', 'oauth', 'authenticate', 'verify', 'verification',
  'recover', 'reset-password', 'wallet', 'checkpoint', 'secure-login', 'account-update'
];

// ── Suspicious Subdomain Impersonations ────────────────────────────────────────
const SUSPICIOUS_SUBDOMAINS = [
  'login.', 'signin.', 'verify.', 'secure.', 'auth.', 'account.',
  'portal.', 'banking.', 'wallet.', 'support.', 'admin.', 'update.', 'myaccount.'
];

// ── Open Redirect Query Parameters ────────────────────────────────────────────
const REDIRECT_PARAMS = ['redirect', 'redirect_to', 'redirect_uri', 'return', 'return_to', 'return_url', 'url', 'next', 'dest', 'destination', 'target', 'r', 'link', 'goto', 'forward'];

// ── Free / Ephemeral Hosting Platforms Abused for Phishing ────────────────────
const FREE_HOSTING = [
  'firebaseapp.com', 'web.app', '000webhostapp.com', 'ngrok-free.app', 'ngrok.io',
  'weebly.com', 'wixsite.com', 'github.io', 'pages.dev', 'vercel.app',
  'netlify.app', 'glitch.me', 'surge.sh', 'render.com', 'railway.app'
];

// ── Shannon Entropy Calculation ───────────────────────────────────────────────
export function calculateShannonEntropy(str: string): number {
  if (!str) return 0;
  const clean = str.replace(/[-_.]/g, '');
  if (clean.length === 0) return 0;
  const freqMap: Record<string, number> = {};
  for (const char of clean) {
    freqMap[char] = (freqMap[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in freqMap) {
    const p = freqMap[char] / clean.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// ── URL Component & Encoding Decoder ──────────────────────────────────────────
export function decodeUrlForensics(rawUrl: string): Array<{ label: string; value: string; danger?: boolean }> {
  const results: Array<{ label: string; value: string; danger?: boolean }> = [];
  const trimmed = rawUrl.trim();

  // Check for dangerous schemes
  if (/^(javascript:|data:|vbscript:)/i.test(trimmed)) {
    results.push({ label: '⚠ Dangerous Scheme', value: 'This URI uses javascript:, data:, or vbscript: — a code injection vector.', danger: true });
    return results;
  }

  // Step 1: Percent-encoding decode
  try {
    const decoded = decodeURIComponent(trimmed);
    if (decoded !== trimmed) {
      results.push({ label: 'Percent-Decoded URL', value: decoded });
    } else {
      results.push({ label: 'Percent-Encoding', value: 'No percent-encoded characters found.' });
    }
  } catch {
    results.push({ label: 'Percent-Decode Error', value: 'URL contains malformed percent-encoding (%XX sequence is invalid).', danger: true });
  }

  // Step 2: Double-encoding detection
  if (/%25[0-9a-fA-F]{2}/i.test(trimmed)) {
    results.push({ label: '⚠ Double Encoding Detected', value: 'URL contains %25XX — a double percent-encoded character used for WAF evasion.', danger: true });
  }

  // Step 3: Detect Base64 blobs in query params
  const b64Pattern = /[?&][^=]+=([A-Za-z0-9+/]{20,}={0,2})/g;
  let match;
  let foundB64 = false;
  while ((match = b64Pattern.exec(trimmed)) !== null) {
    try {
      const decoded = atob(match[1]);
      if (/^[\x20-\x7E]+$/.test(decoded)) {
        results.push({ label: 'Base64 Param Decoded', value: decoded });
        foundB64 = true;
      }
    } catch {
      // Not base64
    }
  }
  if (!foundB64 && trimmed.includes('?')) {
    results.push({ label: 'Base64 Params', value: 'No Base64-encoded query parameters detected.' });
  }

  // Step 4: URL decomposition breakdown
  try {
    const urlObj = new URL(trimmed.startsWith('http') ? trimmed : `https://${trimmed}`);
    results.push({ label: 'Protocol', value: urlObj.protocol });
    results.push({ label: 'Hostname', value: urlObj.hostname });
    if (urlObj.port) results.push({ label: 'Port', value: urlObj.port });
    if (urlObj.pathname !== '/') results.push({ label: 'Path', value: urlObj.pathname });
    if (urlObj.search) results.push({ label: 'Query String', value: urlObj.search });
    if (urlObj.hash) results.push({ label: 'Fragment (#)', value: urlObj.hash });
  } catch {
    results.push({ label: 'Parse Warning', value: 'Could not parse fully into URI components.', danger: true });
  }

  return results;
}

// ── Main PhishGuard Heuristic Analyzer ─────────────────────────────────────────
export function analyzeWithPhishGuard(rawUrl: string): PhishGuardResult {
  const flags: PhishGuardFlag[] = [];
  let riskScore = 0;
  const trimmed = rawUrl.trim();

  const decodedDetails = decodeUrlForensics(trimmed);

  // Normalize URL and extract parts
  const cleanUrl = trimmed.replace(/^https?:\/\//i, '');
  const [hostAndPort, ...pathAndQueryArr] = cleanUrl.split('/');
  const domainOnly = hostAndPort.split(':')[0].toLowerCase();
  const pathAndQuery = pathAndQueryArr.join('/');
  const [pathPart = '', queryPart = ''] = pathAndQuery.split('?');

  const domainParts = domainOnly.split('.');
  const tld = domainParts[domainParts.length - 1] || '';
  const baseDomain = domainParts.slice(-2).join('.');

  let impersonatedBrand: string | null = null;
  let isHomograph = false;

  // 1. IP Address as Host
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(domainOnly)) {
    riskScore += 3;
    flags.push({
      type: 'critical',
      message: `Direct IP Address in URL (${domainOnly}) — bypasses DNS domain reputation checks to conceal malicious hosts.`,
      category: 'Raw IP Host'
    });
  }

  // 2. Target Brand Impersonation & Typosquatting
  for (const brand of BRANDS) {
    for (const pattern of brand.patterns) {
      if (pattern.test(domainOnly)) {
        riskScore += 4;
        impersonatedBrand = brand.name;
        flags.push({
          type: 'critical',
          message: `Brand Impersonation Target: ${brand.name} — domain mimics official service using deceptive typo pattern.`,
          category: 'Brand Impersonation'
        });
        break;
      }
    }
  }

  // 3. High-Risk Suspicious TLD
  if (SUSPICIOUS_TLDS.includes(tld)) {
    riskScore += 2;
    flags.push({
      type: 'warning',
      message: `High-Risk TLD (.${tld}) — statistically correlated with spam, phishing, and disposable throwaway domains.`,
      category: 'Suspicious TLD'
    });
  }

  // 4. Phishing Keywords in Domain
  for (const kw of SUSPICIOUS_KEYWORDS) {
    if (domainOnly.includes(kw)) {
      riskScore += 2;
      flags.push({
        type: 'warning',
        message: `High-Risk Keyword in Hostname ("${kw}") — used to trick users into trusting a fraudulent portal.`,
        category: 'Keyword Deception'
      });
      break;
    }
  }

  // 5. Credential Injection / @ Symbol
  if (trimmed.includes('@')) {
    riskScore += 3;
    flags.push({
      type: 'critical',
      message: 'Credential Redirection Symbol (@) — obscures real host by making the browser ignore everything prior to the @ symbol.',
      category: 'URL Confusion'
    });
  }

  // 6. Excessive Hyphens / Dashes
  const hyphenCount = (domainOnly.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    riskScore += 2;
    flags.push({
      type: 'warning',
      message: `Excessive Hyphens (${hyphenCount} found) — commonly chained to synthesize fake domain names (e.g. login-secure-update-account).`,
      category: 'Domain Structuring'
    });
  }

  // 7. Excessive Subdomains (Deep Dot Hierarchy)
  if (domainParts.length >= 4) {
    riskScore += 2;
    flags.push({
      type: 'warning',
      message: `Excessive Subdomain Depth (${domainParts.length - 1} levels) — deep hierarchies are often used to camouflage attacker domains.`,
      category: 'Subdomain Depth'
    });
  }

  // 8. Abnormal URL Length
  if (trimmed.length > 100) {
    riskScore += 1;
    flags.push({
      type: 'info',
      message: `Abnormal URL Length (${trimmed.length} characters) — elongated URLs are used to hide suspicious parameters outside browser view.`,
      category: 'URL Length'
    });
  }

  // 9. Insecure Protocol (HTTP)
  if (trimmed.startsWith('http://')) {
    riskScore += 2;
    flags.push({
      type: 'warning',
      message: 'Insecure Protocol (HTTP) — unencrypted channel. Sensitive credentials would be transmitted in plaintext.',
      category: 'No Encryption'
    });
  }

  // 10. Leetspeak / Number Substitution
  if (/[a-z][0-9][a-z]/.test(baseDomain)) {
    riskScore += 2;
    flags.push({
      type: 'warning',
      message: 'Leetspeak Number Substitution — numbers replacing letters (e.g. "paypa1", "g00gle") to evade brand filters.',
      category: 'Leetspeak'
    });
  }

  // 11. Domain Length Anomaly (DGA Detection)
  if (baseDomain.length > 30) {
    riskScore += 2;
    flags.push({
      type: 'warning',
      message: `Domain Length Anomaly (${baseDomain.length} chars) — character length indicates potential Domain Generation Algorithm (DGA).`,
      category: 'DGA Malware'
    });
  }

  // 12. Shannon Entropy Ratio
  const entropy = calculateShannonEntropy(baseDomain);
  const cleanBase = baseDomain.replace(/[-_.]/g, '');
  if (cleanBase.length > 15 && entropy > 3.4) {
    riskScore += 2;
    flags.push({
      type: 'warning',
      message: `High Shannon Entropy (${entropy.toFixed(2)}) — character randomness strongly indicates automated DGA C2 malware generation.`,
      category: 'DGA Malware'
    });
  }

  // 13. IDN Punycode Homograph Attack
  if (domainOnly.startsWith('xn--') || domainOnly.includes('.xn--')) {
    riskScore += 4;
    isHomograph = true;
    flags.push({
      type: 'critical',
      message: 'IDN Punycode Homograph Attack Detected — internationalized Unicode domain visually mimics a legitimate brand.',
      category: 'Homograph Attack'
    });
  }

  // 14. Phishing Keywords in Path
  for (const kw of PHISHING_PATH_KEYWORDS) {
    if (pathPart.startsWith(kw) || pathPart.includes(kw + '/') || pathPart.includes(kw + '?')) {
      riskScore += 2;
      flags.push({
        type: 'warning',
        message: `Phishing Keyword in URI Path ("${kw}") — endpoint matches typical credential harvesting entry points.`,
        category: 'Suspicious Path'
      });
      break;
    }
  }

  // 15. Suspicious Subdomain Impersonation on Unrelated Domain
  const KNOWN_LEGIT = ['google.com', 'microsoft.com', 'amazon.com', 'apple.com', 'facebook.com', 'github.com', 'paypal.com', 'netflix.com'];
  const isLegit = KNOWN_LEGIT.some(b => domainOnly.endsWith('.' + b) || domainOnly === b);
  if (!isLegit) {
    for (const sub of SUSPICIOUS_SUBDOMAINS) {
      if (domainOnly.startsWith(sub)) {
        riskScore += 2;
        flags.push({
          type: 'warning',
          message: `Suspicious Subdomain ("${sub.replace('.', '')}") on unrelated apex domain — mimics official login portals.`,
          category: 'Fake Portal Subdomain'
        });
        break;
      }
    }
  }

  // 16. Mixed TLD Abuse (e.g. brand.com.xyz)
  if (/\.(com|net|org|co|io)\.[a-z]{2,10}$/.test(domainOnly)) {
    riskScore += 3;
    flags.push({
      type: 'critical',
      message: 'Mixed TLD Abuse — embeds a legitimate TLD before an attacker TLD (e.g. "paypal.com.xyz") to deceive users reading left-to-right.',
      category: 'Mixed TLD Abuse'
    });
  }

  // 17. Open Redirect Parameters
  const queryLower = queryPart.toLowerCase();
  for (const param of REDIRECT_PARAMS) {
    if (queryLower.includes(`${param}=`)) {
      riskScore += 2;
      flags.push({
        type: 'warning',
        message: `Open Redirect Parameter Detected ("?${param}=") — URL can bounce victims to an unvalidated third-party destination.`,
        category: 'Open Redirect'
      });
      break;
    }
  }

  // 18. Free Hosting Platform Abuse
  for (const host of FREE_HOSTING) {
    if (domainOnly.endsWith(host)) {
      riskScore += 2;
      flags.push({
        type: 'warning',
        message: `Free Hosting Platform (${host}) — frequently abused to deploy anonymous credential harvesting kits without identity verification.`,
        category: 'Free Hosting Abuse'
      });
      break;
    }
  }

  // Final score cap & categorization
  const cappedScore = Math.min(riskScore, 10);
  let riskLevel: 'Critical' | 'High' | 'Medium' | 'Low' | 'Safe' = 'Safe';
  if (cappedScore >= 7) riskLevel = 'Critical';
  else if (cappedScore >= 5) riskLevel = 'High';
  else if (cappedScore >= 3) riskLevel = 'Medium';
  else if (cappedScore >= 1) riskLevel = 'Low';

  if (flags.length === 0) {
    flags.push({
      type: 'safe',
      message: 'No heuristic anomalies or phishing indicators detected. URL matches standard FQDN structures.',
      category: 'Clean Verdict'
    });
  }

  return {
    riskScore: cappedScore,
    riskLevel,
    flags,
    decodedDetails,
    entropy,
    isHomograph,
    impersonatedBrand,
    baseDomain,
    tld,
  };
}
