// ─────────────────────────────────────────────────────────────────────────────
// ThreatAtlas — Canonical Report Schema v1.0
// All scan types (file, url, domain, ip) emit this unified shape.
// ─────────────────────────────────────────────────────────────────────────────

export type ScanType = 'file' | 'url' | 'domain' | 'ip';
export type ScanStatus = 'queued' | 'in_progress' | 'completed' | 'failed';
export type Verdict = 'malicious' | 'suspicious' | 'clean' | 'unknown';

// ── Sub-schemas ───────────────────────────────────────────────────────────────

export interface ReportStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  total: number;
}

export interface ReportEngine {
  engine: string;
  category: string;
  result: string | null;
  method?: string;
  detected: boolean;
}

// File-specific metadata (only present when scan_type === "file")
export interface FileMeta {
  sha256: string;
  sha1: string;
  md5: string;
  name: string;
  names: string[];
  size: number;
  type: string;
  mime_type: string;
  first_seen: number | null;
  last_seen: number | null;
  times_submitted: number;
  tags: string[];
  magic?: string;
  pe_info?: {
    imphash?: string;
    entry_point?: number;
    machine_type?: string;
    sections?: Array<{ name: string; entropy: number; virtual_size: number; raw_size: number }>;
    import_list?: Array<{ library_name: string; imported_functions: string[] }>;
  };
  mitre_attack?: Array<{
    id: string;
    description: string;
    tactic: string;
  }>;
  contacted_ips?: Array<{ ip: string; country?: string; malicious?: boolean }>;
  contacted_domains?: Array<{ domain: string; malicious?: boolean }>;
}

// URL-specific metadata (only present when scan_type === "url")
export interface UrlMeta {
  final_url?: string;
  serving_ip?: string;
  http_status?: number;
  title?: string;
  redirection_chain?: string[];
  categories?: Record<string, string>;
}

// Domain-specific metadata (only present when scan_type === "domain")
export interface DomainMeta {
  registrar?: string;
  creation_date?: number;
  expiration_date?: number;
  reputation?: number;
  tags?: string[];
  categories?: Record<string, string>;
  dns_records?: Array<{ type: string; value: string; ttl?: number }>;
  subdomains?: string[];
  resolutions?: Array<{ ip: string; date: number }>;
}

// IP-specific metadata (only present when scan_type === "ip")
export interface IpMeta {
  asn?: number;
  as_owner?: string;
  country?: string;
  network?: string;
  reputation?: number;
  tags?: string[];
  dns_records?: Array<{ type: string; value: string; ttl?: number }>;
  geolocation?: {
    country: string;
    region: string;
    city: string;
    lat?: number;
    lon?: number;
    isp?: string;
    org?: string;
    timezone?: string;
  };
}

// PhishGuard heuristic result (url scans only)
export interface PhishGuardResult {
  risk_score: number;            // 0–100
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  signals: Array<{
    id: string;
    label: string;
    severity: 'info' | 'warning' | 'danger';
    triggered: boolean;
  }>;
  brand_impersonation?: string;
  typosquatting?: boolean;
  suspicious_tld?: boolean;
  checked_at: string;            // ISO-8601
}

// WebFox network reconnaissance result (url scans only)
export interface WebFoxResult {
  dns: Array<{ type: string; value: string; ttl?: number }>;
  subdomains: string[];
  ssl_cert?: {
    issuer?: string;
    subject?: string;
    valid_from?: string;
    valid_to?: string;
    san?: string[];
    serial_number?: string;
  };
  whois?: {
    registrar?: string;
    created?: string;
    expires?: string;
    registrant?: string;
  };
  open_ports?: Array<{ port: number; service?: string }>;
  checked_at: string;
}

// YARA match result (file scans only)
export interface YaraMatch {
  rule: string;
  tags: string[];
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  matched_strings: Array<{ identifier: string; offset: number; value: string }>;
}

export interface YaraResult {
  engine_version: string;
  rules_count: number;
  matches: YaraMatch[];
  scanned_at: string;            // ISO-8601
}

// ── Root Report ───────────────────────────────────────────────────────────────

export interface ThreatReport {
  schema_version: '1.0';
  task_id: string;
  scan_type: ScanType;

  /** The raw target: URL string, file hash, domain, or IP address */
  target: string;

  status: ScanStatus;
  created_at: string;            // ISO-8601
  completed_at: string | null;  // ISO-8601, null if not yet done

  verdict: Verdict;
  threat_score: number;          // 0–100
  stats: ReportStats;
  engines: ReportEngine[];

  // Type-specific sub-schemas (present based on scan_type)
  file_meta?: FileMeta;
  url_meta?: UrlMeta;
  domain_meta?: DomainMeta;
  ip_meta?: IpMeta;

  // Module results (present only when the module ran)
  phishguard?: PhishGuardResult;
  webfox?: WebFoxResult;
  yara?: YaraResult;
  image_forensics?: any;

  // Community intelligence
  community_comments?: Array<{
    id: string;
    author: string;
    text: string;
    date: number;
    votes: { positive: number; negative: number; abuse: number };
  }>;

  // Relations graph data
  relations?: {
    contacted_ips?: Array<{ ip: string; country?: string; stats?: ReportStats }>;
    contacted_domains?: Array<{ domain: string; stats?: ReportStats }>;
    contacted_urls?: Array<{ url: string; stats?: ReportStats }>;
    communicating_files?: Array<{ id: string; name?: string; stats?: ReportStats }>;
    downloaded_files?: Array<{ id: string; name?: string; stats?: ReportStats }>;
    resolutions?: Array<{ ip: string; date: number; stats?: ReportStats }>;
    subdomains?: Array<{ id: string; stats?: ReportStats }>;
  };
}

// ── Task Queue Types ──────────────────────────────────────────────────────────

export interface ScanTaskResponse {
  task_id: string;
  status: ScanStatus;
  message: string;
  poll_url: string;
}

export interface ScanStatusResponse {
  task_id: string;
  status: ScanStatus;
  progress: number;       // 0–100
  created_at: string;
  completed_at: string | null;
  report?: ThreatReport;
  error?: string;
}
