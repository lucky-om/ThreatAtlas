// ─────────────────────────────────────────────────────────────────────────────
// ThreatAtlas — Report Builder
// Converts any normalizer output → canonical ThreatReport v1.0 JSON schema.
// ─────────────────────────────────────────────────────────────────────────────

import type {
  ThreatReport,
  ReportEngine,
  ReportStats,
  FileMeta,
  UrlMeta,
  DomainMeta,
  IpMeta,
  PhishGuardResult,
  WebFoxResult,
  YaraResult,
  ScanType,
  ScanStatus,
} from '../types/report';

import type {
  NormalizedFile,
  NormalizedAnalysis,
  NormalizedDomain,
  NormalizedIp,
  EngineResult,
  ScanStats,
  EntityRelations,
  CommunityComment,
} from '../services/api';

// ── Helpers ───────────────────────────────────────────────────────────────────

function mapEngines(engines: EngineResult[]): ReportEngine[] {
  return engines.map((e) => ({
    engine: e.engine,
    category: e.category ?? 'undetected',
    result: e.result,
    method: e.method,
    detected: e.detected,
  }));
}

function mapStats(stats: ScanStats): ReportStats {
  return {
    malicious: stats.malicious ?? 0,
    suspicious: stats.suspicious ?? 0,
    harmless: stats.harmless ?? 0,
    undetected: stats.undetected ?? 0,
    total: stats.total ?? 0,
  };
}

function mapRelations(relations?: EntityRelations) {
  if (!relations) return undefined;
  return {
    contacted_ips: relations.contactedIps?.map((r) => ({
      ip: r.ip,
      country: r.country,
      stats: r.stats ? mapStats(r.stats) : undefined,
    })),
    contacted_domains: relations.contactedDomains?.map((r) => ({
      domain: r.domain,
      stats: r.stats ? mapStats(r.stats) : undefined,
    })),
    contacted_urls: relations.contactedUrls?.map((r) => ({
      url: r.url,
      stats: r.stats ? mapStats(r.stats) : undefined,
    })),
    communicating_files: relations.communicatingFiles?.map((r) => ({
      id: r.id,
      name: r.name,
      stats: r.stats ? mapStats(r.stats) : undefined,
    })),
    downloaded_files: relations.downloadedFiles?.map((r) => ({
      id: r.id,
      name: r.name,
      stats: r.stats ? mapStats(r.stats) : undefined,
    })),
    resolutions: relations.resolutions?.map((r) => ({
      ip: r.ip,
      date: r.date,
      stats: r.stats ? mapStats(r.stats) : undefined,
    })),
    subdomains: relations.subdomains?.map((r) => ({
      id: r.id,
      stats: r.stats ? mapStats(r.stats) : undefined,
    })),
  };
}

function mapComments(comments?: CommunityComment[]) {
  if (!comments?.length) return undefined;
  return comments.map((c) => ({
    id: c.id,
    author: c.author,
    text: c.text,
    date: c.date,
    votes: c.votes,
  }));
}

// ── Build from NormalizedFile (file scan) ────────────────────────────────────

export function buildFileReport(
  taskId: string,
  data: NormalizedFile,
  extras?: { yara?: YaraResult; status?: ScanStatus; createdAt?: string }
): ThreatReport {
  const fileMeta: FileMeta = {
    sha256: data.sha256,
    sha1: data.sha1,
    md5: data.md5,
    name: data.name,
    names: data.names,
    size: data.size,
    type: data.type,
    mime_type: data.mimeType,
    first_seen: data.firstSeen || null,
    last_seen: data.lastSeen || null,
    times_submitted: data.timesSubmitted,
    tags: data.tags,
    magic: data.extended?.magic,
    pe_info: data.extended?.peInfo
      ? {
          imphash: data.extended.peInfo.imphash,
          entry_point: data.extended.peInfo.entry_point,
          machine_type: data.extended.peInfo.machine_type,
          sections: data.extended.peInfo.sections,
          import_list: data.extended.peInfo.import_list,
        }
      : undefined,
    mitre_attack: data.extended?.mitreAttack?.map((m) => ({
      id: m.id,
      description: m.signature_description,
      tactic: m.tactic,
    })),
    contacted_ips: data.relations?.contactedIps?.map((r) => ({
      ip: r.ip,
      country: r.country,
      malicious: (r.stats?.malicious ?? 0) > 0,
    })),
    contacted_domains: data.relations?.contactedDomains?.map((r) => ({
      domain: r.domain,
      malicious: (r.stats?.malicious ?? 0) > 0,
    })),
  };

  return {
    schema_version: '1.0',
    task_id: taskId,
    scan_type: 'file',
    target: data.sha256 || data.md5 || data.name,
    status: extras?.status ?? 'completed',
    created_at: extras?.createdAt ?? new Date().toISOString(),
    completed_at: new Date().toISOString(),
    verdict: data.verdict,
    threat_score: calcThreatScore(data.stats),
    stats: mapStats(data.stats),
    engines: mapEngines(data.engines),
    file_meta: fileMeta,
    yara: extras?.yara,
    relations: mapRelations(data.relations),
    community_comments: mapComments(data.comments),
  };
}

// ── Build from NormalizedAnalysis (url / analysis scan) ──────────────────────

export function buildUrlReport(
  taskId: string,
  data: NormalizedAnalysis,
  extras?: {
    phishguard?: PhishGuardResult;
    webfox?: WebFoxResult;
    status?: ScanStatus;
    createdAt?: string;
  }
): ThreatReport {
  const urlMeta: UrlMeta = {
    final_url: data.extended?.httpResponse?.finalUrl,
    serving_ip: data.extended?.httpResponse?.servingIp,
    http_status: data.extended?.httpResponse?.statusCode,
    title: data.extended?.htmlInfo?.title,
    redirection_chain: data.extended?.redirectionChain,
    categories: data.extended?.categories,
  };

  return {
    schema_version: '1.0',
    task_id: taskId,
    scan_type: 'url',
    target: data.url ?? data.id,
    status: extras?.status ?? 'completed',
    created_at: extras?.createdAt ?? new Date().toISOString(),
    completed_at: new Date().toISOString(),
    verdict: data.verdict,
    threat_score: data.threatScore,
    stats: mapStats(data.stats),
    engines: mapEngines(data.engines),
    url_meta: urlMeta,
    phishguard: extras?.phishguard,
    webfox: extras?.webfox,
    relations: mapRelations(data.relations),
    community_comments: mapComments(data.comments),
  };
}

// ── Build from NormalizedDomain ───────────────────────────────────────────────

export function buildDomainReport(
  taskId: string,
  data: NormalizedDomain,
  extras?: {
    phishguard?: PhishGuardResult;
    webfox?: WebFoxResult;
    status?: ScanStatus;
    createdAt?: string;
  }
): ThreatReport {
  const domainMeta: DomainMeta = {
    registrar: data.registrar,
    creation_date: data.creation || undefined,
    expiration_date: data.expiration || undefined,
    reputation: data.reputation,
    tags: data.tags,
    categories: data.categories,
    dns_records: data.dnsRecords,
    subdomains: data.relations?.subdomains?.map((s) => s.id),
    resolutions: data.relations?.resolutions?.map((r) => ({ ip: r.ip, date: r.date })),
  };

  return {
    schema_version: '1.0',
    task_id: taskId,
    scan_type: 'domain',
    target: data.domain,
    status: extras?.status ?? 'completed',
    created_at: extras?.createdAt ?? new Date().toISOString(),
    completed_at: new Date().toISOString(),
    verdict: data.verdict,
    threat_score: calcThreatScore(data.stats),
    stats: mapStats(data.stats),
    engines: mapEngines(data.engines),
    domain_meta: domainMeta,
    phishguard: extras?.phishguard,
    webfox: extras?.webfox,
    relations: mapRelations(data.relations),
    community_comments: mapComments(data.comments),
  };
}

// ── Build from NormalizedIp ───────────────────────────────────────────────────

export function buildIpReport(
  taskId: string,
  data: NormalizedIp,
  extras?: { status?: ScanStatus; createdAt?: string }
): ThreatReport {
  const ipMeta: IpMeta = {
    asn: data.asn ?? undefined,
    as_owner: data.asOwner,
    country: data.country,
    network: data.network,
    reputation: data.reputation,
    tags: data.tags,
    dns_records: data.dnsRecords,
  };

  return {
    schema_version: '1.0',
    task_id: taskId,
    scan_type: 'ip',
    target: data.ip,
    status: extras?.status ?? 'completed',
    created_at: extras?.createdAt ?? new Date().toISOString(),
    completed_at: new Date().toISOString(),
    verdict: data.verdict,
    threat_score: calcThreatScore(data.stats),
    stats: mapStats(data.stats),
    engines: mapEngines(data.engines),
    ip_meta: ipMeta,
    relations: mapRelations(data.relations),
    community_comments: mapComments(data.comments),
  };
}

// ── Generic dispatch ──────────────────────────────────────────────────────────

export function buildReport(
  taskId: string,
  scanType: ScanType,
  data: NormalizedFile | NormalizedAnalysis | NormalizedDomain | NormalizedIp,
  extras?: {
    phishguard?: PhishGuardResult;
    webfox?: WebFoxResult;
    yara?: YaraResult;
    status?: ScanStatus;
    createdAt?: string;
  }
): ThreatReport {
  switch (scanType) {
    case 'file':
      return buildFileReport(taskId, data as NormalizedFile, extras);
    case 'url':
      return buildUrlReport(taskId, data as NormalizedAnalysis, extras);
    case 'domain':
      return buildDomainReport(taskId, data as NormalizedDomain, extras);
    case 'ip':
      return buildIpReport(taskId, data as NormalizedIp, extras);
    default:
      throw new Error(`Unknown scan type: ${scanType}`);
  }
}

// ── Utility ───────────────────────────────────────────────────────────────────

function calcThreatScore(stats: ScanStats): number {
  const total = (stats.malicious ?? 0) + (stats.suspicious ?? 0) +
    (stats.harmless ?? 0) + (stats.undetected ?? 0);
  if (total === 0) return 0;
  return Math.round(((stats.malicious ?? 0) + (stats.suspicious ?? 0)) / total * 100);
}
