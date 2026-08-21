import React, { useState, useCallback } from 'react';
import { detectInputType } from '../services/api';
import { sanitizeInput } from '../utils/sanitize';

interface IocEntry {
  ioc: string;
  type: 'hash' | 'ip' | 'domain' | 'url' | 'unknown';
}

interface IocResult {
  ioc: string;
  type: string;
  verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown' | 'error';
  maliciousEngines?: number;
  totalEngines?: number;
  lastAnalysis?: string;
  tags?: string[];
  urlhausStatus?: string;
  mbStatus?: string;
  error?: string;
}

const SAMPLE_IOCS = `# Paste IOCs below — one per line (IPs, domains, URLs, hashes)
185.220.101.45
wannacry.exe
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
malware.example.com
http://evil-phish.ru/steal.php`;

function parseIocInput(raw: string): IocEntry[] {
  return raw
    .split('\n')
    .map(l => sanitizeInput(l).toLowerCase())
    .filter(l => l && !l.startsWith('#'))
    .map(ioc => ({ ioc, type: detectInputType(ioc) }));
}

async function lookupVt(ioc: IocEntry): Promise<Partial<IocResult>> {
  try {
    let endpoint = '';
    if (ioc.type === 'hash') endpoint = `/api/vt/files/${encodeURIComponent(ioc.ioc)}`;
    else if (ioc.type === 'ip') endpoint = `/api/vt/ip_addresses/${encodeURIComponent(ioc.ioc)}`;
    else if (ioc.type === 'domain') endpoint = `/api/vt/domains/${encodeURIComponent(ioc.ioc)}`;
    else if (ioc.type === 'url') {
      // URL needs to be base64url encoded for VT
      const b64 = btoa(ioc.ioc).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      endpoint = `/api/vt/urls/${b64}`;
    } else {
      return { verdict: 'unknown', error: 'Unknown input type' };
    }

    const res = await fetch(endpoint);
    if (res.status === 404) return { verdict: 'unknown', error: 'Not found in VT database' };
    if (!res.ok) return { verdict: 'error', error: `VT HTTP ${res.status}` };
    const data = await res.json();
    const stats = data?.data?.attributes?.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const total = malicious + suspicious + (stats.harmless || 0) + (stats.undetected || 0);
    const lastTs = data?.data?.attributes?.last_analysis_date;

    return {
      verdict: malicious > 0 ? 'malicious' : suspicious > 0 ? 'suspicious' : total > 0 ? 'clean' : 'unknown',
      maliciousEngines: malicious + suspicious,
      totalEngines: total,
      tags: data?.data?.attributes?.tags || [],
      lastAnalysis: lastTs ? new Date(lastTs * 1000).toLocaleDateString() : '—',
    };
  } catch (e: any) {
    return { verdict: 'error', error: e.message };
  }
}

async function lookupUrlhaus(ioc: IocEntry): Promise<Partial<IocResult>> {
  try {
    const body: Record<string, string> = {};
    if (ioc.type === 'url') body.url = ioc.ioc;
    else if (ioc.type === 'domain' || ioc.type === 'ip') body.host = ioc.ioc;
    else return {};

    const res = await fetch('/api/urlhaus', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) return {};
    const data = await res.json();
    return { urlhausStatus: data.query_status || '—' };
  } catch {
    return {};
  }
}

async function lookupMalwareBazaar(ioc: IocEntry): Promise<Partial<IocResult>> {
  if (ioc.type !== 'hash') return {};
  try {
    const res = await fetch('/api/malwarebazaar', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: 'get_info', hash: ioc.ioc }),
    });
    if (!res.ok) return {};
    const data = await res.json();
    return { mbStatus: data.query_status || '—' };
  } catch {
    return {};
  }
}

const VerdictBadge: React.FC<{ verdict: IocResult['verdict'] }> = ({ verdict }) => {
  const map: Record<string, { label: string; cls: string }> = {
    malicious: { label: 'MALICIOUS', cls: 'verdict-malicious' },
    suspicious: { label: 'SUSPICIOUS', cls: 'verdict-suspicious' },
    clean:      { label: 'CLEAN', cls: 'verdict-clean' },
    unknown:    { label: 'UNKNOWN', cls: 'verdict-unknown' },
    error:      { label: 'ERROR', cls: 'verdict-unknown' },
  };
  const v = map[verdict] || map.unknown;
  return <span className={`verdict-badge ${v.cls}`}>{v.label}</span>;
};

export const IocHunter: React.FC = () => {
  const [iocInput, setIocInput] = useState(SAMPLE_IOCS);
  const [results, setResults] = useState<IocResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [totalCount, setTotalCount] = useState(0);
  const [scanned, setScanned] = useState(false);
  const [filter, setFilter] = useState<'all' | 'malicious' | 'clean' | 'unknown'>('all');

  const handleScan = useCallback(async () => {
    const iocs = parseIocInput(iocInput).slice(0, 50); // limit 50
    if (iocs.length === 0) return;

    setLoading(true);
    setScanned(false);
    setResults([]);
    setProgress(0);
    setTotalCount(iocs.length);

    const batchResults: IocResult[] = [];

    for (let i = 0; i < iocs.length; i++) {
      const ioc = iocs[i];
      // Rate limit: wait between requests
      if (i > 0) await new Promise(r => setTimeout(r, 500));

      const [vtData, urlhausData, mbData] = await Promise.all([
        lookupVt(ioc),
        lookupUrlhaus(ioc),
        lookupMalwareBazaar(ioc),
      ]);

      batchResults.push({
        ioc: ioc.ioc,
        type: ioc.type,
        verdict: vtData.verdict || 'unknown',
        maliciousEngines: vtData.maliciousEngines,
        totalEngines: vtData.totalEngines,
        lastAnalysis: vtData.lastAnalysis,
        tags: vtData.tags || [],
        urlhausStatus: urlhausData.urlhausStatus,
        mbStatus: mbData.mbStatus,
        error: vtData.error,
      });

      setProgress(i + 1);
      setResults([...batchResults]);
    }

    setScanned(true);
    setLoading(false);
  }, [iocInput]);

  const exportCsv = () => {
    const headers = ['IOC', 'Type', 'Verdict', 'Malicious Engines', 'Total Engines', 'Last Analysis', 'URLhaus', 'MalwareBazaar', 'Tags'];
    const rows = results.map(r => [
      r.ioc, r.type, r.verdict,
      r.maliciousEngines ?? '', r.totalEngines ?? '',
      r.lastAnalysis ?? '',
      r.urlhausStatus ?? '',
      r.mbStatus ?? '',
      (r.tags || []).join(';'),
    ]);
    const csv = [headers, ...rows].map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `threatatlas-ioc-hunt-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
  };

  const filteredResults = results.filter(r =>
    filter === 'all' ? true :
    filter === 'malicious' ? (r.verdict === 'malicious' || r.verdict === 'suspicious') :
    r.verdict === filter
  );

  const maliciousCount = results.filter(r => r.verdict === 'malicious' || r.verdict === 'suspicious').length;

  return (
    <div className="module-page">
      <div className="digital-grid" />
      <div style={{ position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 0, background: 'radial-gradient(circle at 70% 30%, rgba(251,146,60,0.06) 0%, transparent 50%)' }} />

      <div className="container" style={{ position: 'relative', zIndex: 10, maxWidth: '1200px', width: '100%' }}>

        {/* Hero */}
        <div className="module-hero">
          <div className="module-badge" style={{ background: 'var(--module-ioc-dim)', border: '1px solid rgba(251,146,60,0.3)', color: 'var(--module-ioc)' }}>
            <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>travel_explore</span>
            IOC Hunter
          </div>
          <h1 className="font-display-lg text-on-surface" style={{ fontSize: '48px', marginBottom: '12px' }}>
            Bulk <span style={{ color: 'var(--module-ioc)' }}>IOC</span> Intelligence
          </h1>
          <p className="font-body-md text-on-surface-variant" style={{ maxWidth: '560px', margin: '0 auto' }}>
            Paste a list of IPs, domains, URLs, or file hashes. Cross-reference against VirusTotal, abuse.ch URLhaus, and MalwareBazaar simultaneously.
          </p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '380px 1fr', gap: '24px', alignItems: 'flex-start' }}>

          {/* Left — Input */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div className="glass-card" style={{ padding: '20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <div className="font-label-caps" style={{ color: 'var(--module-ioc)' }}>IOC List</div>
                <span className="font-code-sm text-on-surface-variant">
                  {parseIocInput(iocInput).length} IOCs (max 50)
                </span>
              </div>
              <textarea
                value={iocInput}
                onChange={e => setIocInput(e.target.value)}
                style={{
                  width: '100%', minHeight: '340px', background: 'rgba(0,0,0,0.5)',
                  border: '1px solid rgba(251,146,60,0.2)', borderRadius: '8px',
                  color: 'var(--on-surface)', fontFamily: 'var(--font-mono)', fontSize: '12px',
                  padding: '14px', resize: 'vertical', outline: 'none', lineHeight: '1.7',
                }}
                onFocus={e => (e.target.style.borderColor = 'rgba(251,146,60,0.5)')}
                onBlur={e => (e.target.style.borderColor = 'rgba(251,146,60,0.2)')}
                placeholder="Paste IOCs here — IPs, domains, URLs, hashes..."
              />

              {loading && (
                <div style={{ marginTop: '12px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                    <span className="font-code-sm text-on-surface-variant">Scanning IOCs...</span>
                    <span className="font-code-sm" style={{ color: 'var(--module-ioc)' }}>{progress}/{totalCount}</span>
                  </div>
                  <div className="score-bar-track">
                    <div className="score-bar-fill" style={{ width: `${(progress / totalCount) * 100}%`, background: 'var(--module-ioc)' }} />
                  </div>
                </div>
              )}

              <button
                onClick={handleScan}
                disabled={loading}
                style={{
                  marginTop: '16px', width: '100%', padding: '14px', borderRadius: '8px',
                  background: loading ? 'rgba(251,146,60,0.08)' : 'rgba(251,146,60,0.15)',
                  border: '1px solid rgba(251,146,60,0.4)', color: 'var(--module-ioc)',
                  fontFamily: 'var(--font-mono)', fontSize: '13px', fontWeight: 700, cursor: loading ? 'not-allowed' : 'pointer',
                  letterSpacing: '0.1em',
                }}
              >
                {loading ? `⟳ SCANNING ${progress}/${totalCount}...` : '▶ HUNT IOCs'}
              </button>
            </div>

            {/* Data Sources */}
            <div className="glass-card" style={{ padding: '20px' }}>
              <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '12px' }}>Intelligence Sources</div>
              {[
                { name: 'VirusTotal', desc: '70+ AV engines', color: 'var(--primary)', icon: 'security' },
                { name: 'abuse.ch URLhaus', desc: 'Malicious URL database', color: 'var(--module-ioc)', icon: 'link_off' },
                { name: 'MalwareBazaar', desc: 'Malware sample intelligence', color: 'var(--module-ioc)', icon: 'bug_report' },
              ].map(src => (
                <div key={src.name} style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '10px', borderRadius: '6px', background: 'rgba(255,255,255,0.02)', marginBottom: '6px' }}>
                  <span className="material-symbols-outlined" style={{ fontSize: '18px', color: src.color }}>{src.icon}</span>
                  <div>
                    <div className="font-data-mono text-on-surface" style={{ fontSize: '13px' }}>{src.name}</div>
                    <div className="font-code-sm text-on-surface-variant">{src.desc}</div>
                  </div>
                  <span style={{ marginLeft: 'auto', width: '8px', height: '8px', background: 'var(--success)', borderRadius: '50%', boxShadow: '0 0 6px var(--success)' }} />
                </div>
              ))}
            </div>
          </div>

          {/* Right — Results */}
          <div>
            {scanned && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                {/* Stats Row */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px' }}>
                  {[
                    { label: 'Total', value: results.length, color: 'var(--primary)' },
                    { label: 'Malicious', value: maliciousCount, color: 'var(--secondary)' },
                    { label: 'Clean', value: results.filter(r => r.verdict === 'clean').length, color: 'var(--success)' },
                    { label: 'Unknown', value: results.filter(r => r.verdict === 'unknown' || r.verdict === 'error').length, color: 'var(--on-surface-variant)' },
                  ].map(stat => (
                    <div key={stat.label} className="glass-card animate-fade-in-up" style={{ padding: '16px', textAlign: 'center' }}>
                      <div style={{ fontSize: '28px', fontWeight: 800, color: stat.color, fontFamily: 'var(--font-mono)' }}>{stat.value}</div>
                      <div className="font-label-caps text-on-surface-variant" style={{ marginTop: '4px' }}>{stat.label}</div>
                    </div>
                  ))}
                </div>

                {/* Filter + Export */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', gap: '8px' }}>
                    {(['all', 'malicious', 'clean', 'unknown'] as const).map(f => (
                      <button
                        key={f}
                        onClick={() => setFilter(f)}
                        style={{
                          padding: '6px 14px', borderRadius: '6px',
                          background: filter === f ? 'rgba(185,66,255,0.15)' : 'rgba(255,255,255,0.04)',
                          border: `1px solid ${filter === f ? 'var(--border-accent)' : 'var(--border)'}`,
                          color: filter === f ? 'var(--primary)' : 'var(--on-surface-variant)',
                          fontFamily: 'var(--font-mono)', fontSize: '11px', fontWeight: 700, cursor: 'pointer',
                          textTransform: 'uppercase',
                        }}
                      >
                        {f}
                      </button>
                    ))}
                  </div>
                  <button
                    onClick={exportCsv}
                    style={{
                      display: 'flex', alignItems: 'center', gap: '6px', padding: '7px 16px', borderRadius: '6px',
                      background: 'rgba(0,255,163,0.08)', border: '1px solid rgba(0,255,163,0.25)', color: 'var(--success)',
                      fontFamily: 'var(--font-mono)', fontSize: '12px', cursor: 'pointer', fontWeight: 700,
                    }}
                  >
                    <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>download</span>
                    Export CSV
                  </button>
                </div>

                {/* Results Table */}
                <div className="glass-card animate-fade-in-up" style={{ padding: '0', overflow: 'hidden' }}>
                  <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                      <thead>
                        <tr style={{ background: 'rgba(0,0,0,0.4)' }}>
                          {['IOC', 'Type', 'Verdict', 'Engines', 'URLhaus', 'MalwareBazaar', 'Last Seen'].map(h => (
                            <th key={h} className="font-label-caps text-on-surface-variant" style={{ padding: '14px 16px', textAlign: 'left', whiteSpace: 'nowrap' }}>{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {filteredResults.map((r, i) => (
                          <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)', transition: 'background 0.15s' }}
                            onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,0.02)')}
                            onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                          >
                            <td style={{ padding: '12px 16px', maxWidth: '260px' }}>
                              <div className="font-data-mono text-primary" style={{ fontSize: '12px', wordBreak: 'break-all', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: '240px', whiteSpace: 'nowrap' }} title={r.ioc}>
                                {r.ioc}
                              </div>
                              {r.error && <div className="font-code-sm" style={{ color: 'var(--secondary)', fontSize: '10px', marginTop: '2px' }}>{r.error}</div>}
                            </td>
                            <td style={{ padding: '12px 16px' }}>
                              <span style={{ padding: '2px 8px', borderRadius: '4px', background: 'rgba(255,255,255,0.05)', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--on-surface-variant)', textTransform: 'uppercase' }}>
                                {r.type}
                              </span>
                            </td>
                            <td style={{ padding: '12px 16px' }}>
                              <VerdictBadge verdict={r.verdict} />
                            </td>
                            <td style={{ padding: '12px 16px' }}>
                              {r.totalEngines !== undefined ? (
                                <span className="font-data-mono" style={{ color: (r.maliciousEngines || 0) > 0 ? 'var(--secondary)' : 'var(--success)', fontSize: '13px', fontWeight: 700 }}>
                                  {r.maliciousEngines}/{r.totalEngines}
                                </span>
                              ) : '—'}
                            </td>
                            <td style={{ padding: '12px 16px' }}>
                              <span className="font-code-sm" style={{ color: r.urlhausStatus === 'is_host' ? 'var(--secondary)' : 'var(--on-surface-variant)' }}>
                                {r.urlhausStatus || '—'}
                              </span>
                            </td>
                            <td style={{ padding: '12px 16px' }}>
                              <span className="font-code-sm" style={{ color: r.mbStatus === 'ok' ? 'var(--secondary)' : 'var(--on-surface-variant)' }}>
                                {r.mbStatus || '—'}
                              </span>
                            </td>
                            <td style={{ padding: '12px 16px' }}>
                              <span className="font-code-sm text-on-surface-variant">{r.lastAnalysis || '—'}</span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}

            {!scanned && !loading && (
              <div className="glass-card" style={{ padding: '64px', textAlign: 'center' }}>
                <span className="material-symbols-outlined" style={{ fontSize: '64px', color: 'var(--module-ioc)', marginBottom: '16px', display: 'block', opacity: 0.5 }}>travel_explore</span>
                <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '8px' }}>Ready to Hunt</h3>
                <p className="font-body-md text-on-surface-variant">Paste your IOC list on the left and click HUNT IOCs to start bulk threat intelligence lookups.</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
