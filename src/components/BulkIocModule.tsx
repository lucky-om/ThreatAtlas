import React, { useState, useCallback } from 'react';
import { detectInputType } from '../services/api';
import { sanitizeInput } from '../utils/sanitize';

interface IocEntry {
  ioc: string;
  type: 'hash' | 'ip' | 'domain' | 'url' | 'unknown';
}

export interface IocResult {
  ioc: string;
  type: string;
  verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown' | 'error';
  maliciousEngines?: number;
  totalEngines?: number;
  lastAnalysis?: string;
  tags?: string[];
  error?: string;
}

const SAMPLE_IOCS = `185.220.101.45
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

export const BulkIocModule: React.FC = () => {
  const [rawInput, setRawInput] = useState(SAMPLE_IOCS);
  const [results, setResults] = useState<IocResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);

  const handleScan = useCallback(async () => {
    const entries = parseIocInput(rawInput);
    if (entries.length === 0) return;

    setLoading(true);
    setResults([]);
    setProgress(0);

    const out: IocResult[] = [];
    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      const vt = await lookupVt(entry);
      const res: IocResult = {
        ioc: entry.ioc,
        type: entry.type,
        verdict: (vt.verdict as any) || 'unknown',
        maliciousEngines: vt.maliciousEngines,
        totalEngines: vt.totalEngines,
        lastAnalysis: vt.lastAnalysis,
        tags: vt.tags,
        error: vt.error,
      };
      out.push(res);
      setResults([...out]);
      setProgress(Math.round(((i + 1) / entries.length) * 100));
    }
    setLoading(false);
  }, [rawInput]);

  return (
    <div style={{ marginTop: '24px', padding: '24px', background: 'rgba(255,255,255,0.02)', borderRadius: '12px', border: '1px solid rgba(0,242,255,0.2)' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h4 className="font-headline-sm text-on-surface" style={{ fontSize: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="material-symbols-outlined text-primary" style={{ fontSize: '20px' }}>travel_explore</span>
            Batch Multi-IOC Threat Hunter
          </h4>
          <p className="font-code-sm text-on-surface-variant" style={{ fontSize: '11px', marginTop: '2px' }}>
            Paste mixed lists of IPs, domains, hashes, and URLs (one per line) for concurrent multi-engine analysis.
          </p>
        </div>
      </div>

      <textarea
        value={rawInput}
        onChange={e => setRawInput(e.target.value)}
        disabled={loading}
        className="font-data-mono"
        style={{
          width: '100%', height: '140px', background: 'rgba(0,0,0,0.4)',
          border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px',
          padding: '12px', color: 'var(--on-surface)', fontSize: '12px', resize: 'vertical',
        }}
      />

      <div style={{ marginTop: '12px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div className="font-code-sm text-on-surface-variant" style={{ fontSize: '11px' }}>
          {parseIocInput(rawInput).length} valid IOCs detected in batch
        </div>

        <button
          type="button"
          onClick={handleScan}
          disabled={loading || parseIocInput(rawInput).length === 0}
          style={{
            padding: '10px 24px', borderRadius: '8px', background: 'var(--primary)',
            border: 'none', color: '#000000', fontFamily: 'var(--font-mono)',
            fontSize: '12px', fontWeight: 700, cursor: loading ? 'not-allowed' : 'pointer',
            display: 'flex', alignItems: 'center', gap: '6px',
          }}
        >
          {loading ? (
            <>
              <span className="material-symbols-outlined spin" style={{ fontSize: '16px' }}>sync</span>
              <span>BATCH SCANNING ({progress}%)...</span>
            </>
          ) : (
            <>
              <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>bolt</span>
              <span>HUNT BATCH IOCS</span>
            </>
          )}
        </button>
      </div>

      {/* Results Table */}
      {results.length > 0 && (
        <div style={{ marginTop: '18px', overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.1)', textAlign: 'left' }}>
                <th style={{ padding: '8px', color: 'var(--on-surface-variant)', fontFamily: 'var(--font-mono)' }}>IOC</th>
                <th style={{ padding: '8px', color: 'var(--on-surface-variant)', fontFamily: 'var(--font-mono)' }}>TYPE</th>
                <th style={{ padding: '8px', color: 'var(--on-surface-variant)', fontFamily: 'var(--font-mono)' }}>VERDICT</th>
                <th style={{ padding: '8px', color: 'var(--on-surface-variant)', fontFamily: 'var(--font-mono)' }}>ENGINES</th>
              </tr>
            </thead>
            <tbody>
              {results.map((r, i) => (
                <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                  <td className="font-data-mono text-primary" style={{ padding: '8px', wordBreak: 'break-all' }}>{r.ioc}</td>
                  <td className="font-code-sm text-on-surface-variant" style={{ padding: '8px', textTransform: 'uppercase' }}>{r.type}</td>
                  <td style={{ padding: '8px' }}>
                    <span style={{
                      padding: '2px 8px', borderRadius: '4px', fontFamily: 'var(--font-mono)', fontSize: '10px', fontWeight: 700,
                      background: r.verdict === 'malicious' ? 'rgba(255,0,60,0.15)' : r.verdict === 'suspicious' ? 'rgba(245,158,11,0.15)' : 'rgba(0,255,163,0.15)',
                      color: r.verdict === 'malicious' ? 'var(--secondary)' : r.verdict === 'suspicious' ? '#f59e0b' : 'var(--success)'
                    }}>
                      {r.verdict.toUpperCase()}
                    </span>
                  </td>
                  <td className="font-data-mono text-on-surface" style={{ padding: '8px' }}>
                    {r.maliciousEngines !== undefined ? `${r.maliciousEngines} / ${r.totalEngines}` : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
