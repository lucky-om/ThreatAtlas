import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { WebFoxReconResult } from '../services/webfox';

interface WebFoxCardProps {
  recon: WebFoxReconResult;
  loading?: boolean;
}

export const WebFoxCard: React.FC<WebFoxCardProps> = ({ recon, loading }) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'dns' | 'subdomains' | 'tech' | 'headers'>('overview');

  const tabs: Array<{ id: typeof activeTab; label: string; icon: string; count?: number }> = [
    { id: 'overview',   label: 'Overview',   icon: 'analytics' },
    { id: 'dns',        label: 'DNS',        icon: 'dns',        count: recon.dnsRecords?.length },
    { id: 'subdomains', label: 'Subdomains', icon: 'account_tree', count: recon.subdomains?.length },
    { id: 'tech',       label: 'Tech Stack', icon: 'code_blocks', count: recon.techStack?.detectedTechs?.length },
    { id: 'headers',    label: 'Headers',    icon: 'security',   count: recon.securityHeaders?.filter(h => h.present).length },
  ];

  const criticalPaths  = recon.techStack?.exposedPaths?.filter(p => p.risk === 'critical') ?? [];
  const exposedCount   = recon.techStack?.exposedPaths?.length ?? 0;

  const headerScore    = recon.headerSecurityScore;
  const scoreColor     = headerScore >= 70 ? '#00ffa3' : headerScore >= 40 ? '#f59e0b' : '#ff2a5f';

  return (
    <div className="glass-card animate-fade-in-up" style={{ padding: '24px', border: '1px solid rgba(245,158,11,0.3)', position: 'relative', overflow: 'hidden' }}>
      
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '16px', borderBottom: '1px solid rgba(255,255,255,0.06)', paddingBottom: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{
            width: '42px', height: '42px', borderRadius: '10px',
            background: 'rgba(245,158,11,0.15)', border: '1px solid rgba(245,158,11,0.4)',
            display: 'flex', alignItems: 'center', justifyContent: 'center'
          }}>
            <span className="material-symbols-outlined" style={{ fontSize: '24px', color: '#f59e0b' }}>travel_explore</span>
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h3 className="font-headline-sm text-on-surface" style={{ fontSize: '17px', fontWeight: 700 }}>WebFox Infrastructure Recon</h3>
              <span style={{ fontSize: '10px', padding: '2px 8px', borderRadius: '4px', background: 'rgba(245,158,11,0.12)', border: '1px solid rgba(245,158,11,0.3)', color: '#f59e0b', fontFamily: 'var(--font-mono)' }}>
                v2.0
              </span>
            </div>
            <p className="font-code-sm text-on-surface-variant" style={{ fontSize: '12px', marginTop: '2px' }}>
              DoH DNS · crt.sh + HackerTarget + AlienVault OTX · RDAP WHOIS · 23-WAF Detection · Tech Fingerprint
            </p>
          </div>
        </div>

        <Link
          to={`/webscan?domain=${encodeURIComponent(recon.domain)}`}
          style={{
            padding: '8px 16px', borderRadius: '8px',
            background: 'rgba(245,158,11,0.15)', border: '1px solid rgba(245,158,11,0.4)',
            color: '#f59e0b', fontFamily: 'var(--font-mono)', fontSize: '12px', fontWeight: 700,
            textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '6px',
            transition: 'all 0.15s'
          }}
          onMouseEnter={e => (e.currentTarget.style.background = 'rgba(245,158,11,0.25)')}
          onMouseLeave={e => (e.currentTarget.style.background = 'rgba(245,158,11,0.15)')}
        >
          <span>Full WebScan</span>
          <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>open_in_new</span>
        </Link>
      </div>

      {/* Critical Path Alert */}
      {criticalPaths.length > 0 && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '10px 14px', borderRadius: '8px', background: 'rgba(255,42,95,0.08)', border: '1px solid rgba(255,42,95,0.4)', marginBottom: '16px' }}>
          <span className="material-symbols-outlined" style={{ fontSize: '18px', color: '#ff2a5f' }}>warning</span>
          <div>
            <div style={{ fontSize: '13px', fontWeight: 700, color: '#ff2a5f' }}>
              {criticalPaths.length} Critical Exposure{criticalPaths.length > 1 ? 's' : ''} Detected
            </div>
            <div style={{ fontSize: '11px', color: '#94a3b8', fontFamily: 'var(--font-mono)', marginTop: '2px' }}>
              {criticalPaths.slice(0, 2).map(p => p.path.split('/').slice(-1)[0]).join(', ')} {criticalPaths.length > 2 ? `+${criticalPaths.length - 2} more` : ''}
            </div>
          </div>
        </div>
      )}

      {loading ? (
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '24px', justifyContent: 'center' }}>
          <span className="material-symbols-outlined spin text-primary" style={{ fontSize: '20px' }}>sync</span>
          <span className="font-code-sm text-on-surface-variant">WebFox running multi-source recon (DNS · Subdomains · Tech Stack)...</span>
        </div>
      ) : (
        <>
          {/* Tab Bar */}
          <div style={{ display: 'flex', gap: '4px', marginBottom: '16px', flexWrap: 'wrap' }}>
            {tabs.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                style={{
                  display: 'flex', alignItems: 'center', gap: '6px',
                  padding: '7px 13px', borderRadius: '7px', cursor: 'pointer',
                  background: activeTab === tab.id ? 'rgba(245,158,11,0.15)' : 'transparent',
                  border: `1px solid ${activeTab === tab.id ? 'rgba(245,158,11,0.5)' : 'rgba(255,255,255,0.08)'}`,
                  color: activeTab === tab.id ? '#f59e0b' : '#64748b',
                  fontFamily: 'var(--font-mono)', fontSize: '11px', fontWeight: 700,
                  transition: 'all 0.15s'
                }}
              >
                <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>{tab.icon}</span>
                {tab.label}
                {tab.count !== undefined && tab.count > 0 && (
                  <span style={{ padding: '1px 5px', borderRadius: '4px', background: 'rgba(245,158,11,0.2)', fontSize: '10px' }}>
                    {tab.count}
                  </span>
                )}
              </button>
            ))}
          </div>

          {/* ── OVERVIEW TAB ── */}
          {activeTab === 'overview' && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '10px' }}>
              {[
                { label: 'PRIMARY IP (A)', value: recon.ip || '—', color: 'var(--primary)' },
                { label: 'DOMAIN REGISTRAR', value: recon.whois?.registrar || 'Not Disclosed', color: 'var(--on-surface)' },
                { label: 'DOMAIN AGE', value: recon.whois?.domainAgeDays ? `${recon.whois.domainAgeDays}d old` : 'Unknown', color: (recon.whois?.domainAgeDays ?? 999) < 30 ? '#ff003c' : '#00ffa3' },
                { label: 'EDGE WAF', value: recon.wafDetected || 'None Detected', color: recon.wafDetected ? '#00ffa3' : '#64748b' },
                { label: 'HEADER SECURITY', value: `${headerScore}%`, color: scoreColor },
                { label: 'SUBDOMAINS FOUND', value: `${recon.subdomains?.length || 0} live`, color: 'var(--on-surface)' },
                { label: 'EXPOSED PATHS', value: exposedCount > 0 ? `${exposedCount} exposed` : 'None', color: exposedCount > 0 ? '#ff2a5f' : '#00ffa3' },
                { label: 'RECON LATENCY', value: recon.latencyMs ? `${recon.latencyMs}ms` : '—', color: '#64748b' },
              ].map((item, i) => (
                <div key={i} style={{ padding: '12px 14px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div className="font-label-caps text-on-surface-variant" style={{ fontSize: '10px' }}>{item.label}</div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', marginTop: '4px', color: item.color, fontWeight: 700, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {item.value}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* ── DNS TAB ── */}
          {activeTab === 'dns' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {recon.dnsRecords && recon.dnsRecords.length > 0 ? recon.dnsRecords.map((rec, i) => (
                <div key={i} style={{ padding: '8px 12px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.05)', display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span style={{ fontSize: '10px', padding: '2px 7px', borderRadius: '4px', background: 'rgba(185,66,255,0.15)', color: 'var(--primary)', fontFamily: 'var(--font-mono)', fontWeight: 700, minWidth: '44px', textAlign: 'center' }}>
                    {rec.type}
                  </span>
                  <span className="font-data-mono text-on-surface" style={{ fontSize: '11px', wordBreak: 'break-all', flex: 1 }}>
                    {rec.value}
                  </span>
                  {rec.ttl && (
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: '#64748b' }}>TTL {rec.ttl}s</span>
                  )}
                </div>
              )) : (
                <div style={{ textAlign: 'center', color: '#64748b', padding: '24px', fontSize: '13px' }}>No DNS records resolved</div>
              )}
            </div>
          )}

          {/* ── SUBDOMAINS TAB ── */}
          {activeTab === 'subdomains' && (
            <div>
              <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)', marginBottom: '10px' }}>
                Sources: crt.sh Certificate Transparency · HackerTarget · AlienVault OTX Passive DNS
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                {recon.subdomains && recon.subdomains.length > 0 ? recon.subdomains.map((sub, i) => (
                  <span key={i} style={{ padding: '5px 10px', borderRadius: '6px', background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--on-surface-variant)' }}>
                    {sub}
                  </span>
                )) : (
                  <span style={{ color: '#64748b', fontSize: '13px' }}>No subdomains discovered via public sources</span>
                )}
              </div>
            </div>
          )}

          {/* ── TECH STACK TAB ── */}
          {activeTab === 'tech' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {/* Server Info */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                <div style={{ padding: '10px 14px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div style={{ fontSize: '10px', color: '#64748b', fontFamily: 'var(--font-mono)' }}>SERVER BANNER</div>
                  <div style={{ fontSize: '12px', color: 'var(--on-surface)', fontFamily: 'var(--font-mono)', marginTop: '4px' }}>{recon.techStack?.serverBanner || '—'}</div>
                </div>
                <div style={{ padding: '10px 14px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div style={{ fontSize: '10px', color: '#64748b', fontFamily: 'var(--font-mono)' }}>POWERED BY</div>
                  <div style={{ fontSize: '12px', color: 'var(--on-surface)', fontFamily: 'var(--font-mono)', marginTop: '4px' }}>{recon.techStack?.poweredBy || '—'}</div>
                </div>
              </div>

              {/* Detected Technologies */}
              {recon.techStack && recon.techStack.detectedTechs.length > 0 && (
                <div>
                  <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)', marginBottom: '8px' }}>DETECTED TECHNOLOGIES ({recon.techStack.detectedTechs.length})</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                    {recon.techStack.detectedTechs.map((tech, i) => (
                      <span key={i} style={{ padding: '4px 10px', borderRadius: '6px', background: 'rgba(0,242,255,0.08)', border: '1px solid rgba(0,242,255,0.25)', fontFamily: 'var(--font-mono)', fontSize: '11px', color: '#00f2ff', fontWeight: 600 }}>
                        {tech}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Exposed Paths */}
              {recon.techStack && recon.techStack.exposedPaths.length > 0 && (
                <div>
                  <div style={{ fontSize: '11px', color: '#ff2a5f', fontFamily: 'var(--font-mono)', marginBottom: '8px' }}>
                    ⚠️ SENSITIVE PATHS EXPOSED ({recon.techStack.exposedPaths.length})
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    {recon.techStack.exposedPaths.map((p, i) => {
                      const riskColor = p.risk === 'critical' ? '#ff2a5f' : p.risk === 'high' ? '#fb923c' : '#f59e0b';
                      return (
                        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '8px 12px', borderRadius: '6px', background: `rgba(255,42,95,0.04)`, border: `1px solid ${riskColor}40` }}>
                          <span style={{ fontSize: '10px', padding: '2px 6px', borderRadius: '4px', background: `${riskColor}20`, color: riskColor, fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                            {p.risk.toUpperCase()}
                          </span>
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: '#e2e8f0', flex: 1, wordBreak: 'break-all' }}>
                            {p.path}
                          </span>
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: '#64748b' }}>
                            HTTP {p.status}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {(!recon.techStack || (recon.techStack.detectedTechs.length === 0 && recon.techStack.exposedPaths.length === 0)) && (
                <div style={{ textAlign: 'center', color: '#64748b', padding: '24px', fontSize: '13px' }}>
                  No tech stack signatures matched (CORS may restrict fingerprinting)
                </div>
              )}
            </div>
          )}

          {/* ── HEADERS TAB ── */}
          {activeTab === 'headers' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '10px' }}>
                <div style={{ fontSize: '24px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: scoreColor }}>
                  {headerScore}%
                </div>
                <div>
                  <div style={{ fontSize: '12px', color: 'var(--on-surface)', fontWeight: 600 }}>Security Header Score</div>
                  <div style={{ fontSize: '11px', color: '#64748b' }}>
                    {recon.securityHeaders?.filter(h => h.present).length ?? 0} / {recon.securityHeaders?.length ?? 0} headers present
                  </div>
                </div>
              </div>
              {recon.securityHeaders?.map((hdr, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '8px 12px', borderRadius: '6px', background: 'rgba(255,255,255,0.02)', border: `1px solid ${hdr.present ? 'rgba(0,255,163,0.2)' : 'rgba(255,42,95,0.15)'}` }}>
                  <span className="material-symbols-outlined" style={{ fontSize: '14px', color: hdr.present ? '#00ffa3' : '#ff2a5f' }}>
                    {hdr.present ? 'check_circle' : 'cancel'}
                  </span>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--on-surface)', fontWeight: 600 }}>
                      {hdr.header}
                    </div>
                    <div style={{ fontSize: '10px', color: '#64748b', marginTop: '1px' }}>{hdr.description}</div>
                    {hdr.present && hdr.value && (
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: '#00ffa3', marginTop: '2px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '400px' }}>
                        {hdr.value}
                      </div>
                    )}
                  </div>
                  <span style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', color: '#64748b' }}>+{hdr.weight}pt</span>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
};
