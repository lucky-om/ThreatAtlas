import React, { useState } from 'react';
import { WebFoxReconResult } from '../services/webfox';

interface WebFoxCardProps {
  recon: WebFoxReconResult;
  loading?: boolean;
}

export const WebFoxCard: React.FC<WebFoxCardProps> = ({ recon, loading }) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'dns' | 'subs' | 'tech' | 'headers' | 'crawl' | 'ports' | 'cves' | 'ssl'>('overview');

  const tabs: Array<{ id: typeof activeTab; label: string; icon: string; count?: number }> = [
    { id: 'overview', label: 'OVERVIEW', icon: 'dashboard' },
    { id: 'dns',      label: 'DNS',      icon: 'dns',       count: recon.dnsRecords?.length },
    { id: 'subs',     label: 'SUBS',     icon: 'lan',       count: recon.subdomains?.length },
    { id: 'tech',     label: 'STACK',    icon: 'memory',    count: recon.techStack?.detectedTechs?.length },
    { id: 'headers',  label: 'HEADERS',  icon: 'security',  count: recon.securityHeaders?.filter(h => h.present).length },
    { id: 'crawl',    label: 'CRAWL',    icon: 'spider',    count: (recon.crawl?.jsSecrets?.length || 0) + (recon.crawl?.jsEndpoints?.length || 0) },
    { id: 'ports',    label: 'PORTS',    icon: 'router',    count: recon.openPorts?.length },
    { id: 'ssl',      label: 'SSL/TLS',  icon: 'lock',      count: recon.sslCert ? 1 : 0 }
  ];

  const criticalPaths  = recon.techStack?.exposedPaths?.filter(p => p.risk === 'critical') ?? [];
  const exposedCount   = recon.techStack?.exposedPaths?.length ?? 0;

  const headerScore    = recon.headerSecurityScore;
  const scoreColor     = headerScore >= 70 ? 'var(--brand-amber)' : headerScore >= 40 ? '#f59e0b' : '#ff2a5f';
  const activePorts = recon.ports ? Object.entries(recon.ports).filter(([_, status]) => status === 'open').map(([p]) => Number(p)) : recon.openPorts;

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
                { label: 'SERVER LIVENESS', value: recon.liveness ? (recon.liveness.isAlive ? `HTTP ${recon.liveness.statusCode}` : 'Offline') : 'Unknown', color: recon.liveness?.isAlive ? 'var(--success)' : '#ff2a5f' },
                { label: 'PRIMARY IP (A)', value: recon.ip || '—', color: 'var(--primary)' },
                { label: 'DOMAIN REGISTRAR', value: recon.whois?.registrar || 'Not Disclosed', color: 'var(--on-surface)' },
                { label: 'DOMAIN AGE', value: recon.whois?.domainAgeDays ? `${recon.whois.domainAgeDays}d old` : 'Unknown', color: (recon.whois?.domainAgeDays ?? 999) < 30 ? '#ff003c' : 'var(--brand-amber)' },
                { label: 'EDGE WAF', value: recon.wafDetected || 'None Detected', color: recon.wafDetected ? 'var(--brand-amber)' : '#64748b' },
                { label: 'HEADER SECURITY', value: `${headerScore}%`, color: scoreColor },
                { label: 'SUBDOMAINS FOUND', value: `${recon.subdomains?.length || 0} live`, color: 'var(--on-surface)' },
                { label: 'SSL CERTIFICATE', value: recon.sslCert ? (recon.sslCert.isValid ? 'Valid' : 'Invalid/Expired') : 'Unknown', color: recon.sslCert?.isValid ? 'var(--success)' : '#ff2a5f' },
                { label: 'OPEN PORTS', value: activePorts ? `${activePorts.length} open` : 'Unknown', color: activePorts && activePorts.length > 3 ? '#fb923c' : 'var(--on-surface)' },
                { label: 'EXPOSED PATHS', value: exposedCount > 0 ? `${exposedCount} exposed` : 'None', color: exposedCount > 0 ? '#ff2a5f' : 'var(--brand-amber)' },
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
                  <span style={{ fontSize: '10px', padding: '2px 7px', borderRadius: '4px', background: 'rgba(255, 107, 53,0.15)', color: 'var(--primary)', fontFamily: 'var(--font-mono)', fontWeight: 700, minWidth: '44px', textAlign: 'center' }}>
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
          {activeTab === 'subs' && (
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

              {/* Extracted Metadata */}
              {recon.techStack?.metadata && (recon.techStack.metadata.title || recon.techStack.metadata.description) && (
                <div style={{ padding: '12px 14px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)', marginBottom: '8px' }}>PAGE METADATA</div>
                  {recon.techStack.metadata.title && (
                    <div style={{ fontSize: '13px', color: 'var(--on-surface)', fontWeight: 600 }}>{recon.techStack.metadata.title}</div>
                  )}
                  {recon.techStack.metadata.description && (
                    <div style={{ fontSize: '12px', color: 'var(--on-surface-variant)', marginTop: '4px' }}>{recon.techStack.metadata.description}</div>
                  )}
                </div>
              )}

              {/* Detected Technologies */}
              {recon.techStack && recon.techStack.detectedTechs.length > 0 && (
                <div>
                  <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)', marginBottom: '8px' }}>DETECTED TECHNOLOGIES ({recon.techStack.detectedTechs.length})</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                    {recon.techStack.detectedTechs.map((tech, i) => (
                      <span key={i} style={{ padding: '4px 10px', borderRadius: '6px', background: 'rgba(255, 69, 0,0.08)', border: '1px solid rgba(255, 69, 0,0.25)', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--brand)', fontWeight: 600 }}>
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

          {/* ── PORTS TAB ── */}
          {activeTab === 'ports' && (
            <div>
              <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)', marginBottom: '10px' }}>
                Open ports discovered via Active TCP Scan (and Shodan InternetDB)
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                {activePorts && activePorts.length > 0 ? activePorts.map((port, i) => (
                  <span key={i} style={{ padding: '8px 14px', borderRadius: '6px', background: 'rgba(255,107,53,0.1)', border: '1px solid rgba(255,107,53,0.3)', fontFamily: 'var(--font-mono)', fontSize: '13px', color: 'var(--primary)', fontWeight: 700 }}>
                    PORT {port}
                  </span>
                )) : (
                  <span style={{ color: '#64748b', fontSize: '13px' }}>No open ports reported for this IP.</span>
                )}
              </div>
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
                  <span className="material-symbols-outlined" style={{ fontSize: '14px', color: hdr.present ? 'var(--brand-amber)' : '#ff2a5f' }}>
                    {hdr.present ? 'check_circle' : 'cancel'}
                  </span>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--on-surface)', fontWeight: 600 }}>
                      {hdr.header}
                    </div>
                    <div style={{ fontSize: '10px', color: '#64748b', marginTop: '1px' }}>{hdr.description}</div>
                    {hdr.present && hdr.value && (
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--brand-amber)', marginTop: '2px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '400px' }}>
                        {hdr.value}
                      </div>
                    )}
                  </div>
                  <span style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', color: '#64748b' }}>+{hdr.weight}pt</span>
                </div>
              ))}
            </div>
          )}

          {/* ── CRAWL TAB ── */}
          {activeTab === 'crawl' && recon.crawl && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
              
              {/* JS Secrets */}
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                  <span className="material-symbols-outlined" style={{ fontSize: '16px', color: '#ff2a5f' }}>key</span>
                  <span className="font-label-caps text-on-surface" style={{ fontSize: '11px' }}>JS Secrets & API Keys</span>
                  <span style={{ marginLeft: 'auto', background: 'rgba(255,255,255,0.05)', padding: '2px 6px', borderRadius: '4px', fontSize: '10px' }}>{recon.crawl.jsSecrets.length} found</span>
                </div>
                {recon.crawl.jsSecrets.length > 0 ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    {recon.crawl.jsSecrets.map((sec, i) => (
                      <div key={i} style={{ background: 'rgba(255,42,95,0.05)', border: '1px solid rgba(255,42,95,0.1)', padding: '8px', borderRadius: '6px' }}>
                        <div style={{ fontSize: '10px', color: '#ff2a5f', fontWeight: 700, marginBottom: '4px' }}>{sec.type}</div>
                        <div className="font-data-mono" style={{ fontSize: '11px', color: '#e2e8f0', wordBreak: 'break-all' }}>{sec.value}</div>
                        <div style={{ fontSize: '9px', color: '#64748b', marginTop: '4px', textAlign: 'right' }}>Found in: {sec.file}</div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{ fontSize: '11px', color: '#64748b' }}>No hardcoded secrets detected in JS.</div>
                )}
              </div>

              {/* API Endpoints */}
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                  <span className="material-symbols-outlined" style={{ fontSize: '16px', color: 'var(--primary)' }}>api</span>
                  <span className="font-label-caps text-on-surface" style={{ fontSize: '11px' }}>Extracted API Endpoints</span>
                  <span style={{ marginLeft: 'auto', background: 'rgba(255,255,255,0.05)', padding: '2px 6px', borderRadius: '4px', fontSize: '10px' }}>{recon.crawl.jsEndpoints.length} found</span>
                </div>
                {recon.crawl.jsEndpoints.length > 0 ? (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                    {recon.crawl.jsEndpoints.map((ep, i) => (
                      <span key={i} className="font-data-mono" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)', padding: '4px 8px', borderRadius: '4px', fontSize: '10px', color: '#e2e8f0' }}>
                        {ep}
                      </span>
                    ))}
                  </div>
                ) : (
                  <div style={{ fontSize: '11px', color: '#64748b' }}>No inline endpoints detected.</div>
                )}
              </div>

              {/* Robots & Sitemap */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                <div style={{ background: 'rgba(255,255,255,0.02)', padding: '10px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.05)', display: 'flex', flexDirection: 'column' }}>
                  <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--on-surface)', marginBottom: '6px' }}>Robots.txt</div>
                  {recon.crawl.robots.found ? (
                    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
                      <div style={{ fontSize: '10px', color: '#94a3b8', marginBottom: '6px' }}>
                        Disallowed: {recon.crawl.robots.disallowed.length} 
                        {recon.crawl.robots.flagged.length > 0 && <span style={{ color: '#ff2a5f', marginLeft: '6px' }}>⚠ High Risk: {recon.crawl.robots.flagged.length} paths</span>}
                      </div>
                      <pre className="custom-scrollbar" style={{ flex: 1, maxHeight: '150px', overflowY: 'auto', background: 'rgba(0,0,0,0.3)', padding: '8px', borderRadius: '4px', fontSize: '10px', color: '#e2e8f0', margin: 0, whiteSpace: 'pre-wrap' }}>
                        {recon.crawl.robots.raw}
                      </pre>
                    </div>
                  ) : <div style={{ fontSize: '10px', color: '#64748b' }}>Not found</div>}
                </div>

                <div style={{ background: 'rgba(255,255,255,0.02)', padding: '10px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.05)', display: 'flex', flexDirection: 'column' }}>
                  <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--on-surface)', marginBottom: '6px' }}>Sitemap.xml</div>
                  {recon.crawl.sitemap.found ? (
                    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
                      <div style={{ fontSize: '10px', color: '#94a3b8', marginBottom: '6px' }}>Urls Extracted: {recon.crawl.sitemap.urls.length}</div>
                      <pre className="custom-scrollbar" style={{ flex: 1, maxHeight: '150px', overflowY: 'auto', background: 'rgba(0,0,0,0.3)', padding: '8px', borderRadius: '4px', fontSize: '10px', color: '#e2e8f0', margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                        {recon.crawl.sitemap.urls.join('\n')}
                      </pre>
                    </div>
                  ) : <div style={{ fontSize: '10px', color: '#64748b' }}>Not found</div>}
                </div>
              </div>

            </div>
          )}

          {/* ── SSL/TLS TAB ── */}
          {activeTab === 'ssl' && recon.sslCert && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '14px', borderRadius: '8px', background: recon.sslCert.isValid ? 'rgba(0,232,122,0.05)' : 'rgba(255,42,95,0.05)', border: `1px solid ${recon.sslCert.isValid ? 'rgba(0,232,122,0.2)' : 'rgba(255,42,95,0.2)'}` }}>
                <span className="material-symbols-outlined" style={{ fontSize: '24px', color: recon.sslCert.isValid ? 'var(--success)' : 'var(--status-malicious)' }}>
                  {recon.sslCert.isValid ? 'lock' : 'lock_open_right'}
                </span>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 700, color: recon.sslCert.isValid ? 'var(--success)' : 'var(--status-malicious)' }}>
                    {recon.sslCert.isValid ? 'Valid Certificate' : 'Invalid / Expired Certificate'}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--on-surface-3)' }}>
                    Expires in {recon.sslCert.daysLeft} days
                  </div>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                <div style={{ background: 'rgba(255,255,255,0.02)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.05)' }}>
                  <div style={{ fontSize: '10px', color: 'var(--on-surface-variant)', fontFamily: 'var(--font-mono)' }}>ISSUER</div>
                  <div style={{ fontSize: '12px', color: 'var(--on-surface)', fontFamily: 'var(--font-mono)', marginTop: '4px' }}>{recon.sslCert.issuer}</div>
                </div>
                <div style={{ background: 'rgba(255,255,255,0.02)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.05)' }}>
                  <div style={{ fontSize: '10px', color: 'var(--on-surface-variant)', fontFamily: 'var(--font-mono)' }}>COMMON NAME</div>
                  <div style={{ fontSize: '12px', color: 'var(--on-surface)', fontFamily: 'var(--font-mono)', marginTop: '4px' }}>{recon.sslCert.commonName}</div>
                </div>
                <div style={{ background: 'rgba(255,255,255,0.02)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.05)' }}>
                  <div style={{ fontSize: '10px', color: 'var(--on-surface-variant)', fontFamily: 'var(--font-mono)' }}>VALID FROM</div>
                  <div style={{ fontSize: '12px', color: 'var(--on-surface)', fontFamily: 'var(--font-mono)', marginTop: '4px' }}>{new Date(recon.sslCert.validFrom).toLocaleDateString()}</div>
                </div>
                <div style={{ background: 'rgba(255,255,255,0.02)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.05)' }}>
                  <div style={{ fontSize: '10px', color: 'var(--on-surface-variant)', fontFamily: 'var(--font-mono)' }}>VALID TO</div>
                  <div style={{ fontSize: '12px', color: 'var(--on-surface)', fontFamily: 'var(--font-mono)', marginTop: '4px' }}>{new Date(recon.sslCert.validTo).toLocaleDateString()}</div>
                </div>
                <div style={{ gridColumn: 'span 2', background: 'rgba(255,255,255,0.02)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.05)' }}>
                  <div style={{ fontSize: '10px', color: 'var(--on-surface-variant)', fontFamily: 'var(--font-mono)' }}>SHA-1 FINGERPRINT</div>
                  <div className="font-data-mono" style={{ fontSize: '11px', color: 'var(--on-surface)', marginTop: '4px', wordBreak: 'break-all' }}>{recon.sslCert.fingerprint}</div>
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
};
