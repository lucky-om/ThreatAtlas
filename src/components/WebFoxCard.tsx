import React from 'react';
import { Link } from 'react-router-dom';
import { WebFoxReconResult } from '../services/webfox';

interface WebFoxCardProps {
  recon: WebFoxReconResult;
  loading?: boolean;
}

export const WebFoxCard: React.FC<WebFoxCardProps> = ({ recon, loading }) => {
  return (
    <div className="glass-card animate-fade-in-up" style={{ padding: '24px', border: '1px solid rgba(245,158,11,0.3)', position: 'relative', overflow: 'hidden' }}>
      
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '20px', borderBottom: '1px solid rgba(255,255,255,0.06)', paddingBottom: '16px' }}>
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
                Recon Core
              </span>
            </div>
            <p className="font-code-sm text-on-surface-variant" style={{ fontSize: '12px', marginTop: '2px' }}>
              DNS over HTTPS • Subdomains • RDAP WHOIS • Edge WAF Detection
            </p>
          </div>
        </div>

        {/* Action Button: Deep WebScan Console */}
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
          <span>Open Full WebScan</span>
          <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>open_in_new</span>
        </Link>
      </div>

      {loading ? (
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '24px', justifyContent: 'center' }}>
          <span className="material-symbols-outlined spin text-primary" style={{ fontSize: '20px' }}>sync</span>
          <span className="font-code-sm text-on-surface-variant">WebFox resolving DoH DNS & infrastructure telemetry...</span>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          
          {/* Summary Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
            
            <div style={{ padding: '12px 14px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
              <div className="font-label-caps text-on-surface-variant" style={{ fontSize: '10px' }}>PRIMARY IP (A RECORD)</div>
              <div className="font-data-mono text-primary" style={{ fontSize: '13px', marginTop: '4px', fontWeight: 700 }}>
                {recon.ip || 'Resolving...'}
              </div>
            </div>

            <div style={{ padding: '12px 14px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
              <div className="font-label-caps text-on-surface-variant" style={{ fontSize: '10px' }}>DOMAIN REGISTRAR</div>
              <div className="font-data-mono text-on-surface" style={{ fontSize: '12px', marginTop: '4px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {recon.whois?.registrar || 'Not Disclosed / RDAP Pending'}
              </div>
            </div>

            <div style={{ padding: '12px 14px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
              <div className="font-label-caps text-on-surface-variant" style={{ fontSize: '10px' }}>DOMAIN AGE</div>
              <div className="font-data-mono" style={{ fontSize: '12px', marginTop: '4px', color: (recon.whois?.domainAgeDays ?? 999) < 30 ? '#ff003c' : 'var(--success)' }}>
                {recon.whois?.domainAgeDays ? `${recon.whois.domainAgeDays} days old` : 'Unknown'}
              </div>
            </div>

            <div style={{ padding: '12px 14px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
              <div className="font-label-caps text-on-surface-variant" style={{ fontSize: '10px' }}>EDGE WAF PROTECTION</div>
              <div className="font-data-mono" style={{ fontSize: '12px', marginTop: '4px', color: recon.wafDetected ? 'var(--success)' : 'var(--on-surface-variant)' }}>
                {recon.wafDetected || 'Direct Origin / None'}
              </div>
            </div>

          </div>

          {/* DNS Records Table */}
          {recon.dnsRecords && recon.dnsRecords.length > 0 && (
            <div>
              <div className="font-label-caps text-on-surface-variant" style={{ fontSize: '11px', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span className="material-symbols-outlined" style={{ fontSize: '16px', color: '#f59e0b' }}>dns</span>
                RESOLVED DNS OVER HTTPS (DoH) RECORDS ({recon.dnsRecords.length})
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '8px' }}>
                {recon.dnsRecords.slice(0, 6).map((rec, i) => (
                  <div key={i} style={{ padding: '8px 12px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.05)', display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <span style={{ fontSize: '10px', padding: '2px 6px', borderRadius: '4px', background: 'rgba(185,66,255,0.15)', color: 'var(--primary)', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                      {rec.type}
                    </span>
                    <span className="font-data-mono text-on-surface" style={{ fontSize: '11px', wordBreak: 'break-all' }}>
                      {rec.value}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Discovered Subdomains Preview */}
          {recon.subdomains && recon.subdomains.length > 0 && (
            <div>
              <div className="font-label-caps text-on-surface-variant" style={{ fontSize: '11px', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span className="material-symbols-outlined" style={{ fontSize: '16px', color: '#f59e0b' }}>account_tree</span>
                ENUMERATED SUBDOMAINS ({recon.subdomains.length})
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                {recon.subdomains.slice(0, 8).map((sub, i) => (
                  <span key={i} style={{ padding: '4px 10px', borderRadius: '6px', background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--on-surface-variant)' }}>
                    {sub}
                  </span>
                ))}
              </div>
            </div>
          )}

        </div>
      )}

    </div>
  );
};
