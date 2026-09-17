import React from 'react';
import { NormalizedIp } from '../services/api';

interface CarrierCardProps {
  ipData: NormalizedIp;
  ip: string;
}

export const CarrierIntelligenceCard: React.FC<CarrierCardProps> = ({ ipData, ip }) => {
  const isMalicious = (ipData.stats?.malicious || 0) > 0;
  const carrierName = ipData.asOwner || ipData.network || 'Telecom / ISP Provider';

  return (
    <div className="glass-card animate-fade-in-up" style={{ padding: '28px', borderColor: 'rgba(255, 69, 0,0.3)', borderLeft: '4px solid var(--primary)' }}>
      {/* Top Badge & Carrier Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px', marginBottom: '24px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
            <span style={{ padding: '3px 10px', borderRadius: '999px', background: 'rgba(255, 69, 0,0.12)', border: '1px solid rgba(255, 69, 0,0.35)', color: 'var(--primary)', fontFamily: 'var(--font-mono)', fontSize: '11px', fontWeight: 700, letterSpacing: '0.05em' }}>
              📡 TELECOM &amp; CELLULAR CARRIER IP
            </span>
            <span style={{ padding: '3px 8px', borderRadius: '4px', background: 'rgba(255,255,255,0.05)', color: 'var(--on-surface-variant)', fontFamily: 'var(--font-mono)', fontSize: '10px' }}>
              Bypassed Web Heuristics
            </span>
          </div>
          <h2 className="font-headline-md text-on-surface" style={{ fontSize: '24px', margin: 0 }}>
            {carrierName}
          </h2>
          <div className="font-code-sm text-on-surface-variant" style={{ marginTop: '4px' }}>
            IP Address: <span className="text-primary font-data-mono">{ip}</span>
          </div>
        </div>

        {/* Threat Status Badge */}
        <div style={{ padding: '10px 16px', borderRadius: '8px', background: isMalicious ? 'rgba(255,0,60,0.12)' : 'rgba(0,255,163,0.1)', border: `1px solid ${isMalicious ? 'rgba(255,0,60,0.4)' : 'rgba(0,255,163,0.3)'}`, textAlign: 'right' }}>
          <div className="font-label-caps" style={{ fontSize: '10px', color: isMalicious ? 'var(--secondary)' : 'var(--success)' }}>
            IP REPUTATION
          </div>
          <div className="font-data-mono" style={{ fontSize: '15px', fontWeight: 700, color: isMalicious ? 'var(--secondary)' : 'var(--success)' }}>
            {isMalicious ? `${ipData.stats.malicious} Engines Flagged` : 'Clean Carrier Route'}
          </div>
        </div>
      </div>

      {/* Notice Banner */}
      <div style={{ padding: '12px 16px', borderRadius: '8px', background: 'rgba(255, 69, 0,0.04)', border: '1px solid rgba(255, 69, 0,0.15)', marginBottom: '24px', display: 'flex', alignItems: 'center', gap: '12px' }}>
        <span className="material-symbols-outlined text-primary" style={{ fontSize: '20px' }}>info</span>
        <span className="font-code-sm text-on-surface-variant" style={{ fontSize: '12px' }}>
          This IP belongs to a telecom carrier (e.g. Jio, Vi, Airtel, AT&amp;T, Verizon). Web phishing algorithms (PhishGuard) and website crawling (WebFox) are automatically bypassed for cellular network infrastructure.
        </span>
      </div>

      {/* Network Metadata Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px' }}>
        <div style={{ padding: '14px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
          <div className="font-label-caps text-on-surface-variant" style={{ fontSize: '10px' }}>AUTONOMOUS SYSTEM</div>
          <div className="font-data-mono text-primary" style={{ fontSize: '14px', fontWeight: 700, marginTop: '4px' }}>
            {ipData.asn ? `AS${ipData.asn}` : 'N/A'}
          </div>
        </div>

        <div style={{ padding: '14px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
          <div className="font-label-caps text-on-surface-variant" style={{ fontSize: '10px' }}>CARRIER / ISP</div>
          <div className="font-data-mono text-on-surface" style={{ fontSize: '13px', marginTop: '4px', wordBreak: 'break-all' }}>
            {ipData.asOwner || ipData.network || 'Mobile Carrier'}
          </div>
        </div>

        <div style={{ padding: '14px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
          <div className="font-label-caps text-on-surface-variant" style={{ fontSize: '10px' }}>COUNTRY / LOCATION</div>
          <div className="font-data-mono text-on-surface" style={{ fontSize: '13px', marginTop: '4px' }}>
            {ipData.country || 'Global'}
          </div>
        </div>

        <div style={{ padding: '14px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
          <div className="font-label-caps text-on-surface-variant" style={{ fontSize: '10px' }}>COMMUNITY SCORE</div>
          <div className="font-data-mono text-success" style={{ fontSize: '13px', marginTop: '4px' }}>
            {ipData.reputation ?? 0} pts
          </div>
        </div>
      </div>
    </div>
  );
};
