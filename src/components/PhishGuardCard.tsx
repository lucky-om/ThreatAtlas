import React from 'react';
import { PhishGuardResult } from '../services/phishguard';

interface PhishGuardCardProps {
  result: PhishGuardResult;
  url: string;
}

export const PhishGuardCard: React.FC<PhishGuardCardProps> = ({ result, url }) => {
  const getRiskColor = (level: string) => {
    switch (level) {
      case 'Critical': return '#ff003c';
      case 'High': return '#ff5e00';
      case 'Medium': return '#f59e0b';
      case 'Low': return '#00f2ff';
      default: return '#00ffa3';
    }
  };

  const riskColor = getRiskColor(result.riskLevel);

  return (
    <div className="glass-card animate-fade-in-up" style={{ padding: '24px', border: `1px solid ${riskColor}40`, position: 'relative', overflow: 'hidden' }}>
      
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '20px', borderBottom: '1px solid rgba(255,255,255,0.06)', paddingBottom: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{
            width: '42px', height: '42px', borderRadius: '10px',
            background: `${riskColor}18`, border: `1px solid ${riskColor}50`,
            display: 'flex', alignItems: 'center', justifyContent: 'center'
          }}>
            <span className="material-symbols-outlined" style={{ fontSize: '24px', color: riskColor }}>phishing</span>
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h3 className="font-headline-sm text-on-surface" style={{ fontSize: '17px', fontWeight: 700 }}>PhishGuard Heuristic Analysis</h3>
              <span style={{ fontSize: '10px', padding: '2px 8px', borderRadius: '4px', background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)', color: 'var(--on-surface-variant)', fontFamily: 'var(--font-mono)' }}>
                v4.0.0 Engine
              </span>
            </div>
            <p className="font-code-sm text-on-surface-variant" style={{ fontSize: '12px', marginTop: '2px', wordBreak: 'break-all' }}>
              Inspecting: <span className="text-primary">{url || result.baseDomain}</span>
            </p>
          </div>
        </div>

        {/* Risk Score Badge */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ textAlign: 'right' }}>
            <div className="font-label-caps text-on-surface-variant" style={{ fontSize: '10px' }}>HEURISTIC RISK SCORE</div>
            <div className="font-data-mono" style={{ fontSize: '20px', fontWeight: 800, color: riskColor }}>
              {result.riskScore} <span style={{ fontSize: '12px', color: 'var(--on-surface-variant)' }}>/ 10</span>
            </div>
          </div>
          <div style={{
            padding: '6px 14px', borderRadius: '8px',
            background: `${riskColor}15`, border: `1px solid ${riskColor}60`,
            color: riskColor, fontFamily: 'var(--font-mono)', fontSize: '12px', fontWeight: 700,
            boxShadow: `0 0 16px ${riskColor}25`
          }}>
            {result.riskLevel.toUpperCase()} RISK
          </div>
        </div>
      </div>

      {/* Brand Impersonation Alert Banner */}
      {result.impersonatedBrand && (
        <div style={{
          padding: '14px 18px', borderRadius: '10px',
          background: 'rgba(255,0,60,0.12)', border: '1px solid rgba(255,0,60,0.4)',
          marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '12px'
        }}>
          <span className="material-symbols-outlined" style={{ fontSize: '22px', color: '#ff003c' }}>warning</span>
          <div>
            <div className="font-headline-sm text-on-surface" style={{ fontSize: '13px', fontWeight: 700, color: '#ff003c' }}>
              CRITICAL: Brand Impersonation Target Identified ({result.impersonatedBrand})
            </div>
            <div className="font-code-sm text-on-surface-variant" style={{ fontSize: '11px', marginTop: '2px' }}>
              Domain is crafted with visual typosquatting to mimic official {result.impersonatedBrand} authentication infrastructure.
            </div>
          </div>
        </div>
      )}

      {/* Grid Summary Metrics */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '12px', marginBottom: '20px' }}>
        
        <div style={{ padding: '12px 14px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
          <div className="font-label-caps text-on-surface-variant" style={{ fontSize: '10px' }}>BASE APEX DOMAIN</div>
          <div className="font-data-mono text-on-surface" style={{ fontSize: '12px', marginTop: '4px', wordBreak: 'break-all' }}>
            {result.baseDomain || 'N/A'}
          </div>
        </div>

        <div style={{ padding: '12px 14px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
          <div className="font-label-caps text-on-surface-variant" style={{ fontSize: '10px' }}>SHANNON ENTROPY</div>
          <div className="font-data-mono" style={{ fontSize: '12px', marginTop: '4px', color: result.entropy > 3.4 ? '#ff5e00' : 'var(--on-surface)' }}>
            {result.entropy.toFixed(2)} {result.entropy > 3.4 ? '⚠️ (High DGA)' : '✓ (Normal)'}
          </div>
        </div>

        <div style={{ padding: '12px 14px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
          <div className="font-label-caps text-on-surface-variant" style={{ fontSize: '10px' }}>IDN HOMOGRAPH</div>
          <div className="font-data-mono" style={{ fontSize: '12px', marginTop: '4px', color: result.isHomograph ? '#ff003c' : 'var(--success)' }}>
            {result.isHomograph ? '🚨 Punycode Detected' : '✓ Clean ASCII'}
          </div>
        </div>

        <div style={{ padding: '12px 14px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
          <div className="font-label-caps text-on-surface-variant" style={{ fontSize: '10px' }}>TLD CLASSIFICATION</div>
          <div className="font-data-mono text-on-surface" style={{ fontSize: '12px', marginTop: '4px' }}>
            .{result.tld || 'none'}
          </div>
        </div>

      </div>

      {/* Flagged Indicators List */}
      <div>
        <h4 className="font-label-caps text-on-surface-variant" style={{ fontSize: '11px', marginBottom: '10px' }}>
          HEURISTIC DETECTION SIGNATURES ({result.flags.length})
        </h4>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {result.flags.map((flag, idx) => {
            const isCrit = flag.type === 'critical';
            const isWarn = flag.type === 'warning';
            const isSafe = flag.type === 'safe';
            const borderColor = isCrit ? 'rgba(255,0,60,0.3)' : isWarn ? 'rgba(245,158,11,0.3)' : isSafe ? 'rgba(0,255,163,0.3)' : 'rgba(0,242,255,0.3)';
            const iconColor = isCrit ? '#ff003c' : isWarn ? '#f59e0b' : isSafe ? '#00ffa3' : '#00f2ff';
            const iconName = isCrit ? 'error' : isWarn ? 'warning' : isSafe ? 'check_circle' : 'info';

            return (
              <div
                key={idx}
                style={{
                  padding: '10px 14px', borderRadius: '8px',
                  background: 'rgba(255,255,255,0.02)',
                  border: `1px solid ${borderColor}`,
                  display: 'flex', alignItems: 'flex-start', gap: '10px'
                }}
              >
                <span className="material-symbols-outlined" style={{ fontSize: '18px', color: iconColor, marginTop: '2px', flexShrink: 0 }}>
                  {iconName}
                </span>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                    <span className="font-label-caps" style={{ fontSize: '10px', color: iconColor }}>
                      {flag.category}
                    </span>
                  </div>
                  <div className="font-code-sm text-on-surface" style={{ fontSize: '12px', marginTop: '2px', lineHeight: '1.5' }}>
                    {flag.message}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

    </div>
  );
};
