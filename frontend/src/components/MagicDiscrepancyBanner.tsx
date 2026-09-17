import React from 'react';
import { MagicDiscrepancyReport } from '../services/mediaForensics';

interface MagicDiscrepancyBannerProps {
  discrepancy: MagicDiscrepancyReport;
}

export const MagicDiscrepancyBanner: React.FC<MagicDiscrepancyBannerProps> = ({ discrepancy }) => {
  if (!discrepancy.hasDiscrepancy) return null;

  return (
    <div style={{
      background: 'rgba(255, 42, 95, 0.08)',
      border: '1px solid rgba(255, 42, 95, 0.4)',
      borderRadius: '10px',
      padding: '16px 20px',
      display: 'flex',
      alignItems: 'center',
      gap: '14px',
      marginBottom: '16px'
    }}>
      <span className="material-symbols-outlined" style={{ color: '#ff2a5f', fontSize: '32px' }}>
        warning
      </span>
      <div style={{ flex: 1 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '2px' }}>
          <span style={{ fontSize: '13px', fontWeight: 800, color: '#ff2a5f', fontFamily: 'var(--font-mono)' }}>
            ⚠️ CRITICAL MASQUERADING ATTACK DETECTED (MAGIC BYTE MISMATCH)
          </span>
        </div>
        <div style={{ fontSize: '12px', color: '#cbd5e1', lineHeight: 1.5 }}>
          {discrepancy.explanation} (Declared Extension: <strong style={{ color: '#ff2a5f' }}>.{discrepancy.declaredExtension}</strong> ➔ Actual Content: <strong style={{ color: 'var(--brand)' }}>{discrepancy.actualFileType}</strong>)
        </div>
      </div>
    </div>
  );
};
