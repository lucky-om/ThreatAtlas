import React from 'react';
import { DnsRecord } from '../services/api';

interface DnsRecordsCardProps {
  records?: DnsRecord[];
}

export const DnsRecordsCard: React.FC<DnsRecordsCardProps> = ({ records }) => {
  if (!records || records.length === 0) return null;

  return (
    <div className="glass-card animate-fade-in-up" style={{ padding: '32px', marginBottom: '24px' }}>
      <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <span className="material-symbols-outlined text-primary">dns</span>
        DNS Records ({records.length})
      </h3>

      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
              <th className="font-label-caps text-on-surface-variant" style={{ padding: '12px', width: '120px' }}>Type</th>
              <th className="font-label-caps text-on-surface-variant" style={{ padding: '12px', width: '100px' }}>TTL</th>
              <th className="font-label-caps text-on-surface-variant" style={{ padding: '12px' }}>Value / Target</th>
            </tr>
          </thead>
          <tbody>
            {records.map((r, i) => (
              <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                <td style={{ padding: '12px' }}>
                  <span className="font-code-sm" style={{ padding: '2px 8px', background: 'rgba(0,242,255,0.1)', color: 'var(--primary)', borderRadius: '4px', border: '1px solid rgba(0,242,255,0.3)' }}>
                    {r.type}
                  </span>
                </td>
                <td style={{ padding: '12px' }} className="font-code-sm text-on-surface-variant">{r.ttl ? `${r.ttl}s` : '-'}</td>
                <td style={{ padding: '12px', wordBreak: 'break-all' }} className="font-data-mono text-on-surface">{r.value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
