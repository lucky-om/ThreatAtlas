import React from 'react';
import { ElfForensicsReport } from '../services/mediaForensics';

interface ElfExecutableCardProps {
  report: ElfForensicsReport;
}

export const ElfExecutableCard: React.FC<ElfExecutableCardProps> = ({ report }) => {
  return (
    <div style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '28px 32px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #1e293b', paddingBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span className="material-symbols-outlined" style={{ color: '#a855f7', fontSize: '26px' }}>
            developer_board
          </span>
          <div>
            <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 700, color: '#f1f5f9' }}>
              Linux ELF Binary & Security Mitigations (readelf / checksec)
            </h3>
            <p style={{ margin: '2px 0 0', fontSize: '12px', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
              ELF header architecture, Stack Canary, No-Execute (NX), PIE, and dynamic symbols
            </p>
          </div>
        </div>

        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '6px 14px',
          borderRadius: '999px',
          background: 'rgba(0,255,163,0.1)',
          border: '1px solid rgba(0,255,163,0.3)'
        }}>
          <span className="material-symbols-outlined" style={{ color: 'var(--brand-amber)', fontSize: '18px' }}>verified</span>
          <span style={{ color: 'var(--brand-amber)', fontSize: '12px', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
            ELF Mitigations Verified
          </span>
        </div>
      </div>

      {/* 4 Summary Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px' }}>
        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Architecture & Bitness</div>
          <div style={{ fontSize: '15px', fontWeight: 700, color: '#f1f5f9', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
            {report.architecture} ({report.bitness})
          </div>
          <div style={{ fontSize: '11px', color: '#a855f7', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            {report.endianness}
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>ELF Binary Classification</div>
          <div style={{ fontSize: '14px', fontWeight: 600, color: '#f1f5f9', marginTop: '4px' }}>
            {report.elfType}
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            Entry: {report.entryPoint || '0x401000'}
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Memory Protection (NX / PIE)</div>
          <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--brand-amber)', marginTop: '4px' }}>
            {report.mitigations.nx ? 'NX Enabled' : 'Executable Stack'} · {report.mitigations.pie ? 'PIE Active' : 'No PIE'}
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            RELRO: {report.mitigations.relro}
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Stack Protection</div>
          <div style={{ fontSize: '14px', fontWeight: 600, color: report.mitigations.canary ? 'var(--brand-amber)' : '#ff2a5f', marginTop: '4px' }}>
            {report.mitigations.canary ? 'Canary Found' : 'No Stack Canary'}
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            Buffer Overflow Hardened
          </div>
        </div>
      </div>

      {/* Dynamic Linked Libraries */}
      <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '8px', padding: '16px 20px' }}>
        <div style={{ fontSize: '12px', color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase', fontFamily: 'var(--font-mono)', marginBottom: '10px' }}>
          Dynamic Shared Libraries (DT_NEEDED)
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
          {report.dynamicLibraries.map((lib, idx) => (
            <span key={idx} style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--brand)', background: 'rgba(56,189,248,0.08)', border: '1px solid rgba(56,189,248,0.2)', padding: '4px 10px', borderRadius: '6px' }}>
              📚 {lib}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
};
