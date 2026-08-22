import React, { useState } from 'react';
import { PeForensicsReport } from '../services/mediaForensics';

interface PeExecutableCardProps {
  report: PeForensicsReport;
}

export const PeExecutableCard: React.FC<PeExecutableCardProps> = ({ report }) => {
  const [activeTab, setActiveTab] = useState<'sections' | 'imports' | 'signatures'>('sections');
  const [importSearch, setImportSearch] = useState('');

  const threatColor = report.threatLevel === 'critical' ? '#ff2a5f' : report.threatLevel === 'suspicious' ? '#fb923c' : report.threatLevel === 'low' ? '#f59e0b' : '#00ffa3';

  const filteredImports = report.imports.filter(imp => {
    if (!importSearch) return true;
    return imp.library.toLowerCase().includes(importSearch.toLowerCase()) || 
           imp.functions.some(f => f.toLowerCase().includes(importSearch.toLowerCase()));
  });

  return (
    <div style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '28px 32px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #1e293b', paddingBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span className="material-symbols-outlined" style={{ color: '#38bdf8', fontSize: '26px' }}>
            terminal
          </span>
          <div>
            <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 700, color: '#f1f5f9' }}>
              Windows PE Executable Static Analysis (PEStudio / DIE)
            </h3>
            <p style={{ margin: '2px 0 0', fontSize: '12px', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
              Section entropy, suspicious Win32 APIs, compiler metadata & packing analysis
            </p>
          </div>
        </div>

        {/* Threat Score Badge */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '6px 14px',
          borderRadius: '999px',
          background: `${threatColor}15`,
          border: `1px solid ${threatColor}40`
        }}>
          <span className="material-symbols-outlined" style={{ color: threatColor, fontSize: '18px' }}>
            {report.threatScore > 0 ? 'warning' : 'verified'}
          </span>
          <span style={{ color: threatColor, fontSize: '12px', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
            PE Threat Score: {report.threatScore}/100 ({report.threatLevel.toUpperCase()})
          </span>
        </div>
      </div>

      {/* 4 Summary Metric Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px' }}>
        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Architecture & Subsystem</div>
          <div style={{ fontSize: '14px', fontWeight: 700, color: '#f1f5f9', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
            {report.machineType || 'x86_64'}
          </div>
          <div style={{ fontSize: '11px', color: '#38bdf8', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            {report.subsystem || 'Win32 GUI'}
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Packing & Obfuscation</div>
          <div style={{ fontSize: '14px', fontWeight: 700, color: report.isPacked ? '#ff2a5f' : '#00ffa3', marginTop: '4px' }}>
            {report.isPacked ? `Packed (${report.packerName || 'High Entropy'})` : 'Standard Binary'}
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            {report.entryPoint ? `Entry: ${report.entryPoint}` : 'Standard Entry'}
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Import Hash (Imphash)</div>
          <div style={{ fontSize: '12px', fontWeight: 600, color: '#f1f5f9', marginTop: '4px', fontFamily: 'var(--font-mono)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {report.imphash || 'N/A'}
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            {report.compileTimestamp ? `Built: ${report.compileTimestamp.slice(0, 10)}` : 'Compiler Timestamp Present'}
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Digital Signature</div>
          <div style={{ fontSize: '14px', fontWeight: 600, color: report.isSigned ? '#00ffa3' : '#94a3b8', marginTop: '4px' }}>
            {report.isSigned ? 'Digitally Signed' : 'Unsigned Binary'}
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {report.signerSubject || 'No Certificate Signer'}
          </div>
        </div>
      </div>

      {/* Sub Tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid #1e293b', gap: '4px' }}>
        {[
          { id: 'sections', label: '📊 Sections & Entropy Table', count: report.sections.length },
          { id: 'imports', label: '📦 Win32 Imports & Dangerous APIs', count: report.suspiciousApis.length },
          { id: 'signatures', label: '🛡️ Threat Signals & Hashes', count: report.signals.length }
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            style={{
              background: 'none',
              border: 'none',
              borderBottom: activeTab === tab.id ? '2px solid #38bdf8' : '2px solid transparent',
              padding: '8px 16px',
              color: activeTab === tab.id ? '#38bdf8' : '#94a3b8',
              fontFamily: 'var(--font-mono)',
              fontSize: '12px',
              fontWeight: activeTab === tab.id ? 700 : 500,
              cursor: 'pointer'
            }}
          >
            {tab.label} {tab.count > 0 && `(${tab.count})`}
          </button>
        ))}
      </div>

      {/* Tab 1: Sections & Entropy */}
      {activeTab === 'sections' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ overflowX: 'auto', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '8px' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
              <thead>
                <tr style={{ background: 'rgba(0,0,0,0.3)', color: '#64748b', textAlign: 'left', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                  <th style={{ padding: '10px 14px' }}>Section</th>
                  <th style={{ padding: '10px 14px' }}>Virtual Address</th>
                  <th style={{ padding: '10px 14px' }}>Virtual Size</th>
                  <th style={{ padding: '10px 14px' }}>Raw Size</th>
                  <th style={{ padding: '10px 14px' }}>Entropy (0-8)</th>
                  <th style={{ padding: '10px 14px' }}>Status</th>
                </tr>
              </thead>
              <tbody>
                {report.sections.map((sec, idx) => (
                  <tr key={idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)', background: sec.isSuspicious ? 'rgba(255,42,95,0.05)' : 'transparent' }}>
                    <td style={{ padding: '10px 14px', fontWeight: 700, color: sec.isSuspicious ? '#ff2a5f' : '#f1f5f9' }}>{sec.name}</td>
                    <td style={{ padding: '10px 14px', color: '#94a3b8' }}>{sec.virtualAddress}</td>
                    <td style={{ padding: '10px 14px', color: '#cbd5e1' }}>{sec.virtualSize.toLocaleString()} B</td>
                    <td style={{ padding: '10px 14px', color: '#cbd5e1' }}>{sec.rawSize.toLocaleString()} B</td>
                    <td style={{ padding: '10px 14px', color: sec.entropy > 7.0 ? '#ff2a5f' : sec.entropy > 6.0 ? '#fb923c' : '#00ffa3', fontWeight: 700 }}>
                      {sec.entropy.toFixed(2)}
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      <span style={{
                        padding: '2px 8px',
                        borderRadius: '4px',
                        fontSize: '10px',
                        fontWeight: 700,
                        background: sec.isSuspicious ? 'rgba(255,42,95,0.15)' : 'rgba(0,255,163,0.1)',
                        color: sec.isSuspicious ? '#ff2a5f' : '#00ffa3'
                      }}>
                        {sec.isSuspicious ? 'PACKED / ENCRYPTED' : 'NORMAL'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 2: Imports & APIs */}
      {activeTab === 'imports' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <input
            type="text"
            placeholder="Filter Win32 APIs or DLL libraries..."
            value={importSearch}
            onChange={e => setImportSearch(e.target.value)}
            style={{
              width: '100%',
              padding: '9px 12px',
              background: 'rgba(0,0,0,0.3)',
              border: '1px solid #334155',
              borderRadius: '8px',
              color: '#ffffff',
              fontSize: '12px',
              fontFamily: 'var(--font-mono)'
            }}
          />

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', maxHeight: '400px', overflowY: 'auto' }}>
            {filteredImports.map((imp, idx) => (
              <div key={idx} style={{ background: 'rgba(0,0,0,0.25)', border: `1px solid ${imp.isDangerous ? 'rgba(255,42,95,0.3)' : 'rgba(255,255,255,0.05)'}`, borderRadius: '8px', padding: '12px 16px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <span style={{ fontSize: '13px', fontWeight: 700, color: imp.isDangerous ? '#ff2a5f' : '#38bdf8', fontFamily: 'var(--font-mono)' }}>
                    📂 {imp.library}
                  </span>
                  <span style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
                    {imp.functions.length} functions
                  </span>
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                  {imp.functions.map((fn, fIdx) => (
                    <span key={fIdx} style={{
                      fontSize: '11px',
                      fontFamily: 'var(--font-mono)',
                      padding: '2px 8px',
                      borderRadius: '4px',
                      background: report.suspiciousApis.includes(fn) ? 'rgba(255,42,95,0.15)' : 'rgba(255,255,255,0.03)',
                      color: report.suspiciousApis.includes(fn) ? '#ff2a5f' : '#cbd5e1',
                      border: report.suspiciousApis.includes(fn) ? '1px solid rgba(255,42,95,0.4)' : '1px solid rgba(255,255,255,0.05)'
                    }}>
                      {fn}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 3: Threat Signals */}
      {activeTab === 'signatures' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {report.signals.map(sig => {
            const sigColor = sig.severity === 'critical' ? '#ff2a5f' : sig.severity === 'high' ? '#fb923c' : '#00ffa3';
            return (
              <div key={sig.id} style={{ background: 'rgba(0,0,0,0.3)', border: `1px solid ${sigColor}30`, borderRadius: '8px', padding: '14px 18px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                  <span style={{ color: '#f1f5f9', fontWeight: 600, fontSize: '13px' }}>{sig.label}</span>
                  <span style={{ background: `${sigColor}15`, border: `1px solid ${sigColor}40`, color: sigColor, padding: '2px 8px', borderRadius: '4px', fontSize: '10px', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
                    {sig.severity.toUpperCase()}
                  </span>
                </div>
                <div style={{ fontSize: '12px', color: '#94a3b8' }}>
                  {sig.details}
                </div>
              </div>
            );
          })}
        </div>
      )}

    </div>
  );
};
