import React, { useState } from 'react';
import { ArchiveForensicsReport } from '../services/mediaForensics';
import { formatBytes } from '../utils/sanitize';

interface ArchiveForensicsCardProps {
  report: ArchiveForensicsReport;
}

export const ArchiveForensicsCard: React.FC<ArchiveForensicsCardProps> = ({ report }) => {
  const [activeTab, setActiveTab] = useState<'files' | 'signals'>('files');
  const [fileSearch, setFileSearch] = useState('');
  const { archiveType, fileCount, uncompressedSize, compressionRatio, isEncrypted, hasExecutables, hasScripts, isPotentialZipBomb, files, threatScore, threatLevel, signals } = report;

  const threatColor = threatLevel === 'critical' ? '#ff2a5f' : threatLevel === 'suspicious' ? '#fb923c' : threatLevel === 'low' ? '#f59e0b' : '#00ffa3';

  const filteredFiles = files.filter(f => !fileSearch || f.name.toLowerCase().includes(fileSearch.toLowerCase()));

  return (
    <div style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '28px 32px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #1e293b', paddingBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span className="material-symbols-outlined" style={{ color: '#eab308', fontSize: '24px' }}>
            folder_zip
          </span>
          <div>
            <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 700, color: '#f1f5f9' }}>
              Archive & Compressed Container Forensics Engine
            </h3>
            <p style={{ margin: '2px 0 0', fontSize: '12px', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
              Contained file catalog, nested droppers, expansion ratio & decompression bomb heuristics
            </p>
          </div>
        </div>

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
            {threatScore > 0 ? 'warning' : 'verified_user'}
          </span>
          <span style={{ color: threatColor, fontSize: '12px', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
            Archive Risk: {threatScore}/100 ({threatLevel.toUpperCase()})
          </span>
        </div>
      </div>

      {/* 4 Summary Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px' }}>
        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Contained Files & Format</div>
          <div style={{ fontSize: '15px', fontWeight: 700, color: '#f1f5f9', marginTop: '4px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {fileCount > 0 ? `${fileCount} Files Contained` : archiveType}
          </div>
          <div style={{ fontSize: '11px', color: '#eab308', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            {archiveType}
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Executable & Script Payloads</div>
          <div style={{ fontSize: '14px', fontWeight: 600, color: hasExecutables || hasScripts ? '#ff2a5f' : '#00ffa3', marginTop: '4px' }}>
            {hasExecutables ? '⚠️ Executables Detected' : hasScripts ? '⚠️ Script Files Detected' : '✓ Clean File Types'}
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            {hasExecutables ? 'Contains .exe, .dll, or .scr' : 'No binary droppers'}
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Expansion & Decompression</div>
          <div style={{ fontSize: '14px', fontWeight: 600, color: isPotentialZipBomb ? '#ff2a5f' : '#f1f5f9', marginTop: '4px' }}>
            Ratio: {compressionRatio}
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            {uncompressedSize ? `Expands to ${formatBytes(uncompressedSize)}` : 'Standard Ratio'}
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Encryption / Password</div>
          <div style={{ fontSize: '14px', fontWeight: 600, color: isEncrypted ? '#fb923c' : '#00ffa3', marginTop: '4px' }}>
            {isEncrypted ? '🔒 Password Protected' : '🔓 Unencrypted'}
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            {isEncrypted ? 'Header / Content Encrypted' : 'Direct Extraction Possible'}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid #1e293b', gap: '4px' }}>
        {[
          { id: 'files', label: '📁 Contained Files Catalog', badge: files.length },
          { id: 'signals', label: '🛡️ Threat & Anomaly Signals', badge: signals.length },
        ].map(t => (
          <button
            key={t.id}
            onClick={() => setActiveTab(t.id as any)}
            style={{
              background: 'none',
              border: 'none',
              borderBottom: activeTab === t.id ? '2px solid #eab308' : '2px solid transparent',
              padding: '8px 16px',
              color: activeTab === t.id ? '#eab308' : '#94a3b8',
              fontFamily: 'var(--font-mono)',
              fontSize: '12px',
              fontWeight: activeTab === t.id ? 700 : 500,
              cursor: 'pointer',
              transition: 'all 0.15s ease',
              display: 'flex',
              alignItems: 'center',
              gap: '6px'
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab 1: Files */}
      {activeTab === 'files' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          {files.length > 5 && (
            <input
              type="text"
              placeholder="Search contained file..."
              value={fileSearch}
              onChange={(e) => setFileSearch(e.target.value)}
              style={{
                background: 'rgba(0,0,0,0.4)',
                border: '1px solid #334155',
                borderRadius: '6px',
                padding: '6px 12px',
                color: '#fff',
                fontSize: '12px',
                fontFamily: 'var(--font-mono)',
                outline: 'none',
                width: '240px'
              }}
            />
          )}

          {filteredFiles.length > 0 ? (
            <div style={{ maxHeight: '380px', overflowY: 'auto', border: '1px solid #1e293b', borderRadius: '8px' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
                <thead>
                  <tr style={{ background: '#0f172a', borderBottom: '1px solid #1e293b', color: '#64748b', position: 'sticky', top: 0 }}>
                    <th style={{ padding: '10px 14px' }}>File Path / Name</th>
                    <th style={{ padding: '10px 14px' }}>Size</th>
                    <th style={{ padding: '10px 14px' }}>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredFiles.map((f, idx) => (
                    <tr key={idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.02)', background: f.isExecutable || f.isScript ? 'rgba(255,42,95,0.05)' : 'transparent' }}>
                      <td style={{ padding: '8px 14px', color: f.isExecutable || f.isScript ? '#ff2a5f' : '#f1f5f9', fontWeight: f.isExecutable ? 700 : 500 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span className="material-symbols-outlined" style={{ fontSize: '16px', color: f.isExecutable ? '#ff2a5f' : '#38bdf8' }}>
                            {f.isExecutable ? 'warning' : 'description'}
                          </span>
                          {f.name}
                        </div>
                      </td>
                      <td style={{ padding: '8px 14px', color: '#94a3b8' }}>
                        {f.size ? formatBytes(f.size) : '-'}
                      </td>
                      <td style={{ padding: '8px 14px' }}>
                        {f.isExecutable ? (
                          <span style={{ background: 'rgba(255,42,95,0.15)', color: '#ff2a5f', padding: '2px 6px', borderRadius: '4px', fontSize: '10px', fontWeight: 700 }}>
                            EXECUTABLE
                          </span>
                        ) : f.isScript ? (
                          <span style={{ background: 'rgba(251,146,60,0.15)', color: '#fb923c', padding: '2px 6px', borderRadius: '4px', fontSize: '10px', fontWeight: 700 }}>
                            SCRIPT
                          </span>
                        ) : (
                          <span style={{ color: '#00ffa3', fontSize: '11px' }}>
                            ✓ Clean
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ padding: '24px', textAlign: 'center', color: '#64748b', background: 'rgba(0,0,0,0.2)', borderRadius: '8px' }} className="font-data-mono">
              Individual file list was encrypted or not provided in the container manifest.
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Signals */}
      {activeTab === 'signals' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {signals.map(sig => {
            const sigColor = sig.severity === 'critical' ? '#ff2a5f' : sig.severity === 'high' ? '#fb923c' : sig.severity === 'medium' ? '#f59e0b' : sig.severity === 'low' ? '#38bdf8' : '#00ffa3';
            return (
              <div key={sig.id} style={{ background: 'rgba(0,0,0,0.3)', border: `1px solid ${sigColor}30`, borderRadius: '8px', padding: '14px 18px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
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
