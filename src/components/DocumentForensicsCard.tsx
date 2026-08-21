import React, { useState } from 'react';
import { DocumentForensicsReport } from '../services/mediaForensics';

interface DocumentForensicsCardProps {
  report: DocumentForensicsReport;
}

export const DocumentForensicsCard: React.FC<DocumentForensicsCardProps> = ({ report }) => {
  const [activeTab, setActiveTab] = useState<'security' | 'meta' | 'pdf' | 'office'>('security');
  const { docType, formatName, pageCount, wordCount, author, creator, producer, creationDate, modifyDate, isEncrypted, hasMacros, hasJavaScript, hasEmbeddedActions, threatScore, threatLevel, pdfDetails, officeDetails, signals } = report;

  const threatColor = threatLevel === 'critical' ? '#ff2a5f' : threatLevel === 'suspicious' ? '#fb923c' : threatLevel === 'low' ? '#f59e0b' : '#00ffa3';

  return (
    <div style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '28px 32px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #1e293b', paddingBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span className="material-symbols-outlined" style={{ color: '#ef4444', fontSize: '24px' }}>
            description
          </span>
          <div>
            <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 700, color: '#f1f5f9' }}>
              Document Security & Macro Forensics Engine
            </h3>
            <p style={{ margin: '2px 0 0', fontSize: '12px', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
              PDF structure objects, VBA macro streams, embedded JavaScript, auto-actions & author telemetry
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
            Document Risk: {threatScore}/100 ({threatLevel.toUpperCase()})
          </span>
        </div>
      </div>

      {/* 4 Summary Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px' }}>
        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Document Type & Pages</div>
          <div style={{ fontSize: '15px', fontWeight: 700, color: '#f1f5f9', marginTop: '4px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {formatName}
          </div>
          <div style={{ fontSize: '11px', color: '#ef4444', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            {pageCount ? `${pageCount} Pages` : wordCount ? `${wordCount} Words` : 'Structured Document'}
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>VBA Macros & Scripts</div>
          <div style={{ fontSize: '14px', fontWeight: 600, color: hasMacros || hasJavaScript ? '#ff2a5f' : '#00ffa3', marginTop: '4px' }}>
            {hasMacros ? '⚠️ VBA Macros Present' : hasJavaScript ? '⚠️ JavaScript Stream' : '✓ No Executable Scripts'}
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            {hasEmbeddedActions ? 'Contains Auto-Run Directives' : 'Passive document'}
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Author & Tooling</div>
          <div style={{ fontSize: '14px', fontWeight: 600, color: '#f1f5f9', marginTop: '4px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {author || 'Anonymous / Stripped'}
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {producer || creator || (officeDetails?.appName ? `${officeDetails.appName}` : 'Standard Tool')}
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Encryption & Access</div>
          <div style={{ fontSize: '14px', fontWeight: 600, color: isEncrypted ? '#fb923c' : '#f1f5f9', marginTop: '4px' }}>
            {isEncrypted ? '🔒 Password / Encrypted' : '🔓 Unrestricted Access'}
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            {modifyDate ? `Modified: ${modifyDate.slice(0, 10)}` : 'Standard Security'}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid #1e293b', gap: '4px' }}>
        {[
          { id: 'security', label: '🛡️ Threat & Exploit Signals', badge: signals.length },
          { id: 'meta', label: '📋 Author & Creation Telemetry' },
          ...(docType === 'pdf' ? [{ id: 'pdf', label: '📄 PDF Internal Objects' }] : []),
          ...(docType !== 'pdf' && officeDetails ? [{ id: 'office', label: '📊 Office VBA & Revision Meta' }] : []),
        ].map(t => (
          <button
            key={t.id}
            onClick={() => setActiveTab(t.id as any)}
            style={{
              background: 'none',
              border: 'none',
              borderBottom: activeTab === t.id ? '2px solid #ef4444' : '2px solid transparent',
              padding: '8px 16px',
              color: activeTab === t.id ? '#ef4444' : '#94a3b8',
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

      {/* Tab 1: Security */}
      {activeTab === 'security' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
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

          {/* Checklist */}
          <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)', borderRadius: '8px', padding: '16px' }}>
            <div style={{ fontSize: '12px', color: '#94a3b8', fontWeight: 600, marginBottom: '12px', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
              Document Exploit & Automation Vector Checks
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '10px', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined" style={{ fontSize: '16px', color: hasMacros ? '#ff2a5f' : '#00ffa3' }}>
                  {hasMacros ? 'cancel' : 'check_circle'}
                </span>
                <span style={{ color: '#cbd5e1' }}>VBA Macro Automation Payload</span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined" style={{ fontSize: '16px', color: hasJavaScript ? '#ff2a5f' : '#00ffa3' }}>
                  {hasJavaScript ? 'cancel' : 'check_circle'}
                </span>
                <span style={{ color: '#cbd5e1' }}>Embedded JavaScript Object Streams</span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined" style={{ fontSize: '16px', color: hasEmbeddedActions ? '#ff2a5f' : '#00ffa3' }}>
                  {hasEmbeddedActions ? 'cancel' : 'check_circle'}
                </span>
                <span style={{ color: '#cbd5e1' }}>Auto-Open & Launch Directives</span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined" style={{ fontSize: '16px', color: isEncrypted ? '#fb923c' : '#00ffa3' }}>
                  {isEncrypted ? 'lock' : 'check_circle'}
                </span>
                <span style={{ color: '#cbd5e1' }}>Document Encryption & DRM Protection</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Meta */}
      {activeTab === 'meta' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '12px' }}>
          {[
            { label: 'Document Format', value: formatName },
            { label: 'Author / Creator', value: author },
            { label: 'Application / Producer', value: producer || creator },
            { label: 'Creation Date', value: creationDate },
            { label: 'Modification Date', value: modifyDate },
            { label: 'Page Count', value: pageCount ? String(pageCount) : undefined },
            { label: 'Word Count', value: wordCount ? String(wordCount) : undefined },
            { label: 'Encryption Status', value: isEncrypted ? 'Encrypted' : 'None' },
          ].filter(item => item.value).map((item, idx) => (
            <div key={idx} style={{ padding: '10px 14px', background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.04)', borderRadius: '6px' }}>
              <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>{item.label}</div>
              <div className="font-data-mono" style={{ fontSize: '13px', color: '#f1f5f9', marginTop: '2px', wordBreak: 'break-all' }}>{item.value}</div>
            </div>
          ))}
        </div>
      )}

      {/* Tab 3: PDF Objects */}
      {activeTab === 'pdf' && pdfDetails && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '12px' }}>
          {[
            { label: 'PDF Specification Version', value: pdfDetails.version },
            { label: 'Fast Web View (Linearized)', value: pdfDetails.isLinearized ? 'Yes' : 'No' },
            { label: 'Object Streams Enabled', value: pdfDetails.objectStreams ? 'Yes' : 'No' },
            { label: 'Tagged PDF Structure', value: pdfDetails.tagged ? 'Yes' : 'No' },
            { label: 'JavaScript Stream Instances', value: pdfDetails.jsCount ? String(pdfDetails.jsCount) : (hasJavaScript ? 'Detected' : '0') },
          ].map((item, idx) => (
            <div key={idx} style={{ padding: '10px 14px', background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.04)', borderRadius: '6px' }}>
              <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>{item.label}</div>
              <div className="font-data-mono" style={{ fontSize: '13px', color: '#f1f5f9', marginTop: '2px' }}>{item.value}</div>
            </div>
          ))}
        </div>
      )}

      {/* Tab 4: Office Details */}
      {activeTab === 'office' && officeDetails && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '12px' }}>
          {[
            { label: 'Creating Application', value: officeDetails.appName },
            { label: 'Application Version', value: officeDetails.appVersion },
            { label: 'Last Modified By', value: officeDetails.lastModifiedBy },
            { label: 'Document Revision Number', value: officeDetails.revisionNumber },
            { label: 'Total Editing Time', value: officeDetails.totalEditTime },
            { label: 'Macro Streams Count', value: officeDetails.macroStreams ? String(officeDetails.macroStreams.length) : undefined },
            { label: 'Auto-Executing Macro Directives', value: officeDetails.autoExecMacros ? officeDetails.autoExecMacros.join(', ') : undefined },
          ].filter(item => item.value).map((item, idx) => (
            <div key={idx} style={{ padding: '10px 14px', background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.04)', borderRadius: '6px' }}>
              <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>{item.label}</div>
              <div className="font-data-mono" style={{ fontSize: '13px', color: '#f1f5f9', marginTop: '2px' }}>{item.value}</div>
            </div>
          ))}
        </div>
      )}

    </div>
  );
};
