import React from 'react';
import { EmailForensicsReport } from '../services/mediaForensics';

interface EmailForensicsCardProps {
  report: EmailForensicsReport;
}

export const EmailForensicsCard: React.FC<EmailForensicsCardProps> = ({ report }) => {
  return (
    <div style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '28px 32px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #1e293b', paddingBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span className="material-symbols-outlined" style={{ color: '#fb923c', fontSize: '26px' }}>
            mail
          </span>
          <div>
            <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 700, color: '#f1f5f9' }}>
              Email Header & Phishing Forensics (.EML / .MSG)
            </h3>
            <p style={{ margin: '2px 0 0', fontSize: '12px', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
              SPF / DKIM / DMARC authentication, relay hop chain tracing & attachment analysis
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
            SPF/DKIM Authenticated
          </span>
        </div>
      </div>

      {/* 4 Summary Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px' }}>
        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Sender Origin (From)</div>
          <div style={{ fontSize: '13px', fontWeight: 700, color: '#f1f5f9', marginTop: '4px', fontFamily: 'var(--font-mono)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {report.from}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--brand)', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            To: {report.to}
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>SPF / DKIM / DMARC</div>
          <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--brand-amber)', marginTop: '4px' }}>
            SPF: {report.authResults.spf.toUpperCase()} · DKIM: {report.authResults.dkim.toUpperCase()}
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            DMARC: {report.authResults.dmarc.toUpperCase()}
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Relay Hops</div>
          <div style={{ fontSize: '14px', fontWeight: 700, color: '#f1f5f9', marginTop: '4px' }}>
            {report.hops.length} Server Relays
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            Hop 1: {report.hops[0]?.byServer || 'Verified'}
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Attachments & URLs</div>
          <div style={{ fontSize: '14px', fontWeight: 600, color: report.attachments.length > 0 ? 'var(--brand)' : '#94a3b8', marginTop: '4px' }}>
            {report.attachments.length} Attachments · {report.extractedUrls.length} Links
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            {report.attachments[0]?.filename || 'No attachments'}
          </div>
        </div>
      </div>

      {/* Hop Chain */}
      <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '8px', padding: '16px 20px' }}>
        <div style={{ fontSize: '12px', color: '#94a3b8', fontWeight: 700, textTransform: 'uppercase', fontFamily: 'var(--font-mono)', marginBottom: '10px' }}>
          Received Relay Routing Hop-Chain
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {report.hops.map((h, i) => (
            <div key={i} style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ color: 'var(--brand)', fontWeight: 700 }}>[Hop {h.hopNumber}]</span>
              <span>Received by <strong style={{ color: '#f1f5f9' }}>{h.byServer}</strong> from {h.fromServer}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
