import React from 'react';
import { PcapForensicsReport } from '../services/mediaForensics';

interface PcapForensicsCardProps {
  report: PcapForensicsReport;
}

export const PcapForensicsCard: React.FC<PcapForensicsCardProps> = ({ report }) => {
  return (
    <div style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '28px 32px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #1e293b', paddingBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span className="material-symbols-outlined" style={{ color: '#00f2ff', fontSize: '26px' }}>
            hub
          </span>
          <div>
            <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 700, color: '#f1f5f9' }}>
              Network PCAP Packet Stream Analysis (Wireshark / Zeek)
            </h3>
            <p style={{ margin: '2px 0 0', fontSize: '12px', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
              Protocol breakdown, DNS queries, HTTP streams, and cleartext credential extraction
            </p>
          </div>
        </div>

        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '6px 14px',
          borderRadius: '999px',
          background: 'rgba(0,242,255,0.1)',
          border: '1px solid rgba(0,242,255,0.3)'
        }}>
          <span className="material-symbols-outlined" style={{ color: '#00f2ff', fontSize: '18px' }}>check_circle</span>
          <span style={{ color: '#00f2ff', fontSize: '12px', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
            PCAP Stream Normal
          </span>
        </div>
      </div>

      {/* 4 Summary Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px' }}>
        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Capture Duration & Packets</div>
          <div style={{ fontSize: '15px', fontWeight: 700, color: '#f1f5f9', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
            {report.packetCount} Packets
          </div>
          <div style={{ fontSize: '11px', color: '#00f2ff', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            Duration: {report.duration}
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>DNS Query Resolves</div>
          <div style={{ fontSize: '15px', fontWeight: 700, color: '#38bdf8', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
            {report.dnsQueries.length} Queries
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            {report.dnsQueries[0] || 'Standard Resolves'}
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Cleartext Auth Inspection</div>
          <div style={{ fontSize: '14px', fontWeight: 600, color: report.cleartextCredentialsDetected ? '#ff2a5f' : '#00ffa3', marginTop: '4px' }}>
            {report.cleartextCredentialsDetected ? 'Cleartext Credentials Found' : 'Encrypted Handshakes'}
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            TLS 1.3 / HTTP/2
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Extracted Network IOCs</div>
          <div style={{ fontSize: '15px', fontWeight: 700, color: '#f1f5f9', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
            {report.extractedIocs.length} IOCs
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            IP & Domain Entities
          </div>
        </div>
      </div>

      {/* Protocol Breakdown & DNS */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '14px' }}>
        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '8px', padding: '16px' }}>
          <div style={{ fontSize: '12px', color: '#00f2ff', fontWeight: 700, fontFamily: 'var(--font-mono)', marginBottom: '10px' }}>
            PROTOCOL BREAKDOWN
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {report.protocols.map((p, i) => (
              <div key={i} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
                <span style={{ color: '#cbd5e1' }}>{p.name}</span>
                <span style={{ color: '#00f2ff', fontWeight: 700 }}>{p.percentage}%</span>
              </div>
            ))}
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '8px', padding: '16px' }}>
          <div style={{ fontSize: '12px', color: '#38bdf8', fontWeight: 700, fontFamily: 'var(--font-mono)', marginBottom: '10px' }}>
            DNS QUERIES CARVED
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {report.dnsQueries.map((q, i) => (
              <div key={i} style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: '#cbd5e1' }}>🔎 {q}</div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
