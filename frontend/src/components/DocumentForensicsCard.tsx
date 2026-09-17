import React, { useState, useEffect } from 'react';

interface PdfForensicsData {
  pageCount: number;
  info: any;
  metadata: any;
  textPreview: string;
  anomalies: string[];
  md5: string;
  sha256: string;
  size: number;
}

export const DocumentForensicsCard: React.FC<{ file?: File }> = ({ file }) => {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<PdfForensicsData | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!file) return;
    if (file.size > 32 * 1024 * 1024) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setError('File is too large for local PDF parsing (Max 32MB).');
      return;
    }

    const analyzePdf = async () => {
      setLoading(true);
      setError(null);
      try {
        const formData = new FormData();
        formData.append('file', file);
        const res = await fetch('/api/forensics/pdf/analyze', {
          method: 'POST',
          body: formData,
        });
        if (!res.ok) throw new Error('PDF parsing failed on backend.');
        const result = await res.json();
        if (result.error) throw new Error(result.error);
        setData(result);
      } catch (err: any) {
        setError(err.message || 'Failed to parse PDF.');
      } finally {
        setLoading(false);
      }
    };

    analyzePdf();
  }, [file]);

  if (!file) return null;

  return (
    <div className="glass-card animate-fade-in-up" style={{ padding: '24px', position: 'relative', overflow: 'hidden', border: '1px solid rgba(245,158,11,0.3)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '20px' }}>
        <div style={{
            width: '42px', height: '42px', borderRadius: '10px',
            background: 'rgba(245,158,11,0.15)', border: '1px solid rgba(245,158,11,0.4)',
            display: 'flex', alignItems: 'center', justifyContent: 'center'
          }}>
            <span className="material-symbols-outlined" style={{ fontSize: '24px', color: '#f59e0b' }}>description</span>
        </div>
        <div>
          <h2 style={{ margin: 0, fontSize: '18px', color: 'var(--on-surface)', fontFamily: 'var(--font-headline)' }}>Document Forensics</h2>
          <p style={{ margin: 0, fontSize: '12px', color: 'var(--on-surface-3)', fontFamily: 'var(--font-mono)' }}>Deep PDF Parsing & Metadata Extraction</p>
        </div>
      </div>

      {loading && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '24px', justifyContent: 'center' }}>
          <span className="material-symbols-outlined spin text-primary" style={{ fontSize: '20px' }}>sync</span>
          <span className="font-code-sm text-on-surface-variant">Parsing PDF structure and extracting text payloads...</span>
        </div>
      )}

      {error && (
        <div style={{ padding: '12px 16px', background: 'rgba(255,42,95,0.08)', border: '1px solid rgba(255,42,95,0.3)', borderRadius: '10px', color: 'var(--status-malicious)', fontFamily: 'var(--font-mono)', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>warning</span>
          <span>{error}</span>
        </div>
      )}

      {data && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Anomalies */}
          {data.anomalies.length > 0 && (
            <div style={{ padding: '14px', background: 'rgba(255,42,95,0.08)', border: '1px solid rgba(255,42,95,0.4)', borderRadius: '8px' }}>
              <div style={{ fontSize: '12px', color: '#ff2a5f', fontFamily: 'var(--font-mono)', fontWeight: 700, marginBottom: '8px' }}>
                ⚠️ MALICIOUS INDICATORS DETECTED ({data.anomalies.length})
              </div>
              <ul style={{ margin: 0, paddingLeft: '20px', color: '#ff2a5f', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>
                {data.anomalies.map((a, i) => <li key={i} style={{ marginBottom: '4px' }}>{a}</li>)}
              </ul>
            </div>
          )}

          {data.anomalies.length === 0 && (
             <div style={{ padding: '14px', background: 'rgba(0,232,122,0.05)', border: '1px solid rgba(0,232,122,0.2)', borderRadius: '8px' }}>
               <div style={{ fontSize: '12px', color: 'var(--status-clean)', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                 ✅ No embedded JavaScript or auto-launch actions detected.
               </div>
             </div>
          )}

          {/* Overview */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '10px' }}>
            {[
              { label: 'PAGES', value: data.pageCount },
              { label: 'AUTHOR', value: data.info?.Author || 'Unknown' },
              { label: 'CREATOR', value: data.info?.Creator || 'Unknown' },
              { label: 'PRODUCER', value: data.info?.Producer || 'Unknown' },
              { label: 'CREATION DATE', value: data.info?.CreationDate?.replace('D:', '') || 'Unknown' }
            ].map((item, i) => (
              <div key={i} style={{ padding: '12px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
                <div style={{ fontSize: '10px', color: 'var(--on-surface-variant)', fontFamily: 'var(--font-mono)' }}>{item.label}</div>
                <div style={{ fontSize: '12px', color: 'var(--on-surface)', fontFamily: 'var(--font-mono)', marginTop: '4px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {item.value}
                </div>
              </div>
            ))}
          </div>

          {/* Text Preview */}
          {data.textPreview && (
            <div>
              <div style={{ fontSize: '11px', color: 'var(--on-surface-3)', fontFamily: 'var(--font-mono)', marginBottom: '8px' }}>TEXT EXTRACTION (PREVIEW)</div>
              <div style={{ padding: '16px', background: 'rgba(0,0,0,0.3)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.05)', color: 'var(--on-surface-variant)', fontSize: '12px', fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap', maxHeight: '300px', overflowY: 'auto' }}>
                {data.textPreview}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
