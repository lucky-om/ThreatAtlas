import React, { useState } from 'react';
import { ImageForensicsReport } from '../services/imageForensics';

interface ImageForensicsCardProps {
  report: ImageForensicsReport;
}

export const ImageForensicsCard: React.FC<ImageForensicsCardProps> = ({ report }) => {
  const [activeTab, setActiveTab] = useState<'stego' | 'exif' | 'hashes' | 'raw'>('stego');
  const [exifSearch, setExifSearch] = useState('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const { geometry, cameraExif, stego, hashes, rawExif } = report;

  // Filter raw EXIF pairs
  const filteredExifEntries = Object.entries(rawExif).filter(([k, v]) => {
    if (!exifSearch) return true;
    return k.toLowerCase().includes(exifSearch.toLowerCase()) || String(v).toLowerCase().includes(exifSearch.toLowerCase());
  });

  const stegoColor = stego.riskLevel === 'critical' ? '#ff2a5f' : stego.riskLevel === 'suspicious' ? '#fb923c' : stego.riskLevel === 'low' ? '#f59e0b' : '#00ffa3';

  return (
    <div style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '28px 32px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      
      {/* ── TOP HEADER ──────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #1e293b', paddingBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span className="material-symbols-outlined" style={{ color: '#38bdf8', fontSize: '24px' }}>
            image_search
          </span>
          <div>
            <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 700, color: '#f1f5f9' }}>
              Deep Image Forensics & Steganography Engine
            </h3>
            <p style={{ margin: '2px 0 0', fontSize: '12px', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
              Optical geometry, camera telemetry, EXIF scraping & hidden payload analysis
            </p>
          </div>
        </div>

        {/* Stego Threat Score Badge */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '6px 14px',
          borderRadius: '999px',
          background: `${stegoColor}15`,
          border: `1px solid ${stegoColor}40`
        }}>
          <span className="material-symbols-outlined" style={{ color: stegoColor, fontSize: '18px' }}>
            {stego.riskScore > 0 ? 'security_update_warning' : 'verified'}
          </span>
          <span style={{ color: stegoColor, fontSize: '12px', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
            Stego Risk: {stego.riskScore}/100 ({stego.riskLevel.toUpperCase()})
          </span>
        </div>
      </div>

      {/* ── 4 QUICK METRIC SUMMARY CARDS ────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '14px' }}>
        {/* 1. Resolution & Aspect Ratio */}
        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Dimensions & Geometry</div>
          <div style={{ fontSize: '16px', fontWeight: 700, color: '#f1f5f9', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
            {geometry.width > 0 ? `${geometry.width} × ${geometry.height}` : 'N/A'}
          </div>
          <div style={{ fontSize: '11px', color: '#38bdf8', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            {geometry.megapixels} · {geometry.aspectRatio}
          </div>
        </div>

        {/* 2. Color Depth & Compression */}
        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Color Profile & Compression</div>
          <div style={{ fontSize: '14px', fontWeight: 600, color: '#f1f5f9', marginTop: '4px' }}>
            {geometry.colorSpace} ({geometry.bitsPerSample ? `${geometry.bitsPerSample * (geometry.colorComponents || 3)}-bit` : '24-bit'})
          </div>
          <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            {geometry.compression} · {geometry.density}
          </div>
        </div>

        {/* 3. Camera / Equipment */}
        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Acquisition Hardware</div>
          <div style={{ fontSize: '14px', fontWeight: 600, color: '#f1f5f9', marginTop: '4px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {cameraExif.make || cameraExif.model ? `${cameraExif.make || ''} ${cameraExif.model || ''}` : 'Hardware Telemetry Stripped'}
          </div>
          <div style={{ fontSize: '11px', color: cameraExif.software ? '#fb923c' : '#64748b', marginTop: '2px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {cameraExif.software ? `Edited in ${cameraExif.software}` : 'No editor signature'}
          </div>
        </div>

        {/* 4. GPS Geolocation Status */}
        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>GPS Geolocation</div>
          <div style={{ fontSize: '14px', fontWeight: 600, color: cameraExif.gps ? '#00ffa3' : '#94a3b8', marginTop: '4px' }}>
            {cameraExif.gps ? '📍 Coordinates Embedded' : 'No GPS Metadata'}
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            {cameraExif.gps ? cameraExif.gps.formatted : 'Location data clean'}
          </div>
        </div>
      </div>

      {/* ── SUB-NAV TABS ────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', borderBottom: '1px solid #1e293b', gap: '4px', overflowX: 'auto' }}>
        {[
          { id: 'stego', label: '🛡️ Steganography & Payloads', badge: stego.signals.length },
          { id: 'exif', label: '📷 Camera & Equipment EXIF', badge: Object.keys(cameraExif).filter(k => (cameraExif as any)[k] !== undefined).length },
          { id: 'hashes', label: '🔍 Perceptual Visual Hashes', badge: null },
          { id: 'raw', label: '📋 Raw Metadata Dictionary', badge: Object.keys(rawExif).length },
        ].map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              style={{
                background: 'none',
                border: 'none',
                borderBottom: isActive ? '2px solid #38bdf8' : '2px solid transparent',
                padding: '8px 16px',
                color: isActive ? '#38bdf8' : '#94a3b8',
                fontFamily: 'var(--font-mono)',
                fontSize: '12px',
                fontWeight: isActive ? 700 : 500,
                cursor: 'pointer',
                transition: 'all 0.15s ease',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                whiteSpace: 'nowrap'
              }}
            >
              {tab.label}
              {tab.badge !== null && tab.badge > 0 && (
                <span style={{ background: 'rgba(255,255,255,0.06)', padding: '1px 6px', borderRadius: '4px', fontSize: '10px' }}>
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* ── SUB-TAB 1: STEGANOGRAPHY & PAYLOADS ──────────────────────────────── */}
      {activeTab === 'stego' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          
          {/* Signal Cards */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {stego.signals.map((sig) => {
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

          {/* Steganography Checklist */}
          <div style={{ marginTop: '10px', background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)', borderRadius: '8px', padding: '16px' }}>
            <div style={{ fontSize: '12px', color: '#94a3b8', fontWeight: 600, marginBottom: '12px', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
              Steganography & Polyglot Heuristic Checks
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '10px', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined" style={{ fontSize: '16px', color: stego.polyglotDetected ? '#ff2a5f' : '#00ffa3' }}>
                  {stego.polyglotDetected ? 'cancel' : 'check_circle'}
                </span>
                <span style={{ color: '#cbd5e1' }}>PHP/Executable Polyglot Signature</span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined" style={{ fontSize: '16px', color: stego.hasTrailingData ? '#ff2a5f' : '#00ffa3' }}>
                  {stego.hasTrailingData ? 'cancel' : 'check_circle'}
                </span>
                <span style={{ color: '#cbd5e1' }}>Trailing Append Data (Post-EOI)</span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined" style={{ fontSize: '16px', color: stego.scriptInjectionDetected ? '#ff2a5f' : '#00ffa3' }}>
                  {stego.scriptInjectionDetected ? 'cancel' : 'check_circle'}
                </span>
                <span style={{ color: '#cbd5e1' }}>EXIF Script / XSS Injections</span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined" style={{ fontSize: '16px', color: '#00ffa3' }}>
                  check_circle
                </span>
                <span style={{ color: '#cbd5e1' }}>Magic Byte Header Integrity</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── SUB-TAB 2: CAMERA & EQUIPMENT EXIF ──────────────────────────────── */}
      {activeTab === 'exif' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          
          {/* GPS Coordinates Viewer (if present) */}
          {cameraExif.gps && (
            <div style={{ background: 'rgba(0, 255, 163, 0.04)', border: '1px solid rgba(0, 255, 163, 0.2)', borderRadius: '8px', padding: '16px 20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
                <div>
                  <div style={{ fontSize: '12px', color: '#00ffa3', fontWeight: 700, textTransform: 'uppercase', fontFamily: 'var(--font-mono)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>location_on</span>
                    Embedded GPS Coordinates Discovered
                  </div>
                  <div style={{ fontSize: '15px', fontWeight: 600, color: '#f1f5f9', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
                    {cameraExif.gps.formatted} {cameraExif.gps.altitude ? `(Alt: ${cameraExif.gps.altitude})` : ''}
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '10px' }}>
                  <a
                    href={cameraExif.gps.googleMapsUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ background: 'rgba(0, 242, 255, 0.1)', border: '1px solid rgba(0, 242, 255, 0.3)', color: '#38bdf8', padding: '5px 12px', borderRadius: '6px', fontSize: '12px', fontFamily: 'var(--font-mono)', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '4px' }}
                  >
                    Google Maps ↗
                  </a>
                  <a
                    href={cameraExif.gps.openStreetMapUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ background: 'rgba(255, 255, 255, 0.05)', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#cbd5e1', padding: '5px 12px', borderRadius: '6px', fontSize: '12px', fontFamily: 'var(--font-mono)', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '4px' }}
                  >
                    OpenStreetMap ↗
                  </a>
                </div>
              </div>
            </div>
          )}

          {/* Camera Settings Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '12px' }}>
            {[
              { label: 'Camera Make', value: cameraExif.make },
              { label: 'Camera Model', value: cameraExif.model },
              { label: 'Lens Model', value: cameraExif.lens },
              { label: 'Software / Tool', value: cameraExif.software },
              { label: 'Exposure Time', value: cameraExif.exposureTime },
              { label: 'Aperture', value: cameraExif.aperture },
              { label: 'ISO Speed', value: cameraExif.iso },
              { label: 'Focal Length', value: cameraExif.focalLength35mm || cameraExif.focalLength },
              { label: 'Flash Mode', value: cameraExif.flash },
              { label: 'White Balance', value: cameraExif.whiteBalance },
              { label: 'Metering Mode', value: cameraExif.meteringMode },
              { label: 'Date/Time Original', value: cameraExif.dateTimeOriginal },
              { label: 'Date/Time Digitized', value: cameraExif.dateTimeDigitized },
              { label: 'Artist / Author', value: cameraExif.artist },
              { label: 'Copyright', value: cameraExif.copyright },
            ].filter(item => item.value).map((item, idx) => (
              <div key={idx} style={{ padding: '10px 14px', background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.04)', borderRadius: '6px' }}>
                <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>{item.label}</div>
                <div className="font-data-mono" style={{ fontSize: '13px', color: '#f1f5f9', marginTop: '2px', wordBreak: 'break-all' }}>{item.value}</div>
              </div>
            ))}
          </div>

          {!cameraExif.make && !cameraExif.model && !cameraExif.dateTimeOriginal && (
            <div style={{ padding: '24px', textAlign: 'center', color: '#64748b', background: 'rgba(0,0,0,0.2)', borderRadius: '8px' }} className="font-data-mono">
              Hardware camera telemetry (Make, Model, Shutter, ISO) was stripped or is not present in this file.
            </div>
          )}
        </div>
      )}

      {/* ── SUB-TAB 3: PERCEPTUAL VISUAL HASHES ─────────────────────────────── */}
      {activeTab === 'hashes' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <p style={{ fontSize: '12px', color: '#94a3b8', margin: 0, fontFamily: 'var(--font-mono)' }}>
            Perceptual hashes and fuzzy signatures allow reverse visual matching across resized, compressed, or tampered copies.
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {[
              { label: 'dHash (Difference Hash)', value: hashes.dhash, desc: 'Tracks gradient directional shifts across 8x8 luminance matrix.' },
              { label: 'aHash (Average Hash)', value: hashes.ahash, desc: 'Computes mean pixel intensity thresholding for scale-invariant matching.' },
              { label: 'pHash (Perceptual Hash)', value: hashes.phash, desc: 'Discrete Cosine Transform (DCT) frequency fingerprint.' },
              { label: 'SSDEEP (Context Triggered Piecewise Hash)', value: hashes.ssdeep, desc: 'Fuzzy hash for similarity clustering across files.' },
              { label: 'TLSH (Trend Micro Locality Sensitive Hash)', value: hashes.tlsh, desc: 'Distance-based clustering signature.' },
            ].filter(h => h.value).map((item, idx) => (
              <div key={idx} style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.05)', borderRadius: '8px', padding: '14px 18px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <span style={{ fontSize: '12px', color: '#38bdf8', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>{item.label}</span>
                  <button 
                    onClick={() => handleCopy(item.value || '', item.label)}
                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: copiedKey === item.label ? '#00ffa3' : '#64748b', display: 'flex', padding: 0 }}
                  >
                    <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>{copiedKey === item.label ? 'check' : 'content_copy'}</span>
                  </button>
                </div>
                <div className="font-data-mono" style={{ fontSize: '13px', color: '#f1f5f9', wordBreak: 'break-all', marginBottom: '4px' }}>
                  {item.value}
                </div>
                <div style={{ fontSize: '11px', color: '#64748b' }}>{item.desc}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── SUB-TAB 4: RAW METADATA DICTIONARY ──────────────────────────────── */}
      {activeTab === 'raw' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
            <span style={{ fontSize: '12px', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
              Showing {filteredExifEntries.length} raw metadata attributes extracted by parser
            </span>

            <input
              type="text"
              placeholder="Search EXIF tag or value..."
              value={exifSearch}
              onChange={(e) => setExifSearch(e.target.value)}
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
          </div>

          <div style={{ maxHeight: '420px', overflowY: 'auto', border: '1px solid #1e293b', borderRadius: '8px' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
              <thead>
                <tr style={{ background: '#0f172a', borderBottom: '1px solid #1e293b', color: '#64748b', position: 'sticky', top: 0 }}>
                  <th style={{ padding: '10px 14px' }}>Metadata Tag</th>
                  <th style={{ padding: '10px 14px' }}>Extracted Value</th>
                </tr>
              </thead>
              <tbody>
                {filteredExifEntries.map(([k, v], idx) => (
                  <tr key={idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.02)' }}>
                    <td style={{ padding: '8px 14px', color: '#38bdf8', fontWeight: 600, width: '240px' }}>{k}</td>
                    <td style={{ padding: '8px 14px', color: '#cbd5e1', wordBreak: 'break-all' }}>{String(v)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

    </div>
  );
};
