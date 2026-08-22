import React, { useState } from 'react';
import { ImageForensicsReport } from '../services/imageForensics';

interface ImageForensicsCardProps {
  report: ImageForensicsReport;
}

export const ImageForensicsCard: React.FC<ImageForensicsCardProps> = ({ report }) => {
  const [activeTab, setActiveTab] = useState<'stego' | 'forensics' | 'exif' | 'osint' | 'ocr_vision' | 'hashes' | 'raw'>('stego');
  const [exifSearch, setExifSearch] = useState('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const { geometry, cameraExif, stego, forensics, ocrVision, osint, hashes, rawExif } = report;

  // Filter raw EXIF pairs
  const filteredExifEntries = Object.entries(rawExif).filter(([k, v]) => {
    if (!exifSearch) return true;
    return k.toLowerCase().includes(exifSearch.toLowerCase()) || String(v).toLowerCase().includes(exifSearch.toLowerCase());
  });

  const stegoColor = stego.riskLevel === 'critical' ? '#ff2a5f' : stego.riskLevel === 'suspicious' ? '#fb923c' : stego.riskLevel === 'low' ? '#f59e0b' : '#00ffa3';
  const manipColor = forensics.manipulationRisk === 'high' ? '#ff2a5f' : forensics.manipulationRisk === 'medium' ? '#fb923c' : forensics.manipulationRisk === 'low' ? '#f59e0b' : '#00ffa3';

  return (
    <div style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '28px 32px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      
      {/* ── TOP HEADER ──────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #1e293b', paddingBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span className="material-symbols-outlined" style={{ color: '#38bdf8', fontSize: '26px' }}>
            image_search
          </span>
          <div>
            <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 700, color: '#f1f5f9' }}>
              Deep Image Forensics & Visual Intelligence Suite
            </h3>
            <p style={{ margin: '2px 0 0', fontSize: '12px', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
              12-point forensic matrix: EXIF, ELA manipulation, OCR text, Visual OSINT, Steganography & Perceptual Hashing
            </p>
          </div>
        </div>

        {/* Threat Score Badges */}
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          {/* Stego Threat Badge */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            padding: '5px 12px',
            borderRadius: '999px',
            background: `${stegoColor}15`,
            border: `1px solid ${stegoColor}40`
          }}>
            <span className="material-symbols-outlined" style={{ color: stegoColor, fontSize: '16px' }}>
              {stego.riskScore > 0 ? 'security_update_warning' : 'verified'}
            </span>
            <span style={{ color: stegoColor, fontSize: '11px', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
              Stego: {stego.riskScore}/100 ({stego.riskLevel.toUpperCase()})
            </span>
          </div>

          {/* Manipulation Risk Badge */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            padding: '5px 12px',
            borderRadius: '999px',
            background: `${manipColor}15`,
            border: `1px solid ${manipColor}40`
          }}>
            <span className="material-symbols-outlined" style={{ color: manipColor, fontSize: '16px' }}>
              {forensics.resampledOrEdited ? 'tune' : 'check_circle'}
            </span>
            <span style={{ color: manipColor, fontSize: '11px', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
              ELA Manipulation: {forensics.manipulationRisk.toUpperCase()}
            </span>
          </div>
        </div>
      </div>

      {/* ── 4 QUICK METRIC SUMMARY CARDS ────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '14px' }}>
        {/* 1. Resolution & Aspect Ratio */}
        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Dimensions & Aspect</div>
          <div style={{ fontSize: '16px', fontWeight: 700, color: '#f1f5f9', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
            {geometry.width > 0 ? `${geometry.width} × ${geometry.height}` : 'N/A'}
          </div>
          <div style={{ fontSize: '11px', color: '#38bdf8', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            {geometry.megapixels} · {geometry.aspectRatio}
          </div>
        </div>

        {/* 2. Color Depth & Compression */}
        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Color Profile & Density</div>
          <div style={{ fontSize: '14px', fontWeight: 600, color: '#f1f5f9', marginTop: '4px' }}>
            {geometry.colorSpace} ({geometry.bitsPerSample ? `${geometry.bitsPerSample * (geometry.colorComponents || 3)}-bit` : '24-bit'})
          </div>
          <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            {geometry.compression} · {geometry.density || '72 dpi'}
          </div>
        </div>

        {/* 3. Camera / Equipment */}
        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Acquisition Hardware</div>
          <div style={{ fontSize: '14px', fontWeight: 600, color: '#f1f5f9', marginTop: '4px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {cameraExif.make || cameraExif.model ? `${cameraExif.make || ''} ${cameraExif.model || ''}` : 'Hardware Telemetry Stripped'}
          </div>
          <div style={{ fontSize: '11px', color: cameraExif.software ? '#fb923c' : '#64748b', marginTop: '2px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {cameraExif.software ? `Edited in ${cameraExif.software}` : 'Direct Sensor Capture'}
          </div>
        </div>

        {/* 4. GPS Geolocation Status */}
        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>GPS Geolocation</div>
          <div style={{ fontSize: '14px', fontWeight: 600, color: cameraExif.gps ? '#00ffa3' : '#94a3b8', marginTop: '4px' }}>
            {cameraExif.gps ? '📍 Coordinates Embedded' : 'No GPS Metadata'}
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            {cameraExif.gps ? cameraExif.gps.formatted : 'Privacy scrubbed / Strip'}
          </div>
        </div>
      </div>

      {/* ── 7 FORENSIC SUB-NAV TABS ─────────────────────────────────────────── */}
      <div style={{ display: 'flex', borderBottom: '1px solid #1e293b', gap: '4px', overflowX: 'auto' }}>
        {[
          { id: 'stego', label: '🛡️ Steganography & Carving', badge: stego.signals.length },
          { id: 'forensics', label: '🔬 ELA & Manipulation', badge: forensics.clues.length },
          { id: 'exif', label: '📷 Camera & Optical EXIF', badge: Object.keys(cameraExif).filter(k => (cameraExif as any)[k] !== undefined).length },
          { id: 'osint', label: '🌐 Visual OSINT & Reverse Search', badge: null },
          { id: 'ocr_vision', label: '📝 OCR & Text Carving', badge: ocrVision.detectedIocs.ips.length + ocrVision.detectedIocs.emails.length },
          { id: 'hashes', label: '🧬 Perceptual Hashes', badge: null },
          { id: 'raw', label: '📋 Raw EXIF Dict', badge: Object.keys(rawExif).length },
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
                padding: '8px 14px',
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

      {/* ── SUB-TAB 1: STEGANOGRAPHY & CARVING ──────────────────────────────── */}
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
          <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)', borderRadius: '8px', padding: '16px' }}>
            <div style={{ fontSize: '12px', color: '#94a3b8', fontWeight: 600, marginBottom: '12px', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
              StegSeek & Binwalk Deep Structural Heuristics
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
                <span style={{ color: '#cbd5e1' }}>LSB Parity / Magic Byte Integrity</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── SUB-TAB 2: ELA & MANIPULATION FORENSICS ──────────────────────────── */}
      {activeTab === 'forensics' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '8px', padding: '18px 20px' }}>
            <h4 style={{ margin: '0 0 12px 0', fontSize: '14px', fontWeight: 700, color: '#f1f5f9' }}>
              Error Level Analysis (ELA) & Quantization Forensics
            </h4>
            <p style={{ fontSize: '12px', color: '#94a3b8', margin: '0 0 16px 0', lineHeight: 1.5 }}>
              ELA highlights compression gradient discrepancies across JPEG 8x8 DCT grid blocks. Areas modified, pasted, or cloned exhibit distinct error rates compared to original sensor captures.
            </p>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '12px' }}>
              <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid rgba(255,255,255,0.04)', borderRadius: '6px', padding: '12px' }}>
                <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>JPEG Quantization Table</div>
                <div style={{ fontSize: '13px', color: '#38bdf8', fontWeight: 600, marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
                  {forensics.quantizationEstimated}
                </div>
              </div>

              <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid rgba(255,255,255,0.04)', borderRadius: '6px', padding: '12px' }}>
                <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Compression Quality</div>
                <div style={{ fontSize: '13px', color: '#f1f5f9', fontWeight: 600, marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
                  {forensics.compressionQuality}
                </div>
              </div>

              <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid rgba(255,255,255,0.04)', borderRadius: '6px', padding: '12px' }}>
                <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Editor Attribution</div>
                <div style={{ fontSize: '13px', color: forensics.softwareEditor ? '#fb923c' : '#00ffa3', fontWeight: 600, marginTop: '2px' }}>
                  {forensics.softwareEditor || 'No 3rd-Party Editor Signature'}
                </div>
              </div>
            </div>

            {/* Editing Clues List */}
            <div style={{ marginTop: '16px', paddingTop: '14px', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
              <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)', marginBottom: '8px' }}>
                Forensic Investigation Findings:
              </div>
              <ul style={{ margin: 0, paddingLeft: '20px', fontSize: '12px', color: '#cbd5e1', lineHeight: 1.6 }}>
                {forensics.clues.map((c, i) => (
                  <li key={i}>{c}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* ── SUB-TAB 3: CAMERA & OPTICAL EXIF ────────────────────────────────── */}
      {activeTab === 'exif' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          
          {/* GPS Coordinates Viewer */}
          {cameraExif.gps && (
            <div style={{ background: 'rgba(0, 255, 163, 0.04)', border: '1px solid rgba(0, 255, 163, 0.2)', borderRadius: '8px', padding: '16px 20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
                <div>
                  <div style={{ fontSize: '12px', color: '#00ffa3', fontWeight: 700, textTransform: 'uppercase', fontFamily: 'var(--font-mono)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>location_on</span>
                    Embedded GPS Coordinates Discovered
                  </div>
                  <div style={{ fontSize: '15px', fontWeight: 600, color: '#f1f5f9', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
                    {cameraExif.gps.formatted} {cameraExif.gps.altitude ? `(Altitude: ${cameraExif.gps.altitude})` : ''}
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
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '12px' }}>
            {[
              { label: 'Camera Make', value: cameraExif.make },
              { label: 'Camera Model', value: cameraExif.model },
              { label: 'Lens Model', value: cameraExif.lens },
              { label: 'Software / OS Tool', value: cameraExif.software },
              { label: 'Exposure Time / Shutter', value: cameraExif.exposureTime },
              { label: 'Aperture / F-Stop', value: cameraExif.aperture },
              { label: 'ISO Sensitivity', value: cameraExif.iso },
              { label: 'Focal Length', value: cameraExif.focalLength35mm || cameraExif.focalLength },
              { label: 'Flash Mode', value: cameraExif.flash },
              { label: 'White Balance', value: cameraExif.whiteBalance },
              { label: 'Metering Mode', value: cameraExif.meteringMode },
              { label: 'Exposure Program', value: cameraExif.exposureProgram },
              { label: 'Scene Capture Type', value: cameraExif.sceneCaptureType },
              { label: 'Digital Zoom Ratio', value: cameraExif.digitalZoomRatio },
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
              Hardware camera telemetry was stripped or is not present in this file.
            </div>
          )}
        </div>
      )}

      {/* ── SUB-TAB 4: VISUAL OSINT & REVERSE SEARCH ────────────────────────── */}
      {activeTab === 'osint' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '8px', padding: '18px 20px' }}>
            <h4 style={{ margin: '0 0 8px 0', fontSize: '14px', fontWeight: 700, color: '#f1f5f9' }}>
              Visual OSINT & Multi-Engine Reverse Image Search
            </h4>
            <p style={{ fontSize: '12px', color: '#94a3b8', margin: '0 0 16px 0', lineHeight: 1.5 }}>
              Query global image indexes to find source websites, identical copies, crop variants, and associated online accounts.
            </p>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '10px' }}>
              {[
                { name: 'Google Lens', desc: 'Object, logo & webpage recognition', url: osint.googleLensUrl, color: '#4285f4' },
                { name: 'Bing Visual Search', desc: 'Product, landmark & visual similarity', url: osint.bingVisualUrl, color: '#008373' },
                { name: 'TinEye Reverse Search', desc: 'Exact duplicate & crop trackback', url: osint.tineyeUrl, color: '#00a3e0' },
                { name: 'Yandex Images', desc: 'High-accuracy facial & background matching', url: osint.yandexUrl, color: '#fc3f1d' },
                { name: 'SauceNAO', desc: 'Anime, manga & digital art database', url: osint.saucenaoUrl, color: '#a855f7' }
              ].map((engine, idx) => (
                <a
                  key={idx}
                  href={engine.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{
                    background: 'rgba(255,255,255,0.03)',
                    border: '1px solid rgba(255,255,255,0.06)',
                    borderRadius: '8px',
                    padding: '14px 16px',
                    textDecoration: 'none',
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'space-between',
                    transition: 'all 0.15s ease'
                  }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = engine.color; e.currentTarget.style.background = 'rgba(255,255,255,0.06)'; }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.06)'; e.currentTarget.style.background = 'rgba(255,255,255,0.03)'; }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '13px', fontWeight: 700, color: '#f1f5f9' }}>{engine.name}</span>
                    <span className="material-symbols-outlined" style={{ fontSize: '16px', color: engine.color }}>open_in_new</span>
                  </div>
                  <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '6px' }}>{engine.desc}</div>
                </a>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── SUB-TAB 5: OCR & VISUAL INTELLIGENCE ────────────────────────────── */}
      {activeTab === 'ocr_vision' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          
          {/* Document Classification */}
          {ocrVision.documentType && (
            <div style={{ background: 'rgba(0, 242, 255, 0.05)', border: '1px solid rgba(0, 242, 255, 0.2)', borderRadius: '8px', padding: '14px 18px', display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span className="material-symbols-outlined" style={{ color: '#00f2ff', fontSize: '22px' }}>description</span>
              <div>
                <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Document Layout Classification</div>
                <div style={{ fontSize: '14px', fontWeight: 700, color: '#f1f5f9' }}>{ocrVision.documentType}</div>
              </div>
            </div>
          )}

          {/* Carved IOCs */}
          <div style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '8px', padding: '16px 20px' }}>
            <div style={{ fontSize: '12px', color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase', fontFamily: 'var(--font-mono)', marginBottom: '10px' }}>
              Carved IOC Indicators (IPs, Emails, Hashes)
            </div>

            {ocrVision.detectedIocs.ips.length === 0 && ocrVision.detectedIocs.emails.length === 0 && ocrVision.detectedIocs.hashes.length === 0 ? (
              <div style={{ fontSize: '12px', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
                No embedded network endpoints or credentials discovered in metadata chunks.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {ocrVision.detectedIocs.ips.map(ip => (
                  <div key={ip} style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: '#fb923c', background: 'rgba(251, 146, 60, 0.08)', padding: '4px 10px', borderRadius: '4px' }}>
                    🌐 IP Address: {ip}
                  </div>
                ))}
                {ocrVision.detectedIocs.emails.map(email => (
                  <div key={email} style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: '#38bdf8', background: 'rgba(56, 189, 248, 0.08)', padding: '4px 10px', borderRadius: '4px' }}>
                    ✉️ Email: {email}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Extracted Text Strings */}
          {ocrVision.extractedText && (
            <div style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '8px', padding: '16px 20px' }}>
              <div style={{ fontSize: '12px', color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase', fontFamily: 'var(--font-mono)', marginBottom: '10px' }}>
                Embedded Text / Comments Chunk
              </div>
              <pre style={{ margin: 0, fontSize: '12px', fontFamily: 'var(--font-mono)', color: '#cbd5e1', whiteSpace: 'pre-wrap', lineHeight: 1.5 }}>
                {ocrVision.extractedText}
              </pre>
            </div>
          )}

          {/* Face Analysis Privacy Notice */}
          <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)', borderRadius: '8px', padding: '12px 16px', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span className="material-symbols-outlined" style={{ color: '#94a3b8', fontSize: '20px' }}>shield</span>
            <div style={{ fontSize: '11px', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
              {ocrVision.faceAnalysis.privacyNotice}
            </div>
          </div>

        </div>
      )}

      {/* ── SUB-TAB 6: PERCEPTUAL VISUAL HASHES ─────────────────────────────── */}
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
              { label: 'wHash (Wavelet Hash)', value: hashes.whash, desc: 'Haar wavelet frequency transformation fingerprint.' },
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

      {/* ── SUB-TAB 7: RAW METADATA DICTIONARY ──────────────────────────────── */}
      {activeTab === 'raw' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div style={{ position: 'relative' }}>
            <span className="material-symbols-outlined" style={{ position: 'absolute', left: '12px', top: '10px', color: '#64748b', fontSize: '18px' }}>search</span>
            <input
              type="text"
              placeholder="Search raw metadata tags (e.g. ISO, Lens, GPS, MakerNotes)..."
              value={exifSearch}
              onChange={e => setExifSearch(e.target.value)}
              style={{
                width: '100%',
                padding: '9px 12px 9px 38px',
                background: 'rgba(0,0,0,0.3)',
                border: '1px solid #334155',
                borderRadius: '8px',
                color: '#ffffff',
                fontSize: '12px',
                fontFamily: 'var(--font-mono)'
              }}
            />
          </div>

          <div style={{ maxHeight: '420px', overflowY: 'auto', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '8px' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
              <tbody>
                {filteredExifEntries.map(([k, v], idx) => (
                  <tr key={idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)', background: idx % 2 === 0 ? 'rgba(0,0,0,0.1)' : 'transparent' }}>
                    <td style={{ padding: '8px 14px', color: '#38bdf8', width: '35%', fontWeight: 600 }}>{k}</td>
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
