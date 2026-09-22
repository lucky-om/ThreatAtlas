import React, { useState, useEffect, useRef } from 'react';
import { 
  Image as ImageIcon, 
  ShieldCheck, 
  AlertTriangle, 
  CheckCircle2, 
  XCircle, 
  Sliders, 
  Copy, 
  Check, 
  Search,
  MapPin,
  FileText
} from 'lucide-react';
import { getBackendBase } from '../services/api';
import { ImageForensicsReport } from '../services/imageForensics';
import StegoWorker from '../workers/stego.worker?worker';

interface ImageForensicsCardProps {
  report: ImageForensicsReport;
  file?: File;
}

export const ImageForensicsCard: React.FC<ImageForensicsCardProps> = ({ report, file }) => {
  const [activeTab, setActiveTab] = useState<'stego' | 'forensics' | 'exif' | 'ocr_vision' | 'hashes' | 'raw'>('stego');
  const [exifSearch, setExifSearch] = useState('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Local state for client-side processing
  const [localExif, setLocalExif] = useState<Record<string, unknown> | null>(null);
  const [localRawExif, setLocalRawExif] = useState<Record<string, unknown>>({});
  const [localHashes, setLocalHashes] = useState<Record<string, string>>({});
  const [localStego, setLocalStego] = useState<any>(null);
  const [rgbAvg, setRgbAvg] = useState<{r: number, g: number, b: number} | null>(null);

  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    if (!file) return;

    let isMounted = true;
    let worker: Worker | null = null;

    const processFile = async () => {
      if (file.size > 32 * 1024 * 1024) {
        if (import.meta.env.DEV) console.error("File exceeds 32 MB limit.");
        return; // Don't process massive files locally or send to backend
      }
      try {
        // 1. Backend EXIF Parsing
        try {
          const formData = new FormData();
          formData.append('file', file);
          const res = await fetch(`${getBackendBase()}/api/forensics/image/exif`, {
            method: 'POST',
            body: formData,
            signal: AbortSignal.timeout(10000)
          });
          if (res.ok) {
            const exifData = await res.json();
            if (isMounted && exifData) {
              setLocalExif(exifData);
              setLocalRawExif(exifData);
            }
          }
        } catch (err) {
          if (import.meta.env.DEV) console.error("Backend EXIF parsing failed", err);
        }

        // 2. Cryptographic Hashing (SHA-256)
        const arrayBuffer = await file.arrayBuffer();
        const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        if (isMounted) {
          setLocalHashes((prev) => ({ ...prev, sha256: hashHex }));
        }

        // 3. Web Worker for Steganography
        worker = new StegoWorker();
        worker.onmessage = (e) => {
          if (e.data.status === 'success' && isMounted) {
            setLocalStego(e.data.stego);
          }
        };
        worker.postMessage(arrayBuffer);

        // 4. Canvas RGB Analysis
        const img = new Image();
        const objectUrl = URL.createObjectURL(file);
        img.onload = () => {
          if (canvasRef.current) {
            const ctx = canvasRef.current.getContext('2d');
            if (ctx) {
              canvasRef.current.width = 100;
              canvasRef.current.height = 100;
              ctx.drawImage(img, 0, 0, 100, 100);
              const imageData = ctx.getImageData(0, 0, 100, 100);
              const data = imageData.data;
              
              let r = 0, g = 0, b = 0;
              for (let i = 0; i < data.length; i += 4) {
                r += data[i];
                g += data[i+1];
                b += data[i+2];
              }
              const pixels = data.length / 4;
              if (isMounted) {
                setRgbAvg({
                  r: Math.round(r / pixels),
                  g: Math.round(g / pixels),
                  b: Math.round(b / pixels)
                });
              }
            }
          }
          URL.revokeObjectURL(objectUrl);
        };
        img.src = objectUrl;

      } catch (err) {
        if (import.meta.env.DEV) console.error("Client-side forensics failed", err);
      }
    };

    processFile();

    return () => {
      isMounted = false;
      if (worker) worker.terminate();
    };
  }, [file]);

  const handleCopy = (text: string, key: string) => {
    try {
      navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
    } catch {
      // ignore
    }
  };

  const { geometry, forensics, ocrVision } = report;
  
  // Merge static with local data
  const finalExif: any = localExif || report.cameraExif;
  const finalRawExif = Object.keys(localRawExif).length > 0 ? localRawExif : report.rawExif;
  const finalStego = localStego || report.stego;
  const finalHashes: any = { ...report.hashes, ...localHashes };

  const filteredExifEntries = Object.entries(finalRawExif).filter(([k, v]) => {
    if (!exifSearch) return true;
    return k.toLowerCase().includes(exifSearch.toLowerCase()) || String(v).toLowerCase().includes(exifSearch.toLowerCase());
  });

  const stegoColor = finalStego.riskLevel === 'critical' ? 'var(--danger)' : finalStego.riskLevel === 'suspicious' ? 'var(--warn)' : finalStego.riskLevel === 'low' ? 'var(--accent)' : 'var(--success)';
  const stegoBg = finalStego.riskLevel === 'critical' ? 'var(--danger-dim)' : finalStego.riskLevel === 'suspicious' ? 'var(--warn-dim)' : finalStego.riskLevel === 'low' ? 'var(--accent-dim)' : 'var(--success-dim)';
  const stegoBorder = finalStego.riskLevel === 'critical' ? 'var(--danger-border)' : finalStego.riskLevel === 'suspicious' ? 'var(--warn-border)' : finalStego.riskLevel === 'low' ? 'var(--accent-border)' : 'var(--success-border)';

  const manipColor = forensics.manipulationRisk === 'high' ? 'var(--danger)' : forensics.manipulationRisk === 'medium' ? 'var(--warn)' : forensics.manipulationRisk === 'low' ? 'var(--accent)' : 'var(--success)';
  const manipBg = forensics.manipulationRisk === 'high' ? 'var(--danger-dim)' : forensics.manipulationRisk === 'medium' ? 'var(--warn-dim)' : forensics.manipulationRisk === 'low' ? 'var(--accent-dim)' : 'var(--success-dim)';
  const manipBorder = forensics.manipulationRisk === 'high' ? 'var(--danger-border)' : forensics.manipulationRisk === 'medium' ? 'var(--warn-border)' : forensics.manipulationRisk === 'low' ? 'var(--accent-border)' : 'var(--success-border)';

  return (
    <div className="glass-card" style={{ padding: '28px 32px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      
      {/* Hidden canvas for RGB extraction */}
      <canvas ref={canvasRef} style={{ display: 'none' }} />

      {/* ── TOP HEADER ──────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border)', paddingBottom: '18px', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{
            width: '40px',
            height: '40px',
            borderRadius: '10px',
            background: 'rgba(255, 69, 0, 0.1)',
            border: '1px solid rgba(255, 69, 0, 0.25)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--brand)',
          }}>
            <ImageIcon size={22} />
          </div>
          <div>
            <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 700, color: 'var(--text)', fontFamily: 'var(--font-display)' }}>
              Deep Image Forensics & Visual Intelligence Suite
            </h3>
            <p style={{ margin: '3px 0 0', fontSize: '12px', color: 'var(--text-2)', fontFamily: 'var(--font-mono)' }}>
              12-point forensic matrix: Local EXIF, ELA manipulation, Steganography & Hashing
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
            background: stegoBg,
            border: `1px solid ${stegoBorder}`
          }}>
            {finalStego.riskScore > 0 ? (
              <AlertTriangle size={14} style={{ color: stegoColor }} />
            ) : (
              <ShieldCheck size={14} style={{ color: stegoColor }} />
            )}
            <span style={{ color: stegoColor, fontSize: '11px', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
              Stego: {finalStego.riskScore}/100 ({finalStego.riskLevel.toUpperCase()})
            </span>
          </div>

          {/* Manipulation Risk Badge */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            padding: '5px 12px',
            borderRadius: '999px',
            background: manipBg,
            border: `1px solid ${manipBorder}`
          }}>
            <Sliders size={14} style={{ color: manipColor }} />
            <span style={{ color: manipColor, fontSize: '11px', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
              ELA Manipulation: {forensics.manipulationRisk.toUpperCase()}
            </span>
          </div>
        </div>
      </div>

      {/* ── 4 QUICK METRIC SUMMARY CARDS ────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '14px' }}>
        {/* 1. Resolution & Aspect Ratio */}
        <div style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: 'var(--text-3)', textTransform: 'uppercase', fontFamily: 'var(--font-mono)', letterSpacing: '0.05em' }}>Dimensions & Aspect</div>
          <div style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text)', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
            {geometry.width > 0 ? `${geometry.width} × ${geometry.height}` : 'N/A'}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--accent)', marginTop: '3px', fontFamily: 'var(--font-mono)' }}>
            {geometry.megapixels} · {geometry.aspectRatio}
          </div>
        </div>

        {/* 2. Color Depth & Compression */}
        <div style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: 'var(--text-3)', textTransform: 'uppercase', fontFamily: 'var(--font-mono)', letterSpacing: '0.05em' }}>Color Profile & Density</div>
          <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text)', marginTop: '4px', fontFamily: 'var(--font-display)' }}>
            {geometry.colorSpace} ({geometry.bitsPerSample ? `${geometry.bitsPerSample * (geometry.colorComponents || 3)}-bit` : '24-bit'})
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-2)', marginTop: '3px', fontFamily: 'var(--font-mono)' }}>
            {geometry.compression} · {geometry.density || '72 dpi'}
          </div>
        </div>

        {/* 3. Camera / Equipment */}
        <div style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: 'var(--text-3)', textTransform: 'uppercase', fontFamily: 'var(--font-mono)', letterSpacing: '0.05em' }}>Acquisition Hardware</div>
          <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text)', marginTop: '4px', fontFamily: 'var(--font-display)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {finalExif.Make || finalExif.Model || finalExif.make || finalExif.model ? `${finalExif.Make || finalExif.make || ''} ${finalExif.Model || finalExif.model || ''}` : 'Hardware Telemetry Stripped'}
          </div>
          <div style={{ fontSize: '12px', color: finalExif.Software || finalExif.software ? 'var(--warn)' : 'var(--text-3)', marginTop: '3px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontFamily: 'var(--font-display)' }}>
            {finalExif.Software || finalExif.software ? `Edited in ${finalExif.Software || finalExif.software}` : 'Direct Sensor Capture'}
          </div>
        </div>

        {/* 4. GPS Geolocation Status */}
        <div style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: 'var(--text-3)', textTransform: 'uppercase', fontFamily: 'var(--font-mono)', letterSpacing: '0.05em' }}>GPS Geolocation</div>
          <div style={{ fontSize: '15px', fontWeight: 600, color: (finalExif.latitude || (finalExif.gps && finalExif.gps.formatted)) ? 'var(--success)' : 'var(--text-2)', marginTop: '4px', fontFamily: 'var(--font-display)' }}>
            {(finalExif.latitude || (finalExif.gps && finalExif.gps.formatted)) ? '📍 Coordinates Embedded' : 'No GPS Metadata'}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-3)', marginTop: '3px', fontFamily: 'var(--font-mono)' }}>
            {finalExif.latitude ? `${finalExif.latitude.toFixed(5)}, ${finalExif.longitude?.toFixed(5)}` : (finalExif.gps ? finalExif.gps.formatted : 'Privacy scrubbed / Strip')}
          </div>
        </div>
      </div>

      {/* ── 6 FORENSIC SUB-NAV TABS ─────────────────────────────────────────── */}
      <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', gap: '4px', overflowX: 'auto', paddingBottom: '10px' }} className="custom-scrollbar">
        {(['stego', 'forensics', 'exif', 'ocr_vision', 'hashes', 'raw'] as const).map(t => (
          <button
            key={t}
            onClick={() => setActiveTab(t)}
            style={{
              padding: '8px 16px',
              background: activeTab === t ? 'rgba(255,255,255,0.1)' : 'transparent',
              border: 'none',
              borderRadius: '8px',
              color: activeTab === t ? '#fff' : 'var(--text-3)',
              fontSize: '12px',
              fontWeight: activeTab === t ? 700 : 500,
              cursor: 'pointer',
              fontFamily: 'var(--font-sans)',
              whiteSpace: 'nowrap',
              transition: 'all 0.2s'
            }}
          >
            {t.replace('_', ' ').toUpperCase()}
          </button>
        ))}
      </div>

      {/* ── SUB-TAB 1: STEGANOGRAPHY & CARVING ──────────────────────────────── */}
      {activeTab === 'stego' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          
          {/* Signal Cards */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {finalStego.signals.map((sig: any) => {
              const sigColor = sig.severity === 'critical' ? 'var(--danger)' : sig.severity === 'high' ? 'var(--warn)' : sig.severity === 'medium' ? 'var(--warn)' : sig.severity === 'low' ? 'var(--accent)' : 'var(--success)';
              return (
                <div key={sig.id} style={{ background: 'var(--surface-2)', border: `1px solid ${sigColor}35`, borderRadius: 'var(--radius-md)', padding: '14px 18px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <span style={{ color: 'var(--text)', fontWeight: 600, fontSize: '13px', fontFamily: 'var(--font-display)' }}>{sig.label}</span>
                    <span style={{ background: `${sigColor}18`, border: `1px solid ${sigColor}40`, color: sigColor, padding: '2px 8px', borderRadius: '4px', fontSize: '10px', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
                      {sig.severity.toUpperCase()}
                    </span>
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-2)', lineHeight: 1.5 }}>
                    {sig.details}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Steganography Checklist */}
          <div style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '16px 20px' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-3)', fontWeight: 600, marginBottom: '14px', textTransform: 'uppercase', fontFamily: 'var(--font-mono)', letterSpacing: '0.05em' }}>
              StegSeek & Binwalk Deep Structural Heuristics
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '12px', fontSize: '12px', fontFamily: 'var(--font-display)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                {finalStego.polyglotDetected ? (
                  <XCircle size={16} style={{ color: 'var(--danger)', flexShrink: 0 }} />
                ) : (
                  <CheckCircle2 size={16} style={{ color: 'var(--success)', flexShrink: 0 }} />
                )}
                <span style={{ color: 'var(--text-2)' }}>PHP/Executable Polyglot Signature</span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                {finalStego.hasTrailingData ? (
                  <XCircle size={16} style={{ color: 'var(--danger)', flexShrink: 0 }} />
                ) : (
                  <CheckCircle2 size={16} style={{ color: 'var(--success)', flexShrink: 0 }} />
                )}
                <span style={{ color: 'var(--text-2)' }}>Trailing Append Data (Post-EOI)</span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                {finalStego.scriptInjectionDetected ? (
                  <XCircle size={16} style={{ color: 'var(--danger)', flexShrink: 0 }} />
                ) : (
                  <CheckCircle2 size={16} style={{ color: 'var(--success)', flexShrink: 0 }} />
                )}
                <span style={{ color: 'var(--text-2)' }}>EXIF Script / XSS Injections</span>
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
              Error Level Analysis (ELA) & Pixel Forensics
            </h4>
            
            {/* Real RGB Data from Canvas */}
            {rgbAvg && (
              <div style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{ width: '40px', height: '40px', borderRadius: '4px', background: `rgb(${rgbAvg.r}, ${rgbAvg.g}, ${rgbAvg.b})`, border: '1px solid rgba(255,255,255,0.2)' }} />
                <div>
                  <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Canvas Global RGB Mean</div>
                  <div style={{ fontSize: '13px', color: '#f1f5f9', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>
                    R: {rgbAvg.r} | G: {rgbAvg.g} | B: {rgbAvg.b}
                  </div>
                </div>
              </div>
            )}

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '12px' }}>
              <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid rgba(255,255,255,0.04)', borderRadius: '6px', padding: '12px' }}>
                <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>JPEG Quantization Table</div>
                <div style={{ fontSize: '13px', color: 'var(--brand)', fontWeight: 600, marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
                  {forensics.quantizationEstimated}
                </div>
              </div>

              <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid rgba(255,255,255,0.04)', borderRadius: '6px', padding: '12px' }}>
                <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Compression Quality</div>
                <div style={{ fontSize: '13px', color: '#f1f5f9', fontWeight: 600, marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
                  {forensics.compressionQuality}
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
          {(finalExif.latitude || (finalExif.gps && finalExif.gps.formatted)) && (
            <div style={{ background: 'rgba(0, 255, 163, 0.04)', border: '1px solid rgba(0, 255, 163, 0.2)', borderRadius: '8px', padding: '16px 20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
                <div>
                  <div style={{ fontSize: '12px', color: 'var(--brand-amber)', fontWeight: 700, textTransform: 'uppercase', fontFamily: 'var(--font-mono)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <MapPin size={16} />
                    Embedded GPS Coordinates Discovered
                  </div>
                  <div style={{ fontSize: '15px', fontWeight: 600, color: '#f1f5f9', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
                    {finalExif.latitude ? `${finalExif.latitude.toFixed(5)}, ${finalExif.longitude?.toFixed(5)}` : (finalExif.gps ? finalExif.gps.formatted : 'N/A')}
                  </div>
                </div>

                {finalExif.latitude && (
                  <div style={{ display: 'flex', gap: '10px' }}>
                    <a
                      href={`https://www.google.com/maps/search/?api=1&query=${finalExif.latitude},${finalExif.longitude}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{ background: 'rgba(255, 69, 0, 0.1)', border: '1px solid rgba(255, 69, 0, 0.3)', color: 'var(--brand)', padding: '5px 12px', borderRadius: '6px', fontSize: '12px', fontFamily: 'var(--font-mono)', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '4px' }}
                    >
                      Google Maps
                    </a>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Camera Settings Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '12px' }}>
            {[
              { label: 'Camera Make', value: finalExif.Make || finalExif.make },
              { label: 'Camera Model', value: finalExif.Model || finalExif.model },
              { label: 'Lens Model', value: finalExif.LensModel || finalExif.lens },
              { label: 'Software / OS Tool', value: finalExif.Software || finalExif.software },
              { label: 'Exposure Time', value: finalExif.ExposureTime },
              { label: 'Aperture / F-Stop', value: finalExif.FNumber },
              { label: 'ISO Sensitivity', value: finalExif.ISO },
              { label: 'Focal Length', value: finalExif.FocalLength },
              { label: 'Flash Mode', value: finalExif.Flash },
              { label: 'White Balance', value: finalExif.WhiteBalance },
              { label: 'Date/Time Original', value: finalExif.DateTimeOriginal || finalExif.dateTimeOriginal },
            ].filter(item => item.value !== undefined && item.value !== null).map((item, idx) => (
              <div key={idx} style={{ padding: '10px 14px', background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.04)', borderRadius: '6px' }}>
                <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>{item.label}</div>
                <div className="font-data-mono" style={{ fontSize: '13px', color: '#f1f5f9', marginTop: '2px', wordBreak: 'break-all' }}>{String(item.value)}</div>
              </div>
            ))}
          </div>

          {!finalExif.Make && !finalExif.make && !finalExif.Model && !finalExif.model && (
            <div style={{ padding: '24px', textAlign: 'center', color: '#64748b', background: 'rgba(0,0,0,0.2)', borderRadius: '8px' }} className="font-data-mono">
              Hardware camera telemetry was stripped or is not present in this file.
            </div>
          )}
        </div>
      )}

      {/* ── SUB-TAB 5: OCR & VISUAL INTELLIGENCE ────────────────────────────── */}
      {activeTab === 'ocr_vision' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          
          {/* Document Classification */}
          {ocrVision.documentType && (
            <div style={{ background: 'rgba(255, 69, 0, 0.05)', border: '1px solid rgba(255, 69, 0, 0.2)', borderRadius: '8px', padding: '14px 18px', display: 'flex', alignItems: 'center', gap: '10px' }}>
              <FileText size={20} style={{ color: 'var(--brand)' }} />
              <div>
                <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Document Layout Classification</div>
                <div style={{ fontSize: '14px', fontWeight: 700, color: '#f1f5f9' }}>{ocrVision.documentType}</div>
              </div>
            </div>
          )}

          {/* Extracted Text (OCR) */}
          {ocrVision.extractedText && (
            <div style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '8px', padding: '16px 20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                <span style={{ fontSize: '12px', color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
                  Extracted Text (OCR)
                </span>
                <button 
                  onClick={() => handleCopy(ocrVision.extractedText || '', 'ocr-text')}
                  style={{ background: 'rgba(255,255,255,0.1)', border: 'none', borderRadius: '4px', cursor: 'pointer', color: copiedKey === 'ocr-text' ? 'var(--brand-amber)' : '#f1f5f9', display: 'flex', padding: '4px 8px', alignItems: 'center', gap: '6px', fontSize: '11px', fontWeight: 600 }}
                >
                  {copiedKey === 'ocr-text' ? <Check size={14} /> : <Copy size={14} />}
                  {copiedKey === 'ocr-text' ? 'COPIED' : 'COPY TEXT'}
                </button>
              </div>
              <pre className="custom-scrollbar" style={{ fontSize: '12px', color: '#e2e8f0', fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap', maxHeight: '200px', overflowY: 'auto', background: 'rgba(0,0,0,0.2)', padding: '12px', borderRadius: '6px', margin: 0, userSelect: 'text' }}>
                {ocrVision.extractedText}
              </pre>
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
                  <div key={email} style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--brand)', background: 'rgba(56, 189, 248, 0.08)', padding: '4px 10px', borderRadius: '4px' }}>
                    ✉️ Email: {email}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Face Analysis Privacy Notice */}
          <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)', borderRadius: '8px', padding: '12px 16px', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <ShieldCheck size={18} style={{ color: '#94a3b8' }} />
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

          {finalHashes.sha256 && (
            <div style={{ background: 'rgba(255, 69, 0, 0.05)', border: '1px solid rgba(255, 69, 0, 0.3)', borderRadius: '8px', padding: '14px 18px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <span style={{ fontSize: '12px', color: 'var(--brand)', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>SHA-256 (Local Web Crypto API)</span>
                <button 
                  onClick={() => handleCopy(finalHashes.sha256 || '', 'sha256')}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: copiedKey === 'sha256' ? 'var(--brand-amber)' : '#64748b', display: 'flex', padding: 0 }}
                >
                  {copiedKey === 'sha256' ? <Check size={15} /> : <Copy size={15} />}
                </button>
              </div>
              <div className="font-data-mono" style={{ fontSize: '13px', color: '#f1f5f9', wordBreak: 'break-all' }}>
                {finalHashes.sha256}
              </div>
            </div>
          )}

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {[
              { label: 'dHash (Difference Hash)', value: finalHashes.dhash, desc: 'Tracks gradient directional shifts across 8x8 luminance matrix.' },
              { label: 'aHash (Average Hash)', value: finalHashes.ahash, desc: 'Computes mean pixel intensity thresholding for scale-invariant matching.' },
              { label: 'pHash (Perceptual Hash)', value: finalHashes.phash, desc: 'Discrete Cosine Transform (DCT) frequency fingerprint.' },
            ].filter(h => h.value).map((item, idx) => (
              <div key={idx} style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.05)', borderRadius: '8px', padding: '14px 18px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <span style={{ fontSize: '12px', color: 'var(--brand)', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>{item.label}</span>
                  <button 
                    onClick={() => handleCopy(item.value || '', item.label)}
                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: copiedKey === item.label ? 'var(--brand-amber)' : '#64748b', display: 'flex', padding: 0 }}
                  >
                    {copiedKey === item.label ? <Check size={15} /> : <Copy size={15} />}
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
          <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
            <Search size={16} style={{ position: 'absolute', left: '12px', color: '#64748b' }} />
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
                    <td style={{ padding: '8px 14px', color: 'var(--brand)', width: '35%', fontWeight: 600 }}>{k}</td>
                    <td style={{ padding: '8px 14px', color: '#cbd5e1', wordBreak: 'break-all' }}>
                      {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                    </td>
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
