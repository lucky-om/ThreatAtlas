import React, { useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { scanFile } from '../services/api';
import { SEO } from '../components/SEO';
import { PageReveal } from '../components/PageReveal';
import { YaraScannerModule } from '../components/YaraScannerModule';
import { useScanHistory } from '../services/historyStore';

export const FileScan: React.FC = () => {
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hashInput, setHashInput] = useState('');
  const [showYara, setShowYara] = useState(false);
  const [isDragOver, setIsDragOver] = useState(false);
  const { history } = useScanHistory();

  const handleFileUpload = async (file: File) => {
    setIsLoading(true);
    setError(null);
    try {
      if (file.size > 32 * 1024 * 1024) throw new Error('File exceeds 32 MB limit.');
      const response = await scanFile(file);
      navigate(`/file/${response.data.id}`, { state: { uploadedFile: file } });
    } catch (err: any) {
      setError(err.message || 'Upload failed. Try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleHashLookup = (e: React.FormEvent) => {
    e.preventDefault();
    const clean = hashInput.trim().toLowerCase();
    if (!clean) return;
    if (!/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(clean)) {
      setError('Enter a valid MD5, SHA-1, or SHA-256 hash.');
      return;
    }
    navigate(`/file/${clean}`);
  };

  const recent = history?.filter(h => h.type === 'file').slice(0, 3) || [];

  return (
    <div style={{ position: 'relative', minHeight: '100vh', paddingTop: '96px', paddingBottom: '64px', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
      <SEO title="File Scanner — ThreatAtlas" description="Upload files or enter a hash for deep multi-engine malware analysis." path="/file" />

      <div className="container" style={{ maxWidth: '820px', width: '100%', position: 'relative', zIndex: 10 }}>
        <PageReveal>

        {/* Title */}
        <div style={{ marginBottom: '32px', display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ background: 'var(--brand-dim)', color: 'var(--brand)', padding: '12px', borderRadius: '12px', display: 'flex' }}>
            <span className="material-symbols-outlined" style={{ fontSize: '32px' }}>upload_file</span>
          </div>
          <div>
            <h1 style={{ fontFamily: 'var(--font-headline)', fontSize: '32px', margin: '0 0 4px 0', color: 'var(--on-surface)' }}>
              <span style={{ color: 'var(--brand)', textShadow: '0 0 20px var(--brand-glow)' }}>File</span> Analysis
            </h1>
            <p style={{ fontFamily: 'var(--font-sans)', color: 'var(--on-surface-3)', margin: 0, fontSize: '15px' }}>
              Upload any file for static and dynamic analysis across 70+ engines.
            </p>
          </div>
        </div>

        {/* Scanner Card */}
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1, duration: 0.5 }} className="glass-card" style={{ overflow: 'hidden', marginBottom: '24px' }}>

          {/* Drop Zone */}
          <div style={{ padding: '28px 28px 0' }}>
            {error && (
              <div style={{ padding: '12px 16px', marginBottom: '20px', background: 'rgba(255,42,95,0.08)', border: '1px solid rgba(255,42,95,0.3)', borderRadius: '10px', color: 'var(--status-malicious)', fontFamily: 'var(--font-mono)', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>warning</span>
                <span>{error}</span>
              </div>
            )}

            <div
              className="dropzone-dashed"
              onDragOver={e => { e.preventDefault(); setIsDragOver(true); }}
              onDragLeave={() => setIsDragOver(false)}
              onDrop={e => { e.preventDefault(); setIsDragOver(false); const f = e.dataTransfer.files[0]; if (f) handleFileUpload(f); }}
              onClick={() => fileInputRef.current?.click()}
              style={{ cursor: 'pointer', padding: '56px 24px', textAlign: 'center', background: isDragOver ? 'rgba(255,69,0,0.1)' : undefined, borderColor: isDragOver ? 'rgba(255,69,0,0.7)' : undefined }}
            >
              <input type="file" ref={fileInputRef} style={{ display: 'none' }} onChange={e => e.target.files?.[0] && handleFileUpload(e.target.files[0])} />
              <motion.span
                animate={isLoading ? { rotate: 360 } : {}}
                transition={{ repeat: Infinity, duration: 1.2, ease: 'linear' }}
                className="material-symbols-outlined"
                style={{ fontSize: '64px', color: 'var(--brand)', display: 'block', marginBottom: '16px', filter: 'drop-shadow(0 0 16px var(--brand-glow))' }}
              >
                {isLoading ? 'sync' : 'cloud_upload'}
              </motion.span>
              <h2 style={{ fontFamily: 'var(--font-headline)', fontSize: '20px', fontWeight: 700, color: 'var(--on-surface)', marginBottom: '8px' }}>
                {isLoading ? 'Uploading & scanning...' : isDragOver ? 'Drop to scan' : 'Drop file here or click to browse'}
              </h2>
              <p style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--on-surface-3)' }}>
                PE · ELF · APK · PDF · Office · ZIP · Images — max 32 MB
              </p>
            </div>
          </div>

          {/* Hash Lookup */}
          <div style={{ padding: '20px 28px 0', borderTop: '1px solid rgba(255,255,255,0.05)', marginTop: '24px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px', flexWrap: 'wrap', gap: '10px' }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', fontWeight: 700, color: 'var(--on-surface-3)', letterSpacing: '0.12em', textTransform: 'uppercase' }}>
                Or Search by Hash
              </span>
              <button
                onClick={() => setShowYara(!showYara)}
                style={{ background: showYara ? 'var(--brand-dim)' : 'rgba(255,255,255,0.04)', border: `1px solid ${showYara ? 'var(--border-2)' : 'rgba(255,255,255,0.08)'}`, borderRadius: '8px', padding: '5px 12px', color: showYara ? 'var(--brand)' : 'var(--on-surface-3)', fontFamily: 'var(--font-mono)', fontSize: '11px', fontWeight: 700, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px', transition: 'all 0.18s' }}
              >
                <span className="material-symbols-outlined" style={{ fontSize: '15px' }}>search_insights</span>
                {showYara ? 'Hide YARA' : 'YARA Pattern Matcher'}
              </button>
            </div>
            <form onSubmit={handleHashLookup} style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
              <input
                type="text"
                className="input-field"
                placeholder="MD5 / SHA-1 / SHA-256 hash"
                value={hashInput}
                onChange={e => setHashInput(e.target.value.toLowerCase())}
                autoCapitalize="none" autoCorrect="off" spellCheck={false}
                style={{ flex: 1, minWidth: '200px', padding: '13px 16px', fontSize: '13px', fontFamily: 'var(--font-mono)' }}
              />
              <button type="submit" className="btn-primary" disabled={!hashInput.trim()} style={{ padding: '0 22px', fontSize: '12px', color: '#fff', whiteSpace: 'nowrap' }}>
                LOOKUP HASH
              </button>
            </form>
          </div>

          {/* Card status footer */}
          <div style={{ padding: '14px 28px', marginTop: '20px', background: 'rgba(0,0,0,0.3)', borderTop: '1px solid rgba(255,255,255,0.04)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--brand)', fontWeight: 700, letterSpacing: '0.10em' }}>
              70+ ENGINES · YARA · FORENSICS · ATLAS INTELLIGENCE
            </span>
            <div style={{ display: 'flex', gap: '6px' }}>
              {['PE', 'ELF', 'APK', 'PDF', 'ZIP', 'IMG'].map(f => (
                <span key={f} style={{ fontSize: '10px', padding: '2px 7px', borderRadius: '4px', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.07)', color: 'var(--on-surface-3)', fontFamily: 'var(--font-mono)' }}>{f}</span>
              ))}
            </div>
          </div>
        </motion.div>

        {/* YARA Module */}
        {showYara && <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}><YaraScannerModule /></motion.div>}

        {/* Recent file scans */}
        {recent.length > 0 && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.3 }} style={{ marginTop: '28px' }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', fontWeight: 700, color: 'var(--on-surface-3)', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span className="material-symbols-outlined" style={{ fontSize: '14px', color: 'var(--brand)' }}>history</span>
              Recent File Scans
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '10px' }}>
              {recent.map(item => {
                const isMal = item.maliciousCount > 0;
                return (
                  <div key={item.id} onClick={() => navigate(`/file/${item.hash || item.id}`)}
                    style={{ background: 'var(--surface-elevated)', border: '1px solid var(--border-subtle)', borderRadius: '10px', padding: '14px 16px', cursor: 'pointer', transition: 'all 0.18s' }}
                    onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--brand)'; e.currentTarget.style.transform = 'translateY(-2px)'; }}
                    onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border-subtle)'; e.currentTarget.style.transform = 'none'; }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                      <span style={{ fontSize: '10px', color: 'var(--brand)', fontFamily: 'var(--font-mono)', fontWeight: 700, letterSpacing: '0.10em' }}>FILE</span>
                      <span style={{ fontSize: '10px', padding: '2px 7px', borderRadius: '4px', background: isMal ? 'rgba(255,42,95,0.12)' : 'rgba(0,232,122,0.10)', border: `1px solid ${isMal ? 'rgba(255,42,95,0.3)' : 'rgba(0,232,122,0.25)'}`, color: isMal ? 'var(--status-malicious)' : 'var(--status-clean)', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                        {isMal ? `${item.maliciousCount} MALICIOUS` : 'CLEAN'}
                      </span>
                    </div>
                    <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--on-surface)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginBottom: '4px' }}>{item.name || item.target}</div>
                    <div style={{ fontSize: '11px', color: 'var(--on-surface-3)', fontFamily: 'var(--font-mono)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.hash || item.target}</div>
                  </div>
                );
              })}
            </div>
          </motion.div>
        )}
        </PageReveal>
      </div>
    </div>
  );
};
