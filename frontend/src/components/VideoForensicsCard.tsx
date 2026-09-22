import React, { useState, useEffect } from 'react';
import { Film, ExternalLink, Loader2, AlertTriangle } from 'lucide-react';
import { getBackendBase } from '../services/api';

interface VideoForensicsCardProps {
  file?: File | null;
}

export const VideoForensicsCard: React.FC<VideoForensicsCardProps> = ({ file }) => {
  const [metadata, setMetadata] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!file) return;
    
    const fetchMetadata = async () => {
      if (file.size > 32 * 1024 * 1024) {
        setError('File exceeds 32 MB limit. Cannot parse media metadata via backend.');
        return;
      }
      setLoading(true);
      setError(null);
      try {
        const formData = new FormData();
        formData.append('file', file);
        const res = await fetch(`${getBackendBase()}/api/forensics/media/metadata`, {
          method: 'POST',
          body: formData,
        });
        if (res.ok) {
          const data = await res.json();
          setMetadata(data);
        } else {
          setError('Backend FFprobe analysis failed. Is FFmpeg installed?');
        }
      } catch (err) {
        setError('Could not connect to backend engine.');
      } finally {
        setLoading(false);
      }
    };
    fetchMetadata();
  }, [file]);

  return (
    <div className="glass-card animate-fade-in-up" style={{ padding: '24px', position: 'relative', overflow: 'hidden' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '20px' }}>
        <Film size={24} color="var(--brand)" />
        <h2 style={{ margin: 0, fontSize: '18px' }}>Deep Video Forensics</h2>
      </div>

      {loading && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '20px', color: 'var(--brand)' }}>
          <Loader2 className="animate-spin" size={18} />
          <span style={{ fontSize: '14px', fontFamily: 'var(--font-mono)' }}>Analyzing media streams via backend...</span>
        </div>
      )}

      {error && (
        <div style={{ background: 'var(--danger-dim)', border: '1px solid var(--danger-border)', padding: '16px', borderRadius: '8px', marginBottom: '20px', display: 'flex', gap: '12px', alignItems: 'center' }}>
          <AlertTriangle color="var(--danger)" size={20} />
          <div style={{ color: 'var(--danger)', fontSize: '14px' }}>{error} Falling back to OSINT mode.</div>
        </div>
      )}

      {metadata && !error && (
        <div style={{ background: 'rgba(0,0,0,0.2)', padding: '16px', borderRadius: '8px', border: '1px solid var(--border)', marginBottom: '20px', maxHeight: '300px', overflowY: 'auto' }}>
          <h3 style={{ fontSize: '14px', marginBottom: '12px', color: 'var(--brand)' }}>FFprobe Container Analysis</h3>
          <pre style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--on-surface-2)', whiteSpace: 'pre-wrap' }}>
            {JSON.stringify(metadata, null, 2)}
          </pre>
        </div>
      )}

      <div style={{ background: 'var(--surface-3)', padding: '16px', borderRadius: '8px', border: '1px solid var(--border)', marginBottom: '16px' }}>
        <p style={{ color: 'var(--text-2)', fontSize: '14px', margin: 0, lineHeight: 1.5 }}>
          Use the following free online tools to verify video origins, extract keyframes, and detect deepfakes:
        </p>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
         <a href="https://www.invid-project.eu/tools-and-services/invid-verification-plugin/" target="_blank" rel="noopener noreferrer" style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 16px', background: 'var(--surface-2)', borderRadius: '6px', textDecoration: 'none', border: '1px solid var(--border)' }}>
           <div>
             <div style={{ color: 'var(--brand)', fontWeight: 'bold', marginBottom: '4px' }}>InVID & WeVerify Plugin</div>
             <div style={{ fontSize: '12px', color: 'var(--text-3)' }}>Deepfake detection, keyframe extraction, and reverse search.</div>
           </div>
           <ExternalLink size={16} color="var(--text-3)" />
         </a>
         <a href="https://citizenevidence.amnestyusa.org/" target="_blank" rel="noopener noreferrer" style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 16px', background: 'var(--surface-2)', borderRadius: '6px', textDecoration: 'none', border: '1px solid var(--border)' }}>
           <div>
             <div style={{ color: 'var(--brand)', fontWeight: 'bold', marginBottom: '4px' }}>Amnesty YouTube Dataviewer</div>
             <div style={{ fontSize: '12px', color: 'var(--text-3)' }}>Extract thumbnails and check exact upload times.</div>
           </div>
           <ExternalLink size={16} color="var(--text-3)" />
         </a>
         <a href="https://lens.google.com" target="_blank" rel="noopener noreferrer" style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 16px', background: 'var(--surface-2)', borderRadius: '6px', textDecoration: 'none', border: '1px solid var(--border)' }}>
           <div>
             <div style={{ color: 'var(--brand)', fontWeight: 'bold', marginBottom: '4px' }}>Google Lens</div>
             <div style={{ fontSize: '12px', color: 'var(--text-3)' }}>Upload a screenshot of the video for reverse image search.</div>
           </div>
           <ExternalLink size={16} color="var(--text-3)" />
         </a>
      </div>
    </div>
  );
};
