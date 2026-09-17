import React from 'react';
import { Music, ExternalLink } from 'lucide-react';

interface AudioForensicsCardProps {
  file?: File | null;
}

export const AudioForensicsCard: React.FC<AudioForensicsCardProps> = () => {
  return (
    <div className="glass-card animate-fade-in-up" style={{ padding: '24px', position: 'relative', overflow: 'hidden' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '20px' }}>
        <Music size={24} color="#00e87a" />
        <h2 style={{ margin: 0, fontSize: '18px' }}>Audio Forensics (OSINT Mode)</h2>
      </div>
      <div style={{ background: 'var(--surface-3)', padding: '16px', borderRadius: '8px', border: '1px solid var(--border)', marginBottom: '16px' }}>
        <p style={{ color: 'var(--text-2)', fontSize: '14px', margin: 0, lineHeight: 1.5 }}>
          Use the following free online tools to analyze audio frequencies, detect splices, or uncover hidden steganography:
        </p>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
         <a href="https://academo.org/demos/3d-spectrogram/" target="_blank" rel="noopener noreferrer" style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 16px', background: 'var(--surface-2)', borderRadius: '6px', textDecoration: 'none', border: '1px solid var(--border)' }}>
           <div>
             <div style={{ color: 'var(--brand-amber)', fontWeight: 'bold', marginBottom: '4px' }}>Academo 3D Spectrogram</div>
             <div style={{ fontSize: '12px', color: 'var(--text-3)' }}>Visualize audio frequencies to spot deepfake splices.</div>
           </div>
           <ExternalLink size={16} color="var(--text-3)" />
         </a>
         <a href="https://stegonline.georgeom.net/" target="_blank" rel="noopener noreferrer" style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 16px', background: 'var(--surface-2)', borderRadius: '6px', textDecoration: 'none', border: '1px solid var(--border)' }}>
           <div>
             <div style={{ color: 'var(--brand-amber)', fontWeight: 'bold', marginBottom: '4px' }}>StegOnline</div>
             <div style={{ fontSize: '12px', color: 'var(--text-3)' }}>Check for trailing data or hidden steganography.</div>
           </div>
           <ExternalLink size={16} color="var(--text-3)" />
         </a>
      </div>
    </div>
  );
};
