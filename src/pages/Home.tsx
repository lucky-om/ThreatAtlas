import React, { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { scanFile, scanUrl } from '../services/api';

export const Home: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'file' | 'url' | 'search'>('file');
  const [inputValue, setInputValue] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  const fileInputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  const handleFileDrop = async (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      await handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      await handleFileUpload(e.target.files[0]);
    }
  };

  const handleFileUpload = async (file: File) => {
    setIsLoading(true);
    setError(null);
    try {
      if (file.size > 32 * 1024 * 1024) {
         throw new Error("File is too large. Maximum size is 32MB.");
      }
      const response = await scanFile(file);
      navigate(`/file/${response.data.id}`);
    } catch (err: any) {
      if (err.response?.status === 401 || err.status === 401) {
         setError("Authentication failed. Ensure a valid VirusTotal API key is configured.");
      } else {
         setError(err.message || 'An error occurred during file upload.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputValue.trim()) return;

    setIsLoading(true);
    setError(null);

    try {
      if (activeTab === 'url') {
        const response = await scanUrl(inputValue);
        navigate(`/url/${response.data.id}`);
      } else if (activeTab === 'search') {
        const val = inputValue.trim();
        if (/^[a-fA-F0-9]{32,64}$/.test(val)) {
           navigate(`/file/${val}`);
        } else {
           const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(val) || /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/.test(val);
           navigate(isIp ? `/ip-address/${val}` : `/domain/${val}`);
        }
      }
    } catch (err: any) {
      if (err.response?.status === 401 || err.status === 401) {
         setError("Authentication failed. Ensure a valid VirusTotal API key is configured.");
      } else {
         setError(err.message || 'An error occurred during scanning.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div style={{ position: 'relative', minHeight: '100vh', paddingTop: '100px', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
      {/* Background Layers */}
      <div className="digital-grid"></div>
      <div className="glow-cyan"></div>

      <div className="container" style={{ position: 'relative', zIndex: 10, maxWidth: '900px' }}>
        
        {/* Dashboard Header */}
        <div className="animate-fade-in-up" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '24px' }}>
          <div>
            <p className="font-code-sm text-primary flex items-center gap-2" style={{ marginBottom: '8px' }}>
              <span className="animate-pulse" style={{ width: '8px', height: '8px', background: 'var(--primary)', borderRadius: '50%', display: 'inline-block' }}></span>
              Protocol: V4 Active
            </p>
            <h1 className="font-display-lg text-on-surface">Global Threat Scan</h1>
          </div>
          <div className="font-code-sm text-on-surface-variant flex gap-6" style={{ display: 'flex', gap: '24px', textAlign: 'right' }}>
            <div>
              <div style={{ color: 'rgba(0, 242, 255, 0.4)' }}>ENGINE</div>
              <div>NEURAL-X</div>
            </div>
            <div>
              <div style={{ color: 'rgba(0, 242, 255, 0.4)' }}>LATENCY</div>
              <div>14MS</div>
            </div>
          </div>
        </div>

        {/* Central Scanner Card */}
        <div className="glass-card glass-card-accent animate-fade-in-up" style={{ padding: '2px', overflow: 'hidden', animationDelay: '0.1s' }}>
          {/* Tabs */}
          <div className="scanner-tabs">
            <button 
              className={`scanner-tab font-label-caps ${activeTab === 'file' ? 'active' : ''}`}
              onClick={() => { setActiveTab('file'); setError(null); }}
            >
              FILE
            </button>
            <button 
              className={`scanner-tab font-label-caps ${activeTab === 'url' ? 'active' : ''}`}
              onClick={() => { setActiveTab('url'); setError(null); }}
            >
              URL
            </button>
            <button 
              className={`scanner-tab font-label-caps ${activeTab === 'search' ? 'active' : ''}`}
              onClick={() => { setActiveTab('search'); setError(null); }}
            >
              SEARCH
            </button>
          </div>

          <div style={{ padding: '48px' }}>
            {error && (
              <div style={{ padding: '16px', marginBottom: '24px', backgroundColor: 'rgba(255, 0, 60, 0.1)', border: '1px solid var(--secondary)', borderRadius: '4px', color: 'var(--secondary)', fontFamily: 'var(--font-mono)', fontSize: '14px' }}>
                <span className="material-symbols-outlined" style={{ verticalAlign: 'middle', marginRight: '8px' }}>warning</span>
                {error}
              </div>
            )}

            {activeTab === 'file' ? (
              <div 
                className="dropzone-dashed"
                onDragOver={(e) => {
                  e.preventDefault();
                  e.currentTarget.style.backgroundColor = 'rgba(0,242,255,0.05)';
                }}
                onDragLeave={(e) => {
                  e.currentTarget.style.backgroundColor = 'rgba(0,242,255,0.02)';
                }}
                onDrop={(e) => {
                  e.currentTarget.style.backgroundColor = 'rgba(0,242,255,0.02)';
                  handleFileDrop(e);
                }}
                onClick={() => fileInputRef.current?.click()}
              >
                <input 
                  type="file" 
                  ref={fileInputRef} 
                  style={{ display: 'none' }} 
                  onChange={handleFileSelect}
                />
                
                {isLoading ? (
                  <span className="material-symbols-outlined text-primary spin" style={{ fontSize: '64px', marginBottom: '16px' }}>sync</span>
                ) : (
                  <span className="material-symbols-outlined text-primary" style={{ fontSize: '64px', marginBottom: '16px' }}>upload_file</span>
                )}
                <h2 className="font-headline-sm text-on-surface" style={{ marginBottom: '8px' }}>
                  {isLoading ? 'UPLOADING & ANALYZING...' : 'Drag & drop a file here or click to select'}
                </h2>
                <p className="font-body-md text-on-surface-variant">Supported formats: PE, ELF, Mach-O, APK, PDF, Office (Max 32MB)</p>
              </div>
            ) : (
              <form onSubmit={handleSubmit}>
                <div className="input-group" style={{ display: 'flex', gap: '16px' }}>
                  <input 
                    type="text" 
                    className="input-field font-data-mono" 
                    placeholder={activeTab === 'url' ? "Enter URL to scan..." : "Enter IP, domain, or file hash..."} 
                    value={inputValue}
                    onChange={(e) => setInputValue(e.target.value)}
                    disabled={isLoading}
                    style={{ fontSize: '16px', padding: '16px' }}
                  />
                  <button type="submit" className="btn-primary" disabled={isLoading || !inputValue.trim()} style={{ padding: '0 32px', fontSize: '14px' }}>
                    {isLoading ? 'ANALYZING...' : 'SCAN'}
                  </button>
                </div>
              </form>
            )}
          </div>

          {/* Card Footer Status */}
          <div style={{ background: 'rgba(0,0,0,0.4)', padding: '16px 32px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid rgba(255,255,255,0.05)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <span className="font-code-sm text-primary">READY FOR SCANNING...</span>
              <div style={{ width: '96px', height: '4px', background: 'rgba(255,255,255,0.1)', borderRadius: '4px', overflow: 'hidden' }}>
                <div className="animate-shimmer" style={{ height: '100%', width: '100%', background: 'var(--primary)' }}></div>
              </div>
            </div>
            <div style={{ display: 'flex', gap: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '4px 12px', background: 'rgba(255,255,255,0.05)', borderRadius: '4px', border: '1px solid rgba(255,255,255,0.1)' }}>
                <span className="material-symbols-outlined text-primary" style={{ fontSize: '16px' }}>terminal</span>
                <span className="font-code-sm text-on-surface uppercase">Sandboxed</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '4px 12px', background: 'rgba(255,255,255,0.05)', borderRadius: '4px', border: '1px solid rgba(255,255,255,0.1)' }}>
                <span className="material-symbols-outlined text-primary" style={{ fontSize: '16px' }}>shield</span>
                <span className="font-code-sm text-on-surface uppercase">Encrypted</span>
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
};
