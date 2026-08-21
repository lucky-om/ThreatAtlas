import React, { useState, useRef, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { scanFile, scanUrl, isValidHash, isValidIp, detectInputType } from '../services/api';
import { sanitizeInput, normalizeUrlForScan } from '../utils/sanitize';
import { YaraScannerModule } from '../components/YaraScannerModule';
import { BulkIocModule } from '../components/BulkIocModule';

type MainTab = 'file' | 'url' | 'search';

interface HomeProps {
  initialTab?: MainTab;
}

export const Home: React.FC<HomeProps> = ({ initialTab }) => {
  const location = useLocation();
  const navigate = useNavigate();

  // Determine active tab from prop, path, or default to 'file'
  const getTabFromPath = (): MainTab => {
    if (initialTab) return initialTab;
    const path = location.pathname.toLowerCase();
    if (path.includes('/url')) return 'url';
    if (path.includes('/search')) return 'search';
    return 'file';
  };

  const [activeTab, setActiveTab] = useState<MainTab>(getTabFromPath);
  const [inputValue, setInputValue] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Sub-module toggles
  const [showYara, setShowYara] = useState(false);
  const [showBulkIoc, setShowBulkIoc] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);

  // Sync tab with URL if route changes
  useEffect(() => {
    setActiveTab(getTabFromPath());
    setError(null);
  }, [location.pathname]);

  const switchTab = (tab: MainTab) => {
    setActiveTab(tab);
    setError(null);
    setInputValue('');
    if (tab === 'file') navigate('/', { replace: true });
    else if (tab === 'url') navigate('/url', { replace: true });
    else if (tab === 'search') navigate('/search', { replace: true });
  };

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
        throw new Error("File exceeds 32MB limit.");
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

  const handleScanSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const clean = sanitizeInput(inputValue).toLowerCase().trim();
    if (!clean) return;

    setIsLoading(true);
    setError(null);

    try {
      if (activeTab === 'file') {
        // Hash search in File tab
        if (isValidHash(clean)) {
          navigate(`/file/${clean}`);
        } else {
          setError('Please enter a valid cryptographic hash (MD5, SHA-1, or SHA-256) or drop a file above.');
        }
      } else if (activeTab === 'url') {
        // URL tab
        const normalized = normalizeUrlForScan(clean);
        const response = await scanUrl(normalized);
        navigate(`/url/${response.data.id}`);
      } else if (activeTab === 'search') {
        // Universal Smart Search
        const detected = detectInputType(clean);
        if (detected === 'hash') {
          navigate(`/file/${clean}`);
        } else if (detected === 'ip') {
          navigate(`/ip-address/${clean}`);
        } else if (detected === 'domain') {
          navigate(`/domain/${encodeURIComponent(clean)}`);
        } else if (detected === 'url') {
          const normalized = normalizeUrlForScan(clean);
          const response = await scanUrl(normalized);
          navigate(`/url/${response.data.id}`);
        } else {
          // Fallback check
          if (isValidIp(clean)) {
            navigate(`/ip-address/${clean}`);
          } else if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(clean)) {
            navigate(`/domain/${encodeURIComponent(clean)}`);
          } else {
            setError('Unrecognized search input. Enter a URL, IP address, domain, or file hash.');
          }
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
    <div style={{ position: 'relative', minHeight: '100vh', paddingTop: '100px', paddingBottom: '64px', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
      {/* Background Layers */}
      <div className="digital-grid"></div>
      <div className="glow-cyan"></div>

      <div className="container" style={{ position: 'relative', zIndex: 10, maxWidth: '980px', width: '100%' }}>
        
        {/* Header */}
        <div className="animate-fade-in-up" style={{ textAlign: 'center', marginBottom: '28px' }}>
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', padding: '4px 14px', background: 'rgba(0, 242, 255, 0.08)', border: '1px solid rgba(0, 242, 255, 0.25)', borderRadius: '999px', marginBottom: '14px' }}>
            <span className="animate-pulse" style={{ width: '6px', height: '6px', background: 'var(--primary)', borderRadius: '50%', display: 'inline-block' }}></span>
            <span className="font-code-sm text-primary" style={{ fontSize: '11px', fontWeight: 700 }}>
              ATLAS-AI THREAT PLATFORM
            </span>
          </div>
          <h1 className="font-display-lg text-on-surface" style={{ fontSize: '44px', letterSpacing: '-0.02em', marginBottom: '8px' }}>
            Analyse suspicious <span className="text-primary">files, URLs, IPs</span>
          </h1>
          <p className="font-body-md text-on-surface-variant" style={{ maxWidth: '640px', margin: '0 auto', fontSize: '14px' }}>
            Multi-engine antivirus heuristics, PhishGuard phishing defense, WebFox network recon, and YARA signature inspection.
          </p>
        </div>

        {/* Central 3-Tab Scanner Card (VirusTotal UI Structure) */}
        <div className="glass-card glass-card-accent animate-fade-in-up" style={{ padding: '2px', overflow: 'hidden', marginBottom: '28px' }}>
          
          {/* Main VirusTotal-Style Tabs */}
          <div className="scanner-tabs">
            <button 
              className={`scanner-tab font-label-caps ${activeTab === 'file' ? 'active' : ''}`}
              onClick={() => switchTab('file')}
            >
              <span className="material-symbols-outlined" style={{ fontSize: '18px', marginRight: '6px', verticalAlign: 'middle' }}>upload_file</span>
              FILE
            </button>
            <button 
              className={`scanner-tab font-label-caps ${activeTab === 'url' ? 'active' : ''}`}
              onClick={() => switchTab('url')}
            >
              <span className="material-symbols-outlined" style={{ fontSize: '18px', marginRight: '6px', verticalAlign: 'middle' }}>link</span>
              URL
            </button>
            <button 
              className={`scanner-tab font-label-caps ${activeTab === 'search' ? 'active' : ''}`}
              onClick={() => switchTab('search')}
            >
              <span className="material-symbols-outlined" style={{ fontSize: '18px', marginRight: '6px', verticalAlign: 'middle' }}>search</span>
              SEARCH
            </button>
          </div>

          <div style={{ padding: '36px' }}>
            {error && (
              <div style={{ padding: '14px 18px', marginBottom: '24px', backgroundColor: 'rgba(255, 0, 60, 0.1)', border: '1px solid var(--secondary)', borderRadius: '8px', color: 'var(--secondary)', fontFamily: 'var(--font-mono)', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span className="material-symbols-outlined" style={{ fontSize: '20px' }}>warning</span>
                <span>{error}</span>
              </div>
            )}

            {/* TAB 1: FILE */}
            {activeTab === 'file' && (
              <div>
                <div 
                  className="dropzone-dashed"
                  onDragOver={(e) => {
                    e.preventDefault();
                    e.currentTarget.style.backgroundColor = 'rgba(185,66,255,0.06)';
                  }}
                  onDragLeave={(e) => {
                    e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.02)';
                  }}
                  onDrop={(e) => {
                    e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.02)';
                    handleFileDrop(e);
                  }}
                  onClick={() => fileInputRef.current?.click()}
                  style={{ cursor: 'pointer', padding: '48px 24px', textAlign: 'center' }}
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
                  <h2 className="font-headline-sm text-on-surface" style={{ marginBottom: '8px', fontSize: '20px' }}>
                    {isLoading ? 'UPLOADING & MULTI-ENGINE SCANNING...' : 'Choose file or drag & drop here'}
                  </h2>
                  <p className="font-body-md text-on-surface-variant" style={{ fontSize: '13px' }}>
                    PE, ELF, Mach-O, Android APK, PDF, Office, ZIP — up to 32MB
                  </p>
                </div>

                {/* Hash Lookup Box & YARA Toggle */}
                <div style={{ marginTop: '24px', borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: '20px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                    <div className="font-label-caps text-on-surface-variant" style={{ fontSize: '11px' }}>
                      Or Search by File Hash:
                    </div>

                    <button
                      type="button"
                      onClick={() => setShowYara(!showYara)}
                      style={{
                        background: showYara ? 'rgba(185,66,255,0.2)' : 'rgba(255,255,255,0.03)',
                        border: `1px solid ${showYara ? 'var(--primary)' : 'rgba(255,255,255,0.1)'}`,
                        borderRadius: '6px', padding: '4px 10px', color: showYara ? 'var(--primary)' : 'var(--on-surface-variant)',
                        fontFamily: 'var(--font-mono)', fontSize: '11px', fontWeight: 600, cursor: 'pointer',
                        display: 'flex', alignItems: 'center', gap: '6px',
                      }}
                    >
                      <span className="material-symbols-outlined" style={{ fontSize: '15px' }}>search_insights</span>
                      <span>{showYara ? 'Hide YARA Module' : '🔬 YARA Rule Pattern Matcher'}</span>
                    </button>
                  </div>

                  <form onSubmit={handleScanSubmit} style={{ display: 'flex', gap: '12px' }}>
                    <input
                      type="text"
                      className="input-field font-data-mono"
                      placeholder="Enter MD5, SHA-1, or SHA-256 hash (e.g. 44d88612fea8a8f36de82e1278abb02f)"
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value.toLowerCase())}
                      autoCapitalize="none"
                      autoCorrect="off"
                      spellCheck="false"
                      style={{ flex: 1, padding: '14px 16px', fontSize: '13px', textTransform: 'lowercase' }}
                    />
                    <button
                      type="submit"
                      className="btn-primary"
                      disabled={isLoading || !inputValue.trim()}
                      style={{ padding: '0 24px', fontSize: '13px' }}
                    >
                      LOOKUP HASH
                    </button>
                  </form>
                </div>

                {/* Embedded YARA Engine */}
                {showYara && <YaraScannerModule />}
              </div>
            )}

            {/* TAB 2: URL */}
            {activeTab === 'url' && (
              <div>
                <div style={{ marginBottom: '20px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                    <span style={{ fontSize: '11px', padding: '2px 8px', borderRadius: '4px', background: 'rgba(245,158,11,0.15)', color: '#f59e0b', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                      PHISHGUARD + WEBFOX
                    </span>
                    <span className="font-code-sm text-on-surface-variant" style={{ fontSize: '12px' }}>
                      Auto-detects HTTP/HTTPS, brand impersonation, and live DoH DNS records
                    </span>
                  </div>
                  <h3 className="font-headline-sm text-on-surface" style={{ fontSize: '18px' }}>
                    Scan URL, Domain or Phishing Link
                  </h3>
                </div>

                <form onSubmit={handleScanSubmit} style={{ display: 'flex', gap: '12px' }}>
                  <input
                    type="text"
                    className="input-field font-data-mono"
                    placeholder="e.g. google.com, luckyverse.tech, or https://paypal-login-verify.xyz"
                    value={inputValue}
                    onChange={(e) => setInputValue(e.target.value.toLowerCase())}
                    autoCapitalize="none"
                    autoCorrect="off"
                    spellCheck="false"
                    disabled={isLoading}
                    style={{ flex: 1, padding: '16px', fontSize: '14px', textTransform: 'lowercase' }}
                  />
                  <button
                    type="submit"
                    className="btn-primary"
                    disabled={isLoading || !inputValue.trim()}
                    style={{ padding: '0 32px', fontSize: '14px', whiteSpace: 'nowrap' }}
                  >
                    {isLoading ? 'ANALYZING...' : 'SCAN URL'}
                  </button>
                </form>

                {/* Quick URL samples */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '16px', flexWrap: 'wrap' }}>
                  <span className="font-label-caps text-on-surface-variant" style={{ fontSize: '10px' }}>Samples:</span>
                  {['google.com', 'luckyverse.tech', 'paypa1-security.xyz/login'].map((s) => (
                    <button
                      key={s}
                      type="button"
                      onClick={() => { setInputValue(s); }}
                      style={{
                        background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)',
                        borderRadius: '4px', padding: '3px 8px', color: 'var(--on-surface-variant)',
                        fontFamily: 'var(--font-mono)', fontSize: '11px', cursor: 'pointer',
                      }}
                    >
                      {s}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* TAB 3: SEARCH */}
            {activeTab === 'search' && (
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '20px', flexWrap: 'wrap', gap: '12px' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                      <span style={{ fontSize: '11px', padding: '2px 8px', borderRadius: '4px', background: 'rgba(0,242,255,0.15)', color: 'var(--primary)', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                        UNIVERSAL SEARCH
                      </span>
                      <span className="font-code-sm text-on-surface-variant" style={{ fontSize: '12px' }}>
                        Auto-detects IP, Domain, URL, or File Hash + Telecom carrier bypass
                      </span>
                    </div>
                    <h3 className="font-headline-sm text-on-surface" style={{ fontSize: '18px' }}>
                      Search URL, IP address, domain, or file hash
                    </h3>
                  </div>

                  <button
                    type="button"
                    onClick={() => setShowBulkIoc(!showBulkIoc)}
                    style={{
                      background: showBulkIoc ? 'rgba(0,242,255,0.2)' : 'rgba(255,255,255,0.03)',
                      border: `1px solid ${showBulkIoc ? 'var(--primary)' : 'rgba(255,255,255,0.1)'}`,
                      borderRadius: '6px', padding: '6px 12px', color: showBulkIoc ? 'var(--primary)' : 'var(--on-surface-variant)',
                      fontFamily: 'var(--font-mono)', fontSize: '11px', fontWeight: 600, cursor: 'pointer',
                      display: 'flex', alignItems: 'center', gap: '6px',
                    }}
                  >
                    <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>travel_explore</span>
                    <span>{showBulkIoc ? 'Single Search' : '⚡ Batch Multi-IOC Hunter'}</span>
                  </button>
                </div>

                {!showBulkIoc ? (
                  <>
                    <form onSubmit={handleScanSubmit} style={{ display: 'flex', gap: '12px' }}>
                      <input
                        type="text"
                        className="input-field font-data-mono"
                        placeholder="URL, IP address (e.g. 8.8.8.8, Jio/Vi), domain, or file hash..."
                        value={inputValue}
                        onChange={(e) => setInputValue(e.target.value.toLowerCase())}
                        autoCapitalize="none"
                        autoCorrect="off"
                        spellCheck="false"
                        disabled={isLoading}
                        style={{ flex: 1, padding: '16px', fontSize: '14px', textTransform: 'lowercase' }}
                      />
                      <button
                        type="submit"
                        className="btn-primary"
                        disabled={isLoading || !inputValue.trim()}
                        style={{ padding: '0 32px', fontSize: '14px', whiteSpace: 'nowrap' }}
                      >
                        {isLoading ? 'SEARCHING...' : 'SEARCH'}
                      </button>
                    </form>

                    {/* Quick Search samples */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '16px', flexWrap: 'wrap' }}>
                      <span className="font-label-caps text-on-surface-variant" style={{ fontSize: '10px' }}>Samples:</span>
                      {['49.207.200.1 (Jio/Vi IP)', 'google.com', '1.1.1.1', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'].map((s) => (
                        <button
                          key={s}
                          type="button"
                          onClick={() => { setInputValue(s.split(' ')[0]); }}
                          style={{
                            background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)',
                            borderRadius: '4px', padding: '3px 8px', color: 'var(--on-surface-variant)',
                            fontFamily: 'var(--font-mono)', fontSize: '11px', cursor: 'pointer',
                          }}
                        >
                          {s}
                        </button>
                      ))}
                    </div>
                  </>
                ) : (
                  <BulkIocModule />
                )}
              </div>
            )}

          </div>

          {/* Card Footer Status */}
          <div style={{ background: 'rgba(0,0,0,0.4)', padding: '16px 32px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid rgba(255,255,255,0.05)', flexWrap: 'wrap', gap: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <span className="font-code-sm text-primary">70+ AV ENGINES + YARA + PHISHGUARD + WEBFOX</span>
              <div style={{ width: '96px', height: '4px', background: 'rgba(255,255,255,0.1)', borderRadius: '4px', overflow: 'hidden' }}>
                <div className="animate-shimmer" style={{ height: '100%', width: '100%', background: 'var(--primary)' }}></div>
              </div>
            </div>
            <div style={{ display: 'flex', gap: '8px' }}>
              {['FILE', 'URL', 'SEARCH', 'YARA', 'BATCH IOC'].map(fmt => (
                <span key={fmt} style={{ fontSize: '10px', padding: '2px 8px', borderRadius: '4px', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)', color: 'var(--on-surface-variant)', fontFamily: 'var(--font-mono)' }}>
                  {fmt}
                </span>
              ))}
            </div>
          </div>

        </div>

      </div>
    </div>
  );
};
