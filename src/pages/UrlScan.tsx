import React, { useState, useCallback, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { analyzeWithPhishGuard, PhishGuardResult } from '../services/phishguard';
import { runWebFoxRecon, WebFoxReconResult } from '../services/webfox';
import { normalizeUrlForScan, sanitizeInput } from '../utils/sanitize';
import { PhishGuardCard } from '../components/PhishGuardCard';
import { WebFoxCard } from '../components/WebFoxCard';
import { scanUrl } from '../services/api';

export const UrlScan: React.FC = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const initialUrl = searchParams.get('url') || searchParams.get('q') || searchParams.get('domain') || '';
  const [inputValue, setInputValue] = useState(initialUrl);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Analysis state
  const [scannedUrl, setScannedUrl] = useState<string>('');
  const [phishResult, setPhishResult] = useState<PhishGuardResult | null>(null);
  const [webfoxResult, setWebfoxResult] = useState<WebFoxReconResult | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'phishguard' | 'webfox' | 'dns'>('overview');

  const executeUrlScan = useCallback(async (rawInput: string) => {
    const clean = sanitizeInput(rawInput).toLowerCase().trim();
    if (!clean) return;

    setLoading(true);
    setError(null);
    setPhishResult(null);
    setWebfoxResult(null);
    setActiveTab('overview');

    try {
      // Normalize URL (auto attaches https:// if bare domain like google.com, luckyverse.tech)
      const normalizedUrl = normalizeUrlForScan(clean);
      setScannedUrl(normalizedUrl);

      // 1. PhishGuard Heuristic Engine
      const pg = analyzeWithPhishGuard(normalizedUrl);
      setPhishResult(pg);

      // 2. WebFox Network Recon
      const domain = normalizedUrl.replace(/^https?:\/\//i, '').split('/')[0];
      const wf = await runWebFoxRecon(domain);
      setWebfoxResult(wf);
    } catch (err: any) {
      console.error(err);
      setError(err.message || 'URL Scan encountered an issue. Please verify target.');
    } finally {
      setLoading(false);
    }
  }, []);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    executeUrlScan(inputValue);
  };

  useEffect(() => {
    if (initialUrl) {
      executeUrlScan(initialUrl);
    }
  }, [initialUrl, executeUrlScan]);

  const handleDeepVtScan = async () => {
    if (!scannedUrl) return;
    try {
      setLoading(true);
      const res = await scanUrl(scannedUrl);
      navigate(`/url/${res.data.id}`);
    } catch (err: any) {
      setError('VirusTotal 70+ vendor scan submission failed. Check API key configuration.');
      setLoading(false);
    }
  };

  return (
    <div className="module-page" style={{ position: 'relative', minHeight: '100vh', paddingTop: '100px', paddingBottom: '64px' }}>
      <div className="digital-grid" />
      <div style={{ position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 0, background: 'radial-gradient(circle at 50% 20%, rgba(245,158,11,0.06) 0%, transparent 60%)' }} />

      <div className="container" style={{ position: 'relative', zIndex: 10, maxWidth: '1100px', width: '100%' }}>

        {/* Hero */}
        <div className="module-hero" style={{ textAlign: 'center', marginBottom: '32px' }}>
          <div className="module-badge" style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', background: 'rgba(245,158,11,0.12)', border: '1px solid rgba(245,158,11,0.35)', color: '#f59e0b', padding: '4px 14px', borderRadius: '999px', fontFamily: 'var(--font-mono)', fontSize: '11px', fontWeight: 700, marginBottom: '14px' }}>
            <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>phishing</span>
            PhishGuard &amp; WebFox URL Scanner
          </div>
          <h1 className="font-display-lg text-on-surface" style={{ fontSize: '42px', marginBottom: '10px' }}>
            URL &amp; Website <span style={{ color: '#f59e0b' }}>Threat Scanner</span>
          </h1>
          <p className="font-body-md text-on-surface-variant" style={{ maxWidth: '640px', margin: '0 auto', fontSize: '14px' }}>
            Inspect any website or URL for phishing, brand impersonation, typosquatting, Shannon entropy anomalies, and network infrastructure.
          </p>
        </div>

        {/* Search Card */}
        <div className="glass-card glass-card-accent animate-fade-in-up" style={{ padding: '28px', marginBottom: '32px', borderColor: 'rgba(245,158,11,0.35)' }}>
          <form onSubmit={handleSubmit} style={{ display: 'flex', gap: '12px' }}>
            <input
              type="text"
              className="input-field font-data-mono"
              placeholder="e.g. google.com, luckyverse.tech or https://paypal-secure-portal.com/login"
              value={inputValue}
              onChange={e => setInputValue(e.target.value.toLowerCase())}
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck="false"
              disabled={loading}
              style={{ fontSize: '15px', padding: '16px', flex: 1, textTransform: 'lowercase' }}
            />
            <button
              type="submit"
              disabled={loading || !inputValue.trim()}
              style={{
                padding: '16px 32px', borderRadius: '8px',
                background: loading ? 'rgba(245,158,11,0.1)' : 'linear-gradient(135deg, rgba(245,158,11,0.3), rgba(185,66,255,0.3))',
                border: '1px solid rgba(245,158,11,0.5)', color: '#ffffff',
                fontFamily: 'var(--font-mono)', fontSize: '13px', fontWeight: 700,
                cursor: loading ? 'not-allowed' : 'pointer', letterSpacing: '0.08em',
                display: 'flex', alignItems: 'center', gap: '8px',
              }}
            >
              {loading ? (
                <>
                  <span className="material-symbols-outlined spin" style={{ fontSize: '18px' }}>sync</span>
                  <span>ANALYZING...</span>
                </>
              ) : (
                <>
                  <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>search</span>
                  <span>SCAN URL</span>
                </>
              )}
            </button>
          </form>

          {/* Quick Demo Chips */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '14px', flexWrap: 'wrap' }}>
            <span className="font-label-caps text-on-surface-variant" style={{ fontSize: '10px' }}>Try Sample URLs:</span>
            {[
              { label: 'Clean Domain (google.com)', query: 'google.com' },
              { label: 'Live Site (luckyverse.tech)', query: 'luckyverse.tech' },
              { label: 'Phishing Pattern (paypa1-security.xyz)', query: 'paypa1-security.xyz/login' },
              { label: 'Open Redirect Pattern', query: 'https://login-verify.net?redirect=evil.com' },
            ].map((sample, i) => (
              <button
                key={i}
                type="button"
                onClick={() => { setInputValue(sample.query); executeUrlScan(sample.query); }}
                style={{
                  background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)',
                  borderRadius: '4px', padding: '3px 8px', color: 'var(--on-surface-variant)',
                  fontFamily: 'var(--font-mono)', fontSize: '11px', cursor: 'pointer',
                }}
                onMouseEnter={e => (e.currentTarget.style.color = '#f59e0b')}
                onMouseLeave={e => (e.currentTarget.style.color = 'var(--on-surface-variant)')}
              >
                {sample.label}
              </button>
            ))}
          </div>
        </div>

        {/* Error Alert */}
        {error && (
          <div className="glass-card animate-fade-in-up" style={{ padding: '16px 20px', marginBottom: '24px', borderColor: '#ff003c', display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span className="material-symbols-outlined" style={{ color: '#ff003c', fontSize: '24px' }}>error</span>
            <span className="font-code-sm text-on-surface">{error}</span>
          </div>
        )}

        {/* Loading Skeleton */}
        {loading && (
          <div className="glass-card animate-fade-in-up" style={{ padding: '48px', textAlign: 'center', marginBottom: '32px' }}>
            <span className="material-symbols-outlined text-primary spin" style={{ fontSize: '48px', marginBottom: '16px' }}>travel_explore</span>
            <h3 className="font-headline-sm text-on-surface">Gathering URL &amp; Website Intelligence...</h3>
            <p className="font-code-sm text-on-surface-variant" style={{ marginTop: '4px' }}>
              Executing PhishGuard heuristic models, DoH DNS resolution, and RDAP registration checks for <span className="text-primary">{scannedUrl}</span>
            </p>
          </div>
        )}

        {/* Result Area */}
        {!loading && (phishResult || webfoxResult) && (
          <div className="animate-fade-in-up" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            
            {/* Top Target Meta Bar */}
            <div className="glass-card" style={{ padding: '20px 24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px', borderLeft: '4px solid #f59e0b' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span className="font-label-caps text-on-surface-variant" style={{ fontSize: '11px' }}>SCANNED TARGET:</span>
                  <span style={{ fontSize: '10px', padding: '2px 8px', borderRadius: '4px', background: 'rgba(245,158,11,0.15)', color: '#f59e0b', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                    URL / WEBSITE
                  </span>
                </div>
                <div className="font-headline-sm text-primary" style={{ fontSize: '20px', marginTop: '4px', wordBreak: 'break-all' }}>
                  {scannedUrl}
                </div>
              </div>

              {/* 1-Click VirusTotal Deep Scan Button */}
              <button
                onClick={handleDeepVtScan}
                style={{
                  padding: '10px 20px', borderRadius: '8px', background: 'rgba(185,66,255,0.15)',
                  border: '1px solid rgba(185,66,255,0.4)', color: 'var(--primary)', fontFamily: 'var(--font-mono)',
                  fontSize: '12px', fontWeight: 700, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px',
                }}
              >
                <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>radar</span>
                <span>Run 70+ Vendor AV Scan</span>
              </button>
            </div>

            {/* Sub-Tabs */}
            <div className="scanner-tabs" style={{ marginBottom: '8px', flexWrap: 'wrap' }}>
              {[
                { id: 'overview', label: 'OVERVIEW', icon: 'dashboard' },
                { id: 'phishguard', label: 'PHISHGUARD FORENSICS', icon: 'phishing' },
                { id: 'webfox', label: 'WEBFOX RECON', icon: 'travel_explore' },
                { id: 'dns', label: 'DNS OVER HTTPS', icon: 'dns' },
              ].map(t => (
                <button
                  key={t.id}
                  className={`scanner-tab font-label-caps ${activeTab === t.id ? 'active' : ''}`}
                  onClick={() => setActiveTab(t.id as any)}
                >
                  <span className="material-symbols-outlined" style={{ fontSize: '16px', marginRight: '6px', verticalAlign: 'middle' }}>{t.icon}</span>
                  {t.label}
                </button>
              ))}
            </div>

            {/* Tab: Overview */}
            {activeTab === 'overview' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                {phishResult && <PhishGuardCard result={phishResult} url={scannedUrl} />}
                {webfoxResult && <WebFoxCard recon={webfoxResult} />}
              </div>
            )}

            {/* Tab: PhishGuard */}
            {activeTab === 'phishguard' && phishResult && (
              <div>
                <PhishGuardCard result={phishResult} url={scannedUrl} />
              </div>
            )}

            {/* Tab: WebFox */}
            {activeTab === 'webfox' && webfoxResult && (
              <div>
                <WebFoxCard recon={webfoxResult} />
              </div>
            )}

            {/* Tab: DNS */}
            {activeTab === 'dns' && webfoxResult && (
              <div className="glass-card animate-fade-in-up" style={{ padding: '24px' }}>
                <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span className="material-symbols-outlined" style={{ color: '#f59e0b' }}>dns</span>
                  DNS over HTTPS Resolution ({webfoxResult.dnsRecords.length} records)
                </h3>
                {webfoxResult.dnsRecords.length > 0 ? (
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '10px' }}>
                    {webfoxResult.dnsRecords.map((r, i) => (
                      <div key={i} style={{ padding: '12px 16px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontSize: '11px', padding: '2px 8px', borderRadius: '4px', background: 'rgba(185,66,255,0.15)', color: 'var(--primary)', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                          {r.type}
                        </span>
                        <span className="font-data-mono text-on-surface" style={{ fontSize: '12px', wordBreak: 'break-all', textAlign: 'right' }}>
                          {r.value}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="font-code-sm text-on-surface-variant">No DNS records returned.</p>
                )}
              </div>
            )}

          </div>
        )}

      </div>
    </div>
  );
};
