import React, { useState, useCallback, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { SEO } from '../components/SEO';
import { analyzeWithPhishGuard, PhishGuardResult } from '../services/phishguard';
import { runWebFoxRecon, WebFoxReconResult } from '../services/webfox';
import { normalizeUrlForScan, sanitizeInput, isTelecomCarrier } from '../utils/sanitize';
import { PhishGuardCard } from '../components/PhishGuardCard';
import { WebFoxCard } from '../components/WebFoxCard';
import { CarrierIntelligenceCard } from '../components/CarrierIntelligenceCard';
import { lookupIpGeo, scanUrl, NormalizedIp } from '../services/api';
import { PageHeader } from '../components/PageHeader';
import { PageReveal } from '../components/PageReveal';

type ScanMode = 'auto' | 'url' | 'domain' | 'ip';

export const WebScan: React.FC = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const initialQuery = searchParams.get('q') || searchParams.get('domain') || searchParams.get('url') || searchParams.get('ip') || '';
  const [inputValue, setInputValue] = useState(initialQuery);
  const [scanMode, setScanMode] = useState<ScanMode>('auto');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Analysis state
  const [scannedTarget, setScannedTarget] = useState<string>('');
  const [detectedType, setDetectedType] = useState<'url' | 'domain' | 'ip'>('url');
  const [isCarrierIp, setIsCarrierIp] = useState(false);
  const [phishResult, setPhishResult] = useState<PhishGuardResult | null>(null);
  const [webfoxResult, setWebfoxResult] = useState<WebFoxReconResult | null>(null);
  const [ipResult, setIpResult] = useState<NormalizedIp | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'phishguard' | 'webfox' | 'dns' | 'whois' | 'ip'>('overview');

  const executeUnifiedScan = useCallback(async (rawInput: string) => {
    const clean = sanitizeInput(rawInput).toLowerCase().trim();
    if (!clean) return;

    setLoading(true);
    setError(null);
    setPhishResult(null);
    setWebfoxResult(null);
    setIpResult(null);
    setIsCarrierIp(false);
    setScannedTarget(clean);
    setActiveTab('overview');

    try {
      // 1. Determine entity type
      const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(clean) || /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/.test(clean);
      const isExplicitUrl = /^https?:\/\//i.test(clean) || clean.includes('/') || clean.includes('?');
      
      const type: 'url' | 'domain' | 'ip' = isIp ? 'ip' : isExplicitUrl ? 'url' : 'domain';
      setDetectedType(type);

      if (type === 'ip') {
        // Run IP Geolocation & Threat lookup
        const ipData = await lookupIpGeo(clean);
        setIpResult(ipData as any);

        // Check if IP belongs to a telecom / cellular carrier (e.g. Jio, Vi, Airtel, BSNL, Verizon, etc.)
        const carrierDetected = isTelecomCarrier(ipData?.asOwner || '', ipData?.network || '');
        if (carrierDetected) {
          setIsCarrierIp(true);
          // Telecom / carrier IPs do NOT run website-specific PhishGuard or WebFox website scans
        } else {
          // Cloud / Hosting / Server IP -> run WebFox DNS / IP check
          const wf = await runWebFoxRecon(clean);
          setWebfoxResult(wf);
        }
      } else if (type === 'url') {
        // URL -> Run PhishGuard + WebFox
        const normalizedUrl = normalizeUrlForScan(clean);
        const pg = analyzeWithPhishGuard(normalizedUrl);
        setPhishResult(pg);

        const domain = normalizedUrl.replace(/^https?:\/\//i, '').split('/')[0];
        const [wf, ipData] = await Promise.allSettled([
          runWebFoxRecon(domain),
          lookupIpGeo(domain),
        ]);

        if (wf.status === 'fulfilled') setWebfoxResult(wf.value);
        if (ipData.status === 'fulfilled') setIpResult(ipData.value as any);
      } else {
        // Domain -> Run PhishGuard + WebFox
        const normalizedUrl = `https://${clean}`;
        const pg = analyzeWithPhishGuard(normalizedUrl);
        setPhishResult(pg);

        const [wf, ipData] = await Promise.allSettled([
          runWebFoxRecon(clean),
          lookupIpGeo(clean),
        ]);

        if (wf.status === 'fulfilled') setWebfoxResult(wf.value);
        if (ipData.status === 'fulfilled') setIpResult(ipData.value as any);
      }
    } catch (err: any) {
      if (import.meta.env.DEV) console.error(err);
      setError(err.message || 'Unified scan encountered an issue. Please verify target.');
    } finally {
      setLoading(false);
    }
  }, []);

  const handleScanSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    executeUnifiedScan(inputValue);
  };

  useEffect(() => {
    if (initialQuery) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      executeUnifiedScan(initialQuery);
    }
  }, [initialQuery, executeUnifiedScan]);

  const handleDeepVtScan = async () => {
    if (!scannedTarget) return;
    try {
      setLoading(true);
      const res = await scanUrl(scannedTarget);
      navigate(`/url/${res.data.id}`);
    } catch (err: any) {
      setError('Scan submission failed. Check API key configuration.');
      setLoading(false);
    }
  };

  return (
    <div className="module-page" style={{ position: 'relative', minHeight: '100vh', paddingTop: '100px', paddingBottom: '64px' }}>
      <SEO title="WebScan & PhishGuard - Web Reconnaissance" description="Deep website reconnaissance examining typosquatting, phishing heuristics, DNS records, and SSL cipher strength." path="/webscan" />
      
      <div style={{ position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 0, background: 'radial-gradient(circle at 50% 20%, rgba(232,25,44,0.06) 0%, transparent 60%)' }} />

      <div className="container" style={{ position: 'relative', zIndex: 10, maxWidth: '1100px', width: '100%' }}>
        <PageReveal>

        {/* Hero */}
        <PageHeader
          badge="Unified Web, URL & IP Reconnaissance"
          badgeIcon="travel_explore"
          preTitleHighlight="Web, URL & IP"
          title="Intelligence"
          description="Multi-vector intelligence integrating PhishGuard heuristic scoring, WebFox network recon (DNS, WHOIS, TLS, subdomains), and telecom carrier IP geolocation."
        />

        {/* Search & Mode Selector Card */}
        <div className="glass-card glass-card-accent animate-fade-in-up" style={{ padding: '28px', marginBottom: '32px', borderColor: 'rgba(245,158,11,0.35)' }}>
          
          {/* Mode Selector Tabs */}
          <div style={{ display: 'flex', gap: '8px', marginBottom: '16px', flexWrap: 'wrap' }}>
            {[
              { id: 'auto', label: 'AUTO-DETECT', icon: 'auto_awesome' },
              { id: 'url', label: 'URL / PHISHING', icon: 'phishing' },
              { id: 'domain', label: 'DOMAIN RECON', icon: 'dns' },
              { id: 'ip', label: 'IP GEOLOCATION', icon: 'public' },
            ].map(m => (
              <button
                key={m.id}
                onClick={() => setScanMode(m.id as ScanMode)}
                style={{
                  display: 'flex', alignItems: 'center', gap: '6px', padding: '6px 14px',
                  borderRadius: '6px', fontFamily: 'var(--font-mono)', fontSize: '11px', fontWeight: 700,
                  cursor: 'pointer', transition: 'all 0.15s',
                  background: scanMode === m.id ? 'rgba(232,25,44,0.15)' : 'rgba(255,255,255,0.03)',
                  border: `1px solid ${scanMode === m.id ? 'rgba(232,25,44,0.5)' : 'rgba(255,255,255,0.08)'}`,
                  color: scanMode === m.id ? 'var(--primary)' : 'var(--on-surface-variant)',
                }}
              >
                <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>{m.icon}</span>
                <span>{m.label}</span>
              </button>
            ))}
          </div>

          {/* Unified Input Bar */}
          <form onSubmit={handleScanSubmit} style={{ display: 'flex', gap: '12px' }}>
            <input
              type="text"
              className="input-field font-data-mono"
              placeholder={
                scanMode === 'ip' ? "e.g. 8.8.8.8, Jio/Vi IP, or 1.1.1.1" :
                scanMode === 'domain' ? "e.g. google.com or luckyverse.tech" :
                scanMode === 'url' ? "e.g. https://phishing-portal.com/login" :
                "Enter URL (https://...), domain (google.com), or IP address..."
              }
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
                background: loading ? 'rgba(245,158,11,0.1)' : 'linear-gradient(135deg, rgba(245,158,11,0.3), rgba(255, 107, 53,0.3))',
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
                  <span>SCAN TARGET</span>
                </>
              )}
            </button>
          </form>

          {/* Quick Demo Target Chips */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '14px', flexWrap: 'wrap' }}>
            <span className="font-label-caps text-on-surface-variant" style={{ fontSize: '10px' }}>Quick Samples:</span>
            {[
              { label: 'Website: google.com', query: 'google.com' },
              { label: 'Website: luckyverse.tech', query: 'luckyverse.tech' },
              { label: 'Phishing URL: paypa1-verify.xyz', query: 'paypa1-verify.xyz/login' },
              { label: 'ISP / Telecom IP: 49.207.200.1 (Jio/Vi/Airtel)', query: '49.207.200.1' },
              { label: 'DNS IP: 1.1.1.1 (Cloudflare)', query: '1.1.1.1' },
            ].map((sample, i) => (
              <button
                key={i}
                type="button"
                onClick={() => { setInputValue(sample.query); executeUnifiedScan(sample.query); }}
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
            <h3 className="font-headline-sm text-on-surface">Gathering Multi-Vector Intelligence...</h3>
            <p className="font-code-sm text-on-surface-variant" style={{ marginTop: '4px' }}>
              Executing intelligence pipeline for <span className="text-primary">{scannedTarget}</span>
            </p>
          </div>
        )}

        {/* Result Area */}
        {!loading && (phishResult || webfoxResult || ipResult || isCarrierIp) && (
          <div className="animate-fade-in-up" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            
            {/* Top Target Meta Bar */}
            <div className="glass-card" style={{ padding: '20px 24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px', borderLeft: '4px solid var(--primary)' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span className="font-label-caps text-on-surface-variant" style={{ fontSize: '11px' }}>SCANNED ENTITY:</span>
                  <span style={{ fontSize: '10px', padding: '2px 8px', borderRadius: '4px', background: 'rgba(232,25,44,0.15)', color: 'var(--primary)', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                    {isCarrierIp ? 'TELECOM / ISP CARRIER' : detectedType.toUpperCase()}
                  </span>
                </div>
                <div className="font-headline-sm text-primary" style={{ fontSize: '20px', marginTop: '4px', wordBreak: 'break-all' }}>
                  {scannedTarget}
                </div>
              </div>

              {/* 1-Click Deep Scan Button */}
              <button
                onClick={handleDeepVtScan}
                style={{
                  padding: '10px 20px', borderRadius: '8px', background: 'rgba(255, 107, 53,0.15)',
                  border: '1px solid rgba(255, 107, 53,0.4)', color: 'var(--primary)', fontFamily: 'var(--font-mono)',
                  fontSize: '12px', fontWeight: 700, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px',
                }}
              >
                <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>radar</span>
                <span>Run 70+ Vendor AV Scan</span>
              </button>
            </div>

            {/* If Carrier IP: Render dedicated CarrierIntelligenceCard */}
            {isCarrierIp && ipResult ? (
              <CarrierIntelligenceCard ipData={ipResult} ip={scannedTarget} />
            ) : (
              /* If Website / Domain / Cloud Server: Render PhishGuard, WebFox, and Sub-Tabs */
              <>
                {/* Sub-Tabs */}
                <div className="scanner-tabs" style={{ marginBottom: '8px', flexWrap: 'wrap' }}>
                  {[
                    { id: 'overview', label: 'OVERVIEW', icon: 'dashboard' },
                    { id: 'phishguard', label: 'PHISHGUARD FORENSICS', icon: 'phishing' },
                    { id: 'webfox', label: 'WEBFOX RECON', icon: 'travel_explore' },
                    { id: 'dns', label: 'DNS OVER HTTPS', icon: 'dns' },
                    { id: 'ip', label: 'IP & GEOLOCATION', icon: 'public' },
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
                    {phishResult && <PhishGuardCard result={phishResult} url={scannedTarget} />}
                    {webfoxResult && <WebFoxCard recon={webfoxResult} />}
                  </div>
                )}

                {/* Tab: PhishGuard */}
                {activeTab === 'phishguard' && phishResult && (
                  <div>
                    <PhishGuardCard result={phishResult} url={scannedTarget} />
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
                      <span className="material-symbols-outlined" style={{ color: 'var(--primary)' }}>dns</span>
                      DNS over HTTPS Resolution ({webfoxResult.dnsRecords.length} records)
                    </h3>
                    {webfoxResult.dnsRecords.length > 0 ? (
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '10px' }}>
                        {webfoxResult.dnsRecords.map((r, i) => (
                          <div key={i} style={{ padding: '12px 16px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ fontSize: '11px', padding: '2px 8px', borderRadius: '4px', background: 'rgba(255, 107, 53,0.15)', color: 'var(--primary)', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
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

                {/* Tab: IP & Geo */}
                {activeTab === 'ip' && (
                  <div className="glass-card animate-fade-in-up" style={{ padding: '24px' }}>
                    <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className="material-symbols-outlined" style={{ color: 'var(--primary)' }}>public</span>
                      IP Address Geolocation &amp; Network
                    </h3>
                    {ipResult ? (
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '14px' }}>
                        <div style={{ padding: '14px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
                          <div className="font-label-caps text-on-surface-variant">IP ADDRESS</div>
                          <div className="font-data-mono text-primary" style={{ fontSize: '15px', fontWeight: 700, marginTop: '4px' }}>{ipResult.ip}</div>
                        </div>
                        <div style={{ padding: '14px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
                          <div className="font-label-caps text-on-surface-variant">COUNTRY / LOCATION</div>
                          <div className="font-data-mono text-on-surface" style={{ fontSize: '14px', marginTop: '4px' }}>{ipResult.country || 'Global'}</div>
                        </div>
                        <div style={{ padding: '14px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
                          <div className="font-label-caps text-on-surface-variant">ASN / OWNER</div>
                          <div className="font-data-mono text-on-surface" style={{ fontSize: '14px', marginTop: '4px' }}>{ipResult.asOwner || 'N/A'}</div>
                        </div>
                        <div style={{ padding: '14px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
                          <div className="font-label-caps text-on-surface-variant">COMMUNITY REPUTATION</div>
                          <div className="font-data-mono text-success" style={{ fontSize: '14px', marginTop: '4px' }}>{ipResult.reputation ?? 0} pts</div>
                        </div>
                      </div>
                    ) : (
                      <p className="font-code-sm text-on-surface-variant">No IP Geolocation metadata available for this entity.</p>
                    )}
                  </div>
                )}
              </>
            )}

          </div>
          )}

        </PageReveal>
      </div>
    </div>
  );
};
