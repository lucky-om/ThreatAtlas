import React, { useState, useCallback, useEffect } from 'react';
import { useSearchParams, useParams } from 'react-router-dom';
import { lookupIpGeo, isValidIp, NormalizedIp } from '../services/api';
import { sanitizeInput, isTelecomCarrier } from '../utils/sanitize';
import { CarrierIntelligenceCard } from '../components/CarrierIntelligenceCard';
import { EngineGrid } from '../components/EngineGrid';
import { RelationsCard } from '../components/RelationsCard';
import { DnsRecordsCard } from '../components/DnsRecordsCard';
import { CommunityCommentsCard } from '../components/CommunityCommentsCard';

type Tab = 'SUMMARY' | 'DETECTION' | 'DETAILS' | 'RELATIONS' | 'COMMUNITY';

export const IpLookup: React.FC = () => {
  const { query: pathQuery } = useParams();
  const [searchParams] = useSearchParams();

  const initialIp = pathQuery || searchParams.get('ip') || searchParams.get('q') || '';
  const [inputValue, setInputValue] = useState(initialIp);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ipResult, setIpResult] = useState<NormalizedIp | null>(null);
  const [scannedIp, setScannedIp] = useState<string>('');
  const [isCarrier, setIsCarrier] = useState(false);
  const [activeTab, setActiveTab] = useState<Tab>('SUMMARY');

  const executeIpLookup = useCallback(async (rawInput: string) => {
    const clean = sanitizeInput(rawInput).toLowerCase().trim().replace(/^https?:\/\//, '').split('/')[0];
    if (!clean) return;

    if (!isValidIp(clean)) {
      setError('Please enter a valid IPv4 or IPv6 address (e.g. 8.8.8.8, 1.1.1.1, or 49.207.200.1).');
      return;
    }

    setLoading(true);
    setError(null);
    setIpResult(null);
    setIsCarrier(false);
    setScannedIp(clean);
    setActiveTab('SUMMARY');

    try {
      const data = await lookupIpGeo(clean);
      setIpResult(data as any);

      // Check if carrier IP
      const carrierDetected = isTelecomCarrier(data?.asOwner || data?.network || '', data?.network || '');
      setIsCarrier(carrierDetected);
    } catch (err: any) {
      console.error(err);
      setError(err.message || 'IP lookup failed. Please verify the IP address.');
    } finally {
      setLoading(false);
    }
  }, []);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    executeIpLookup(inputValue);
  };

  useEffect(() => {
    if (initialIp) {
      executeIpLookup(initialIp);
    }
  }, [initialIp, executeIpLookup]);

  return (
    <div className="module-page" style={{ position: 'relative', minHeight: '100vh', paddingTop: '100px', paddingBottom: '64px' }}>
      <div className="digital-grid" />
      <div style={{ position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 0, background: 'radial-gradient(circle at 50% 20%, rgba(0,242,255,0.06) 0%, transparent 60%)' }} />

      <div className="container" style={{ position: 'relative', zIndex: 10, maxWidth: '1100px', width: '100%' }}>

        {/* Hero */}
        <div className="module-hero" style={{ textAlign: 'center', marginBottom: '32px' }}>
          <div className="module-badge" style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', background: 'rgba(0,242,255,0.12)', border: '1px solid rgba(0,242,255,0.35)', color: 'var(--primary)', padding: '4px 14px', borderRadius: '999px', fontFamily: 'var(--font-mono)', fontSize: '11px', fontWeight: 700, marginBottom: '14px' }}>
            <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>public</span>
            Global IP &amp; Geolocation Intelligence
          </div>
          <h1 className="font-display-lg text-on-surface" style={{ fontSize: '42px', marginBottom: '10px' }}>
            IP Address <span className="text-primary">Intelligence</span>
          </h1>
          <p className="font-body-md text-on-surface-variant" style={{ maxWidth: '640px', margin: '0 auto', fontSize: '14px' }}>
            Investigate any IPv4 or IPv6 address for geographical origin, Autonomous System (ASN), telecom carrier/ISP routing, and VirusTotal threat reputation.
          </p>
        </div>

        {/* Search Card */}
        <div className="glass-card glass-card-accent animate-fade-in-up" style={{ padding: '28px', marginBottom: '32px' }}>
          <form onSubmit={handleSubmit} style={{ display: 'flex', gap: '12px' }}>
            <input
              type="text"
              className="input-field font-data-mono"
              placeholder="Enter IPv4 or IPv6 address — e.g. 8.8.8.8, 1.1.1.1, or 49.207.200.1"
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
                background: loading ? 'rgba(0,242,255,0.1)' : 'var(--primary)',
                border: 'none', color: '#000000',
                fontFamily: 'var(--font-mono)', fontSize: '13px', fontWeight: 700,
                cursor: loading ? 'not-allowed' : 'pointer', letterSpacing: '0.08em',
                display: 'flex', alignItems: 'center', gap: '8px',
              }}
            >
              {loading ? (
                <>
                  <span className="material-symbols-outlined spin" style={{ fontSize: '18px' }}>sync</span>
                  <span>LOOKING UP...</span>
                </>
              ) : (
                <>
                  <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>search</span>
                  <span>LOOKUP IP</span>
                </>
              )}
            </button>
          </form>

          {/* Quick Demo Chips */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '14px', flexWrap: 'wrap' }}>
            <span className="font-label-caps text-on-surface-variant" style={{ fontSize: '10px' }}>Try Sample IPs:</span>
            {[
              { label: 'Jio / Vi / Airtel Carrier (49.207.200.1)', ip: '49.207.200.1' },
              { label: 'Cloudflare DNS (1.1.1.1)', ip: '1.1.1.1' },
              { label: 'Google Public DNS (8.8.8.8)', ip: '8.8.8.8' },
              { label: 'Quad9 Security DNS (9.9.9.9)', ip: '9.9.9.9' },
            ].map((sample, i) => (
              <button
                key={i}
                type="button"
                onClick={() => { setInputValue(sample.ip); executeIpLookup(sample.ip); }}
                style={{
                  background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)',
                  borderRadius: '4px', padding: '3px 8px', color: 'var(--on-surface-variant)',
                  fontFamily: 'var(--font-mono)', fontSize: '11px', cursor: 'pointer',
                }}
                onMouseEnter={e => (e.currentTarget.style.color = 'var(--primary)')}
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
            <span className="material-symbols-outlined text-primary spin" style={{ fontSize: '48px', marginBottom: '16px' }}>public</span>
            <h3 className="font-headline-sm text-on-surface">Querying IP Geolocation &amp; Threat Database...</h3>
            <p className="font-code-sm text-on-surface-variant" style={{ marginTop: '4px' }}>
              Resolving Autonomous System, ASN route, and reputation records for <span className="text-primary">{scannedIp}</span>
            </p>
          </div>
        )}

        {/* Results Area */}
        {!loading && ipResult && (
          <div className="animate-fade-in-up" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>

            {/* Carrier Banner if telecom carrier */}
            {isCarrier && (
              <CarrierIntelligenceCard ipData={ipResult} ip={scannedIp} />
            )}

            {/* Tabs */}
            <div className="scanner-tabs" style={{ alignSelf: 'center', flexWrap: 'wrap' }}>
              {(['SUMMARY', 'DETECTION', 'DETAILS', 'RELATIONS', 'COMMUNITY'] as Tab[]).map((t) => (
                <button
                  key={t}
                  className={`scanner-tab font-label-caps ${activeTab === t ? 'active' : ''}`}
                  onClick={() => setActiveTab(t)}
                >
                  {t}
                </button>
              ))}
            </div>

            {/* SUMMARY TAB */}
            {activeTab === 'SUMMARY' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '24px' }}>

                  {/* Geolocation Card */}
                  <div className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
                    <h3 className="font-label-caps text-on-surface-variant" style={{ marginBottom: '24px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>location_on</span>
                      Geolocation &amp; Network
                    </h3>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                      <div>
                        <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '4px' }}>Query Target</div>
                        <div className="font-data-mono text-primary">{ipResult.ip}</div>
                      </div>
                      <div>
                        <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '4px' }}>Country</div>
                        <div className="font-headline-sm text-on-surface">{ipResult.country || '—'}</div>
                      </div>
                      <div>
                        <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '4px' }}>Network / ISP</div>
                        <div className="font-body-md text-on-surface">{ipResult.asOwner || ipResult.network || '—'}</div>
                      </div>
                      <div>
                        <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '4px' }}>ASN</div>
                        <div className="font-data-mono text-on-surface">{ipResult.asn ? `AS${ipResult.asn}` : '—'}</div>
                      </div>
                    </div>
                  </div>

                  {/* Threat Intelligence Card */}
                  <div className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
                    <h3 className="font-label-caps text-on-surface-variant" style={{ marginBottom: '24px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>shield</span>
                      Threat Intelligence
                    </h3>

                    <div style={{ marginBottom: '24px' }}>
                      <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '8px' }}>Verdict</div>
                      <div className="font-headline-sm" style={{
                        color: ipResult.verdict === 'malicious' ? 'var(--secondary)' : ipResult.verdict === 'suspicious' ? '#ffb300' : 'var(--success)',
                        textTransform: 'uppercase'
                      }}>
                        {ipResult.verdict}
                      </div>
                    </div>

                    <div style={{ marginBottom: '24px' }}>
                      <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '8px' }}>Engine Detections</div>
                      <div className="font-data-mono" style={{ fontSize: '24px', color: (ipResult.stats?.malicious || 0) > 0 ? 'var(--secondary)' : 'var(--on-surface)' }}>
                        {ipResult.stats?.malicious || 0} <span className="text-on-surface-variant" style={{ fontSize: '16px' }}>/ {(ipResult.stats?.malicious || 0) + (ipResult.stats?.undetected || 0) + (ipResult.stats?.harmless || 0)}</span>
                      </div>
                    </div>

                    <div>
                      <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '8px' }}>Reputation Score</div>
                      <div className="font-data-mono" style={{ color: (ipResult.reputation || 0) >= 0 ? 'var(--success)' : 'var(--secondary)' }}>
                        {ipResult.reputation ?? 0} points
                      </div>
                    </div>
                  </div>

                </div>
              </div>
            )}

            {/* DETECTION TAB */}
            {activeTab === 'DETECTION' && (
              <div className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
                <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '24px' }}>Security Vendors' Analysis</h3>
                {ipResult.engines && ipResult.engines.length > 0 ? (
                  <EngineGrid results={ipResult.engines} />
                ) : (
                  <div style={{ textAlign: 'center', padding: '48px', color: 'var(--on-surface-variant)' }}>
                    No engine detections returned.
                  </div>
                )}
              </div>
            )}

            {/* DETAILS TAB */}
            {activeTab === 'DETAILS' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                {ipResult.dnsRecords && ipResult.dnsRecords.length > 0 && (
                  <DnsRecordsCard records={ipResult.dnsRecords} />
                )}
              </div>
            )}

            {/* RELATIONS TAB */}
            {activeTab === 'RELATIONS' && (
              <div>
                <RelationsCard relations={ipResult.relations || {}} />
              </div>
            )}

            {/* COMMUNITY TAB */}
            {activeTab === 'COMMUNITY' && (
              <div>
                <CommunityCommentsCard comments={ipResult.comments || []} />
              </div>
            )}

          </div>
        )}

      </div>
    </div>
  );
};
