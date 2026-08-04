import React, { useEffect, useState } from 'react';
import { useParams, useSearchParams, useNavigate } from 'react-router-dom';
import { lookupIpGeo, NormalizedIp } from '../services/api';
import { AiSummary } from '../components/AiSummary';
import { EngineGrid } from '../components/EngineGrid';
import { RelationsCard } from '../components/RelationsCard';
import { DnsRecordsCard } from '../components/DnsRecordsCard';
import { CommunityCommentsCard } from '../components/CommunityCommentsCard';

interface LookupProps {
  type?: 'domain' | 'ip';
}

type Tab = 'SUMMARY' | 'DETECTION' | 'DETAILS' | 'RELATIONS' | 'COMMUNITY';

export const Lookup: React.FC<LookupProps> = ({ type }) => {
  const { query: pathQuery, tab } = useParams();
  const [searchParams] = useSearchParams();
  const query = pathQuery || searchParams.get('q') || undefined;
  const navigate = useNavigate();

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<(NormalizedIp & { vtAvailable?: boolean }) | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>('SUMMARY');

  useEffect(() => {
    if (tab) {
      const upperTab = tab.toUpperCase() as Tab;
      if (['SUMMARY', 'DETECTION', 'DETAILS', 'RELATIONS', 'COMMUNITY'].includes(upperTab)) {
        setActiveTab(upperTab);
      }
    }
  }, [tab]);

  useEffect(() => {
    if (!query) return;
    const fetchLookup = async () => {
      setLoading(true);
      setError(null);
      setResult(null);
      try {
        const data = await lookupIpGeo(query);
        setResult(data as any);
      } catch (err: any) {
        console.error(err);
        setError(err.message || 'An error occurred during lookup.');
      } finally {
        setLoading(false);
      }
    };
    fetchLookup();
  }, [query]);

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const q = fd.get('q')?.toString().trim();
    if (q) {
      const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(q) || /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/.test(q);
      navigate(isIp ? `/ip-address/${encodeURIComponent(q)}` : `/domain/${encodeURIComponent(q)}`);
    }
  };

  const handleTabChange = (t: Tab) => {
    setActiveTab(t);
    const isIp = result?.ip ? /^(\d{1,3}\.){3}\d{1,3}$/.test(result.ip) || /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/.test(result.ip) : type === 'ip';
    const basePath = isIp ? `/ip-address/${query}` : `/domain/${query}`;
    navigate(`${basePath}/${t.toLowerCase()}`, { replace: true });
  };

  return (
    <div style={{ position: 'relative', minHeight: '100vh', paddingTop: '100px', paddingBottom: '64px', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
      <div className="digital-grid"></div>
      <div className="glow-cyan" style={{ background: 'radial-gradient(circle at top right, rgba(0, 242, 255, 0.1) 0%, transparent 50%)' }}></div>

      <div className="container" style={{ position: 'relative', zIndex: 10, maxWidth: '1000px', width: '100%' }}>

        {/* Header */}
        <div className="animate-fade-in-up" style={{ marginBottom: '32px', textAlign: 'center' }}>
          <h1 className="font-display-lg text-on-surface" style={{ marginBottom: '16px' }}>IP &amp; Domain Intelligence</h1>
          <p className="font-body-md text-on-surface-variant">Get detailed geographical, network, WHOIS, DNS, and VirusTotal threat data.</p>

          <form onSubmit={handleSubmit} style={{ display: 'flex', gap: '16px', marginTop: '24px', maxWidth: '600px', margin: '24px auto 0' }}>
            <input
              type="text"
              name="q"
              className="input-field font-data-mono"
              placeholder="Enter IP (8.8.8.8) or domain (example.com)"
              defaultValue={query || ''}
              style={{ flex: 1, padding: '16px', fontSize: '16px' }}
            />
            <button type="submit" className="btn-primary" disabled={loading} style={{ padding: '0 32px' }}>
              {loading ? 'SEARCHING...' : 'LOOKUP'}
            </button>
          </form>
        </div>

        {/* Loading */}
        {loading && (
          <div style={{ textAlign: 'center', padding: '48px' }}>
            <span className="material-symbols-outlined text-primary spin" style={{ fontSize: '48px', display: 'block', marginBottom: '16px' }}>sync</span>
            <h3 className="font-headline-sm text-on-surface">Fetching threat intelligence...</h3>
          </div>
        )}

        {/* Error */}
        {error && !loading && (
          <div className="glass-card" style={{ maxWidth: '800px', margin: '0 auto', borderColor: 'var(--secondary)', padding: '32px', textAlign: 'center' }}>
            <span className="material-symbols-outlined text-secondary" style={{ fontSize: '48px', display: 'block', marginBottom: '16px', filter: 'drop-shadow(0 0 10px rgba(255,0,60,0.5))' }}>warning</span>
            <h3 className="font-headline-sm text-secondary" style={{ marginBottom: '8px' }}>Lookup Failed</h3>
            <p className="font-data-mono text-on-surface-variant">{error}</p>
          </div>
        )}

        {/* Results */}
        {result && !loading && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>

            {/* Limited mode banner */}
            {!result.vtAvailable && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', padding: '12px 20px', background: 'rgba(255, 179, 0, 0.08)', border: '1px solid rgba(255, 179, 0, 0.3)', borderRadius: '4px' }}>
                <span className="material-symbols-outlined" style={{ color: '#ffb300', fontSize: '18px' }}>info</span>
                <span className="font-code-sm" style={{ color: '#ffb300' }}>
                  LIMITED MODE — Geo data available. VirusTotal threat data requires a valid VT API key.{' '}
                  <a href="https://virustotal.com" target="_blank" rel="noopener noreferrer" style={{ color: 'var(--primary)', textDecoration: 'underline' }}>Get a free key →</a>
                </span>
              </div>
            )}

            {/* Tabs Navigation */}
            <div className="scanner-tabs animate-fade-in-up" style={{ alignSelf: 'center', flexWrap: 'wrap' }}>
              {(['SUMMARY', 'DETECTION', 'DETAILS', 'RELATIONS', 'COMMUNITY'] as Tab[]).map((t) => (
                <button
                  key={t}
                  className={`scanner-tab font-label-caps ${activeTab === t ? 'active' : ''}`}
                  onClick={() => handleTabChange(t)}
                >
                  {t}
                </button>
              ))}
            </div>

            {/* SUMMARY TAB */}
            {activeTab === 'SUMMARY' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '24px' }}>

                  {/* Geolocation */}
                  <div className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
                    <h3 className="font-label-caps text-on-surface-variant" style={{ marginBottom: '24px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>location_on</span>
                      Geolocation &amp; Network
                    </h3>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                      <div>
                        <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '4px' }}>Query Target</div>
                        <div className="font-data-mono text-primary">{result.ip}</div>
                      </div>
                      <div>
                        <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '4px' }}>Country</div>
                        <div className="font-headline-sm text-on-surface">{result.country || '—'}</div>
                      </div>
                      <div>
                        <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '4px' }}>Network / ISP</div>
                        <div className="font-body-md text-on-surface">{result.asOwner || '—'}</div>
                      </div>
                      <div>
                        <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '4px' }}>ASN</div>
                        <div className="font-data-mono text-on-surface">{result.asn ? `AS${result.asn}` : '—'}</div>
                      </div>
                    </div>
                  </div>

                  {/* Network / Threat Details */}
                  <div className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
                    <h3 className="font-label-caps text-on-surface-variant" style={{ marginBottom: '24px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>shield</span>
                      Threat Intelligence
                    </h3>

                    <div style={{ marginBottom: '24px' }}>
                      <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '8px' }}>Verdict</div>
                      <div className="font-headline-sm" style={{
                        color: result.verdict === 'malicious' ? 'var(--secondary)' : result.verdict === 'suspicious' ? '#ffb300' : 'var(--primary)',
                        textTransform: 'capitalize',
                        filter: result.verdict === 'malicious' ? 'drop-shadow(0 0 6px rgba(255,0,60,0.5))' : undefined
                      }}>
                        {result.vtAvailable ? result.verdict : 'N/A — Limited Mode'}
                      </div>
                    </div>

                    <div style={{ display: 'flex', gap: '12px' }}>
                      <div style={{ flex: 1, background: 'rgba(255,0,60,0.05)', border: '1px solid rgba(255,0,60,0.2)', padding: '16px', borderRadius: '4px', textAlign: 'center' }}>
                        <div className="font-display-lg text-secondary" style={{ fontSize: '28px', lineHeight: '36px' }}>{result.stats?.malicious || 0}</div>
                        <div className="font-label-caps text-secondary">Malicious</div>
                      </div>
                      <div style={{ flex: 1, background: 'rgba(255,179,0,0.05)', border: '1px solid rgba(255,179,0,0.2)', padding: '16px', borderRadius: '4px', textAlign: 'center' }}>
                        <div className="font-display-lg" style={{ fontSize: '28px', lineHeight: '36px', color: '#ffb300' }}>{result.stats?.suspicious || 0}</div>
                        <div className="font-label-caps" style={{ color: '#ffb300' }}>Suspicious</div>
                      </div>
                      <div style={{ flex: 1, background: 'rgba(0,242,255,0.05)', border: '1px solid rgba(0,242,255,0.2)', padding: '16px', borderRadius: '4px', textAlign: 'center' }}>
                        <div className="font-display-lg text-primary" style={{ fontSize: '28px', lineHeight: '36px' }}>{(result.stats?.harmless || 0) + (result.stats?.undetected || 0)}</div>
                        <div className="font-label-caps text-primary">Clean</div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* AI Summary */}
                <div className="animate-fade-in-up">
                  <AiSummary threatData={result} type={result.ip ? 'ip' : 'url'} />
                </div>
              </div>
            )}

            {/* DETECTION TAB */}
            {activeTab === 'DETECTION' && (
              <div className="animate-fade-in-up">
                {result.engines && result.engines.length > 0 ? (
                  <>
                    <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '16px', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '8px' }}>Security vendors' analysis</h3>
                    <EngineGrid results={result.engines} />
                  </>
                ) : (
                  <div className="glass-card" style={{ padding: '48px', textAlign: 'center' }}>
                    <p className="font-body-md text-on-surface-variant">No engine detection results available.</p>
                  </div>
                )}
              </div>
            )}

            {/* DETAILS TAB */}
            {activeTab === 'DETAILS' && (
              <div className="animate-fade-in-up">
                <DnsRecordsCard records={result.dnsRecords} />
                
                <div className="glass-card" style={{ padding: '32px' }}>
                  <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span className="material-symbols-outlined text-primary">info</span>
                    Basic Properties
                  </h3>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '20px' }}>
                    <div>
                      <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '4px' }}>Reputation Score</div>
                      <div className="font-data-mono text-on-surface">{result.reputation || 0}</div>
                    </div>
                    <div>
                      <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '4px' }}>Last Analysis Date</div>
                      <div className="font-code-sm text-on-surface">{result.lastSeen ? new Date(result.lastSeen * 1000).toUTCString() : 'N/A'}</div>
                    </div>
                    {result.tags && result.tags.length > 0 && (
                      <div style={{ gridColumn: '1 / -1' }}>
                        <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '8px' }}>Tags</div>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                          {result.tags.map(tag => (
                            <span key={tag} className="font-code-sm" style={{ padding: '4px 10px', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '4px', color: 'var(--primary)' }}>
                              {tag}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* RELATIONS TAB */}
            {activeTab === 'RELATIONS' && (
              <div className="animate-fade-in-up">
                <RelationsCard relations={result.relations} />
              </div>
            )}

            {/* COMMUNITY TAB */}
            {activeTab === 'COMMUNITY' && (
              <div className="animate-fade-in-up">
                <CommunityCommentsCard comments={result.comments} />
              </div>
            )}

          </div>
        )}

      </div>
    </div>
  );
};
