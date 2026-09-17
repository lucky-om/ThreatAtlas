import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { isValidHash, isValidIp, detectInputType, scanUrl } from '../services/api';
import { sanitizeInput, normalizeUrlForScan } from '../utils/sanitize';
import { SEO } from '../components/SEO';
import { BulkIocModule } from '../components/BulkIocModule';
import { useScanHistory } from '../services/historyStore';
import { PageReveal } from '../components/PageReveal';


export const SearchPage: React.FC = () => {
  const navigate = useNavigate();
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showBulk, setShowBulk] = useState(false);
  const { history } = useScanHistory();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const clean = sanitizeInput(input).toLowerCase().trim();
    if (!clean) return;

    setIsLoading(true);
    setError(null);

    try {
      const detected = detectInputType(clean);
      if (detected === 'hash' || isValidHash(clean)) {
        navigate(`/file/${clean}`);
      } else if (detected === 'ip' || isValidIp(clean)) {
        navigate(`/ip-address/${clean}`);
      } else if (detected === 'domain' || /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(clean)) {
        navigate(`/domain/${encodeURIComponent(clean)}`);
      } else if (detected === 'url' || clean.startsWith('http')) {
        const res = await scanUrl(normalizeUrlForScan(clean));
        navigate(`/url/${res.data.id}`);
      } else {
        setError('Unrecognized input. Enter a URL, IP, domain, or file hash.');
      }
    } catch (err: any) {
      setError(err.message || 'Search failed. Try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const recent = history?.slice(0, 4) || [];

  return (
    <div style={{ position: 'relative', minHeight: '100vh', paddingTop: '96px', paddingBottom: '64px', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
      <SEO title="Search — ThreatAtlas" description="Universal threat intelligence search: IP addresses, domains, file hashes, and URLs." path="/search" />

      <div className="container" style={{ maxWidth: '820px', width: '100%', position: 'relative', zIndex: 10 }}>
        <PageReveal>

        {/* Title */}
        <div style={{ marginBottom: '32px', display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ background: 'var(--module-ioc-dim)', color: 'var(--module-ioc)', padding: '12px', borderRadius: '12px', display: 'flex' }}>
            <span className="material-symbols-outlined" style={{ fontSize: '32px' }}>radar</span>
          </div>
          <div>
            <h1 style={{ fontFamily: 'var(--font-headline)', fontSize: '32px', margin: '0 0 4px 0', color: 'var(--on-surface)' }}>
              <span style={{ color: 'var(--brand)', textShadow: '0 0 20px var(--brand-glow)' }}>IOC</span> Search
            </h1>
            <p style={{ fontFamily: 'var(--font-sans)', color: 'var(--on-surface-3)', margin: 0, fontSize: '15px' }}>
              Universal threat intelligence search: IPs, Domains, URLs, and Hashes.
            </p>
          </div>
        </div>

        {/* Search Card */}
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1, duration: 0.5 }} className="glass-card" style={{ overflow: 'hidden', marginBottom: '24px' }}>
          <div style={{ padding: '28px' }}>

            {/* Auto-detect types */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px', flexWrap: 'wrap' }}>
              {['IP ADDRESS', 'DOMAIN', 'FILE HASH', 'URL'].map(t => (
                <span key={t} style={{ fontSize: '10px', padding: '3px 9px', borderRadius: '4px', background: 'rgba(251,146,60,0.08)', border: '1px solid rgba(251,146,60,0.2)', color: 'var(--module-ioc)', fontFamily: 'var(--font-mono)', fontWeight: 700, letterSpacing: '0.08em' }}>{t}</span>
              ))}
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--on-surface-3)' }}>— auto-detected</span>
            </div>

            {error && (
              <div style={{ padding: '12px 16px', marginBottom: '16px', background: 'rgba(255,42,95,0.08)', border: '1px solid rgba(255,42,95,0.3)', borderRadius: '10px', color: 'var(--status-malicious)', fontFamily: 'var(--font-mono)', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>warning</span>
                {error}
              </div>
            )}

            <form onSubmit={handleSubmit}>
              <div style={{ position: 'relative', marginBottom: '14px' }}>
                <span className="material-symbols-outlined" style={{ position: 'absolute', left: '18px', top: '50%', transform: 'translateY(-50%)', fontSize: '20px', color: 'var(--on-surface-3)', pointerEvents: 'none' }}>manage_search</span>
                <input
                  type="text"
                  value={input}
                  onChange={e => setInput(e.target.value)}
                  placeholder="IP, domain, URL, or file hash..."
                  autoCapitalize="none" autoCorrect="off" spellCheck={false}
                  disabled={isLoading}
                  style={{ width: '100%', padding: '17px 18px 17px 50px', background: 'rgba(0,0,0,0.32)', border: '1px solid var(--border)', borderRadius: '14px', color: 'var(--on-surface)', fontFamily: 'var(--font-mono)', fontSize: '15px', outline: 'none', transition: 'border-color 0.2s', boxSizing: 'border-box' }}
                  onFocus={e => e.target.style.borderColor = 'var(--module-ioc)'}
                  onBlur={e => e.target.style.borderColor = 'var(--border)'}
                />
              </div>

              <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                <button type="submit" className="btn-primary" disabled={isLoading || !input.trim()}
                  style={{ flex: 1, padding: '14px', fontSize: '13px', color: '#fff', minWidth: '140px', background: 'linear-gradient(135deg, var(--module-ioc) 0%, var(--brand) 100%)', boxShadow: '0 4px 20px rgba(251,146,60,0.25)' }}>
                  {isLoading ? (
                    <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}>
                      <motion.span className="material-symbols-outlined" animate={{ rotate: 360 }} transition={{ repeat: Infinity, duration: 1.2, ease: 'linear' }} style={{ fontSize: '18px' }}>sync</motion.span>
                      SEARCHING...
                    </span>
                  ) : 'SEARCH'}
                </button>
                <button type="button" onClick={() => setShowBulk(!showBulk)}
                  style={{ padding: '14px 20px', background: showBulk ? 'var(--brand-dim)' : 'rgba(255,255,255,0.04)', border: `1px solid ${showBulk ? 'var(--border-2)' : 'rgba(255,255,255,0.08)'}`, borderRadius: '999px', color: showBulk ? 'var(--brand)' : 'var(--on-surface-3)', fontFamily: 'var(--font-mono)', fontSize: '11px', fontWeight: 700, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px', transition: 'all 0.18s', whiteSpace: 'nowrap' }}>
                  <span className="material-symbols-outlined" style={{ fontSize: '15px' }}>travel_explore</span>
                  {showBulk ? 'Single Search' : 'Batch IOC Hunt'}
                </button>
              </div>
            </form>
          </div>

          {/* Footer bar */}
          <div style={{ padding: '14px 28px', background: 'rgba(0,0,0,0.25)', borderTop: '1px solid rgba(255,255,255,0.04)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--module-ioc)', fontWeight: 700, letterSpacing: '0.10em' }}>
              ABUSE.CH · URLHAUS · MALWAREBAZAAR · GEO-IP
            </span>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--on-surface-3)' }}>
              Auto-detects target type
            </span>
          </div>
        </motion.div>

        {/* Bulk IOC */}
        {showBulk && (
          <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} style={{ marginBottom: '24px' }}>
            <BulkIocModule />
          </motion.div>
        )}

        {/* Recent searches */}
        {recent.length > 0 && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.3 }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', fontWeight: 700, color: 'var(--on-surface-3)', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span className="material-symbols-outlined" style={{ fontSize: '14px', color: 'var(--module-ioc)' }}>history</span>
              Recent Searches
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '10px' }}>
              {recent.map(item => {
                const isMal = item.maliciousCount > 0;
                const path = item.type === 'file' ? `/file/${item.hash || item.id}` : item.type === 'url' ? `/url/${item.id}` : item.type === 'ip' ? `/ip-address/${item.target}` : `/domain/${encodeURIComponent(item.target)}`;
                return (
                  <div key={item.id + item.timestamp} onClick={() => navigate(path)}
                    style={{ background: 'var(--surface-elevated)', border: '1px solid var(--border-subtle)', borderRadius: '10px', padding: '14px 16px', cursor: 'pointer', transition: 'all 0.18s' }}
                    onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--module-ioc)'; e.currentTarget.style.transform = 'translateY(-2px)'; }}
                    onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border-subtle)'; e.currentTarget.style.transform = 'none'; }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                      <span style={{ fontSize: '10px', color: 'var(--module-ioc)', fontFamily: 'var(--font-mono)', fontWeight: 700, letterSpacing: '0.10em', textTransform: 'uppercase' }}>{item.type}</span>
                      <span style={{ fontSize: '10px', padding: '2px 7px', borderRadius: '4px', background: isMal ? 'rgba(255,42,95,0.12)' : 'rgba(0,232,122,0.10)', border: `1px solid ${isMal ? 'rgba(255,42,95,0.3)' : 'rgba(0,232,122,0.25)'}`, color: isMal ? 'var(--status-malicious)' : 'var(--status-clean)', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                        {isMal ? `${item.maliciousCount} THREAT` : 'CLEAN'}
                      </span>
                    </div>
                    <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--on-surface)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.name || item.target}</div>
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
