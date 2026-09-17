import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { scanUrl } from '../services/api';
import { normalizeUrlForScan } from '../utils/sanitize';
import { SEO } from '../components/SEO';
import { PageReveal } from '../components/PageReveal';
import { useScanHistory } from '../services/historyStore';

export const UrlScanPage: React.FC = () => {
  const navigate = useNavigate();
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { history } = useScanHistory();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const raw = input.trim();
    if (!raw) return;
    setIsLoading(true);
    setError(null);
    try {
      const normalized = normalizeUrlForScan(raw);
      const response = await scanUrl(normalized);
      navigate(`/url/${response.data.id}`);
    } catch (err: any) {
      setError(err.message || 'URL scan failed. Check the address and try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const recent = history?.filter(h => h.type === 'url').slice(0, 3) || [];

  return (
    <div style={{ position: 'relative', minHeight: '100vh', paddingTop: '96px', paddingBottom: '64px', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
      <SEO title="URL Scanner — ThreatAtlas" description="Scan URLs and domains for phishing, malware, and reputation threats." path="/url" />

      <div className="container" style={{ maxWidth: '820px', width: '100%', position: 'relative', zIndex: 10 }}>
        <PageReveal>

        {/* Title */}
        <div style={{ marginBottom: '32px', display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ background: 'var(--module-webscan-dim)', color: 'var(--module-webscan)', padding: '12px', borderRadius: '12px', display: 'flex' }}>
            <span className="material-symbols-outlined" style={{ fontSize: '32px' }}>language</span>
          </div>
          <div>
            <h1 style={{ fontFamily: 'var(--font-headline)', fontSize: '32px', margin: '0 0 4px 0', color: 'var(--on-surface)' }}>
              <span style={{ color: 'var(--brand)', textShadow: '0 0 20px var(--brand-glow)' }}>URL</span> Analysis
            </h1>
            <p style={{ fontFamily: 'var(--font-sans)', color: 'var(--on-surface-3)', margin: 0, fontSize: '15px' }}>
              Scan URLs and domains for phishing, malware, and reputation threats.
            </p>
          </div>
        </div>

        {/* Scanner Card */}
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1, duration: 0.5 }} className="glass-card" style={{ overflow: 'hidden', marginBottom: '24px' }}>
          <div style={{ padding: '28px' }}>

            {/* Badges */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px', flexWrap: 'wrap' }}>
              {['PHISHGUARD', 'WEBFOX RECON', 'DNS-over-HTTPS', 'TLS AUDIT'].map(badge => (
                <span key={badge} style={{ fontSize: '10px', padding: '3px 9px', borderRadius: '4px', background: 'rgba(255,140,0,0.1)', border: '1px solid rgba(255,140,0,0.25)', color: 'var(--brand-amber)', fontFamily: 'var(--font-mono)', fontWeight: 700, letterSpacing: '0.08em' }}>{badge}</span>
              ))}
            </div>

            {error && (
              <div style={{ padding: '12px 16px', marginBottom: '16px', background: 'rgba(255,42,95,0.08)', border: '1px solid rgba(255,42,95,0.3)', borderRadius: '10px', color: 'var(--status-malicious)', fontFamily: 'var(--font-mono)', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>warning</span>
                {error}
              </div>
            )}

            <form onSubmit={handleSubmit}>
              {/* Big input */}
              <div style={{ position: 'relative', marginBottom: '14px' }}>
                <span className="material-symbols-outlined" style={{ position: 'absolute', left: '18px', top: '50%', transform: 'translateY(-50%)', fontSize: '20px', color: 'var(--on-surface-3)', pointerEvents: 'none' }}>link</span>
                <input
                  type="text"
                  value={input}
                  onChange={e => setInput(e.target.value.toLowerCase())}
                  placeholder="https://example.com or paypal-login.xyz"
                  autoCapitalize="none" autoCorrect="off" spellCheck={false}
                  disabled={isLoading}
                  style={{ width: '100%', padding: '17px 18px 17px 50px', background: 'rgba(0,0,0,0.32)', border: '1px solid var(--border)', borderRadius: '14px', color: 'var(--on-surface)', fontFamily: 'var(--font-mono)', fontSize: '15px', outline: 'none', transition: 'border-color 0.2s', boxSizing: 'border-box' }}
                  onFocus={e => e.target.style.borderColor = 'var(--brand-amber)'}
                  onBlur={e => e.target.style.borderColor = 'var(--border)'}
                />
              </div>

              <button type="submit" className="btn-primary" disabled={isLoading || !input.trim()}
                style={{ width: '100%', padding: '14px', fontSize: '13px', color: '#fff', background: 'linear-gradient(135deg, var(--brand-amber) 0%, var(--brand) 100%)', boxShadow: '0 4px 20px rgba(255,140,0,0.3)' }}>
                {isLoading ? (
                  <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}>
                    <motion.span className="material-symbols-outlined" animate={{ rotate: 360 }} transition={{ repeat: Infinity, duration: 1.2, ease: 'linear' }} style={{ fontSize: '18px' }}>sync</motion.span>
                    ANALYZING LINK...
                  </span>
                ) : 'SCAN URL'}
              </button>
            </form>
          </div>

          {/* What we check */}
          <div style={{ padding: '16px 28px', background: 'rgba(0,0,0,0.25)', borderTop: '1px solid rgba(255,255,255,0.04)', display: 'flex', flexWrap: 'wrap', gap: '16px' }}>
            {[
              { icon: 'phishing', label: 'Phishing Detection' },
              { icon: 'dns', label: 'DNS Records' },
              { icon: 'security', label: 'TLS Certificate' },
              { icon: 'language', label: 'RDAP Registration' },
              { icon: 'bug_report', label: 'Malware Signatures' },
            ].map(item => (
              <div key={item.label} style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                <span className="material-symbols-outlined" style={{ fontSize: '14px', color: 'var(--brand-amber)' }}>{item.icon}</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--on-surface-3)', fontWeight: 600 }}>{item.label}</span>
              </div>
            ))}
          </div>
        </motion.div>

        {/* Recent URL scans */}
        {recent.length > 0 && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.3 }} style={{ marginTop: '8px' }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', fontWeight: 700, color: 'var(--on-surface-3)', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span className="material-symbols-outlined" style={{ fontSize: '14px', color: 'var(--brand-amber)' }}>history</span>
              Recent URL Scans
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '10px' }}>
              {recent.map(item => {
                const isMal = item.maliciousCount > 0;
                return (
                  <div key={item.id} onClick={() => navigate(`/url/${item.id}`)}
                    style={{ background: 'var(--surface-elevated)', border: '1px solid var(--border-subtle)', borderRadius: '10px', padding: '14px 16px', cursor: 'pointer', transition: 'all 0.18s' }}
                    onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--brand-amber)'; e.currentTarget.style.transform = 'translateY(-2px)'; }}
                    onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border-subtle)'; e.currentTarget.style.transform = 'none'; }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                      <span style={{ fontSize: '10px', color: 'var(--brand-amber)', fontFamily: 'var(--font-mono)', fontWeight: 700, letterSpacing: '0.10em' }}>URL</span>
                      <span style={{ fontSize: '10px', padding: '2px 7px', borderRadius: '4px', background: isMal ? 'rgba(255,42,95,0.12)' : 'rgba(0,232,122,0.10)', border: `1px solid ${isMal ? 'rgba(255,42,95,0.3)' : 'rgba(0,232,122,0.25)'}`, color: isMal ? 'var(--status-malicious)' : 'var(--status-clean)', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                        {isMal ? `${item.maliciousCount} THREAT` : 'CLEAN'}
                      </span>
                    </div>
                    <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--on-surface)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.target}</div>
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
