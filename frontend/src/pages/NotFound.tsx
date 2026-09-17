import React from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import { SEO } from '../components/SEO';

export const NotFound: React.FC = () => {
  return (
    <div className="module-page" style={{ justifyContent: 'center', alignItems: 'center', textAlign: 'center' }}>
      <SEO title="404 — Page Not Found" description="This page does not exist on ThreatAtlas." path="/404" />

      {/* Big 404 background text */}
      <div style={{
        position: 'absolute',
        top: '50%', left: '50%',
        transform: 'translate(-50%, -50%)',
        fontFamily: 'var(--font-display)',
        fontSize: 'clamp(160px, 22vw, 320px)',
        lineHeight: 1,
        color: 'rgba(255, 69, 0, 0.04)',
        letterSpacing: '0.02em',
        userSelect: 'none',
        pointerEvents: 'none',
        zIndex: 0,
      }}>
        404
      </div>

      <motion.div
        initial={{ opacity: 0, y: 32 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
        style={{ position: 'relative', zIndex: 10, padding: '0 16px' }}
      >
        {/* Status badge */}
        <div style={{
          display: 'inline-flex', alignItems: 'center', gap: '8px',
          padding: '4px 14px', marginBottom: '24px',
          background: 'var(--brand-dim)', border: '1px solid var(--border-2)',
          borderRadius: '999px',
        }}>
          <span className="material-symbols-outlined" style={{ fontSize: '14px', color: 'var(--brand)' }}>warning</span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', fontWeight: 700, color: 'var(--brand)', letterSpacing: '0.14em' }}>
            HTTP 404
          </span>
        </div>

        <h1 style={{
          fontFamily: 'var(--font-display)',
          fontSize: 'clamp(60px, 10vw, 120px)',
          lineHeight: 0.95,
          color: 'var(--on-surface)',
          marginBottom: '20px',
          letterSpacing: '0.02em',
        }}>
          TARGET <span style={{ color: 'var(--brand)', textShadow: '0 0 40px var(--brand-glow)' }}>NOT FOUND</span>
        </h1>

        <p style={{
          fontFamily: 'var(--font-sans)',
          fontSize: '15px',
          color: 'var(--on-surface-3)',
          maxWidth: '480px',
          margin: '0 auto 36px',
          lineHeight: 1.7,
        }}>
          The route you're looking for doesn't exist or has been moved. Return to the scanner and continue your investigation.
        </p>

        {/* Glowing divider line */}
        <div style={{
          width: '120px', height: '2px',
          background: 'linear-gradient(90deg, transparent, var(--brand), var(--brand-amber), transparent)',
          margin: '0 auto 36px',
          borderRadius: '1px',
          boxShadow: '0 0 12px var(--brand-glow)',
        }} />

        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', justifyContent: 'center' }}>
          <Link to="/" className="btn-primary" style={{ textDecoration: 'none', padding: '12px 32px', fontSize: '13px' }}>
            Return to Scanner
          </Link>
          <Link to="/search" style={{
            padding: '12px 24px', borderRadius: '999px',
            background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border-subtle)',
            color: 'var(--on-surface-2)', fontFamily: 'var(--font-mono)',
            fontSize: '12px', textDecoration: 'none', fontWeight: 600,
            letterSpacing: '0.08em', textTransform: 'uppercase',
            transition: 'all 0.18s ease',
          }}
          onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--brand)'; e.currentTarget.style.color = 'var(--brand)'; }}
          onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border-subtle)'; e.currentTarget.style.color = 'var(--on-surface-2)'; }}
          >
            IP & Domain Lookup
          </Link>
        </div>

        {/* Quick nav links */}
        <div style={{ marginTop: '48px', display: 'flex', gap: '24px', justifyContent: 'center', flexWrap: 'wrap' }}>
          {[
            { to: '/', label: 'File Scanner', icon: 'upload_file' },
            { to: '/url', label: 'URL Scanner', icon: 'link' },
            { to: '/about', label: 'About', icon: 'info' },
          ].map(link => (
            <Link
              key={link.to}
              to={link.to}
              style={{
                display: 'flex', alignItems: 'center', gap: '6px',
                fontFamily: 'var(--font-mono)', fontSize: '11px', fontWeight: 700,
                color: 'var(--on-surface-3)', textDecoration: 'none',
                letterSpacing: '0.10em', textTransform: 'uppercase',
                transition: 'color 0.18s ease',
              }}
              onMouseEnter={e => (e.currentTarget.style.color = 'var(--brand)')}
              onMouseLeave={e => (e.currentTarget.style.color = 'var(--on-surface-3)')}
            >
              <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>{link.icon}</span>
              {link.label}
            </Link>
          ))}
        </div>
      </motion.div>
    </div>
  );
};
