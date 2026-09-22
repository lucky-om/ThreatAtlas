import React from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';

interface FooterLink { to: string; label: string; highlight?: boolean; }
interface FooterColumn { heading: string; links: FooterLink[]; }

const COLUMNS: FooterColumn[] = [
  {
    heading: 'Platform',
    links: [
      { to: '/about',   label: 'How It Works' },
      { to: '/contact', label: 'Contact' },
      { to: '/terms',   label: 'Terms of Service' },
      { to: '/privacy', label: 'Privacy Notice' },
      { to: '/rules',   label: 'Rules & Guidelines' },
    ],
  },
  {
    heading: 'Tools',
    links: [
      { to: '/',       label: 'File Scanner' },
      { to: '/url',    label: 'URL Scanner' },
      { to: '/search', label: 'IP & Domain Lookup' },
      { to: '/yara',   label: 'YARA Pattern Engine' },
    ],
  },
  {
    heading: 'Intelligence',
    links: [
      { to: '/about',      label: 'Detection Methodology' },
      { to: '/ioc-hunter', label: 'Threat Feed Sources' },
      { to: '/about',      label: 'Atlas AI Engine' },
      { to: '/contact',    label: 'Report False Positive' },
    ],
  },
];

// Real engine integrations — no vendor brand names exposed
const ENGINE_BADGES = [
  { label: 'Multi-AV Engines',  color: 'var(--brand)',             dim: 'var(--brand-dim)' },
  { label: 'YARA Engine',       color: 'var(--module-yara)',       dim: 'var(--module-yara-dim)' },
  { label: 'PhishGuard',        color: 'var(--status-suspicious)', dim: 'var(--status-sus-dim)' },
  { label: 'WebFox Recon',      color: 'var(--module-webscan)',    dim: 'var(--module-webscan-dim)' },
  { label: 'Atlas Intelligence',color: 'var(--brand-ember)',       dim: 'var(--amber-dim)' },
];

export const Footer: React.FC = () => {
  const year = new Date().getFullYear();

  return (
    <footer className="vt-footer" role="contentinfo">
      <div className="vt-footer-container">

        {/* Top: branding + tagline */}
        <div style={{
          display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start',
          marginBottom: '48px', flexWrap: 'wrap', gap: '24px',
          paddingBottom: '36px', borderBottom: '1px solid rgba(255,255,255,0.06)',
        }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
              <motion.img
                whileHover={{ scale: 1.08 }}
                src="/images/logo-round.png"
                alt="ThreatAtlas"
                width={38}
                height={38}
                style={{
                  borderRadius: '10px',
                  objectFit: 'cover',
                  filter: 'drop-shadow(0 0 8px rgba(255, 69, 0, 0.4))',
                }}
              />
              <div>
                <span className="text-glow-crimson" style={{
                  fontFamily: 'var(--font-sans)',
                  fontSize: '22px',
                  fontWeight: 700,
                  letterSpacing: '0.02em',
                  color: 'var(--on-surface)',
                  display: 'block',
                }}>
                  Threat<span style={{ color: 'var(--brand)' }}>Atlas</span>
                </span>
              </div>
            </div>
            <p style={{
              fontFamily: 'var(--font-sans)',
              fontSize: '13px',
              color: 'var(--on-surface-3)',
              maxWidth: '280px',
              lineHeight: 1.7,
            }}>
              Multi-engine threat intelligence platform for security analysts, incident responders, and researchers.
            </p>
          </div>


        </div>

        {/* Navigation columns */}
        <div className="vt-footer-grid">
          {COLUMNS.map(col => (
            <div key={col.heading} className="vt-footer-col">
              <h4 className="vt-footer-heading">{col.heading}</h4>
              <ul className="vt-footer-links">
                {col.links.map(link => (
                  <li key={link.label}>
                    <Link to={link.to} className={link.highlight ? 'vt-link-highlighted' : ''}>
                      {link.label}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}

          {/* Legal column */}
          <div className="vt-footer-col">
            <h4 className="vt-footer-heading">Legal</h4>
            <ul className="vt-footer-links">
              <li><Link to="/terms">Terms of Service</Link></li>
              <li><Link to="/privacy">Privacy Policy</Link></li>
              <li><Link to="/rules">Acceptable Use</Link></li>
            </ul>
          </div>

          {/* Integrated Engines Column */}
          <div className="vt-footer-col">
            <div>
              <div style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '10px',
                fontWeight: 700,
                color: 'var(--brand)',
                letterSpacing: '0.14em',
                textTransform: 'uppercase',
                marginBottom: '14px',
              }}>
                Integrated Engines
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                {ENGINE_BADGES.map(b => (
                  <motion.div
                    key={b.label}
                    whileHover={{ x: 4, backgroundColor: b.dim, borderColor: `${b.color}44` }}
                    transition={{ type: 'spring', stiffness: 400, damping: 30 }}
                    style={{
                      display: 'flex', alignItems: 'center', gap: '8px',
                      padding: '5px 10px',
                      border: '1px solid transparent',
                      borderRadius: '6px',
                      cursor: 'default',
                    }}
                  >
                    <span style={{
                      width: '5px', height: '5px',
                      borderRadius: '50%',
                      background: b.color,
                      boxShadow: `0 0 5px ${b.color}`,
                      flexShrink: 0,
                    }} />
                    <span style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '11px',
                      color: b.color,
                      fontWeight: 600,
                    }}>
                      {b.label}
                    </span>
                  </motion.div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Bottom bar */}
        <div className="vt-footer-bottom">
          <div className="vt-footer-brand">
            <img
              src="/images/logo-round.png"
              alt="ThreatAtlas"
              width={20} height={20}
              style={{ borderRadius: '5px', objectFit: 'cover' }}
            />
            <span>© {year} ThreatAtlas. All rights reserved.</span>
          </div>

          <div className="vt-footer-actions">


          </div>
        </div>
      </div>
    </footer>
  );
};
