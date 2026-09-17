import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { ScanHistoryDrawer } from './ScanHistoryDrawer';
import { useScanHistory } from '../services/historyStore';

export const Navbar: React.FC = () => {
  const location = useLocation();
  const { history } = useScanHistory();
  const [scrolled, setScrolled] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);

  // Close mobile menu on route change
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setMobileOpen(false);
  }, [location.pathname]);

  // Darken navbar on scroll
  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  const isActive = (path: string) => {
    if (path === '/') return location.pathname === '/';
    return location.pathname.startsWith(path);
  };

  const NAV_LINKS = [
    { path: '/',        label: 'Home',    icon: 'home' },
    { path: '/file',    label: 'File',    icon: 'upload_file' },
    { path: '/url',     label: 'URL',     icon: 'link' },
    { path: '/search',  label: 'Search',  icon: 'search' },
    { path: '/about',   label: 'About',   icon: 'info' },
  ];

  return (
    <>
      <nav
        className="nav"
        role="navigation"
        aria-label="Main navigation"
        style={{
          background: scrolled
            ? 'rgba(7, 5, 10, 0.94)'
            : 'rgba(7, 5, 10, 0.72)',
        }}
      >
        {/* Logo */}
        <Link to="/" style={{ display: 'flex', alignItems: 'center', gap: '10px', textDecoration: 'none', flexShrink: 0 }}>
          <motion.img
            src="/images/logo-round.png"
            alt="ThreatAtlas"
            width={36}
            height={36}
            whileHover={{ scale: 1.08, rotate: -3 }}
            transition={{ type: 'spring', stiffness: 400, damping: 25 }}
            style={{
              borderRadius: '10px',
              objectFit: 'contain',
              filter: 'drop-shadow(0 0 8px rgba(255, 69, 0, 0.5))',
            }}
          />
          <div style={{ lineHeight: 1 }}>
            <span className="text-glow-crimson" style={{
              fontFamily: 'var(--font-sans)',
              fontSize: '24px',
              fontWeight: 700,
              letterSpacing: '0.02em',
              color: 'var(--on-surface)',
              display: 'block',
            }}>
              Threat<span style={{ color: 'var(--brand)' }}>Atlas</span>
            </span>
          </div>
        </Link>

        {/* Desktop Navigation */}
        <div className="nav-links" style={{ display: 'flex', alignItems: 'center', gap: '2px' }}>
          {NAV_LINKS.map(link => (
            <Link
              key={link.path}
              to={link.path}
              className={isActive(link.path) ? 'active' : ''}
            >
              {link.label.toUpperCase()}
            </Link>
          ))}

          {/* History Button */}
          <button
            onClick={() => setHistoryOpen(true)}
            aria-label="Scan history"
            style={{
              background: 'none',
              border: 'none',
              color: history.length > 0 ? 'var(--brand)' : 'var(--on-surface-3)',
              padding: '7px 14px',
              fontFamily: 'var(--font-mono)',
              fontSize: '11px',
              fontWeight: 700,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              letterSpacing: '0.12em',
              textTransform: 'uppercase',
              transition: 'color 0.18s ease',
              borderRadius: '8px',
              position: 'relative',
            }}
            onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255, 69, 0, 0.07)')}
            onMouseLeave={e => (e.currentTarget.style.background = 'none')}
          >
            <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>history</span>
            HISTORY
            {history.length > 0 && (
              <motion.span
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                style={{
                  background: 'var(--brand-dim)',
                  border: '1px solid var(--border-2)',
                  color: 'var(--brand)',
                  padding: '1px 6px',
                  borderRadius: '999px',
                  fontSize: '10px',
                  fontWeight: 700,
                }}
              >
                {history.length}
              </motion.span>
            )}
          </button>
        </div>

        {/* Mobile Hamburger */}
        <button
          className="mobile-menu-btn"
          onClick={() => setMobileOpen(o => !o)}
          aria-label="Toggle navigation"
          aria-expanded={mobileOpen}
          style={{
            background: 'none',
            border: '1px solid var(--border)',
            borderRadius: '8px',
            padding: '7px',
            cursor: 'pointer',
            color: 'var(--on-surface)',
            display: 'none',
          }}
        >
          <span className="material-symbols-outlined" style={{ fontSize: '22px', display: 'block' }}>
            {mobileOpen ? 'close' : 'menu'}
          </span>
        </button>
      </nav>

      {/* Mobile Drawer */}
      <AnimatePresence>
        {mobileOpen && (
          <motion.div
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
            style={{
              position: 'fixed',
              top: '60px', left: 0, right: 0, bottom: 0,
              background: 'rgba(7, 5, 10, 0.97)',
              zIndex: 99,
              overflowY: 'auto',
              borderTop: '1px solid var(--border)',
              backdropFilter: 'blur(16px)',
            }}
          >
            <div style={{ padding: '20px 16px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
              {[...NAV_LINKS, { path: '/', label: 'History', icon: 'history' }].map((link, i) => (
                link.label === 'History' ? (
                  <button
                    key="history-mobile"
                    onClick={() => { setMobileOpen(false); setHistoryOpen(true); }}
                    style={{
                      display: 'flex', alignItems: 'center', gap: '14px',
                      padding: '14px 16px', borderRadius: '10px',
                      background: 'transparent', border: 'none', cursor: 'pointer',
                      color: 'var(--on-surface-3)',
                      fontFamily: 'var(--font-mono)', fontSize: '13px', fontWeight: 700,
                      letterSpacing: '0.10em', textAlign: 'left', width: '100%',
                      borderLeft: '2px solid transparent',
                      transition: 'all 0.18s ease',
                    }}
                    onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,69,0,0.07)'; e.currentTarget.style.color = 'var(--on-surface)'; }}
                    onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = 'var(--on-surface-3)'; }}
                  >
                    <span className="material-symbols-outlined" style={{ fontSize: '20px', color: 'var(--brand)' }}>history</span>
                    HISTORY {history.length > 0 && `(${history.length})`}
                  </button>
                ) : (
                  <Link
                    key={link.path + i}
                    to={link.path}
                    style={{
                      display: 'flex', alignItems: 'center', gap: '14px',
                      padding: '14px 16px', borderRadius: '10px',
                      textDecoration: 'none',
                      background: isActive(link.path) ? 'rgba(255, 69, 0, 0.10)' : 'transparent',
                      color: isActive(link.path) ? 'var(--brand)' : 'var(--on-surface-3)',
                      fontFamily: 'var(--font-mono)', fontSize: '13px', fontWeight: 700,
                      letterSpacing: '0.10em',
                      borderLeft: isActive(link.path) ? '2px solid var(--brand)' : '2px solid transparent',
                    }}
                  >
                    <span className="material-symbols-outlined" style={{ fontSize: '20px', color: 'var(--brand)' }}>
                      {link.icon}
                    </span>
                    {link.label.toUpperCase()}
                  </Link>
                )
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Persistent Scan History Drawer */}
      <ScanHistoryDrawer isOpen={historyOpen} onClose={() => setHistoryOpen(false)} />
    </>
  );
};
