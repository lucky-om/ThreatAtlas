import React, { useState, useRef, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export const Navbar: React.FC = () => {
  const location = useLocation();
  const { user, isAuthenticated, openAuthModal, logout } = useAuth();

  const [mobileOpen, setMobileOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);

  const profileRef = useRef<HTMLDivElement>(null);

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (profileRef.current && !profileRef.current.contains(e.target as Node)) {
        setProfileOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  // Close mobile menu on route change
  useEffect(() => {
    setMobileOpen(false);
    setProfileOpen(false);
  }, [location.pathname]);

  const isActive = (path: string) => {
    if (path === '/') return location.pathname === '/';
    return location.pathname.startsWith(path);
  };

  return (
    <>
      <nav className="nav" role="navigation" aria-label="Main navigation">
        {/* Logo */}
        <div className="flex items-center gap-4">
          <Link to="/" className="flex items-center gap-2" style={{ textDecoration: 'none' }}>
            <span className="material-symbols-outlined text-primary" style={{ fontSize: '28px' }}>shield_with_heart</span>
            <span className="font-headline-md text-primary" style={{ fontWeight: 700, letterSpacing: '-0.02em' }}>ThreatAtlas</span>
          </Link>
          {/* Live indicator */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '5px', padding: '3px 8px', background: 'rgba(0,255,163,0.08)', border: '1px solid rgba(0,255,163,0.2)', borderRadius: '999px' }}>
            <span className="animate-pulse" style={{ width: '6px', height: '6px', background: 'var(--success)', borderRadius: '50%', display: 'inline-block', boxShadow: '0 0 6px var(--success)' }}></span>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--success)', fontWeight: 600 }}>LIVE</span>
          </div>
        </div>

        {/* Desktop Navigation */}
        <div className="nav-links font-label-caps" style={{ display: 'flex', alignItems: 'center' }}>
          <Link to="/" className={location.pathname === '/' || location.pathname.includes('/file') || location.pathname.includes('/upload') ? 'active' : ''}>FILE</Link>
          <Link to="/url" className={location.pathname.includes('/url') ? 'active' : ''}>URL</Link>
          <Link to="/search" className={location.pathname.includes('/search') || location.pathname.includes('/lookup') || location.pathname.includes('/ip-address') || location.pathname.includes('/domain') ? 'active' : ''}>SEARCH</Link>
          <Link to="/about" className={location.pathname.includes('/about') ? 'active' : ''}>ABOUT</Link>

          {/* User Auth Profile / Login Button */}
          {isAuthenticated && user ? (
            <div ref={profileRef} style={{ position: 'relative', marginLeft: '12px' }}>
              <button
                onClick={() => setProfileOpen(o => !o)}
                style={{
                  background: 'rgba(185,66,255,0.12)', border: '1px solid rgba(185,66,255,0.35)',
                  borderRadius: '999px', padding: '4px 12px 4px 6px', display: 'flex', alignItems: 'center',
                  gap: '8px', cursor: 'pointer', transition: 'all 0.15s',
                }}
                onMouseEnter={e => (e.currentTarget.style.borderColor = 'var(--primary)')}
                onMouseLeave={e => (e.currentTarget.style.borderColor = 'rgba(185,66,255,0.35)')}
              >
                <div style={{
                  width: '24px', height: '24px', borderRadius: '50%', background: 'linear-gradient(135deg, #b942ff, #00f2ff)',
                  color: '#ffffff', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: '11px', fontWeight: 800, fontFamily: 'var(--font-mono)',
                }}>
                  {user.name.charAt(0).toUpperCase()}
                </div>
                <span className="font-data-mono text-on-surface" style={{ fontSize: '12px', fontWeight: 600 }}>
                  {user.name.split(' ')[0]}
                </span>
                <span className="material-symbols-outlined text-primary" style={{ fontSize: '16px' }}>expand_more</span>
              </button>

              {/* Profile Dropdown */}
              {profileOpen && (
                <div style={{
                  position: 'absolute', top: 'calc(100% + 8px)', right: 0, minWidth: '260px',
                  background: 'var(--surface-elevated)', border: '1px solid var(--border-accent)',
                  borderRadius: '12px', padding: '16px', zIndex: 1000,
                  boxShadow: '0 16px 48px rgba(0,0,0,0.7), 0 0 0 1px rgba(185,66,255,0.1)',
                  animation: 'fadeInDown 0.15s ease',
                }}>
                  <div style={{ borderBottom: '1px solid rgba(255,255,255,0.06)', paddingBottom: '12px', marginBottom: '12px' }}>
                    <div className="font-headline-sm text-on-surface" style={{ fontSize: '14px' }}>{user.name}</div>
                    <div className="font-code-sm text-on-surface-variant" style={{ fontSize: '11px' }}>{user.email}</div>
                    <div style={{ marginTop: '8px', display: 'inline-block', padding: '2px 8px', borderRadius: '4px', background: 'rgba(0,255,163,0.1)', border: '1px solid rgba(0,255,163,0.3)', color: 'var(--success)', fontFamily: 'var(--font-mono)', fontSize: '10px', fontWeight: 700 }}>
                      ✓ {user.tier}
                    </div>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '12px', fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--on-surface-variant)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span>Role:</span>
                      <span className="text-primary">{user.role}</span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span>Status:</span>
                      <span className="text-success">Verified Active</span>
                    </div>
                  </div>

                  <button
                    onClick={logout}
                    style={{
                      width: '100%', padding: '8px', borderRadius: '6px', background: 'rgba(255,0,60,0.1)',
                      border: '1px solid rgba(255,0,60,0.3)', color: 'var(--secondary)', fontFamily: 'var(--font-mono)',
                      fontSize: '12px', fontWeight: 700, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px',
                    }}
                  >
                    <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>logout</span>
                    Sign Out
                  </button>
                </div>
              )}
            </div>
          ) : (
            <button
              onClick={() => openAuthModal('login')}
              style={{
                marginLeft: '12px', padding: '7px 18px', borderRadius: '8px',
                background: 'linear-gradient(135deg, rgba(185,66,255,0.15), rgba(0,242,255,0.15))',
                border: '1px solid rgba(185,66,255,0.4)', color: '#ffffff',
                fontFamily: 'var(--font-mono)', fontSize: '11px', fontWeight: 700, cursor: 'pointer',
                letterSpacing: '0.1em', display: 'flex', alignItems: 'center', gap: '6px',
                boxShadow: '0 0 16px rgba(185,66,255,0.2)', transition: 'all 0.15s',
              }}
              onMouseEnter={e => { e.currentTarget.style.boxShadow = '0 0 24px rgba(185,66,255,0.4)'; e.currentTarget.style.borderColor = 'var(--primary)'; }}
              onMouseLeave={e => { e.currentTarget.style.boxShadow = '0 0 16px rgba(185,66,255,0.2)'; e.currentTarget.style.borderColor = 'rgba(185,66,255,0.4)'; }}
            >
              <span className="material-symbols-outlined" style={{ fontSize: '16px', color: 'var(--primary)' }}>login</span>
              SIGN IN
            </button>
          )}
        </div>

        {/* Mobile Hamburger */}
        <button
          className="mobile-menu-btn"
          onClick={() => setMobileOpen(o => !o)}
          aria-label="Toggle mobile menu"
          aria-expanded={mobileOpen}
          style={{
            background: 'none', border: '1px solid var(--border)', borderRadius: '8px',
            padding: '8px', cursor: 'pointer', color: 'var(--on-surface)',
            display: 'none', // shown via CSS media query
          }}
        >
          <span className="material-symbols-outlined" style={{ fontSize: '24px', display: 'block' }}>
            {mobileOpen ? 'close' : 'menu'}
          </span>
        </button>
      </nav>

      {/* Mobile Drawer */}
      {mobileOpen && (
        <div style={{
          position: 'fixed', top: '64px', left: 0, right: 0, bottom: 0,
          background: 'rgba(5,5,10,0.97)', zIndex: 999, overflowY: 'auto',
          borderTop: '1px solid var(--border)', backdropFilter: 'blur(12px)',
          animation: 'fadeInDown 0.2s ease',
        }}>
          <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            {/* User Info on Mobile */}
            {isAuthenticated && user ? (
              <div style={{ padding: '12px 16px', background: 'rgba(185,66,255,0.1)', borderRadius: '10px', marginBottom: '12px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div className="font-data-mono text-on-surface" style={{ fontSize: '13px', fontWeight: 700 }}>{user.name}</div>
                  <div className="font-code-sm text-on-surface-variant" style={{ fontSize: '11px' }}>{user.email}</div>
                </div>
                <button
                  onClick={logout}
                  style={{ background: 'none', border: '1px solid rgba(255,0,60,0.4)', borderRadius: '6px', color: 'var(--secondary)', padding: '4px 10px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}
                >
                  Logout
                </button>
              </div>
            ) : (
              <button
                onClick={() => { setMobileOpen(false); openAuthModal('login'); }}
                style={{ width: '100%', padding: '14px', borderRadius: '10px', background: 'var(--primary)', border: 'none', color: '#ffffff', fontFamily: 'var(--font-mono)', fontSize: '13px', fontWeight: 700, marginBottom: '12px' }}
              >
                SIGN IN / REGISTER
              </button>
            )}

            {[
              { path: '/', label: 'FILE', icon: 'upload_file' },
              { path: '/url', label: 'URL', icon: 'link' },
              { path: '/search', label: 'SEARCH', icon: 'search' },
              { path: '/about', label: 'ABOUT', icon: 'info' },
            ].map(link => (
              <Link
                key={link.path}
                to={link.path}
                style={{
                  display: 'flex', alignItems: 'center', gap: '12px', padding: '14px 16px',
                  borderRadius: '10px', textDecoration: 'none',
                  background: isActive(link.path) ? 'rgba(185,66,255,0.1)' : 'transparent',
                  color: isActive(link.path) ? 'var(--primary)' : 'var(--on-surface)',
                  fontFamily: 'var(--font-mono)', fontSize: '14px', fontWeight: 700, letterSpacing: '0.08em',
                }}
              >
                <span className="material-symbols-outlined" style={{ fontSize: '20px' }}>{link.icon}</span>
                {link.label.toUpperCase()}
              </Link>
            ))}
          </div>
        </div>
      )}
    </>
  );
};
