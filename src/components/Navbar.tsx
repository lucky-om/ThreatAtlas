import React from 'react';
import { Link, useLocation } from 'react-router-dom';

export const Navbar: React.FC = () => {
  const location = useLocation();

  const links = [
    { path: '/', label: 'Scanner' },
    { path: '/lookup', label: 'Lookup' },
    { path: '/about', label: 'About' },
  ];

  const isActive = (path: string) => {
    if (path === '/') return location.pathname === '/';
    return location.pathname.startsWith(path);
  };

  return (
    <nav className="nav" role="navigation">
      <div className="flex items-center gap-4">
        <Link to="/" className="flex items-center gap-2" style={{ textDecoration: 'none' }}>
          <span className="material-symbols-outlined text-primary" style={{ fontSize: '28px' }}>shield_with_heart</span>
          <span className="font-headline-md text-primary" style={{ fontWeight: 700, letterSpacing: '-0.02em' }}>ThreatAtlas</span>
        </Link>
      </div>

      <div className="nav-links font-label-caps" style={{ display: 'flex' }}>
        {links.map((link) => (
          <Link
            key={link.path}
            to={link.path}
            className={isActive(link.path) ? 'active' : ''}
          >
            {link.label}
          </Link>
        ))}
      </div>

    </nav>
  );
};
