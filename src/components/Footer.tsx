import React from 'react';
import { Link } from 'react-router-dom';
import { Shield, Github, Twitter } from 'lucide-react';

export const Footer: React.FC = () => {
  return (
    <footer className="footer">
      <div className="container footer-grid">
        <div>
          <div className="footer-brand">
            <Shield size={24} color="var(--primary)" />
            <span>ThreatAtlas</span>
          </div>
          <p style={{ color: 'var(--on-surface-variant)', marginTop: '16px', fontSize: '14px', lineHeight: '24px' }}>
            Advanced threat intelligence and malware analysis platform for security professionals.
          </p>
        </div>

        <div>
          <h4 className="footer-heading">Platform</h4>
          <ul className="footer-links">
            <li><Link to="/">Scanner</Link></li>
            <li><Link to="/lookup">IP/Domain Lookup</Link></li>
            <li><Link to="/about#api">API Access</Link></li>
          </ul>
        </div>

        <div>
          <h4 className="footer-heading">Legal</h4>
          <ul className="footer-links">
            <li><Link to="/privacy">Privacy Policy</Link></li>
            <li><Link to="/terms">Terms of Service</Link></li>
            <li><Link to="/rules">Rules & Regulations</Link></li>
          </ul>
        </div>

        <div>
          <h4 className="footer-heading">Connect</h4>
          <div style={{ display: 'flex', gap: '16px', marginTop: '16px' }}>
            <a href="https://github.com/lucky-om/+" target="_blank" rel="noopener noreferrer" style={{ color: 'var(--on-surface-variant)', transition: 'color 0.2s' }} onMouseEnter={e => e.currentTarget.style.color = 'var(--primary)'} onMouseLeave={e => e.currentTarget.style.color = 'var(--on-surface-variant)'}>
              <Github size={20} />
            </a>
            <a href="#" style={{ color: 'var(--on-surface-variant)', transition: 'color 0.2s' }} onMouseEnter={e => e.currentTarget.style.color = 'var(--primary)'} onMouseLeave={e => e.currentTarget.style.color = 'var(--on-surface-variant)'}>
              <Twitter size={20} />
            </a>
          </div>
        </div>
      </div>
      <div className="container" style={{ marginTop: '48px', paddingTop: '24px', borderTop: '1px solid var(--border)', textAlign: 'center', color: 'var(--on-surface-variant)', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
        <p>&copy; {new Date().getFullYear()} ThreatAtlas. Built by Luckyverse.</p>
      </div>
    </footer>
  );
};
