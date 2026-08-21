import React from 'react';
import { Link } from 'react-router-dom';

export const Footer: React.FC = () => {
  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <footer className="vt-footer" role="contentinfo">
      <div className="vt-footer-container">
        {/* Columns Grid */}
        <div className="vt-footer-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))' }}>
          
          {/* Column 1: Platform */}
          <div className="vt-footer-col">
            <h4 className="vt-footer-heading">Platform</h4>
            <ul className="vt-footer-links">
              <li>
                <Link to="/about">How It Works</Link>
              </li>
              <li>
                <Link to="/contact" className="vt-link-highlighted">Security Support</Link>
              </li>
              <li>
                <span className="vt-link-group">
                  <Link to="/terms">ToS</Link>
                  <span className="vt-link-divider">|</span>
                  <Link to="/privacy">Privacy Notice</Link>
                </span>
              </li>
              <li>
                <Link to="/rules">Rules & Guidelines</Link>
              </li>
            </ul>
          </div>

          {/* Column 2: Tools & Modules */}
          <div className="vt-footer-col">
            <h4 className="vt-footer-heading">Security Tools</h4>
            <ul className="vt-footer-links">
              <li>
                <Link to="/yara">YARA Rule Engine</Link>
              </li>
              <li>
                <Link to="/webscan">WebScan (PhishGuard + WebFox)</Link>
              </li>
              <li>
                <Link to="/ioc-hunter">Bulk IOC Hunter</Link>
              </li>
              <li>
                <Link to="/lookup">IP & Domain Lookup</Link>
              </li>
              <li>
                <Link to="/threat-graph">3D Threat Graph</Link>
              </li>
            </ul>
          </div>

          {/* Column 3: Intelligence & Core */}
          <div className="vt-footer-col">
            <h4 className="vt-footer-heading">Intelligence & AI</h4>
            <ul className="vt-footer-links">
              <li>
                <Link to="/about" className="vt-link-highlighted">Detection Architecture</Link>
              </li>
              <li>
                <Link to="/about">Atlas AI Intelligence</Link>
              </li>
              <li>
                <Link to="/ioc-hunter">Open Threat Feeds</Link>
              </li>
              <li>
                <Link to="/contact">Report False Positive</Link>
              </li>
            </ul>
          </div>

        </div>

        {/* Bottom Bar: Copyright & Actions */}
        <div className="vt-footer-bottom">
          <div className="vt-footer-brand">
            <span className="material-symbols-outlined" style={{ fontSize: '20px', color: 'var(--primary)' }}>shield_with_heart</span>
            <span>ThreatAtlas &copy; {new Date().getFullYear()} — Advanced Threat Intelligence</span>
          </div>

          <div className="vt-footer-actions">
            {/* Scroll to top button */}
            <button
              onClick={scrollToTop}
              className="vt-scroll-top-btn"
              title="Scroll to top"
              aria-label="Scroll to top"
            >
              <span className="material-symbols-outlined" style={{ fontSize: '20px' }}>keyboard_arrow_up</span>
            </button>
          </div>
        </div>

      </div>
    </footer>
  );
};
