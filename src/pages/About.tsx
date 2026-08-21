import React from 'react';
import { Link } from 'react-router-dom';

export const About: React.FC = () => {
  return (
    <div className="module-page">
      <div className="digital-grid" />
      <div style={{ position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 0, background: 'radial-gradient(circle at 50% 25%, rgba(185,66,255,0.06) 0%, transparent 60%)' }} />

      <div className="container" style={{ position: 'relative', zIndex: 10, maxWidth: '1000px', width: '100%' }}>
        
        {/* Hero */}
        <div className="module-hero">
          <div className="module-badge" style={{ background: 'rgba(185,66,255,0.12)', border: '1px solid rgba(185,66,255,0.3)', color: 'var(--primary)' }}>
            <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>shield</span>
            Architecture & Mission
          </div>
          <h1 className="font-display-lg text-on-surface" style={{ fontSize: '46px', marginBottom: '14px' }}>
            About <span className="text-primary">ThreatAtlas</span>
          </h1>
          <p className="font-body-md text-on-surface-variant" style={{ maxWidth: '640px', margin: '0 auto' }}>
            ThreatAtlas is a next-generation open threat intelligence and malware triage platform built for security analysts, incident responders, and researchers.
          </p>
        </div>

        {/* Mission Card */}
        <div className="glass-card animate-fade-in-up" style={{ padding: '36px', marginBottom: '28px' }}>
          <h2 className="font-headline-sm text-primary" style={{ marginBottom: '14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="material-symbols-outlined">target</span>
            Our Mission
          </h2>
          <p className="font-body-md text-on-surface" style={{ lineHeight: '1.7', fontSize: '15px' }}>
            Our goal is to make deep, multi-layered threat analysis transparent, lightning-fast, and accessible. By correlating signals across 70+ antivirus engines, dynamic behavioral sandboxes, phishing heuristic scorers, and open-source intelligence feeds, ThreatAtlas provides clear, actionable verdicts on files, URLs, domains, and IP addresses.
          </p>
        </div>

        {/* Core Pillars Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '20px', marginBottom: '28px' }}>
          
          <div className="glass-card animate-fade-in-up" style={{ padding: '24px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
              <span className="material-symbols-outlined text-primary" style={{ fontSize: '24px' }}>radar</span>
              <h3 className="font-headline-sm text-on-surface" style={{ fontSize: '16px' }}>Multi-Engine Scanning</h3>
            </div>
            <p className="font-code-sm text-on-surface-variant" style={{ lineHeight: '1.6' }}>
              Aggregates verdicts across premier antivirus vendors, static signature scanners, and file deduplication hashes (SHA-256, MD5, SSDEEP).
            </p>
          </div>

          <div className="glass-card animate-fade-in-up" style={{ padding: '24px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
              <span className="material-symbols-outlined text-primary" style={{ fontSize: '24px' }}>travel_explore</span>
              <h3 className="font-headline-sm text-on-surface" style={{ fontSize: '16px' }}>WebScan Recon & PhishGuard</h3>
            </div>
            <p className="font-code-sm text-on-surface-variant" style={{ lineHeight: '1.6' }}>
              Deep website inspection examining typosquatting against top brands, DNS over HTTPS records, RDAP registration, and SSL/TLS cipher strength.
            </p>
          </div>

          <div className="glass-card animate-fade-in-up" style={{ padding: '24px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
              <span className="material-symbols-outlined text-primary" style={{ fontSize: '24px' }}>search_insights</span>
              <h3 className="font-headline-sm text-on-surface" style={{ fontSize: '16px' }}>YARA Rule Engine</h3>
            </div>
            <p className="font-code-sm text-on-surface-variant" style={{ lineHeight: '1.6' }}>
              Built-in YARA rule compiler and execution engine with pre-loaded signatures for ransomware, Cobalt Strike, Mimikatz, and webshells.
            </p>
          </div>

          <div className="glass-card animate-fade-in-up" style={{ padding: '24px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
              <span className="material-symbols-outlined text-primary" style={{ fontSize: '24px' }}>psychology</span>
              <h3 className="font-headline-sm text-on-surface" style={{ fontSize: '16px' }}>Atlas AI Core</h3>
            </div>
            <p className="font-code-sm text-on-surface-variant" style={{ lineHeight: '1.6' }}>
              Interactive AI threat analyst powered by Groq LLaMA models, delivering real-time heuristic synthesis, YARA guidance, and triage insights.
            </p>
          </div>

        </div>

        {/* Quick Action Navigation */}
        <div className="glass-card animate-fade-in-up" style={{ padding: '28px', textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '16px' }}>
          <h3 className="font-headline-sm text-on-surface">Ready to start threat investigation?</h3>
          <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', justifyContent: 'center' }}>
            <Link to="/" className="btn-primary" style={{ textDecoration: 'none', padding: '10px 24px', fontSize: '13px' }}>
              Launch Scanner
            </Link>
            <Link to="/webscan" style={{ padding: '10px 24px', borderRadius: '8px', background: 'rgba(245,158,11,0.12)', border: '1px solid rgba(245,158,11,0.35)', color: '#f59e0b', fontFamily: 'var(--font-mono)', fontSize: '13px', textDecoration: 'none', fontWeight: 600 }}>
              Inspect URL with WebScan
            </Link>
            <Link to="/yara" style={{ padding: '10px 24px', borderRadius: '8px', background: 'rgba(34,211,238,0.12)', border: '1px solid rgba(34,211,238,0.35)', color: 'var(--module-yara)', fontFamily: 'var(--font-mono)', fontSize: '13px', textDecoration: 'none', fontWeight: 600 }}>
              YARA Engine
            </Link>
          </div>
        </div>

      </div>
    </div>
  );
};
