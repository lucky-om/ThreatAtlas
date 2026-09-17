import React from 'react';
import { motion, Variants } from 'framer-motion';
import { SEO } from '../components/SEO';
import { Link } from 'react-router-dom';

const PILLARS = [
  {
    icon: 'radar',
    title: 'Multi-Engine Scanning',
    desc: 'Aggregates verdicts across 70+ antivirus vendors, static signature scanners, and file deduplication hashes (SHA-256, MD5, SSDEEP).',
    color: 'var(--brand)',
  },
  {
    icon: 'travel_explore',
    title: 'WebScan & PhishGuard',
    desc: 'Deep website inspection: typosquatting detection, DNS-over-HTTPS, RDAP registration, TLS cipher audit, and brand impersonation scoring.',
    color: 'var(--status-suspicious)',
  },
  {
    icon: 'search_insights',
    title: 'YARA Pattern Engine',
    desc: 'In-browser YARA rule compiler and execution engine with pre-loaded signatures for ransomware, Cobalt Strike, Mimikatz, and webshells.',
    color: 'var(--module-yara)',
  },
  {
    icon: 'psychology',
    title: 'Atlas Intelligence',
    desc: 'On-demand threat analyst delivering heuristic synthesis, YARA guidance, CVE mapping, and real-time triage insights.',
    color: 'var(--brand-ember)',
  },
  {
    icon: 'hub',
    title: 'Threat Graph',
    desc: 'Interactive 3D graph of IP, domain, and hash relationships — visualize lateral movement and infrastructure clusters.',
    color: 'var(--module-graph)',
  },
  {
    icon: 'inventory',
    title: 'Bulk IOC Hunter',
    desc: 'Submit hundreds of indicators simultaneously across VirusTotal, URLhaus, MalwareBazaar, and Abuse.ch feeds.',
    color: 'var(--module-ioc)',
  },
];

const staggerContainer = {
  hidden: {},
  show: { transition: { staggerChildren: 0.08 } },
};

const fadeUp: Variants = {
  hidden: { opacity: 0, y: 28 },
  show: { opacity: 1, y: 0, transition: { duration: 0.55, ease: 'easeOut' } },
};

export const About: React.FC = () => {
  return (
    <div className="module-page">
      <SEO
        title="About — ThreatAtlas Platform Architecture"
        description="ThreatAtlas multi-engine threat intelligence platform — architecture, methodology, and integrated security tools."
        path="/about"
      />

      <div className="container" style={{ position: 'relative', zIndex: 10, maxWidth: '1040px', width: '100%' }}>

        {/* Hero */}
        <motion.div
          initial={{ opacity: 0, y: 32 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
          style={{ textAlign: 'center', marginBottom: '60px' }}
        >
          <div style={{
            display: 'inline-flex', alignItems: 'center', gap: '8px',
            padding: '4px 14px', marginBottom: '20px',
            background: 'var(--brand-dim)', border: '1px solid var(--border-2)',
            borderRadius: '999px',
          }}>
            <span className="material-symbols-outlined" style={{ fontSize: '14px', color: 'var(--brand)' }}>shield</span>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', fontWeight: 700, color: 'var(--brand)', letterSpacing: '0.14em' }}>
              PLATFORM ARCHITECTURE
            </span>
          </div>

          <h1 style={{
            fontFamily: 'var(--font-display)',
            fontSize: 'clamp(52px, 7vw, 90px)',
            lineHeight: 0.95,
            letterSpacing: '0.02em',
            color: 'var(--on-surface)',
            marginBottom: '20px',
          }}>
            ABOUT <span style={{ color: 'var(--brand)', textShadow: '0 0 40px var(--brand-glow)' }}>THREATATLAS</span>
          </h1>

          <p style={{
            fontFamily: 'var(--font-sans)',
            fontSize: '16px',
            color: 'var(--on-surface-3)',
            maxWidth: '640px',
            margin: '0 auto',
            lineHeight: 1.75,
          }}>
            A multi-engine threat intelligence platform built for security analysts, incident responders, and researchers who need fast, accurate, and transparent verdicts.
          </p>
        </motion.div>

        {/* Mission card */}
        <motion.div
          initial={{ opacity: 0, y: 24 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.1 }}
          className="glass-card"
          style={{
            padding: '36px 40px',
            marginBottom: '32px',
            borderLeft: '3px solid var(--brand)',
            background: 'rgba(255, 69, 0, 0.03)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
            <span className="material-symbols-outlined" style={{ color: 'var(--brand)', fontSize: '26px' }}>target</span>
            <h2 style={{ fontFamily: 'var(--font-headline)', fontSize: '20px', fontWeight: 700, color: 'var(--on-surface)' }}>
              Mission Statement
            </h2>
          </div>
          <p style={{ fontFamily: 'var(--font-sans)', fontSize: '15px', color: 'var(--on-surface-2)', lineHeight: 1.75 }}>
            Make deep, multi-layered threat analysis transparent, fast, and accessible — without walled gardens or opaque black-box verdicts. By correlating signals across 70+ antivirus engines, behavioral heuristics, phishing scorers, and open-source intelligence feeds, ThreatAtlas delivers clear, actionable results on files, URLs, domains, and IP addresses.
          </p>
        </motion.div>

        {/* Capabilities grid */}
        <div style={{ marginBottom: '16px' }}>
          <div style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '10px',
            fontWeight: 700,
            color: 'var(--brand)',
            letterSpacing: '0.16em',
            textTransform: 'uppercase',
            marginBottom: '20px',
          }}>
            Core Capabilities
          </div>

          <motion.div
            variants={staggerContainer}
            initial="hidden"
            animate="show"
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
              gap: '16px',
              marginBottom: '32px',
            }}
          >
            {PILLARS.map(pillar => (
              <motion.div
                key={pillar.title}
                variants={fadeUp}
                className="glass-card"
                style={{ padding: '24px 28px' }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                  <div style={{
                    width: '40px', height: '40px',
                    borderRadius: '10px',
                    background: `${pillar.color}18`,
                    border: `1px solid ${pillar.color}44`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    flexShrink: 0,
                  }}>
                    <span className="material-symbols-outlined" style={{ fontSize: '20px', color: pillar.color }}>
                      {pillar.icon}
                    </span>
                  </div>
                  <h3 style={{ fontFamily: 'var(--font-headline)', fontSize: '16px', fontWeight: 700, color: 'var(--on-surface)', margin: 0 }}>
                    {pillar.title}
                  </h3>
                </div>
                <p style={{ fontFamily: 'var(--font-sans)', fontSize: '13px', color: 'var(--on-surface-3)', lineHeight: 1.7, margin: 0 }}>
                  {pillar.desc}
                </p>
              </motion.div>
            ))}
          </motion.div>
        </div>

        {/* Data sources */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="glass-card"
          style={{ padding: '28px 32px', marginBottom: '32px' }}
        >
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', fontWeight: 700, color: 'var(--brand)', letterSpacing: '0.16em', marginBottom: '18px' }}>
            DATA SOURCES & INTEGRATIONS
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px' }}>
            {[
              'Multi-AV Engine API', 'URLhaus (Abuse.ch)', 'MalwareBazaar', 'ThreatFox',
              'DNS-over-HTTPS (Cloudflare)', 'RDAP IANA', 'ipapi.co Geo', 'Mozilla SSL Labs',
            ].map(source => (
              <span key={source} style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '11px',
                padding: '4px 12px',
                borderRadius: '6px',
                background: 'var(--brand-dim)',
                border: '1px solid var(--border)',
                color: 'var(--on-surface-2)',
                fontWeight: 500,
              }}>
                {source}
              </span>
            ))}
          </div>
        </motion.div>

        {/* CTA */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6 }}
          className="glass-card"
          style={{ padding: '36px', textAlign: 'center' }}
        >
          <h3 style={{ fontFamily: 'var(--font-headline)', fontSize: '22px', fontWeight: 700, color: 'var(--on-surface)', marginBottom: '8px' }}>
            Ready to investigate a threat?
          </h3>
          <p style={{ fontFamily: 'var(--font-sans)', fontSize: '14px', color: 'var(--on-surface-3)', marginBottom: '24px' }}>
            Submit a file, URL, IP, or domain and get results across all engines in seconds.
          </p>
          <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', justifyContent: 'center' }}>
            <Link to="/" className="btn-primary" style={{ textDecoration: 'none', padding: '12px 28px', fontSize: '13px' }}>
              Launch Scanner
            </Link>
            <Link to="/search" style={{
              padding: '12px 24px', borderRadius: '999px',
              background: 'var(--brand-dim)', border: '1px solid var(--border-2)',
              color: 'var(--brand)', fontFamily: 'var(--font-mono)',
              fontSize: '12px', textDecoration: 'none', fontWeight: 700,
              letterSpacing: '0.08em', textTransform: 'uppercase',
            }}>
              IP & Domain Lookup
            </Link>
          </div>
        </motion.div>

      </div>
    </div>
  );
};
