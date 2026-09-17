import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { AnimatedTitle } from '../components/AnimatedTitle';

export const Privacy: React.FC = () => {
  const [activeSection, setActiveSection] = useState('scope');

  const scrollTo = (id: string) => {
    setActiveSection(id);
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  const sections = [
    { id: 'scope', label: '1. Scope & Core Purpose' },
    { id: 'submitted-data', label: '2. Analyzed Artifacts & Samples' },
    { id: 'sharing', label: '3. Security Community Sharing' },
    { id: 'telemetry', label: '4. Technical Telemetry & Logs' },
    { id: 'legal-basis', label: '5. Legal Basis (GDPR & Global)' },
    { id: 'retention', label: '6. Storage & Data Retention' },
    { id: 'user-rights', label: '7. Your Rights & Removal Requests' },
    { id: 'false-positives', label: '8. False Positive Dispute Process' },
    { id: 'subprocessors', label: '9. Third-Party Engines & Partners' },
    { id: 'security', label: '10. Security Measures' },
    { id: 'contact', label: '11. Privacy Contact & DPO' },
  ];

  return (
    <div className="module-page">
      
      <div style={{ position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 0, background: 'radial-gradient(circle at 50% 20%, rgba(255, 107, 53,0.06) 0%, transparent 60%)' }} />

      <div className="container" style={{ position: 'relative', zIndex: 10, maxWidth: '1280px', width: '100%' }}>
        
        {/* Header */}
        <div className="module-hero" style={{ textAlign: 'left', marginBottom: '32px' }}>
          <div className="module-badge" style={{ background: 'rgba(255, 107, 53,0.12)', border: '1px solid rgba(255, 107, 53,0.3)', color: 'var(--primary)' }}>
            <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>policy</span>
            Legal & Data Governance
          </div>
          <AnimatedTitle
            text={<span>ThreatAtlas <span style={{ color: "var(--brand)" }}>Privacy Policy</span></span>}
            as="h1"
            style={{ fontFamily: 'var(--font-display)', fontSize: 'clamp(32px, 5.5vw, 52px)', fontWeight: 800, letterSpacing: '-0.04em', lineHeight: 1.05, marginBottom: '12px', color: 'var(--text)' }}
          />
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
            <span className="font-code-sm text-on-surface-variant">Last Revised: August 2026</span>
            <span style={{ width: '4px', height: '4px', borderRadius: '50%', background: 'rgba(255,255,255,0.2)' }} />
            <span className="font-code-sm text-success">Compliant with Global Threat Intelligence Standards</span>
          </div>
        </div>

        {/* Warning Callout Box */}
        <div className="glass-card animate-fade-in-up" style={{ padding: '20px 24px', marginBottom: '32px', borderLeft: '4px solid var(--secondary)', background: 'rgba(255,42,95,0.04)' }}>
          <div style={{ display: 'flex', gap: '14px', alignItems: 'flex-start' }}>
            <span className="material-symbols-outlined text-secondary" style={{ fontSize: '24px', marginTop: '2px', flexShrink: 0 }}>warning</span>
            <div>
              <div className="font-headline-sm text-on-surface" style={{ fontSize: '16px', marginBottom: '4px' }}>
                Important Notice Concerning Uploaded Samples & URLs
              </div>
              <p className="font-body-md text-on-surface-variant" style={{ fontSize: '14px', lineHeight: '1.6', margin: 0 }}>
                ThreatAtlas is a collective threat analysis and malware detection intelligence utility. <strong>Any file, hash, URL, or domain you submit for scanning is distributed to participating antivirus vendors, security researchers, CERTs, and threat research partners worldwide</strong> to improve threat detection and vaccine creation. <strong>Do NOT upload personal, confidential, proprietary, or sensitive personal data.</strong>
              </p>
            </div>
          </div>
        </div>

        {/* Two-Column Layout */}
        <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: '32px', alignItems: 'flex-start' }}>
          
          {/* Left Table of Contents */}
          <div className="glass-card animate-fade-in-up" style={{ padding: '20px', position: 'sticky', top: '96px' }}>
            <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '16px', borderBottom: '1px solid rgba(255,255,255,0.06)', paddingBottom: '10px' }}>
              Policy Sections
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              {sections.map(sec => (
                <button
                  key={sec.id}
                  onClick={() => scrollTo(sec.id)}
                  style={{
                    textAlign: 'left', padding: '8px 12px', borderRadius: '6px',
                    background: activeSection === sec.id ? 'rgba(255, 107, 53,0.12)' : 'transparent',
                    border: `1px solid ${activeSection === sec.id ? 'rgba(255, 107, 53,0.3)' : 'transparent'}`,
                    color: activeSection === sec.id ? 'var(--primary)' : 'var(--on-surface-variant)',
                    fontFamily: 'var(--font-sans)', fontSize: '13px', fontWeight: activeSection === sec.id ? 600 : 400,
                    cursor: 'pointer', transition: 'all 0.15s',
                  }}
                >
                  {sec.label}
                </button>
              ))}
            </div>
          </div>

          {/* Right Main Policy Content */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
            
            {/* Section 1 */}
            <div id="scope" className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
              <h2 className="font-headline-sm text-primary" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined">shield</span>
                1. Scope & Core Purpose
              </h2>
              <div className="font-body-md text-on-surface" style={{ lineHeight: '1.7', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <p>
                  This Privacy Policy describes how ThreatAtlas ("we", "our", or "the Platform") collects, processes, analyzes, and shares technical artifacts, cyber threat telemetry, and user information when you interact with our web interface, REST APIs, or scanning tools.
                </p>
                <p>
                  Our primary mission is to protect global internet infrastructure by providing automated, vendor-neutral threat analysis. We achieve this by correlating submissions across multiple antivirus engines, sandbox execution environments, and open-source intelligence (OSINT) repositories.
                </p>
              </div>
            </div>

            {/* Section 2 */}
            <div id="submitted-data" className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
              <h2 className="font-headline-sm text-primary" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined">folder_open</span>
                2. Analyzed Artifacts & Submitted Samples
              </h2>
              <div className="font-body-md text-on-surface" style={{ lineHeight: '1.7', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <p>
                  When you submit content to ThreatAtlas, we ingest and generate the following categories of data:
                </p>
                <ul style={{ paddingLeft: '24px', display: 'flex', flexDirection: 'column', gap: '8px', color: 'var(--on-surface-variant)' }}>
                  <li><strong className="text-on-surface">Binary & Document Files:</strong> Executables (PE, ELF, Mach-O), Office documents, scripts, archives, and PDFs submitted for automated static and dynamic analysis.</li>
                  <li><strong className="text-on-surface">Cryptographic Hashes:</strong> MD5, SHA-1, SHA-256, SSDEEP, TLSH, and Authentihash values generated from your files.</li>
                  <li><strong className="text-on-surface">Network Endpoints & URLs:</strong> Full URL paths, domain names, hostnames, IP addresses, and Autonomous System Numbers (ASNs) submitted for scanning or extracted during sandbox execution.</li>
                  <li><strong className="text-on-surface">Extracted Metadata:</strong> ExifTool data, PE headers, imports, exports, code signing certificates, compilation timestamps, and MITRE ATT&CK® tactical techniques.</li>
                  <li><strong className="text-on-surface">Sandbox Behavioral Telemetry:</strong> Simulated process trees, registry key modifications, network connections, DNS resolutions, and mutex creations captured during isolated execution.</li>
                </ul>
              </div>
            </div>

            {/* Section 3 */}
            <div id="sharing" className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
              <h2 className="font-headline-sm text-primary" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined">hub</span>
                3. Security Community & Partner Sharing
              </h2>
              <div className="font-body-md text-on-surface" style={{ lineHeight: '1.7', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <p>
                  Like major threat intelligence platforms, ThreatAtlas operates on a collaborative intelligence model. By submitting artifacts to ThreatAtlas, you understand and acknowledge that:
                </p>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px', marginTop: '8px' }}>
                  <div style={{ padding: '16px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
                    <div className="font-data-mono text-primary" style={{ marginBottom: '6px' }}>Antivirus Vendors</div>
                    <div className="font-code-sm text-on-surface-variant">Samples are shared with 70+ AV scanning engines to correct false positives and generate new antivirus definitions.</div>
                  </div>
                  <div style={{ padding: '16px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
                    <div className="font-data-mono text-primary" style={{ marginBottom: '6px' }}>CERTs & CSIRTs</div>
                    <div className="font-code-sm text-on-surface-variant">National and enterprise computer emergency response teams use threat feeds to triage critical zero-day exploits.</div>
                  </div>
                  <div style={{ padding: '16px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
                    <div className="font-data-mono text-primary" style={{ marginBottom: '6px' }}>Open Threat Feeds</div>
                    <div className="font-code-sm text-on-surface-variant">Public malicious indicators are indexed on repositories like URLhaus, MalwareBazaar, and AlienVault OTX.</div>
                  </div>
                </div>
              </div>
            </div>

            {/* Section 4 */}
            <div id="telemetry" className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
              <h2 className="font-headline-sm text-primary" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined">data_object</span>
                4. Technical Telemetry & Operational Logs
              </h2>
              <div className="font-body-md text-on-surface" style={{ lineHeight: '1.7', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <p>
                  When accessing our website or API, our servers automatically record standard HTTP access logs:
                </p>
                <ul style={{ paddingLeft: '24px', display: 'flex', flexDirection: 'column', gap: '6px', color: 'var(--on-surface-variant)' }}>
                  <li>Client IP address and geographic country/region (used for DDoS mitigation and rate-limiting).</li>
                  <li>User-Agent, browser type, and operating system details.</li>
                  <li>Timestamps, requested endpoints, HTTP status codes, and payload byte lengths.</li>
                  <li>API authentication token identifiers (to enforce tier quotas and detect unauthorized abuse).</li>
                </ul>
                <p>
                  We do not sell, rent, or commercialize your personal access logs to advertising brokers.
                </p>
              </div>
            </div>

            {/* Section 5 */}
            <div id="legal-basis" className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
              <h2 className="font-headline-sm text-primary" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined">gavel</span>
                5. Legal Basis for Processing (GDPR & Global Privacy)
              </h2>
              <div className="font-body-md text-on-surface" style={{ lineHeight: '1.7', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <p>
                  Under Article 6(1)(f) of the General Data Protection Regulation (GDPR) and comparable global data protection legislation, our processing of technical cyber artifacts and network telemetry is grounded in <strong>Legitimate Interests</strong>:
                </p>
                <div style={{ padding: '16px', background: 'rgba(0,255,163,0.04)', border: '1px solid rgba(0,255,163,0.2)', borderRadius: '8px', color: 'var(--on-surface)' }}>
                  <em>"The processing of personal data to the extent strictly necessary and proportionate for the purposes of ensuring network and information security... constitutes a legitimate interest of the data controller concerned."</em> (GDPR Recital 49).
                </div>
                <p>
                  Where you submit voluntary inquiries through our Contact Portal, processing is based on your explicit consent (Article 6(1)(a)).
                </p>
              </div>
            </div>

            {/* Section 6 */}
            <div id="retention" className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
              <h2 className="font-headline-sm text-primary" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined">inventory_2</span>
                6. Storage & Data Retention
              </h2>
              <div className="font-body-md text-on-surface" style={{ lineHeight: '1.7', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <p>
                  To maintain historical continuity of malware intelligence and prevent threat resurgence:
                </p>
                <ul style={{ paddingLeft: '24px', display: 'flex', flexDirection: 'column', gap: '6px', color: 'var(--on-surface-variant)' }}>
                  <li><strong className="text-on-surface">Cryptographic Reports & Hash Indices:</strong> Retained indefinitely in our threat archive to provide rapid cache lookup for security analysts.</li>
                  <li><strong className="text-on-surface">Web Server Access Logs:</strong> Retained for a rolling period of 90 days for audit, security telemetry, and DDoS mitigation before automatic aggregation or purging.</li>
                  <li><strong className="text-on-surface">Support Ticket Messages:</strong> Retained for up to 12 months following ticket resolution to assist with subsequent related inquiries.</li>
                </ul>
              </div>
            </div>

            {/* Section 7 */}
            <div id="user-rights" className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
              <h2 className="font-headline-sm text-primary" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined">account_circle</span>
                7. Your Data Protection Rights
              </h2>
              <div className="font-body-md text-on-surface" style={{ lineHeight: '1.7', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <p>
                  Depending on your jurisdiction, you hold statutory rights regarding your personal data:
                </p>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px' }}>
                  <div style={{ padding: '12px 16px', background: 'rgba(255,255,255,0.03)', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.06)' }}>
                    <div className="font-data-mono text-on-surface" style={{ fontWeight: 600 }}>Right to Access</div>
                    <div className="font-code-sm text-on-surface-variant" style={{ fontSize: '12px' }}>Request confirmation of personal data held about you.</div>
                  </div>
                  <div style={{ padding: '12px 16px', background: 'rgba(255,255,255,0.03)', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.06)' }}>
                    <div className="font-data-mono text-on-surface" style={{ fontWeight: 600 }}>Right to Erasure</div>
                    <div className="font-code-sm text-on-surface-variant" style={{ fontSize: '12px' }}>Request deletion of personal information where applicable.</div>
                  </div>
                  <div style={{ padding: '12px 16px', background: 'rgba(255,255,255,0.03)', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.06)' }}>
                    <div className="font-data-mono text-on-surface" style={{ fontWeight: 600 }}>Right to Rectification</div>
                    <div className="font-code-sm text-on-surface-variant" style={{ fontSize: '12px' }}>Correct inaccurate or incomplete personal contact records.</div>
                  </div>
                  <div style={{ padding: '12px 16px', background: 'rgba(255,255,255,0.03)', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.06)' }}>
                    <div className="font-data-mono text-on-surface" style={{ fontWeight: 600 }}>Right to Object</div>
                    <div className="font-code-sm text-on-surface-variant" style={{ fontSize: '12px' }}>Object to processing based on legitimate interests.</div>
                  </div>
                </div>
              </div>
            </div>

            {/* Section 8 */}
            <div id="false-positives" className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
              <h2 className="font-headline-sm text-primary" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined">fact_check</span>
                8. False Positive & Sample Removal Procedure
              </h2>
              <div className="font-body-md text-on-surface" style={{ lineHeight: '1.7', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <p>
                  If your software, domain, or website has been misclassified as malicious by scanning engines, or if an accidental submission contained proprietary data:
                </p>
                <ol style={{ paddingLeft: '24px', display: 'flex', flexDirection: 'column', gap: '8px', color: 'var(--on-surface-variant)' }}>
                  <li>Submit a False Positive Ticket via our <Link to="/contact" className="text-primary">Contact Support Portal</Link> selecting "False Positive Report".</li>
                  <li>Include the SHA-256 hash, URL, or domain, along with documentation proving legitimate ownership and clean verification.</li>
                  <li>For proprietary data removal, provide proof of authorization and the specific hash identifiers to initiate our sample quarantine and redaction protocol.</li>
                </ol>
              </div>
            </div>

            {/* Section 9 */}
            <div id="subprocessors" className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
              <h2 className="font-headline-sm text-primary" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined">dns</span>
                9. Third-Party Engines & Sub-processors
              </h2>
              <div className="font-body-md text-on-surface" style={{ lineHeight: '1.7', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <p>
                  ThreatAtlas proxies and interfaces with reputable third-party threat intelligence APIs to execute scans:
                </p>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {[
                    { name: 'ThreatAtlas Engine v3 (Google Cloud / Chronicle)', purpose: 'Antivirus multi-engine scan aggregation and file sandbox metadata' },
                    { name: 'Google DNS over HTTPS (dns.google)', purpose: 'Encrypted DNS resolution and record verification' },
                    { name: 'RDAP.org & ARIN Registry', purpose: 'Public domain registration and WHOIS authority lookup' },
                    { name: 'Abuse.ch (URLhaus & MalwareBazaar)', purpose: 'Open-source threat feed verification and malware family tagging' },
                    { name: 'IP-API Geolocation Gateway', purpose: 'Network ASN, ISP, and geographic geolocation routing' },
                  ].map(sub => (
                    <div key={sub.name} style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 14px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.05)', flexWrap: 'wrap', gap: '8px' }}>
                      <span className="font-data-mono text-on-surface" style={{ fontSize: '13px' }}>{sub.name}</span>
                      <span className="font-code-sm text-on-surface-variant" style={{ fontSize: '12px' }}>{sub.purpose}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Section 10 */}
            <div id="security" className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
              <h2 className="font-headline-sm text-primary" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined">lock</span>
                10. Technical & Organizational Security
              </h2>
              <div className="font-body-md text-on-surface" style={{ lineHeight: '1.7', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <p>
                  We implement robust cybersecurity controls to protect transit and storage:
                </p>
                <ul style={{ paddingLeft: '24px', display: 'flex', flexDirection: 'column', gap: '6px', color: 'var(--on-surface-variant)' }}>
                  <li>Strict TLS 1.3 encryption on all external network transit.</li>
                  <li>Server-side API key header injection preventing client credential exposure.</li>
                  <li>Isolated sandbox execution environments with air-gapped network emulation.</li>
                  <li>Automated rate-limiting and burst protection mitigating automated harvesting attacks.</li>
                </ul>
              </div>
            </div>

            {/* Section 11 */}
            <div id="contact" className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
              <h2 className="font-headline-sm text-primary" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined">contact_mail</span>
                11. Privacy Contact & Inquiries
              </h2>
              <div className="font-body-md text-on-surface" style={{ lineHeight: '1.7', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <p>
                  For privacy inquiries, sample quarantine requests, or to exercise data subject rights under GDPR/CCPA, please contact our Data Governance team:
                </p>
                <div style={{ padding: '16px', background: 'rgba(255, 107, 53,0.06)', borderRadius: '8px', border: '1px solid rgba(255, 107, 53,0.2)' }}>
                  <div className="font-data-mono text-on-surface" style={{ fontWeight: 600 }}>ThreatAtlas Data Protection Office</div>
                  <div className="font-code-sm text-on-surface-variant" style={{ marginTop: '4px' }}>Email: privacy@threatatlas.local</div>
                  <div className="font-code-sm text-on-surface-variant">Online Portal: <Link to="/contact" className="text-primary">threatatlas.local/contact</Link></div>
                </div>
              </div>
            </div>

          </div>

        </div>

      </div>
    </div>
  );
};
