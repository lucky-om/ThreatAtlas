import React, { useState } from 'react';
import { Link } from 'react-router-dom';

export const Terms: React.FC = () => {
  const [activeSection, setActiveSection] = useState('acceptance');

  const scrollTo = (id: string) => {
    setActiveSection(id);
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  const sections = [
    { id: 'acceptance', label: '1. Acceptance & Scope' },
    { id: 'service-desc', label: '2. Nature of the Service' },
    { id: 'submission-license', label: '3. License on Submissions' },
    { id: 'user-obligations', label: '4. Prohibited Submissions & Conduct' },
    { id: 'detection-disclaimer', label: '5. Detection Accuracy & Disclaimers' },
    { id: 'api-fair-use', label: '6. API Access & Rate Limits' },
    { id: 'ip-rights', label: '7. Intellectual Property' },
    { id: 'liability', label: '8. Limitation of Liability' },
    { id: 'indemnity', label: '9. Indemnification' },
    { id: 'termination', label: '10. Suspension & Termination' },
    { id: 'governing-law', label: '11. Governing Law & Updates' },
  ];

  return (
    <div className="module-page">
      <div className="digital-grid" />
      <div style={{ position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 0, background: 'radial-gradient(circle at 50% 20%, rgba(185,66,255,0.06) 0%, transparent 60%)' }} />

      <div className="container" style={{ position: 'relative', zIndex: 10, maxWidth: '1280px', width: '100%' }}>
        
        {/* Header */}
        <div className="module-hero" style={{ textAlign: 'left', marginBottom: '32px' }}>
          <div className="module-badge" style={{ background: 'rgba(185,66,255,0.12)', border: '1px solid rgba(185,66,255,0.3)', color: 'var(--primary)' }}>
            <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>gavel</span>
            Terms of Service
          </div>
          <h1 className="font-display-lg text-on-surface" style={{ fontSize: '42px', marginBottom: '12px' }}>
            ThreatAtlas <span className="text-primary">Terms of Service</span>
          </h1>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
            <span className="font-code-sm text-on-surface-variant">Effective Date: August 2026</span>
            <span style={{ width: '4px', height: '4px', borderRadius: '50%', background: 'rgba(255,255,255,0.2)' }} />
            <span className="font-code-sm text-on-surface-variant">Version 2.0</span>
          </div>
        </div>

        {/* Warning Callout Box */}
        <div className="glass-card animate-fade-in-up" style={{ padding: '20px 24px', marginBottom: '32px', borderLeft: '4px solid var(--primary)', background: 'rgba(185,66,255,0.04)' }}>
          <div style={{ display: 'flex', gap: '14px', alignItems: 'flex-start' }}>
            <span className="material-symbols-outlined text-primary" style={{ fontSize: '24px', marginTop: '2px', flexShrink: 0 }}>verified_user</span>
            <div>
              <div className="font-headline-sm text-on-surface" style={{ fontSize: '16px', marginBottom: '4px' }}>
                Summary of Core Terms
              </div>
              <p className="font-body-md text-on-surface-variant" style={{ fontSize: '14px', lineHeight: '1.6', margin: 0 }}>
                By uploading files, URLs, or querying data on ThreatAtlas, you agree that submitted artifacts will be shared with the global cybersecurity community for threat research. You must have the necessary rights to submit any content, and you must not use our scanning engines to develop or optimize active malware.
              </p>
            </div>
          </div>
        </div>

        {/* Two-Column Layout */}
        <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: '32px', alignItems: 'flex-start' }}>
          
          {/* Left Table of Contents */}
          <div className="glass-card animate-fade-in-up" style={{ padding: '20px', position: 'sticky', top: '96px' }}>
            <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '16px', borderBottom: '1px solid rgba(255,255,255,0.06)', paddingBottom: '10px' }}>
              Terms Navigation
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              {sections.map(sec => (
                <button
                  key={sec.id}
                  onClick={() => scrollTo(sec.id)}
                  style={{
                    textAlign: 'left', padding: '8px 12px', borderRadius: '6px',
                    background: activeSection === sec.id ? 'rgba(185,66,255,0.12)' : 'transparent',
                    border: `1px solid ${activeSection === sec.id ? 'rgba(185,66,255,0.3)' : 'transparent'}`,
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

          {/* Right Main Terms Content */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
            
            {/* Section 1 */}
            <div id="acceptance" className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
              <h2 className="font-headline-sm text-primary" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined">handshake</span>
                1. Acceptance & Scope of Agreement
              </h2>
              <div className="font-body-md text-on-surface" style={{ lineHeight: '1.7', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <p>
                  These Terms of Service ("Terms") constitute a legally binding agreement between you ("User", "you", or "your") and ThreatAtlas ("we", "us", or "our") governing your access to and use of the ThreatAtlas platform, website, REST APIs, desktop tools, and associated telemetry services.
                </p>
                <p>
                  By accessing the website, uploading a file, submitting a URL or IP, or integrating our API into your systems, you signify your irrevocable acceptance of these Terms. If you are acting on behalf of an enterprise or organization, you represent that you possess the requisite authority to bind that entity.
                </p>
              </div>
            </div>

            {/* Section 2 */}
            <div id="service-desc" className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
              <h2 className="font-headline-sm text-primary" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined">radar</span>
                2. Nature of the ThreatAtlas Service
              </h2>
              <div className="font-body-md text-on-surface" style={{ lineHeight: '1.7', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <p>
                  ThreatAtlas is an automated multi-engine threat intelligence and malware triage utility. The platform aggregates static analysis signatures, dynamic sandbox behavior reports, DNS records, TLS certificate telemetry, and community indicators to assess potential risks associated with digital artifacts.
                </p>
                <p>
                  ThreatAtlas is designed strictly as a diagnostic, investigative, and educational tool for security analysts, incident responders, and system administrators. It is not intended as a substitute for active endpoint detection and response (EDR) or perimeter firewall software.
                </p>
              </div>
            </div>

            {/* Section 3 */}
            <div id="submission-license" className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
              <h2 className="font-headline-sm text-primary" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined">share</span>
                3. License Grant on Submitted Samples
              </h2>
              <div className="font-body-md text-on-surface" style={{ lineHeight: '1.7', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <p>
                  By submitting any file, URL, domain, IP address, comment, or YARA rule to ThreatAtlas, you grant ThreatAtlas and its security research partners a <strong>worldwide, irrevocable, perpetual, transferable, non-exclusive, royalty-free license</strong> to:
                </p>
                <ul style={{ paddingLeft: '24px', display: 'flex', flexDirection: 'column', gap: '8px', color: 'var(--on-surface-variant)' }}>
                  <li>Analyze, execute in simulated environments, reverse-engineer, and extract heuristic indicators.</li>
                  <li>Store, index, correlate, and make metadata reports publicly queryable by hash or identifier.</li>
                  <li>Distribute full binary payloads and execution telemetry to participating antivirus vendors, security researchers, CERTs, and cybersecurity intelligence feeds for vaccine generation and threat mitigation.</li>
                </ul>
                <p>
                  You represent and warrant that you hold all rights, titles, and permissions necessary to grant this license without infringing third-party copyrights or non-disclosure agreements.
                </p>
              </div>
            </div>

            {/* Section 4 */}
            <div id="user-obligations" className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
              <h2 className="font-headline-sm text-primary" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined">block</span>
                4. Prohibited Submissions & User Conduct
              </h2>
              <div className="font-body-md text-on-surface" style={{ lineHeight: '1.7', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <p>
                  You strictly agree NOT to perform any of the following activities on or through the Platform:
                </p>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '12px' }}>
                  <div style={{ padding: '14px', background: 'rgba(255,42,95,0.04)', borderRadius: '8px', border: '1px solid rgba(255,42,95,0.2)' }}>
                    <strong className="text-secondary">Confidential / PII Data</strong>
                    <p className="font-code-sm text-on-surface-variant" style={{ marginTop: '4px' }}>Do not submit files containing customer databases, medical records, trade secrets, or unredacted personal identifiers.</p>
                  </div>
                  <div style={{ padding: '14px', background: 'rgba(255,42,95,0.04)', borderRadius: '8px', border: '1px solid rgba(255,42,95,0.2)' }}>
                    <strong className="text-secondary">Malware Weaponization</strong>
                    <p className="font-code-sm text-on-surface-variant" style={{ marginTop: '4px' }}>Do not use our scanning engines to test, refine, or evade antivirus detection for malware you intend to deploy maliciously.</p>
                  </div>
                  <div style={{ padding: '14px', background: 'rgba(255,42,95,0.04)', borderRadius: '8px', border: '1px solid rgba(255,42,95,0.2)' }}>
                    <strong className="text-secondary">Denial of Service / Scraping</strong>
                    <p className="font-code-sm text-on-surface-variant" style={{ marginTop: '4px' }}>Do not flood the API, bypass rate-limits, execute unauthorized vulnerability probing, or scrape intelligence en masse.</p>
                  </div>
                  <div style={{ padding: '14px', background: 'rgba(255,42,95,0.04)', borderRadius: '8px', border: '1px solid rgba(255,42,95,0.2)' }}>
                    <strong className="text-secondary">Harassment & Defamation</strong>
                    <p className="font-code-sm text-on-surface-variant" style={{ marginTop: '4px' }}>Do not submit false commentary or malicious votes intended to unfairly damage legitimate software reputations.</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Section 5 */}
            <div id="detection-disclaimer" className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
              <h2 className="font-headline-sm text-primary" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined">warning_amber</span>
                5. Detection Accuracy & False Positives Disclaimer
              </h2>
              <div className="font-body-md text-on-surface" style={{ lineHeight: '1.7', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <p>
                  ThreatAtlas aggregates scan results produced by third-party antivirus engines and external threat feeds. Consequently:
                </p>
                <ul style={{ paddingLeft: '24px', display: 'flex', flexDirection: 'column', gap: '8px', color: 'var(--on-surface-variant)' }}>
                  <li><strong className="text-on-surface">No Guarantee of Safety (False Negatives):</strong> A clean (0/70) detection score does not certify that a file or website is free of advanced persistent threats (APTs), zero-day exploits, or targeted malware.</li>
                  <li><strong className="text-on-surface">Potential Misclassification (False Positives):</strong> Security engines occasionally flag legitimate software (e.g. packers, miners, administration tools) as suspicious. A positive detection does not conclusively prove malicious intent.</li>
                  <li><strong className="text-on-surface">Independent Verification Required:</strong> You are solely responsible for verifying and determining whether to execute, open, or interact with scanned files.</li>
                </ul>
              </div>
            </div>

            {/* Section 6 */}
            <div id="api-fair-use" className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
              <h2 className="font-headline-sm text-primary" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined">terminal</span>
                6. API Access & Rate Limiting Guidelines
              </h2>
              <div className="font-body-md text-on-surface" style={{ lineHeight: '1.7', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <p>
                  API access to ThreatAtlas and our proxy endpoints is subject to quota and rate constraints:
                </p>
                <ul style={{ paddingLeft: '24px', display: 'flex', flexDirection: 'column', gap: '6px', color: 'var(--on-surface-variant)' }}>
                  <li>Standard free public tier is rate-limited to 4 requests per minute and 500 requests per day per IP/token.</li>
                  <li>Clients must implement exponential backoff on HTTP 429 status codes.</li>
                  <li>Sharing or publishing private API keys is strictly prohibited and grounds for immediate revocation.</li>
                </ul>
              </div>
            </div>

            {/* Section 7 */}
            <div id="ip-rights" className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
              <h2 className="font-headline-sm text-primary" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined">copyright</span>
                7. Intellectual Property & Trademarks
              </h2>
              <div className="font-body-md text-on-surface" style={{ lineHeight: '1.7', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <p>
                  The ThreatAtlas platform interface, design system, Atlas AI analysis algorithms, and proprietary code are the exclusive intellectual property of ThreatAtlas. Third-party engine names, logos, and trademarks (e.g., VirusTotal, Google Safe Browsing, MITRE ATT&CK®) belong to their respective proprietors and are referenced strictly for identification and compatibility attribution.
                </p>
              </div>
            </div>

            {/* Section 8 */}
            <div id="liability" className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
              <h2 className="font-headline-sm text-primary" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined">security</span>
                8. Limitation of Liability
              </h2>
              <div className="font-body-md text-on-surface" style={{ lineHeight: '1.7', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <p>
                  TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, THREATATLAS AND ITS OPERATORS, AFFILIATES, AND SCAN ENGINE PARTNERS SHALL NOT BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, CONSEQUENTIAL, SPECIAL, OR PUNITIVE DAMAGES, INCLUDING BUT NOT LIMITED TO:
                </p>
                <ul style={{ paddingLeft: '24px', display: 'flex', flexDirection: 'column', gap: '6px', color: 'var(--on-surface-variant)' }}>
                  <li>Loss of profits, data, goodwill, or business interruption.</li>
                  <li>System compromise, malware infection, or data breach resulting from opening analyzed artifacts.</li>
                  <li>Reputational damage resulting from false positive classifications by upstream vendor engines.</li>
                  <li>Service unavailability, latency, or API downtime.</li>
                </ul>
              </div>
            </div>

            {/* Section 9 */}
            <div id="indemnity" className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
              <h2 className="font-headline-sm text-primary" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined">verified</span>
                9. User Indemnification
              </h2>
              <div className="font-body-md text-on-surface" style={{ lineHeight: '1.7', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <p>
                  You agree to defend, indemnify, and hold harmless ThreatAtlas, its officers, directors, employees, and licensors from and against any third-party claims, damages, liabilities, costs, and legal fees arising out of your violation of these Terms, unauthorized submission of proprietary data, or unlawful use of scan outputs.
                </p>
              </div>
            </div>

            {/* Section 10 */}
            <div id="termination" className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
              <h2 className="font-headline-sm text-primary" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined">cancel</span>
                10. Suspension & Termination of Access
              </h2>
              <div className="font-body-md text-on-surface" style={{ lineHeight: '1.7', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <p>
                  We reserve the unilateral right to suspend, terminate, or throttle access to any IP address, user account, or API key at any time without prior notice if we detect abusive activity, terms violations, or security threats directed against our infrastructure.
                </p>
              </div>
            </div>

            {/* Section 11 */}
            <div id="governing-law" className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
              <h2 className="font-headline-sm text-primary" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined">balance</span>
                11. Governing Law & Modifications
              </h2>
              <div className="font-body-md text-on-surface" style={{ lineHeight: '1.7', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <p>
                  We may revise these Terms from time to time. Continued use of the platform following the posting of amended terms signifies your agreement to the modified provisions.
                </p>
                <div style={{ padding: '16px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div className="font-data-mono text-on-surface" style={{ fontWeight: 600 }}>Legal & Compliance Office</div>
                  <div className="font-code-sm text-on-surface-variant" style={{ marginTop: '4px' }}>Email: legal@threatatlas.local</div>
                  <div className="font-code-sm text-on-surface-variant">Support Portal: <Link to="/contact" className="text-primary">threatatlas.local/contact</Link></div>
                </div>
              </div>
            </div>

          </div>

        </div>

      </div>
    </div>
  );
};
