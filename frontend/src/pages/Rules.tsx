import React, { useState } from 'react';
import { Link } from 'react-router-dom';

export const Rules: React.FC = () => {
  const [activeSection, setActiveSection] = useState('submission-rules');

  const scrollTo = (id: string) => {
    setActiveSection(id);
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  const sections = [
    { id: 'submission-rules', label: '1. File & URL Submission Rules' },
    { id: 'supported-formats', label: '2. Supported Formats & Size Limits' },
    { id: 'malware-handling', label: '3. Live Malware Sample Protocol' },
    { id: 'api-etiquette', label: '4. API Rate Limits & Etiquette' },
    { id: 'community-conduct', label: '5. Community Voting & Comments' },
    { id: 'vendor-whitelisting', label: '6. Developer & Software Whitelisting' },
    { id: 'zero-tolerance', label: '7. Zero-Tolerance Violations' },
  ];

  return (
    <div className="module-page">
      
      <div style={{ position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 0, background: 'radial-gradient(circle at 50% 20%, rgba(34,211,238,0.06) 0%, transparent 60%)' }} />

      <div className="container" style={{ position: 'relative', zIndex: 10, maxWidth: '1280px', width: '100%' }}>
        
        {/* Header */}
        <div className="module-hero" style={{ textAlign: 'left', marginBottom: '32px' }}>
          <div className="module-badge" style={{ background: 'rgba(34,211,238,0.12)', border: '1px solid rgba(34,211,238,0.3)', color: 'var(--module-yara)' }}>
            <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>rule</span>
            Guidelines & Standards
          </div>
          <h1 className="font-display-lg text-on-surface" style={{ fontSize: '42px', marginBottom: '12px' }}>
            ThreatAtlas <span style={{ color: "var(--brand)" }}>Rules & Guidelines</span>
          </h1>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
            <span className="font-code-sm text-on-surface-variant">Standardized Security Protocol</span>
            <span style={{ width: '4px', height: '4px', borderRadius: '50%', background: 'rgba(255,255,255,0.2)' }} />
            <span className="font-code-sm text-success">Applies to All Web & API Submissions</span>
          </div>
        </div>

        {/* Two-Column Layout */}
        <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: '32px', alignItems: 'flex-start' }}>
          
          {/* Left Table of Contents */}
          <div className="glass-card animate-fade-in-up" style={{ padding: '20px', position: 'sticky', top: '96px' }}>
            <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '16px', borderBottom: '1px solid rgba(255,255,255,0.06)', paddingBottom: '10px' }}>
              Guideline Sections
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              {sections.map(sec => (
                <button
                  key={sec.id}
                  onClick={() => scrollTo(sec.id)}
                  style={{
                    textAlign: 'left', padding: '8px 12px', borderRadius: '6px',
                    background: activeSection === sec.id ? 'rgba(34,211,238,0.12)' : 'transparent',
                    border: `1px solid ${activeSection === sec.id ? 'rgba(34,211,238,0.3)' : 'transparent'}`,
                    color: activeSection === sec.id ? 'var(--module-yara)' : 'var(--on-surface-variant)',
                    fontFamily: 'var(--font-sans)', fontSize: '13px', fontWeight: activeSection === sec.id ? 600 : 400,
                    cursor: 'pointer', transition: 'all 0.15s',
                  }}
                >
                  {sec.label}
                </button>
              ))}
            </div>
          </div>

          {/* Right Main Content */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
            
            {/* Section 1 */}
            <div id="submission-rules" className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
              <h2 className="font-headline-sm text-on-surface" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--module-yara)' }}>
                <span className="material-symbols-outlined">upload_file</span>
                1. File & URL Submission Rules
              </h2>
              <div className="font-body-md text-on-surface" style={{ lineHeight: '1.7', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <p>
                  To preserve data integrity across our multi-engine aggregation pipelines, all users submitting files or URLs must adhere to the following rules:
                </p>
                <ul style={{ paddingLeft: '24px', display: 'flex', flexDirection: 'column', gap: '8px', color: 'var(--on-surface-variant)' }}>
                  <li><strong className="text-on-surface">Authorized Content Only:</strong> Submit only files, URLs, or network endpoints that you have legal authorization to analyze or investigate for security research.</li>
                  <li><strong className="text-on-surface">No PII or Confidential Files:</strong> Do not upload unencrypted employee records, medical files, API secret keys, database dumps, or copyrighted proprietary code.</li>
                  <li><strong className="text-on-surface">Public Community Dissemination:</strong> Samples are automatically shared with antivirus vendors and CERT teams worldwide. Uploaded samples cannot be rescinded post-analysis without submitting a formal False Positive / Quarantine ticket.</li>
                </ul>
              </div>
            </div>

            {/* Section 2 */}
            <div id="supported-formats" className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
              <h2 className="font-headline-sm text-on-surface" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--module-yara)' }}>
                <span className="material-symbols-outlined">category</span>
                2. Supported Formats & File Size Limits
              </h2>
              <div className="font-body-md text-on-surface" style={{ lineHeight: '1.7', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <p>
                  ThreatAtlas supports direct binary upload and automated format parsing for up to <strong>32MB per file</strong> via the web UI and REST API:
                </p>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px', marginTop: '8px' }}>
                  {[
                    { type: 'Windows Executables', ext: '.exe, .dll, .sys, .msi, .scr' },
                    { type: 'Linux Binaries', ext: '.elf, .so, .bin, .deb, .rpm' },
                    { type: 'macOS Mach-O', ext: '.macho, .dylib, .app, .pkg' },
                    { type: 'Mobile Payloads', ext: '.apk, .dex, .ipa, .aab' },
                    { type: 'Documents & Office', ext: '.pdf, .docx, .xlsx, .rtf, .pptx' },
                    { type: 'Scripts & Macros', ext: '.ps1, .vbs, .bat, .sh, .py, .js' },
                    { type: 'Compressed Archives', ext: '.zip, .7z, .tar, .gz, .rar' },
                    { type: 'Web & Email', ext: '.html, .eml, .msg, .php' },
                  ].map(f => (
                    <div key={f.type} style={{ padding: '12px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.06)' }}>
                      <div className="font-data-mono text-primary" style={{ fontSize: '13px', fontWeight: 600 }}>{f.type}</div>
                      <div className="font-code-sm text-on-surface-variant" style={{ fontSize: '11px', marginTop: '2px' }}>{f.ext}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Section 3 */}
            <div id="malware-handling" className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
              <h2 className="font-headline-sm text-on-surface" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--module-yara)' }}>
                <span className="material-symbols-outlined">bug_report</span>
                3. Live Malware Sample Protocol
              </h2>
              <div className="font-body-md text-on-surface" style={{ lineHeight: '1.7', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <p>
                  Security researchers submitting live malware binaries or zero-day proof-of-concepts should follow industry-standard honeypot conventions:
                </p>
                <ul style={{ paddingLeft: '24px', display: 'flex', flexDirection: 'column', gap: '8px', color: 'var(--on-surface-variant)' }}>
                  <li>Zip archives containing live malware should use the standard industry password <code>infected</code> or <code>clean</code>.</li>
                  <li>Include contextual threat tags (e.g. ransomware family, campaign actor, CVE identifier) in your submission comments.</li>
                  <li>Do not execute or unpack live malicious binaries outside of air-gapped virtualized sandbox environments.</li>
                </ul>
              </div>
            </div>

            {/* Section 4 */}
            <div id="api-etiquette" className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
              <h2 className="font-headline-sm text-on-surface" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--module-yara)' }}>
                <span className="material-symbols-outlined">speed</span>
                4. API Rate Limits & Quota Etiquette
              </h2>
              <div className="font-body-md text-on-surface" style={{ lineHeight: '1.7', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <p>
                  To ensure equitable resource allocation across all threat analysts:
                </p>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px' }}>
                  <div style={{ padding: '14px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
                    <div className="font-label-caps text-on-surface-variant">Rate Limit</div>
                    <div className="font-headline-sm text-on-surface" style={{ fontSize: '18px', marginTop: '4px' }}>4 req / min</div>
                    <div className="font-code-sm text-on-surface-variant" style={{ fontSize: '11px', marginTop: '2px' }}>Public free tier per IP</div>
                  </div>
                  <div style={{ padding: '14px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
                    <div className="font-label-caps text-on-surface-variant">Daily Quota</div>
                    <div className="font-headline-sm text-on-surface" style={{ fontSize: '18px', marginTop: '4px' }}>500 queries / day</div>
                    <div className="font-code-sm text-on-surface-variant" style={{ fontSize: '11px', marginTop: '2px' }}>Reset at 00:00 UTC</div>
                  </div>
                  <div style={{ padding: '14px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
                    <div className="font-label-caps text-on-surface-variant">Backoff Strategy</div>
                    <div className="font-headline-sm text-on-surface" style={{ fontSize: '18px', marginTop: '4px' }}>HTTP 429 Retry</div>
                    <div className="font-code-sm text-on-surface-variant" style={{ fontSize: '11px', marginTop: '2px' }}>Wait 15s before retry</div>
                  </div>
                </div>
                <p>
                  Bulk automated lookups should always query the cryptographic hash first before uploading new file payloads to conserve network bandwidth and improve throughput.
                </p>
              </div>
            </div>

            {/* Section 5 */}
            <div id="community-conduct" className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
              <h2 className="font-headline-sm text-on-surface" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--module-yara)' }}>
                <span className="material-symbols-outlined">forum</span>
                5. Community Comments & Voting Guidelines
              </h2>
              <div className="font-body-md text-on-surface" style={{ lineHeight: '1.7', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <p>
                  Community comments and votes help analysts verify threat context:
                </p>
                <ul style={{ paddingLeft: '24px', display: 'flex', flexDirection: 'column', gap: '8px', color: 'var(--on-surface-variant)' }}>
                  <li><strong className="text-on-surface">Evidence-Based Findings:</strong> Provide actionable context when commenting on reports (e.g. C2 IP addresses, dropped files, malware family, MITRE techniques).</li>
                  <li><strong className="text-on-surface">No Defamatory Claims:</strong> Do not post unsubstantiated accusations against software developers or commercial vendors without technical IOC proof.</li>
                  <li><strong className="text-on-surface">No Spam or Promotional Links:</strong> Commercial advertisements, SEO links, and affiliate spam are purged automatically and result in permanent IP bans.</li>
                </ul>
              </div>
            </div>

            {/* Section 6 */}
            <div id="vendor-whitelisting" className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
              <h2 className="font-headline-sm text-on-surface" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--module-yara)' }}>
                <span className="material-symbols-outlined">verified_user</span>
                6. Developer & Software Vendor Whitelisting
              </h2>
              <div className="font-body-md text-on-surface" style={{ lineHeight: '1.7', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <p>
                  To minimize false positive detections on legitimate software products:
                </p>
                <ol style={{ paddingLeft: '24px', display: 'flex', flexDirection: 'column', gap: '8px', color: 'var(--on-surface-variant)' }}>
                  <li>Digitally sign all software binaries using a valid Extended Validation (EV) Code Signing Certificate from a recognized Certificate Authority.</li>
                  <li>Submit new software releases to ThreatAtlas prior to public distribution so participating antivirus vendors can index clean signatures.</li>
                  <li>In the event of a false positive classification, submit a dispute ticket via the <Link to="/contact" className="text-primary">Support Portal</Link> with hash verification and developer contact details.</li>
                </ol>
              </div>
            </div>

            {/* Section 7 */}
            <div id="zero-tolerance" className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
              <h2 className="font-headline-sm text-on-surface" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--secondary)' }}>
                <span className="material-symbols-outlined text-secondary">dangerous</span>
                7. Zero-Tolerance Violations
              </h2>
              <div className="font-body-md text-on-surface" style={{ lineHeight: '1.7', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <p>
                  Engaging in any of the following activities will result in immediate permanent blocking and referral to competent law enforcement agencies:
                </p>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '12px' }}>
                  <div style={{ padding: '12px', background: 'rgba(255,42,95,0.06)', borderRadius: '6px', border: '1px solid rgba(255,42,95,0.25)' }}>
                    <div className="font-data-mono text-secondary" style={{ fontWeight: 600 }}>DDoS & Infrastructure Attacks</div>
                    <div className="font-code-sm text-on-surface-variant" style={{ fontSize: '11px', marginTop: '2px' }}>Denial-of-service or volumetric floods targeting ThreatAtlas servers or proxy endpoints.</div>
                  </div>
                  <div style={{ padding: '12px', background: 'rgba(255,42,95,0.06)', borderRadius: '6px', border: '1px solid rgba(255,42,95,0.25)' }}>
                    <div className="font-data-mono text-secondary" style={{ fontWeight: 600 }}>Malware Evasion Optimization</div>
                    <div className="font-code-sm text-on-surface-variant" style={{ fontSize: '11px', marginTop: '2px' }}>Automated iterative submissions to verify if newly compiled malware evades antivirus engines.</div>
                  </div>
                  <div style={{ padding: '12px', background: 'rgba(255,42,95,0.06)', borderRadius: '6px', border: '1px solid rgba(255,42,95,0.25)' }}>
                    <div className="font-data-mono text-secondary" style={{ fontWeight: 600 }}>Bulk Intelligence Scraping</div>
                    <div className="font-code-sm text-on-surface-variant" style={{ fontSize: '11px', marginTop: '2px' }}>Unauthorized programmatic data harvesting bypassing API authentication.</div>
                  </div>
                </div>
              </div>
            </div>

          </div>

        </div>

      </div>
    </div>
  );
};
