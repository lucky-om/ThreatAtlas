import React, { useState } from 'react';

export const Contact: React.FC = () => {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [category, setCategory] = useState('general');
  const [subject, setSubject] = useState('');
  const [message, setMessage] = useState('');
  const [submitted, setSubmitted] = useState(false);
  const [sending, setSending] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name || !email || !message) return;
    setSending(true);
    setTimeout(() => {
      setSending(false);
      setSubmitted(true);
    }, 600);
  };

  const resetForm = () => {
    setName('');
    setEmail('');
    setCategory('general');
    setSubject('');
    setMessage('');
    setSubmitted(false);
  };

  return (
    <div className="module-page">
      <div className="digital-grid" />
      <div style={{ position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 0, background: 'radial-gradient(circle at 50% 30%, rgba(185,66,255,0.06) 0%, transparent 60%)' }} />

      <div className="container" style={{ position: 'relative', zIndex: 10, maxWidth: '1000px', width: '100%' }}>
        
        {/* Header */}
        <div className="module-hero">
          <div className="module-badge" style={{ background: 'rgba(185,66,255,0.12)', border: '1px solid rgba(185,66,255,0.3)', color: 'var(--primary)' }}>
            <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>support_agent</span>
            Support & Inquiries
          </div>
          <h1 className="font-display-lg text-on-surface" style={{ fontSize: '46px', marginBottom: '12px' }}>
            Contact <span className="text-primary">ThreatAtlas</span> Team
          </h1>
          <p className="font-body-md text-on-surface-variant" style={{ maxWidth: '600px', margin: '0 auto' }}>
            Have a question, feedback, feature request, or false positive to report? Get in touch directly with our security engineering team.
          </p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '32px', alignItems: 'flex-start' }}>
          
          {/* Left: Contact Form */}
          <div className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
            {submitted ? (
              <div style={{ textAlign: 'center', padding: '32px 16px' }}>
                <div style={{ width: '64px', height: '64px', borderRadius: '50%', background: 'rgba(0,255,163,0.12)', border: '1px solid var(--success)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 20px', color: 'var(--success)' }}>
                  <span className="material-symbols-outlined" style={{ fontSize: '32px' }}>check_circle</span>
                </div>
                <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '8px' }}>Message Received!</h3>
                <p className="font-body-md text-on-surface-variant" style={{ marginBottom: '24px' }}>
                  Thank you for reaching out. Your ticket has been logged and our team will review it shortly.
                </p>
                <button
                  onClick={resetForm}
                  className="btn-primary"
                  style={{ padding: '10px 24px', fontSize: '13px' }}
                >
                  Send Another Message
                </button>
              </div>
            ) : (
              <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '4px' }}>Submit an Inquiry</h3>
                
                <div>
                  <label className="font-label-caps text-on-surface-variant" style={{ display: 'block', marginBottom: '8px' }}>Full Name *</label>
                  <input
                    type="text"
                    required
                    className="input-field font-data-mono"
                    placeholder="e.g. Alex Mercer"
                    value={name}
                    onChange={e => setName(e.target.value)}
                    style={{ width: '100%', padding: '12px 16px', fontSize: '14px' }}
                  />
                </div>

                <div>
                  <label className="font-label-caps text-on-surface-variant" style={{ display: 'block', marginBottom: '8px' }}>Email Address *</label>
                  <input
                    type="email"
                    required
                    className="input-field font-data-mono"
                    placeholder="alex@company.com"
                    value={email}
                    onChange={e => setEmail(e.target.value)}
                    style={{ width: '100%', padding: '12px 16px', fontSize: '14px' }}
                  />
                </div>

                <div>
                  <label className="font-label-caps text-on-surface-variant" style={{ display: 'block', marginBottom: '8px' }}>Inquiry Category</label>
                  <select
                    className="input-field font-data-mono"
                    value={category}
                    onChange={e => setCategory(e.target.value)}
                    style={{ width: '100%', padding: '12px 16px', fontSize: '14px', background: 'var(--surface-elevated)', color: 'var(--on-surface)' }}
                  >
                    <option value="general">General Inquiry / Feedback</option>
                    <option value="false_positive">False Positive Report</option>
                    <option value="technical">Technical Support & Analysis</option>
                    <option value="feature">Feature Request / Suggestion</option>
                    <option value="security">Security Vulnerability Report</option>
                  </select>
                </div>

                <div>
                  <label className="font-label-caps text-on-surface-variant" style={{ display: 'block', marginBottom: '8px' }}>Subject</label>
                  <input
                    type="text"
                    className="input-field font-data-mono"
                    placeholder="Brief summary of your inquiry"
                    value={subject}
                    onChange={e => setSubject(e.target.value)}
                    style={{ width: '100%', padding: '12px 16px', fontSize: '14px' }}
                  />
                </div>

                <div>
                  <label className="font-label-caps text-on-surface-variant" style={{ display: 'block', marginBottom: '8px' }}>Message / Details *</label>
                  <textarea
                    required
                    rows={5}
                    className="input-field font-data-mono"
                    placeholder="Please include relevant artifact hashes, URLs, domain names, or system logs if applicable..."
                    value={message}
                    onChange={e => setMessage(e.target.value)}
                    style={{ width: '100%', padding: '14px 16px', fontSize: '13px', resize: 'vertical' }}
                  />
                </div>

                <button
                  type="submit"
                  disabled={sending}
                  className="btn-primary"
                  style={{ width: '100%', padding: '14px', fontSize: '14px', marginTop: '8px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}
                >
                  {sending ? (
                    <>
                      <span className="material-symbols-outlined spin" style={{ fontSize: '18px' }}>sync</span>
                      Submitting...
                    </>
                  ) : (
                    <>
                      <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>send</span>
                      Send Message
                    </>
                  )}
                </button>
              </form>
            )}
          </div>

          {/* Right: Quick Info & Direct Channels */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            
            <div className="glass-card animate-fade-in-up" style={{ padding: '24px' }}>
              <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span className="material-symbols-outlined" style={{ fontSize: '16px', color: 'var(--primary)' }}>help_center</span>
                Frequently Asked
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div>
                  <div className="font-data-mono text-on-surface" style={{ fontSize: '13px', fontWeight: 600, marginBottom: '4px' }}>How do I configure my VirusTotal API Key?</div>
                  <div className="font-code-sm text-on-surface-variant" style={{ fontSize: '12px' }}>
                    Add your free or enterprise API key into the <code>.env</code> file under <code>VT_API_KEY</code>. The backend server automatically proxies and injects your key.
                  </div>
                </div>
                <div>
                  <div className="font-data-mono text-on-surface" style={{ fontSize: '13px', fontWeight: 600, marginBottom: '4px' }}>Reporting a False Positive?</div>
                  <div className="font-code-sm text-on-surface-variant" style={{ fontSize: '12px' }}>
                    Select "False Positive Report" in the category dropdown above and provide the SHA-256 hash or domain along with proof of legitimate origin.
                  </div>
                </div>
                <div>
                  <div className="font-data-mono text-on-surface" style={{ fontSize: '13px', fontWeight: 600, marginBottom: '4px' }}>Is my uploaded data public?</div>
                  <div className="font-code-sm text-on-surface-variant" style={{ fontSize: '12px' }}>
                    Files and URLs scanned via VirusTotal become part of the global threat intelligence ecosystem to help the cybersecurity community detect zero-days.
                  </div>
                </div>
              </div>
            </div>

            <div className="glass-card animate-fade-in-up" style={{ padding: '24px' }}>
              <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span className="material-symbols-outlined" style={{ fontSize: '16px', color: 'var(--success)' }}>hub</span>
                Direct Channels
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span className="material-symbols-outlined text-primary" style={{ fontSize: '20px' }}>mail</span>
                  <div>
                    <div className="font-data-mono text-on-surface" style={{ fontSize: '13px' }}>Email Support</div>
                    <div className="font-code-sm text-on-surface-variant" style={{ fontSize: '12px' }}>security@threatatlas.local</div>
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span className="material-symbols-outlined text-primary" style={{ fontSize: '20px' }}>code</span>
                  <div>
                    <div className="font-data-mono text-on-surface" style={{ fontSize: '13px' }}>GitHub Issues</div>
                    <div className="font-code-sm text-on-surface-variant" style={{ fontSize: '12px' }}>github.com/lucky-om/ThreatAtlas</div>
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span className="material-symbols-outlined text-primary" style={{ fontSize: '20px' }}>shield</span>
                  <div>
                    <div className="font-data-mono text-on-surface" style={{ fontSize: '13px' }}>Security Team</div>
                    <div className="font-code-sm text-on-surface-variant" style={{ fontSize: '12px' }}>intel-response@threatatlas.local</div>
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
