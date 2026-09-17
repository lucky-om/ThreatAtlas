import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { MagneticButton } from '../components/MagneticButton';
import { PageReveal } from '../components/PageReveal';
import { TiltWrapper } from '../components/TiltWrapper';
import { SEO } from '../components/SEO';

const FEATURES = [
  {
    icon: 'search_check',
    title: 'Multi-AV File Scanning',
    desc: 'Submit files up to 32MB. We dynamically query VirusTotal and MalwareBazaar to cross-reference against 70+ AV engines.',
    path: '/file',
    color: 'var(--brand)',
    bg: 'var(--brand-dim)'
  },
  {
    icon: 'language',
    title: 'Web & URL Intelligence',
    desc: 'Analyze domains and URLs. Powered by PhishGuard, URLhaus, and our proprietary WebFox engine for deep DNS & TLS recon.',
    path: '/url',
    color: 'var(--module-webscan)',
    bg: 'var(--module-webscan-dim)'
  },
  {
    icon: 'radar',
    title: 'IP & Infrastructure',
    desc: 'Lookup IPv4/IPv6 addresses to identify malicious nodes, telecom carriers, and associated malware campaigns.',
    path: '/search',
    color: 'var(--module-ioc)',
    bg: 'var(--module-ioc-dim)'
  },
  {
    icon: 'search_insights',
    title: 'YARA Pattern Engine',
    desc: 'Test custom YARA signatures directly in your browser against live text or real threat telemetry attributes.',
    path: '/yara',
    color: 'var(--module-yara)',
    bg: 'var(--module-yara-dim)'
  },
  {
    icon: 'hub',
    title: 'Threat Graph',
    desc: 'Visualize complex relationships between IPs, domains, and files. Uncover complete adversarial infrastructure visually.',
    path: '/threat-graph',
    color: 'var(--status-malicious)',
    bg: 'var(--status-mal-dim)'
  },
  {
    icon: 'smart_toy',
    title: 'Atlas AI',
    desc: 'Chat with our advanced threat analyst AI. It summarizes findings, reverse-engineers scripts, and creates YARA rules on the fly.',
    path: '#',
    color: 'var(--brand-ember)',
    bg: 'var(--amber-dim)'
  }
];

export const Home: React.FC = () => {
  return (
    <>
      <SEO
        title="ThreatAtlas — Threat Intelligence & Malware Analysis"
        description="Cross-reference IPs, domains, files, and URLs against 7 integrated security engines in real-time."
        path="/"
      />
      <div className="module-page" style={{ paddingTop: '80px', paddingBottom: '80px' }}>
        <div className="container" style={{ position: 'relative', zIndex: 10, maxWidth: '1200px', width: '100%' }}>
          <PageReveal>

            {/* Hero Section */}
            <div style={{ textAlign: 'center', marginBottom: '80px', marginTop: '40px' }}>
              <motion.div
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.5, ease: "easeOut" }}
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: '8px',
                  padding: '6px 16px', marginBottom: '24px',
                  background: 'var(--brand-dim)', border: '1px solid var(--border)',
                  borderRadius: '999px',
                }}
              >
                <span className="material-symbols-outlined" style={{ fontSize: '14px', color: 'var(--brand)' }}>bolt</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', fontWeight: 700, color: 'var(--brand)', letterSpacing: '0.14em' }}>
                  THREATATLAS ENGINE V2.0
                </span>
              </motion.div>

              <h1 style={{
                fontFamily: "'Space Grotesk', sans-serif",
                fontSize: 'clamp(32px, 5vw, 64px)',
                fontWeight: 800,
                lineHeight: 1.05,
                letterSpacing: '-0.03em',
                color: 'var(--on-surface)',
                marginBottom: '16px',
              }}>
                <span style={{ color: 'var(--brand)' }}>Threat</span> Intelligence & <span style={{ color: 'var(--brand)' }}>Malware</span> Analysis
              </h1>

              <p style={{
                fontFamily: 'var(--font-sans)',
                fontSize: '18px',
                color: 'var(--on-surface-2)',
                maxWidth: '700px',
                margin: '0 auto',
                lineHeight: 1.6,
                marginBottom: '40px'
              }}>
                ThreatAtlas is an advanced security intelligence platform. We combine 70+ AV engines, YARA rules, and deep forensic metadata extraction to help SOC analysts and researchers dissect malware, network infrastructure, and evasive payloads faster.
              </p>

              <div style={{ display: 'flex', gap: '16px', justifyContent: 'center', flexWrap: 'wrap' }}>
                <Link to="/file" style={{ textDecoration: 'none' }}>
                  <MagneticButton
                    magneticPull={0.2}
                    style={{
                      display: 'flex', alignItems: 'center', gap: '10px',
                      background: 'var(--brand)', color: '#fff',
                      border: 'none', borderRadius: '12px',
                      padding: '14px 28px',
                      fontFamily: 'var(--font-sans)', fontSize: '15px', fontWeight: 600,
                      cursor: 'pointer',
                      boxShadow: '0 0 20px var(--brand-glow)',
                    }}
                  >
                    <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>rocket_launch</span>
                    START ANALYZING
                  </MagneticButton>
                </Link>
                <a href="#features" style={{ textDecoration: 'none' }}>
                  <MagneticButton
                    magneticPull={0.15}
                    style={{
                      display: 'flex', alignItems: 'center', gap: '10px',
                      background: 'var(--surface-2)', color: 'var(--on-surface)',
                      border: '1px solid var(--border-subtle)', borderRadius: '12px',
                      padding: '14px 28px',
                      fontFamily: 'var(--font-sans)', fontSize: '15px', fontWeight: 600,
                      cursor: 'pointer',
                    }}
                  >
                    LEARN MORE
                  </MagneticButton>
                </a>
              </div>
            </div>

            {/* Features Bento Grid */}
            <motion.div
              initial="hidden"
              whileInView="visible"
              viewport={{ once: true, margin: "-100px" }}
              variants={{
                hidden: { opacity: 0 },
                visible: {
                  opacity: 1,
                  transition: { staggerChildren: 0.15 }
                }
              }}
              id="features"
              style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '24px' }}
            >
              {FEATURES.map((feature, i) => {
                const isAi = feature.title === 'Atlas AI Copilot';

                const cardContent = (
                  <div style={{ padding: '32px', height: '100%', display: 'flex', flexDirection: 'column' }}>
                    <div style={{
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      width: '48px', height: '48px', borderRadius: '12px',
                      background: feature.bg, color: feature.color,
                      marginBottom: '20px'
                    }}>
                      <span className="material-symbols-outlined" style={{ fontSize: '24px' }}>{feature.icon}</span>
                    </div>
                    <h3 style={{
                      fontFamily: 'var(--font-headline)', fontSize: '20px', fontWeight: 600,
                      color: 'var(--on-surface)', marginBottom: '12px', letterSpacing: '-0.01em'
                    }}>
                      {feature.title}
                    </h3>
                    <p style={{
                      fontFamily: 'var(--font-sans)', fontSize: '14px', color: 'var(--on-surface-3)',
                      lineHeight: 1.6, flex: 1
                    }}>
                      {feature.desc}
                    </p>

                    <div style={{ marginTop: 'auto', paddingTop: '24px' }}>
                      <motion.div
                        whileHover={{ x: 8 }}
                        transition={{ type: "spring", stiffness: 400, damping: 25 }}
                        style={{
                          display: 'inline-flex', alignItems: 'center', gap: '8px',
                          fontFamily: 'var(--font-mono)', fontSize: '12px', fontWeight: 600,
                          color: '#fff', background: feature.bg, padding: '8px 16px', borderRadius: '8px',
                          border: `1px solid ${feature.color}`
                        }}
                      >
                        LAUNCH MODULE
                        <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>arrow_forward</span>
                      </motion.div>
                    </div>
                  </div>
                );

                const Wrapper = ({ children }: { children: React.ReactNode }) => (
                  <TiltWrapper
                    maxRotation={3}
                    scaleOnHover={1.02}
                    className="feature-card"
                    style={{ height: '100%' }}
                  >
                    {children}
                  </TiltWrapper>
                );

                return (
                  <motion.div
                    key={i}
                    variants={{
                      hidden: { opacity: 0, y: 30, scale: 0.95 },
                      visible: { opacity: 1, y: 0, scale: 1, transition: { type: "spring", stiffness: 100, damping: 20 } }
                    }}
                    style={{ height: '100%' }}
                  >
                    {isAi ? (
                      <div onClick={() => window.dispatchEvent(new Event('open-ai-chat'))} style={{ cursor: 'pointer', height: '100%', display: 'block' }}>
                        <Wrapper>{cardContent}</Wrapper>
                      </div>
                    ) : (
                      <Link to={feature.path} style={{ textDecoration: 'none', display: 'block', height: '100%' }}>
                        <Wrapper>{cardContent}</Wrapper>
                      </Link>
                    )}
                  </motion.div>
                );
              })}
            </motion.div>

          </PageReveal>
        </div>
      </div>
    </>
  );
};
