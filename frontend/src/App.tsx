import React, { useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useLocation, useParams } from 'react-router-dom';
import { AnimatePresence } from 'framer-motion';
import { HelmetProvider } from 'react-helmet-async';
import { Navbar } from './components/Navbar';
import { Footer } from './components/Footer';
import { AiChatbot } from './components/AiChatbot';
import { ScrollToTopButton } from './components/ScrollToTop';
import { ParticleField } from './components/ParticleField';
import { MountainLoader } from './components/MountainLoader';

// Pages
import { Home } from './pages/Home';
import { FileScan } from './pages/FileScan';
import { UrlScanPage } from './pages/UrlScanPage';
import { SearchPage } from './pages/SearchPage';
import { Results } from './pages/Results';
import { IpLookup } from './pages/IpLookup';
import { ThreatGraph } from './pages/ThreatGraph';
import { IocHunter } from './pages/IocHunter';
import { YaraScanner } from './pages/YaraScanner';
import { WebScan } from './pages/WebScan';
import { About } from './pages/About';
import { Privacy } from './pages/Privacy';
import { Terms } from './pages/Terms';
import { Rules } from './pages/Rules';
import { Contact } from './pages/Contact';
import { NotFound } from './pages/NotFound';
import { ErrorBoundary } from './components/ErrorBoundary';

// IP redirect: /ip/:query → /ip-address/:query
const IpRedirect: React.FC = () => {
  const { query, tab } = useParams<{ query: string; tab?: string }>();
  return <Navigate to={tab ? `/ip-address/${query}/${tab}` : `/ip-address/${query}`} replace />;
};

const ScrollToTop = () => {
  const { pathname } = useLocation();
  React.useEffect(() => { window.scrollTo(0, 0); }, [pathname]);
  return null;
};

const AnimatedRoutes = () => {
  const location = useLocation();
  return (
    <AnimatePresence mode="wait">
      <Routes location={location} key={location.pathname}>
      {/* ── Primary 3 Scanner Pages ── */}
      <Route path="/"          element={<Home />} />
      <Route path="/file"      element={<FileScan />} />
      <Route path="/url"       element={<UrlScanPage />} />
      <Route path="/search"    element={<SearchPage />} />
        <Route path="/lookup"    element={<Navigate to="/search" replace />} />

        {/* ── Legacy redirects ── */}
        <Route path="/gui/home/upload" element={<Navigate to="/file" replace />} />
        <Route path="/gui/home/url"    element={<Navigate to="/url" replace />} />
        <Route path="/gui/home/search" element={<Navigate to="/search" replace />} />
        <Route path="/url-scan"        element={<Navigate to="/url" replace />} />

        {/* ── Dedicated Tool Pages ── */}
        <Route path="/webscan"       element={<WebScan />} />
        <Route path="/threat-graph"  element={<ThreatGraph />} />
        <Route path="/ioc-hunter"    element={<IocHunter />} />
        <Route path="/hunter"        element={<Navigate to="/ioc-hunter" replace />} />
        <Route path="/yara"          element={<YaraScanner />} />
        <Route path="/yara-scanner"  element={<Navigate to="/yara" replace />} />

        {/* ── IP Intelligence ── */}
        <Route path="/ip-intelligence" element={<IpLookup />} />
        <Route path="/ip-lookup"       element={<Navigate to="/ip-intelligence" replace />} />

        {/* ── Analysis Results ── */}
        <Route path="/file/:hash/:tab?"        element={<Results />} />
        <Route path="/file/*"                  element={<Results />} />
        <Route path="/url/:id/:tab?"           element={<Results />} />
        <Route path="/domain/:query/:tab?"     element={<Results />} />
        <Route path="/ip-address/:query/:tab?" element={<Results />} />
        <Route path="/ip/:query/:tab?"         element={<IpRedirect />} />

        {/* ── Legal / Info ── */}
        <Route path="/about"   element={<About />} />
        <Route path="/privacy" element={<Privacy />} />
        <Route path="/terms"   element={<Terms />} />
        <Route path="/rules"   element={<Rules />} />
        <Route path="/contact" element={<Contact />} />

        {/* ── 404 ── */}
        <Route path="*" element={<NotFound />} />
      </Routes>
    </AnimatePresence>
  );
};

export const App: React.FC = () => {
  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      const glow = document.getElementById('ambient-glow');
      if (glow) {
        // Calculate relative position 0 to 1
        const x = e.clientX / window.innerWidth;
        const y = e.clientY / window.innerHeight;
        glow.style.background = `radial-gradient(circle at ${x * 100}% ${y * 100}%, rgba(232, 25, 44, 0.15) 0%, rgba(232, 25, 44, 0.02) 40%, transparent 60%)`;
      }
    };
    window.addEventListener('mousemove', handleMouseMove);
    return () => window.removeEventListener('mousemove', handleMouseMove);
  }, []);

  return (
    <HelmetProvider>
      <BrowserRouter>
        <ScrollToTop />

        {/* Global background layers */}
        <div className="mountain-bg" aria-hidden="true" />
        <div className="vignette-overlay" aria-hidden="true" />
        <div className="ambient-glow" aria-hidden="true" id="ambient-glow" />
        <div className="grain-overlay" aria-hidden="true" />

        {/* Ember watermark */}
        <div style={{ position: 'fixed', bottom: -140, left: '50%', transform: 'translateX(-50%) scale(2)', opacity: 0.04, zIndex: 0, pointerEvents: 'none' }}>
          <MountainLoader />
        </div>

        {/* Floating ember particles */}
        <ParticleField count={28} />

        <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh', position: 'relative', zIndex: 1 }}>
          <Navbar />
          <main style={{ flex: 1 }}>
            <ErrorBoundary>
              <AnimatedRoutes />
            </ErrorBoundary>
          </main>
          <Footer />
          <AiChatbot />
          <ScrollToTopButton />
        </div>
      </BrowserRouter>
    </HelmetProvider>
  );
};
