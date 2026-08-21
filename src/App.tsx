import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { AuthModal } from './components/AuthModal';
import { Navbar } from './components/Navbar';
import { Footer } from './components/Footer';
import { AiChatbot } from './components/AiChatbot';
import { Home } from './pages/Home';
import { Results } from './pages/Results';
import { IpLookup } from './pages/IpLookup';
import { About } from './pages/About';
import { Privacy } from './pages/Privacy';
import { Terms } from './pages/Terms';
import { Rules } from './pages/Rules';
import { Contact } from './pages/Contact';

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <BrowserRouter>
        <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh', position: 'relative' }}>
          <Navbar />
          <main style={{ flex: 1 }}>
            <Routes>
              {/* Primary 3 VirusTotal Views */}
              <Route path="/" element={<Home initialTab="file" />} />
              <Route path="/file" element={<Home initialTab="file" />} />
              <Route path="/gui/home/upload" element={<Home initialTab="file" />} />

              <Route path="/url" element={<Home initialTab="url" />} />
              <Route path="/url-scan" element={<Home initialTab="url" />} />
              <Route path="/webscan" element={<Home initialTab="url" />} />
              <Route path="/gui/home/url" element={<Home initialTab="url" />} />

              <Route path="/search" element={<Home initialTab="search" />} />
              <Route path="/lookup" element={<Home initialTab="search" />} />
              <Route path="/ip-lookup" element={<Home initialTab="search" />} />
              <Route path="/gui/home/search" element={<Home initialTab="search" />} />

              {/* Analysis Results */}
              <Route path="/file/:hash/:tab?" element={<Results />} />
              <Route path="/url/:id/:tab?" element={<Results />} />
              <Route path="/domain/:query/:tab?" element={<Results />} />
              <Route path="/ip-address/:query/:tab?" element={<IpLookup />} />

              {/* Information & Legal */}
              <Route path="/about" element={<About />} />
              <Route path="/privacy" element={<Privacy />} />
              <Route path="/terms" element={<Terms />} />
              <Route path="/rules" element={<Rules />} />
              <Route path="/contact" element={<Contact />} />

              <Route path="*" element={
                <div className="container" style={{ paddingTop: '8rem', textAlign: 'center', minHeight: '60vh' }}>
                  <h1>404 - Not Found</h1>
                  <p>The page you are looking for does not exist.</p>
                </div>
              } />
            </Routes>
          </main>
          <Footer />
          {/* Global Floating AI Security Chatbot */}
          <AiChatbot />
          {/* Global User Authentication Modal with OTP 2FA */}
          <AuthModal />
        </div>
      </BrowserRouter>
    </AuthProvider>
  );
};
