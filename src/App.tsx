import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Navbar } from './components/Navbar';
import { Footer } from './components/Footer';
import { Home } from './pages/Home';
import { Results } from './pages/Results';
import { Lookup } from './pages/Lookup';
import { About } from './pages/About';
import { Privacy } from './pages/Privacy';
import { Terms } from './pages/Terms';

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
        <Navbar />
        <main style={{ flex: 1 }}>
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/file/:hash/:tab?" element={<Results />} />
            <Route path="/url/:id/:tab?" element={<Results />} />
            <Route path="/results" element={<Results />} />
            <Route path="/domain/:query/:tab?" element={<Lookup type="domain" />} />
            <Route path="/ip-address/:query/:tab?" element={<Lookup type="ip" />} />
            <Route path="/lookup" element={<Lookup />} />
            <Route path="/about" element={<About />} />
            <Route path="/privacy" element={<Privacy />} />
            <Route path="/terms" element={<Terms />} />
            <Route path="*" element={
              <div className="container" style={{ paddingTop: '8rem', textAlign: 'center', minHeight: '60vh' }}>
                <h1>404 - Not Found</h1>
                <p>The page you are looking for does not exist.</p>
              </div>
            } />
          </Routes>
        </main>
        <Footer />
      </div>
    </BrowserRouter>
  );
};
