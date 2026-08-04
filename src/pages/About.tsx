import React from 'react';

export const About: React.FC = () => {
  return (
    <div className="container" style={{ paddingTop: '8rem', paddingBottom: '4rem', maxWidth: '800px', margin: '0 auto' }}>
      <h1>About ThreatAtlas</h1>
      <p style={{ color: 'var(--text-secondary)', fontSize: '1.1rem', marginBottom: '2rem' }}>
        ThreatAtlas is a modern, responsive web application designed for security professionals to analyze threats in real-time.
      </p>
      
      <div className="card" style={{ marginBottom: '2rem' }}>
        <h2 style={{ borderBottom: '1px solid var(--border)', paddingBottom: '1rem', marginBottom: '1.5rem' }}>Our Mission</h2>
        <p>
          We aim to provide comprehensive threat intelligence tools that are accessible, secure, and easy to use. By aggregating data from multiple antivirus engines and threat intelligence feeds, we help you make informed decisions about files, domains, and IP addresses.
        </p>
      </div>

      <div className="card" id="api">
        <h2 style={{ borderBottom: '1px solid var(--border)', paddingBottom: '1rem', marginBottom: '1.5rem' }}>API Access</h2>
        <p>
          ThreatAtlas uses external threat intelligence providers (like VirusTotal and ip-api). To use our platform, a valid API key must be configured in the backend proxy. 
        </p>
        <p>
          Please ensure your API key is correctly set up. A <code>401 Unauthorized</code> error during scans indicates an invalid or missing API key. Note: Gemini API keys will not work for VirusTotal endpoints.
        </p>
      </div>
    </div>
  );
};
