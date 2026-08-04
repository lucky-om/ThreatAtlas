import React from 'react';

export const Privacy: React.FC = () => {
  return (
    <div className="container" style={{ paddingTop: '8rem', paddingBottom: '4rem', maxWidth: '800px', margin: '0 auto' }}>
      <h1>Privacy Policy</h1>
      
      <div className="card" style={{ marginTop: '2rem' }}>
        <h3>1. Information We Collect</h3>
        <p>We collect information you provide directly to us when using the ThreatAtlas service, including uploaded files, URLs, domains, and IP addresses submitted for scanning.</p>
        
        <h3 style={{ marginTop: '2rem' }}>2. How We Use Information</h3>
        <p>Submitted data is passed to third-party threat intelligence providers (such as VirusTotal) to generate analysis reports. We do not permanently store your uploaded files.</p>
        
        <h3 style={{ marginTop: '2rem' }}>3. Data Security</h3>
        <p>We implement reasonable security measures to protect your data, but please be aware that no transmission over the internet is completely secure. Do not upload sensitive or personally identifiable information.</p>
      </div>
    </div>
  );
};
