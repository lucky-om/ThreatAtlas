import React from 'react';

export const Rules: React.FC = () => {
  return (
    <div className="container" style={{ paddingTop: '8rem', paddingBottom: '4rem', maxWidth: '800px', margin: '0 auto' }}>
      <h1>Rules & Regulations</h1>
      
      <div className="card" style={{ marginTop: '2rem' }}>
        <h3>API Usage Guidelines</h3>
        <ul style={{ paddingLeft: '1.5rem', marginTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          <li><strong>Rate Limiting:</strong> Standard API requests are limited based on your provider's tier (e.g., VirusTotal free tier limits to 4 requests per minute).</li>
          <li><strong>File Size:</strong> Direct uploads are strictly limited to 32MB.</li>
          <li><strong>Authentication:</strong> All backend requests must be properly authenticated using a valid API key. Unauthorized requests will be rejected.</li>
          <li><strong>Prohibited Content:</strong> Do not upload classified, proprietary, or highly confidential company data, as it will be shared with the broader security community.</li>
        </ul>
      </div>
    </div>
  );
};
