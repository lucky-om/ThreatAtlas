import React from 'react';

export const Terms: React.FC = () => {
  return (
    <div className="container" style={{ paddingTop: '8rem', paddingBottom: '4rem', maxWidth: '800px', margin: '0 auto' }}>
      <h1>Terms of Service</h1>
      
      <div className="card" style={{ marginTop: '2rem' }}>
        <h3>1. Acceptance of Terms</h3>
        <p>By accessing or using ThreatAtlas, you agree to be bound by these Terms of Service. If you do not agree to all terms, do not use our services.</p>
        
        <h3 style={{ marginTop: '2rem' }}>2. Acceptable Use</h3>
        <p>You agree not to use the service for any unlawful purpose or in any way that could damage, disable, overburden, or impair the service. Automated scraping or abusive usage is strictly prohibited.</p>
        
        <h3 style={{ marginTop: '2rem' }}>3. Disclaimer of Warranties</h3>
        <p>The service is provided "as is" and "as available". We do not warrant the accuracy, completeness, or usefulness of the threat intelligence data provided. You rely on such information strictly at your own risk.</p>
      </div>
    </div>
  );
};
