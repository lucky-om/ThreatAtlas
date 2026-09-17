import React from 'react';
import { Helmet } from 'react-helmet-async';

interface SEOProps {
  title?: string;
  description?: string;
  type?: 'website' | 'article' | 'webapp';
  path?: string;
}

export const SEO: React.FC<SEOProps> = ({ 
  title = 'ThreatAtlas', 
  description = 'ThreatAtlas provides real-time threat intelligence by analyzing files, URLs, domains, and IPs across 70+ engines with YARA, PhishGuard, and WebFox.',
  type = 'website',
  path = ''
}) => {
  const domain = 'https://threatatlas.luckyverse.tech';
  const canonicalUrl = `${domain}${path}`;
  const fullTitle = title === 'ThreatAtlas' ? title : `${title} | ThreatAtlas`;

  // Local Business / Software App Schema
  const structuredData = {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    "name": "ThreatAtlas",
    "applicationCategory": "SecurityApplication",
    "operatingSystem": "Web",
    "description": description,
    "url": domain,
    "offers": {
      "@type": "Offer",
      "price": "0",
      "priceCurrency": "USD"
    }
  };

  return (
    <Helmet>
      <title>{fullTitle}</title>
      <meta name="description" content={description} />
      <link rel="canonical" href={canonicalUrl} />
      
      {/* Open Graph */}
      <meta property="og:title" content={fullTitle} />
      <meta property="og:description" content={description} />
      <meta property="og:type" content={type} />
      <meta property="og:url" content={canonicalUrl} />
      
      {/* Twitter */}
      <meta name="twitter:title" content={fullTitle} />
      <meta name="twitter:description" content={description} />
      
      {/* Structured Data */}
      <script type="application/ld+json">
        {JSON.stringify(structuredData)}
      </script>
    </Helmet>
  );
};
