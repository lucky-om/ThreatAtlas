import React, { useState, useEffect, useRef } from 'react';

interface AiSummaryProps {
  threatData: any;
  type: 'file' | 'ip' | 'domain' | 'url';
}

export const AiSummary: React.FC<AiSummaryProps> = ({ threatData, type }) => {
  const [summary, setSummary] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const contentRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let isMounted = true;

    const fetchSummary = async () => {
      setLoading(true);
      setError(null);
      setSummary('');

      try {
        const prompt = type === 'file' 
          ? `You are an expert cybersecurity analyst. Provide a brief, concise, and highly technical summary of the following file threat report in 3-4 sentences. Do not use conversational filler. Focus on key malicious behaviors, signatures, and risk levels.\n\nData: ${JSON.stringify(threatData)}`
          : type === 'url'
            ? `You are an expert cybersecurity analyst. Provide a brief, concise, and highly technical summary of the following website/URL threat report in 3-4 sentences. Do not use conversational filler. Focus on phishing, malware distribution, or other malicious activities.\n\nData: ${JSON.stringify(threatData)}`
            : `You are an expert cybersecurity analyst. Provide a brief, concise, and highly technical summary of the following IP/Domain threat report in 3-4 sentences. Do not use conversational filler. Focus on network reputation, associated malware, and risk levels.\n\nData: ${JSON.stringify(threatData)}`;

        let response = await fetch('/api/gemini/v1beta/models/gemini-flash-latest:generateContent', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: { maxOutputTokens: 250, temperature: 0.2 },
          })
        });

        // Handle rate limits by retrying once after 5 seconds
        if (response.status === 429) {
          await new Promise(resolve => setTimeout(resolve, 5000));
          response = await fetch('/api/gemini/v1beta/models/gemini-flash-latest:generateContent', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              contents: [{ parts: [{ text: prompt }] }],
              generationConfig: { maxOutputTokens: 250, temperature: 0.2 },
            })
          });
        }

        if (!response.ok) {
          const errorJson = await response.json().catch(() => ({}));
          throw new Error(errorJson?.error?.message || 'Failed to generate AI summary.');
        }

        const result = await response.json();
        const text = result.candidates?.[0]?.content?.parts?.[0]?.text || 'No summary available.';
        
        if (isMounted) {
          setSummary(text);
        }
      } catch (err: any) {
        if (isMounted) setError(err.message);
      } finally {
        if (isMounted) setLoading(false);
      }
    };

    fetchSummary();

    return () => { isMounted = false; };
  }, [threatData, type]);

  // Typewriter effect
  useEffect(() => {
    if (summary && contentRef.current) {
      contentRef.current.textContent = '';
      let i = 0;
      const typeWriter = setInterval(() => {
        if (contentRef.current && i < summary.length) {
          contentRef.current.textContent += summary.charAt(i);
          i++;
        } else {
          clearInterval(typeWriter);
        }
      }, 15);
      return () => clearInterval(typeWriter);
    }
  }, [summary]);

  return (
    <div className="glass-card animate-fade-in-up" style={{ padding: '24px', borderColor: 'var(--primary)', position: 'relative', overflow: 'hidden' }}>
      <div className="glow-cyan" style={{ opacity: 0.2, top: '-50%', left: '-50%', width: '200%', height: '200%' }}></div>
      <div style={{ position: 'relative', zIndex: 1 }}>
        <h3 className="font-label-caps text-primary" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>psychology</span>
          Neural-X AI Analysis
        </h3>
        
        {loading ? (
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center', color: 'var(--on-surface-variant)' }}>
            <span className="material-symbols-outlined spin" style={{ fontSize: '16px' }}>sync</span>
            <span className="font-code-sm">Generating intelligent summary...</span>
          </div>
        ) : error ? (
          <div className="font-code-sm text-secondary">
            [SYS_ERR]: AI subsystem offline. {error}
          </div>
        ) : (
          <div 
            ref={contentRef} 
            className="font-code-sm text-on-surface" 
            style={{ 
              lineHeight: '1.6', 
              whiteSpace: 'pre-wrap', 
              borderLeft: '2px solid var(--primary)', 
              paddingLeft: '16px' 
            }}
          >
            {/* Typewriter fills this */}
          </div>
        )}
      </div>
    </div>
  );
};
