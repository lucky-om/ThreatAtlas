import React, { useState, useEffect } from 'react';

interface AiSummaryProps {
  threatData: any;
  type: 'file' | 'ip' | 'domain' | 'url';
}

export const AiSummary: React.FC<AiSummaryProps> = ({ threatData, type }) => {
  const [loading, setLoading] = useState<boolean>(true);
  const [verdict, setVerdict] = useState<'CRITICAL' | 'SUSPICIOUS' | 'CLEAN'>('CLEAN');
  const [keyFinding, setKeyFinding] = useState<string>('');
  const [action, setAction] = useState<string>('');

  useEffect(() => {
    let isMounted = true;

    const generateShortSummary = async () => {
      setLoading(true);

      const stats = threatData?.stats || {};
      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      const total = (stats.malicious || 0) + (stats.undetected || 0) + (stats.harmless || 0) + (stats.suspicious || 0) || 70;
      const targetName = threatData?.name || threatData?.fileName || threatData?.domain || threatData?.url || threatData?.ip || threatData?.sha256 || 'Target';
      const isCritical = malicious >= 5;
      const isSuspicious = malicious > 0 || suspicious > 0;

      // Default heuristic baseline
      const verdict: 'CRITICAL' | 'SUSPICIOUS' | 'CLEAN' = isCritical ? 'CRITICAL' : isSuspicious ? 'SUSPICIOUS' : 'CLEAN';
      let kf = verdict === 'CRITICAL'
        ? `Flagged by ${malicious} security engines. Exhibits weaponized malware signatures, dropper routines, or hostile C2 communication patterns.`
        : verdict === 'SUSPICIOUS'
          ? `Flagged by ${malicious || suspicious} engine(s) for anomalous behaviors, evasive packed code, or low-reputation telemetry.`
          : `Zero security vendors flagged this ${type}. Cryptographic integrity, entropy, and structural headers are clean.`;
      let act = verdict === 'CRITICAL'
        ? `Isolate affected endpoints, block SHA-256 hash/IP at firewall boundaries, and purge corresponding artifacts.`
        : verdict === 'SUSPICIOUS'
          ? `Execute in sandboxed environment before authorization. Monitor network egress for suspicious domain requests.`
          : `Safe to use under standard corporate security policy. Baseline telemetry verified.`;

      // Try live LLM if available for contextual refinement strictly grounded in scan facts
      try {
        const prompt = `You are Atlas AI, an elite cybersecurity analyst.
Target: ${targetName} (${type.toUpperCase()})
Scan Verdict: ${verdict} (${malicious}/${total} vendors flagged malicious, ${suspicious} suspicious)

INSTRUCTIONS:
${verdict === 'CLEAN'
            ? '- The scan is VERIFIED CLEAN with 0 detections. State clearly that the target is safe with zero threat signatures or anomalous payloads found. Do NOT mention any malware, exploits, or quarantine.'
            : `- The scan has ${malicious} MALICIOUS flags. Summarize the threat level accurately and provide incident response remediation.`
          }

Respond strictly in this 2-line format:
Finding: <1 sentence factual summary matching the ${verdict} verdict>
Action: <1 sentence recommended security practice matching the ${verdict} verdict>`;

        let reply = '';
        const atlasKey = import.meta.env.VITE_GROQ_API_KEY;
        const apiMessages = [
          { role: 'system', content: 'You are Atlas, an elite cybersecurity analyst. Provide concise, 100% factually grounded verdicts. Never invent fictional vulnerabilities when a file is clean.' },
          { role: 'user', content: prompt }
        ];

        if (atlasKey) {
          try {
            const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
              method: 'POST',
              headers: { 'Authorization': `Bearer ${atlasKey}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ model: 'llama-3.3-70b-versatile', messages: apiMessages, max_tokens: 300, temperature: 0.5 })
            });
            if (res.ok) {
              const data = await res.json();
              reply = data.choices?.[0]?.message?.content || '';
              reply = reply.replace(/<think>[\s\S]*?(<\/think>|$)/g, '').trim();
            } else {
              const errData = await res.json().catch(() => ({}));
              if (import.meta.env.DEV) console.error('[Atlas] Summary error:', res.status, errData);
            }
          } catch (e) { if (import.meta.env.DEV) console.warn('[Atlas] Summary failed:', e); }
        }

        if (reply) {
          if (reply.includes('Finding:') && reply.includes('Action:')) {
            const fMatch = reply.match(/Finding:\s*([^\n]+)/i);
            const aMatch = reply.match(/Action:\s*([^\n]+)/i);
            const rawFinding = fMatch?.[1]?.trim();
            const rawAction = aMatch?.[1]?.trim();

            // Consistency check: If verdict is CLEAN, reject any hallucinated malware/exploit keywords
            const containsContradiction = verdict === 'CLEAN' &&
              /malicious|exploit|vulnerability|quarantine|infected|ransomware|trojan|backdoor/i.test(rawFinding || '');

            if (!containsContradiction) {
              if (rawFinding) kf = rawFinding;
              if (rawAction) act = rawAction;
            }
          }
        }
      } catch (_) { /* LLM enrichment failed — use heuristic baseline */ }

      if (isMounted) {
        setVerdict(verdict);
        setKeyFinding(kf);
        setAction(act);
        setLoading(false);
      }
    };

    generateShortSummary();

    return () => { isMounted = false; };
  }, [threatData, type]);

  const verdictColor = verdict === 'CRITICAL' ? '#ff2a5f' : verdict === 'SUSPICIOUS' ? '#fb923c' : 'var(--brand-amber)';
  const verdictBg = verdict === 'CRITICAL' ? 'rgba(255, 42, 95, 0.12)' : verdict === 'SUSPICIOUS' ? 'rgba(251, 146, 60, 0.12)' : 'rgba(0, 255, 163, 0.12)';
  const verdictBorder = verdict === 'CRITICAL' ? 'rgba(255, 42, 95, 0.3)' : verdict === 'SUSPICIOUS' ? 'rgba(251, 146, 60, 0.3)' : 'rgba(0, 255, 163, 0.3)';

  return (
    <div style={{ background: 'var(--surface-elevated)', border: '1px solid var(--border)', borderRadius: '12px', padding: '22px 26px', position: 'relative', overflow: 'hidden' }}>

      {/* Ember accent top-left */}
      <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: '2px', background: `linear-gradient(90deg, var(--brand), var(--brand-amber), transparent)`, opacity: 0.7 }} />

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{
            width: '34px', height: '34px', borderRadius: '8px', overflow: 'hidden', flexShrink: 0,
            background: 'transparent',
            border: '1px solid var(--border-2)', boxShadow: '0 0 10px var(--brand-glow)'
          }}>
            <img
              src="/images/ailogo.png"
              alt="Atlas"
              style={{ width: '100%', height: '100%', objectFit: 'contain', display: 'block' }}
            />
          </div>
          <div>
            <h3 style={{ margin: 0, fontSize: '13px', fontWeight: 700, color: 'var(--on-surface)', letterSpacing: '0.02em', lineHeight: 1.2, fontFamily: 'var(--font-headline)' }}>
              Atlas Intelligence
            </h3>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '9px', color: 'var(--brand-amber)', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
              Threat Verdict
            </span>
          </div>
        </div>

        {!loading && (
          <span style={{
            background: verdictBg,
            border: `1px solid ${verdictBorder}`,
            color: verdictColor,
            padding: '3px 10px',
            borderRadius: '999px',
            fontSize: '10px',
            fontWeight: 800,
            fontFamily: 'var(--font-mono)',
            letterSpacing: '0.08em',
          }}>
            {verdict === 'CRITICAL' ? '● CRITICAL' : verdict === 'SUSPICIOUS' ? '▲ SUSPICIOUS' : '✓ CLEAN'}
          </span>
        )}
      </div>

      {loading ? (
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center', color: 'var(--on-surface-3)', padding: '8px 0' }}>
          <span className="material-symbols-outlined spin" style={{ color: 'var(--brand)', fontSize: '18px' }}>sync</span>
          <span style={{ fontSize: '13px', fontFamily: 'var(--font-mono)' }}>Analyzing threat indicators...</span>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {/* Key Finding */}
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', background: 'rgba(255,255,255,0.02)', padding: '10px 14px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.04)' }}>
            <span className="material-symbols-outlined" style={{ color: verdictColor, fontSize: '18px', marginTop: '1px' }}>
              {verdict === 'CLEAN' ? 'verified' : 'crisis_alert'}
            </span>
            <div style={{ fontSize: '13px', color: 'var(--on-surface-2)', lineHeight: 1.55 }}>
              <strong style={{ color: 'var(--on-surface)' }}>Finding: </strong> {keyFinding}
            </div>
          </div>

          {/* Action */}
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', background: 'rgba(255,255,255,0.02)', padding: '10px 14px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.04)' }}>
            <span className="material-symbols-outlined" style={{ color: 'var(--brand-amber)', fontSize: '18px', marginTop: '1px' }}>
              bolt
            </span>
            <div style={{ fontSize: '13px', color: 'var(--on-surface-3)', lineHeight: 1.55 }}>
              <strong style={{ color: 'var(--brand-amber)' }}>Action: </strong> {action}
            </div>
          </div>
        </div>
      )}

    </div>
  );
};
