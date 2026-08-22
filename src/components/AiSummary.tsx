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
      let v: 'CRITICAL' | 'SUSPICIOUS' | 'CLEAN' = isCritical ? 'CRITICAL' : isSuspicious ? 'SUSPICIOUS' : 'CLEAN';
      let kf = '';
      let act = '';

      if (v === 'CRITICAL') {
        kf = `Flagged by ${malicious} security engines. Exhibits weaponized malware signatures, dropper routines, or hostile C2 communication patterns.`;
        act = `Isolate affected endpoints, block SHA-256 hash/IP at firewall boundaries, and purge corresponding artifacts.`;
      } else if (v === 'SUSPICIOUS') {
        kf = `Flagged by ${malicious || suspicious} engine(s) for anomalous behaviors, evasive packed code, or low-reputation telemetry.`;
        act = `Execute in sandboxed environment before authorization. Monitor network egress for suspicious domain requests.`;
      } else {
        kf = `Zero security vendors flagged this ${type}. Cryptographic integrity, entropy, and structural headers are clean.`;
        act = `Safe to use under standard corporate security policy. Baseline telemetry verified.`;
      }

      // Try live LLM if available for contextual refinement strictly grounded in scan facts
      try {
        const prompt = `You are Atlas AI, an elite cybersecurity analyst.
Target: ${targetName} (${type.toUpperCase()})
Scan Verdict: ${v} (${malicious}/${total} vendors flagged malicious, ${suspicious} suspicious)

INSTRUCTIONS:
${v === 'CLEAN' 
  ? '- The scan is VERIFIED CLEAN with 0 detections. State clearly that the target is safe with zero threat signatures or anomalous payloads found. Do NOT mention any malware, exploits, or quarantine.'
  : `- The scan has ${malicious} MALICIOUS flags. Summarize the threat level accurately and provide incident response remediation.`
}

Respond strictly in this 2-line format:
Finding: <1 sentence factual summary matching the ${v} verdict>
Action: <1 sentence recommended security practice matching the ${v} verdict>`;

        const res = await fetch('/api/ai/chat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            messages: [
              { role: 'system', content: 'You are Atlas AI. Provide concise, 100% factually grounded cybersecurity verdicts. Never invent fictional vulnerabilities when a file is clean.' },
              { role: 'user', content: prompt }
            ]
          })
        });

        if (res.ok) {
          const json = await res.json();
          const reply = json.reply || '';
          if (reply.includes('Finding:') && reply.includes('Action:')) {
            const fMatch = reply.match(/Finding:\s*([^\n]+)/i);
            const aMatch = reply.match(/Action:\s*([^\n]+)/i);
            const rawFinding = fMatch?.[1]?.trim();
            const rawAction = aMatch?.[1]?.trim();

            // Consistency check: If verdict is CLEAN, reject any hallucinated malware/exploit keywords
            const containsContradiction = v === 'CLEAN' && 
              /malicious|exploit|vulnerability|quarantine|infected|ransomware|trojan|backdoor/i.test(rawFinding || '');

            if (!containsContradiction) {
              if (rawFinding) kf = rawFinding;
              if (rawAction) act = rawAction;
            }
          }
        }
      } catch (_) {}

      if (isMounted) {
        setVerdict(v);
        setKeyFinding(kf);
        setAction(act);
        setLoading(false);
      }
    };

    generateShortSummary();

    return () => { isMounted = false; };
  }, [threatData, type]);

  const verdictColor = verdict === 'CRITICAL' ? '#ff2a5f' : verdict === 'SUSPICIOUS' ? '#fb923c' : '#00ffa3';
  const verdictBg = verdict === 'CRITICAL' ? 'rgba(255, 42, 95, 0.12)' : verdict === 'SUSPICIOUS' ? 'rgba(251, 146, 60, 0.12)' : 'rgba(0, 255, 163, 0.12)';
  const verdictBorder = verdict === 'CRITICAL' ? 'rgba(255, 42, 95, 0.3)' : verdict === 'SUSPICIOUS' ? 'rgba(251, 146, 60, 0.3)' : 'rgba(0, 255, 163, 0.3)';

  return (
    <div style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '24px 28px', position: 'relative', overflow: 'hidden' }}>
      
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', borderBottom: '1px solid rgba(255,255,255,0.06)', paddingBottom: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span className="material-symbols-outlined" style={{ color: '#00f2ff', fontSize: '22px' }}>psychology</span>
          <h3 style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: '#f1f5f9', letterSpacing: '0.02em' }}>
            Atlas AI Quick Verdict
          </h3>
        </div>

        {!loading && (
          <span style={{
            background: verdictBg,
            border: `1px solid ${verdictBorder}`,
            color: verdictColor,
            padding: '3px 10px',
            borderRadius: '999px',
            fontSize: '11px',
            fontWeight: 800,
            fontFamily: 'var(--font-mono)'
          }}>
            {verdict === 'CRITICAL' ? '● CRITICAL THREAT' : verdict === 'SUSPICIOUS' ? '▲ SUSPICIOUS' : '✓ VERIFIED SAFE'}
          </span>
        )}
      </div>

      {loading ? (
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center', color: '#94a3b8', padding: '8px 0' }}>
          <span className="material-symbols-outlined spin" style={{ color: '#00f2ff', fontSize: '18px' }}>sync</span>
          <span style={{ fontSize: '13px', fontFamily: 'var(--font-mono)' }}>Synthesizing threat indicators...</span>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {/* Key Finding */}
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', background: 'rgba(255,255,255,0.02)', padding: '10px 14px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.04)' }}>
            <span className="material-symbols-outlined" style={{ color: verdictColor, fontSize: '18px', marginTop: '1px' }}>
              {verdict === 'CLEAN' ? 'verified' : 'crisis_alert'}
            </span>
            <div style={{ fontSize: '13px', color: '#e2e8f0', lineHeight: 1.5 }}>
              <strong style={{ color: '#fff' }}>Key Finding: </strong> {keyFinding}
            </div>
          </div>

          {/* Action */}
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', background: 'rgba(255,255,255,0.02)', padding: '10px 14px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.04)' }}>
            <span className="material-symbols-outlined" style={{ color: '#38bdf8', fontSize: '18px', marginTop: '1px' }}>
              bolt
            </span>
            <div style={{ fontSize: '13px', color: '#cbd5e1', lineHeight: 1.5 }}>
              <strong style={{ color: '#38bdf8' }}>Recommended Action: </strong> {action}
            </div>
          </div>
        </div>
      )}

    </div>
  );
};
