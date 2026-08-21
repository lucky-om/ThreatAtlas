import React, { useState, useCallback } from 'react';

// ── Built-in YARA Rule Examples ──────────────────────────────────────────────
const EXAMPLE_RULES: Array<{ name: string; label: string; rule: string }> = [
  {
    name: 'ransomware_strings',
    label: 'Ransomware Strings',
    rule: `rule Ransomware_Generic {
  meta:
    description = "Detects common ransomware indicators"
    author = "ThreatAtlas"
    severity = "critical"
  strings:
    $s1 = "Your files have been encrypted" nocase
    $s2 = "pay the ransom" nocase
    $s3 = ".locked" nocase
    $s4 = "bitcoin" nocase
    $s5 = "decrypt" nocase
  condition:
    2 of them
}`
  },
  {
    name: 'cobalt_strike_beacon',
    label: 'Cobalt Strike Beacon',
    rule: `rule CobaltStrike_Beacon {
  meta:
    description = "Detects Cobalt Strike Beacon signatures"
    author = "ThreatAtlas"
    severity = "critical"
  strings:
    $cs1 = "beacon.x64.dll" nocase
    $cs2 = "beacon.dll" nocase
    $cs3 = "%d is an x64 process" nocase
    $cs4 = "ReflectiveDll.x64.dll" nocase
    $cs5 = "MZ" at 0
  condition:
    ($cs5 at 0) and (1 of ($cs1, $cs2, $cs3, $cs4))
}`
  },
  {
    name: 'mimikatz_detection',
    label: 'Mimikatz / Credential Dumping',
    rule: `rule Mimikatz_Generic {
  meta:
    description = "Detects Mimikatz credential dumping tool"
    author = "ThreatAtlas"
    severity = "high"
  strings:
    $m1 = "mimikatz" nocase
    $m2 = "sekurlsa::" nocase
    $m3 = "lsadump::" nocase
    $m4 = "privilege::debug" nocase
    $m5 = "Pass-the-Hash" nocase
  condition:
    2 of them
}`
  },
  {
    name: 'webshell_detection',
    label: 'PHP Web Shell',
    rule: `rule PHP_Webshell {
  meta:
    description = "Detects common PHP web shells"
    author = "ThreatAtlas"
    severity = "high"
  strings:
    $p1 = "eval(base64_decode" nocase
    $p2 = "system($_" nocase
    $p3 = "passthru($_" nocase
    $p4 = "exec($_GET" nocase
    $p5 = "shell_exec(" nocase
    $p6 = "@eval(" nocase
  condition:
    2 of them
}`
  },
  {
    name: 'macro_malware',
    label: 'Office Macro Malware',
    rule: `rule OfficeMacro_Malware {
  meta:
    description = "Detects malicious Office macros"
    author = "ThreatAtlas"
    severity = "medium"
  strings:
    $macro1 = "AutoOpen" nocase
    $macro2 = "Document_Open" nocase
    $macro3 = "Shell(" nocase
    $macro4 = "WScript.Shell" nocase
    $macro5 = "CreateObject" nocase
    $macro6 = "powershell" nocase
  condition:
    ($macro1 or $macro2) and (2 of ($macro3, $macro4, $macro5, $macro6))
}`
  },
];

// ── Lightweight client-side YARA-like string matcher ─────────────────────────
interface StringDef {
  name: string;
  pattern: string;
  nocase: boolean;
}

interface ParsedRule {
  ruleName: string;
  meta: Record<string, string>;
  strings: StringDef[];
  conditionRaw: string;
}

interface MatchResult {
  ruleName: string;
  meta: Record<string, string>;
  matchedStrings: Array<{ name: string; pattern: string; matchedValue: string }>;
  verdict: 'MATCH' | 'NO MATCH';
}

function parseYaraRule(ruleText: string): ParsedRule[] {
  const rules: ParsedRule[] = [];
  const ruleRegex = /rule\s+(\w+)\s*\{([\s\S]*?)\}/gm;
  let match;
  while ((match = ruleRegex.exec(ruleText)) !== null) {
    const ruleName = match[1];
    const body = match[2];
    const meta: Record<string, string> = {};
    const metaBlock = body.match(/meta:([\s\S]*?)(?=strings:|condition:|$)/);
    if (metaBlock) {
      const metaLines = metaBlock[1].matchAll(/(\w+)\s*=\s*"([^"]*)"/g);
      for (const ml of metaLines) meta[ml[1]] = ml[2];
    }
    const strings: StringDef[] = [];
    const strBlock = body.match(/strings:([\s\S]*?)(?=condition:|$)/);
    if (strBlock) {
      const strLines = strBlock[1].matchAll(/(\$\w+)\s*=\s*"([^"]*)"(\s+nocase)?/g);
      for (const sl of strLines) {
        strings.push({ name: sl[1], pattern: sl[2], nocase: !!sl[3] });
      }
    }
    const condMatch = body.match(/condition:([\s\S]*)/);
    const conditionRaw = condMatch ? condMatch[1].trim() : '';
    rules.push({ ruleName, meta, strings, conditionRaw });
  }
  return rules;
}

function matchRuleAgainstContent(rule: ParsedRule, content: string): MatchResult {
  const matchedStrings: MatchResult['matchedStrings'] = [];

  for (const strDef of rule.strings) {
    const searchContent = strDef.nocase ? content.toLowerCase() : content;
    const searchPattern = strDef.nocase ? strDef.pattern.toLowerCase() : strDef.pattern;
    const idx = searchContent.indexOf(searchPattern);
    if (idx !== -1) {
      matchedStrings.push({
        name: strDef.name,
        pattern: strDef.pattern,
        matchedValue: content.substring(Math.max(0, idx - 10), Math.min(content.length, idx + strDef.pattern.length + 10))
      });
    }
  }

  // Evaluate simple conditions
  const cond = rule.conditionRaw;
  let verdict: 'MATCH' | 'NO MATCH' = 'NO MATCH';

  if (cond.includes('all of them')) {
    verdict = matchedStrings.length === rule.strings.length ? 'MATCH' : 'NO MATCH';
  } else {
    const nOfMatch = cond.match(/(\d+)\s+of\s+them/);
    const nOfStringsMatch = cond.match(/(\d+)\s+of\s+\(([^)]+)\)/);
    if (nOfMatch) {
      verdict = matchedStrings.length >= parseInt(nOfMatch[1]) ? 'MATCH' : 'NO MATCH';
    } else if (nOfStringsMatch) {
      // count how many named strings matched
      verdict = matchedStrings.length >= parseInt(nOfStringsMatch[1]) ? 'MATCH' : 'NO MATCH';
    } else if (matchedStrings.length > 0) {
      verdict = 'MATCH';
    }
  }

  return { ruleName: rule.ruleName, meta: rule.meta, matchedStrings, verdict };
}

// ── YARA Scanner Page ─────────────────────────────────────────────────────────
export const YaraScanner: React.FC = () => {
  const [ruleText, setRuleText] = useState(EXAMPLE_RULES[0].rule);
  const [hashInput, setHashInput] = useState('');
  const [textInput, setTextInput] = useState('');
  const [inputMode, setInputMode] = useState<'hash' | 'text'>('text');
  const [results, setResults] = useState<MatchResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scanned, setScanned] = useState(false);
  const [vtFileData, setVtFileData] = useState<any>(null);

  const loadExample = (rule: typeof EXAMPLE_RULES[number]) => {
    setRuleText(rule.rule);
  };

  const buildScanContent = (vtData: any): string => {
    const attrs = vtData?.data?.attributes || {};
    const parts: string[] = [];
    // Build a text representation of file attributes to match against
    if (attrs.meaningful_name) parts.push(attrs.meaningful_name);
    if (attrs.names) parts.push(...attrs.names);
    if (attrs.tags) parts.push(...attrs.tags);
    if (attrs.magic) parts.push(attrs.magic);
    if (attrs.type_description) parts.push(attrs.type_description);
    // MITRE techniques
    if (attrs.mitre_attack_techniques) {
      attrs.mitre_attack_techniques.forEach((t: any) => {
        if (t.signature_description) parts.push(t.signature_description);
      });
    }
    // Signature info
    if (attrs.signature_info) {
      Object.values(attrs.signature_info).forEach((v: any) => parts.push(String(v)));
    }
    // Import list
    if (attrs.pe_info?.import_list) {
      attrs.pe_info.import_list.forEach((imp: any) => {
        parts.push(imp.library_name);
        if (imp.imported_functions) parts.push(...imp.imported_functions);
      });
    }
    // Analysis results (engine descriptions)
    if (attrs.last_analysis_results) {
      Object.values(attrs.last_analysis_results).forEach((r: any) => {
        if (r.result) parts.push(r.result);
      });
    }
    return parts.join('\n');
  };

  const handleScan = useCallback(async () => {
    setLoading(true);
    setError(null);
    setResults([]);
    setScanned(false);

    try {
      const parsedRules = parseYaraRule(ruleText);
      if (parsedRules.length === 0) {
        throw new Error('No valid YARA rules found. Check rule syntax.');
      }

      let content = '';

      if (inputMode === 'hash') {
        if (!hashInput.trim()) throw new Error('Enter a file hash to scan.');
        const res = await fetch(`/api/vt/files/${encodeURIComponent(hashInput.trim())}`);
        if (!res.ok) throw new Error(`VT lookup failed: ${res.status === 404 ? 'File not found in VirusTotal database.' : `HTTP ${res.status}`}`);
        const vtData = await res.json();
        setVtFileData(vtData);
        content = buildScanContent(vtData);
      } else {
        content = textInput;
        if (!content.trim()) throw new Error('Enter some text content to match against.');
        setVtFileData(null);
      }

      const matchResults = parsedRules.map(rule => matchRuleAgainstContent(rule, content));
      setResults(matchResults);
      setScanned(true);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [ruleText, hashInput, textInput, inputMode]);

  const matchCount = results.filter(r => r.verdict === 'MATCH').length;

  return (
    <div className="module-page">
      <div className="digital-grid" />
      <div style={{ position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 0, background: 'radial-gradient(circle at 30% 60%, rgba(34,211,238,0.06) 0%, transparent 50%)' }} />

      <div className="container" style={{ position: 'relative', zIndex: 10, maxWidth: '1300px', width: '100%' }}>

        {/* Hero */}
        <div className="module-hero">
          <div className="module-badge" style={{ background: 'var(--module-yara-dim)', border: '1px solid rgba(34,211,238,0.3)', color: 'var(--module-yara)' }}>
            <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>search_insights</span>
            YARA Scanner
          </div>
          <h1 className="font-display-lg text-on-surface" style={{ fontSize: '48px', marginBottom: '12px' }}>
            YARA <span style={{ color: 'var(--module-yara)' }}>Rule</span> Engine
          </h1>
          <p className="font-body-md text-on-surface-variant" style={{ maxWidth: '560px', margin: '0 auto' }}>
            Write or select a YARA rule and match it against a VirusTotal file hash or raw text content. Server-side matching powered by Node.js.
          </p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>

          {/* Left Panel — Rule Editor */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {/* Example Rules */}
            <div className="glass-card" style={{ padding: '20px' }}>
              <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '12px' }}>Quick Load Examples</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                {EXAMPLE_RULES.map(r => (
                  <button
                    key={r.name}
                    onClick={() => loadExample(r)}
                    style={{
                      padding: '6px 14px', borderRadius: '6px', border: '1px solid rgba(34,211,238,0.25)',
                      background: 'rgba(34,211,238,0.06)', color: 'var(--module-yara)',
                      fontFamily: 'var(--font-mono)', fontSize: '11px', cursor: 'pointer',
                      transition: 'all 0.15s',
                    }}
                    onMouseEnter={e => (e.currentTarget.style.background = 'rgba(34,211,238,0.14)')}
                    onMouseLeave={e => (e.currentTarget.style.background = 'rgba(34,211,238,0.06)')}
                  >
                    {r.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Rule Editor */}
            <div className="glass-card" style={{ padding: '20px', flex: 1 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <div className="font-label-caps" style={{ color: 'var(--module-yara)' }}>YARA Rule Editor</div>
                <span className="font-code-sm text-on-surface-variant">
                  {ruleText.split('\n').length} lines
                </span>
              </div>
              <textarea
                value={ruleText}
                onChange={e => setRuleText(e.target.value)}
                style={{
                  width: '100%', minHeight: '420px', background: 'rgba(0,0,0,0.5)',
                  border: '1px solid rgba(34,211,238,0.2)', borderRadius: '8px',
                  color: 'var(--on-surface)', fontFamily: 'var(--font-mono)', fontSize: '13px',
                  padding: '16px', resize: 'vertical', outline: 'none', lineHeight: '1.6',
                  transition: 'border-color 0.2s',
                }}
                onFocus={e => (e.target.style.borderColor = 'rgba(34,211,238,0.5)')}
                onBlur={e => (e.target.style.borderColor = 'rgba(34,211,238,0.2)')}
                spellCheck={false}
                placeholder="Enter YARA rule here..."
              />
            </div>
          </div>

          {/* Right Panel — Input + Results */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {/* Input Mode */}
            <div className="glass-card" style={{ padding: '20px' }}>
              <div style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}>
                {(['text', 'hash'] as const).map(mode => (
                  <button
                    key={mode}
                    onClick={() => setInputMode(mode)}
                    className={`scanner-tab font-label-caps ${inputMode === mode ? 'active' : ''}`}
                    style={{ flex: 1 }}
                  >
                    {mode === 'text' ? '📝 RAW TEXT' : '🔍 VT HASH LOOKUP'}
                  </button>
                ))}
              </div>

              {inputMode === 'text' ? (
                <textarea
                  value={textInput}
                  onChange={e => setTextInput(e.target.value)}
                  placeholder="Paste file strings, content, or any text to match YARA rules against..."
                  style={{
                    width: '100%', minHeight: '120px', background: 'rgba(0,0,0,0.4)',
                    border: '1px solid var(--border)', borderRadius: '8px',
                    color: 'var(--on-surface)', fontFamily: 'var(--font-mono)', fontSize: '13px',
                    padding: '12px', resize: 'vertical', outline: 'none',
                  }}
                />
              ) : (
                <div>
                  <input
                    type="text"
                    className="input-field font-data-mono"
                    placeholder="Enter MD5, SHA1, or SHA256 hash..."
                    value={hashInput}
                    onChange={e => setHashInput(e.target.value)}
                    style={{ fontSize: '14px', padding: '14px' }}
                  />
                  <p className="font-code-sm text-on-surface-variant" style={{ marginTop: '8px', fontSize: '11px' }}>
                    File metadata from VirusTotal will be extracted and matched against your rule strings.
                  </p>
                </div>
              )}

              {error && (
                <div style={{ marginTop: '12px', padding: '12px 16px', background: 'rgba(255,0,60,0.1)', border: '1px solid rgba(255,0,60,0.3)', borderRadius: '8px', color: 'var(--secondary)', fontFamily: 'var(--font-mono)', fontSize: '13px' }}>
                  ⚠ {error}
                </div>
              )}

              <button
                onClick={handleScan}
                disabled={loading}
                style={{
                  marginTop: '16px', width: '100%', padding: '14px', borderRadius: '8px',
                  background: loading ? 'rgba(34,211,238,0.1)' : 'rgba(34,211,238,0.15)',
                  border: '1px solid rgba(34,211,238,0.4)', color: 'var(--module-yara)',
                  fontFamily: 'var(--font-mono)', fontSize: '13px', fontWeight: 700, cursor: loading ? 'not-allowed' : 'pointer',
                  letterSpacing: '0.1em', transition: 'all 0.2s',
                }}
              >
                {loading ? '⟳ SCANNING...' : '▶ RUN YARA SCAN'}
              </button>
            </div>

            {/* Results */}
            {scanned && (
              <div className="glass-card animate-fade-in-up" style={{ padding: '20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                  <div className="font-label-caps" style={{ color: 'var(--module-yara)' }}>Scan Results</div>
                  <div style={{ display: 'flex', gap: '8px' }}>
                    <span style={{ padding: '3px 10px', borderRadius: '999px', background: matchCount > 0 ? 'rgba(255,0,60,0.12)' : 'rgba(0,255,163,0.1)', border: `1px solid ${matchCount > 0 ? 'rgba(255,0,60,0.4)' : 'rgba(0,255,163,0.3)'}`, fontFamily: 'var(--font-mono)', fontSize: '11px', color: matchCount > 0 ? 'var(--secondary)' : 'var(--success)', fontWeight: 700 }}>
                      {matchCount} MATCH{matchCount !== 1 ? 'ES' : ''}
                    </span>
                  </div>
                </div>

                {vtFileData && (
                  <div style={{ marginBottom: '16px', padding: '12px', background: 'rgba(34,211,238,0.06)', border: '1px solid rgba(34,211,238,0.15)', borderRadius: '8px' }}>
                    <div className="font-code-sm text-on-surface-variant" style={{ marginBottom: '4px' }}>Matched against VT file:</div>
                    <div className="font-data-mono text-on-surface" style={{ fontSize: '12px', wordBreak: 'break-all' }}>
                      {vtFileData?.data?.attributes?.meaningful_name || vtFileData?.data?.id}
                    </div>
                  </div>
                )}

                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  {results.map((r, idx) => (
                    <div key={idx} style={{
                      padding: '16px', borderRadius: '10px',
                      background: r.verdict === 'MATCH' ? 'rgba(255,0,60,0.06)' : 'rgba(255,255,255,0.02)',
                      border: `1px solid ${r.verdict === 'MATCH' ? 'rgba(255,0,60,0.25)' : 'rgba(255,255,255,0.06)'}`,
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: r.verdict === 'MATCH' ? '12px' : '0' }}>
                        <div>
                          <span className="font-data-mono text-on-surface" style={{ fontWeight: 700 }}>{r.ruleName}</span>
                          {r.meta.description && (
                            <div className="font-code-sm text-on-surface-variant" style={{ marginTop: '2px' }}>{r.meta.description}</div>
                          )}
                        </div>
                        <span style={{
                          padding: '3px 10px', borderRadius: '999px', fontFamily: 'var(--font-mono)', fontSize: '11px', fontWeight: 700,
                          background: r.verdict === 'MATCH' ? 'rgba(255,0,60,0.15)' : 'rgba(255,255,255,0.05)',
                          border: `1px solid ${r.verdict === 'MATCH' ? 'rgba(255,0,60,0.4)' : 'rgba(255,255,255,0.1)'}`,
                          color: r.verdict === 'MATCH' ? 'var(--secondary)' : 'var(--on-surface-variant)',
                        }}>
                          {r.verdict}
                        </span>
                      </div>

                      {r.verdict === 'MATCH' && r.matchedStrings.map((ms, i) => (
                        <div key={i} style={{ display: 'flex', gap: '8px', alignItems: 'flex-start', marginTop: '6px', padding: '8px 10px', background: 'rgba(0,0,0,0.3)', borderRadius: '6px' }}>
                          <span style={{ color: 'var(--module-yara)', fontFamily: 'var(--font-mono)', fontSize: '12px', flexShrink: 0 }}>{ms.name}</span>
                          <span style={{ color: 'var(--on-surface-variant)', fontFamily: 'var(--font-mono)', fontSize: '11px', wordBreak: 'break-all' }}>"{ms.matchedValue}"</span>
                        </div>
                      ))}

                      {r.meta.severity && (
                        <div style={{ marginTop: '8px' }}>
                          <span style={{ padding: '2px 8px', borderRadius: '4px', fontFamily: 'var(--font-mono)', fontSize: '10px', fontWeight: 700, letterSpacing: '0.1em', background: r.meta.severity === 'critical' ? 'rgba(255,0,60,0.15)' : r.meta.severity === 'high' ? 'rgba(255,100,0,0.15)' : 'rgba(255,179,0,0.15)', color: r.meta.severity === 'critical' ? 'var(--secondary)' : r.meta.severity === 'high' ? '#ff6400' : '#ffb300', border: '1px solid currentColor', borderColor: 'inherit' }}>
                            {r.meta.severity.toUpperCase()}
                          </span>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
