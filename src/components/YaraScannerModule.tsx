import React, { useState } from 'react';

// ── Built-in YARA Rule Presets ──────────────────────────────────────────────
export const EXAMPLE_YARA_RULES = [
  {
    name: 'ransomware_generic',
    label: 'Ransomware Strings',
    rule: `rule Ransomware_Generic {
  meta:
    description = "Detects common ransomware extortion indicators"
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
    description = "Detects Cobalt Strike Beacon in-memory signatures"
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
    name: 'mimikatz_dump',
    label: 'Mimikatz Credential Dumper',
    rule: `rule Mimikatz_Generic {
  meta:
    description = "Detects Mimikatz credential dumping artifacts"
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
    name: 'php_webshell',
    label: 'PHP Web Shell',
    rule: `rule PHP_Webshell {
  meta:
    description = "Detects common obfuscated PHP web shells"
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
    description = "Detects malicious VBA Office macros"
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

export interface MatchResult {
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
      verdict = matchedStrings.length >= parseInt(nOfStringsMatch[1]) ? 'MATCH' : 'NO MATCH';
    } else if (matchedStrings.length > 0) {
      verdict = 'MATCH';
    }
  }

  return { ruleName: rule.ruleName, meta: rule.meta, matchedStrings, verdict };
}

export const YaraScannerModule: React.FC = () => {
  const [ruleText, setRuleText] = useState(EXAMPLE_YARA_RULES[0].rule);
  const [testContent, setTestContent] = useState('');
  const [results, setResults] = useState<MatchResult[]>([]);
  const [scanned, setScanned] = useState(false);

  const handleTestRule = () => {
    if (!ruleText.trim() || !testContent.trim()) return;
    const parsed = parseYaraRule(ruleText);
    if (parsed.length === 0) {
      setResults([{ ruleName: 'Custom_Rule', meta: {}, matchedStrings: [], verdict: 'NO MATCH' }]);
      setScanned(true);
      return;
    }
    const matchResults = parsed.map(r => matchRuleAgainstContent(r, testContent));
    setResults(matchResults);
    setScanned(true);
  };

  return (
    <div style={{ marginTop: '24px', padding: '24px', background: 'rgba(255,255,255,0.02)', borderRadius: '12px', border: '1px solid rgba(185,66,255,0.2)' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h4 className="font-headline-sm text-on-surface" style={{ fontSize: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="material-symbols-outlined text-primary" style={{ fontSize: '20px' }}>search_insights</span>
            Embedded YARA Rule Pattern Matcher
          </h4>
          <p className="font-code-sm text-on-surface-variant" style={{ fontSize: '11px', marginTop: '2px' }}>
            Select rule presets or compose custom YARA signatures to test against memory, strings, or file buffers.
          </p>
        </div>

        {/* Rule Preset Chips */}
        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
          {EXAMPLE_YARA_RULES.map((preset) => (
            <button
              key={preset.name}
              type="button"
              onClick={() => setRuleText(preset.rule)}
              style={{
                background: 'rgba(185,66,255,0.1)', border: '1px solid rgba(185,66,255,0.3)',
                borderRadius: '6px', padding: '4px 10px', color: 'var(--primary)',
                fontFamily: 'var(--font-mono)', fontSize: '11px', fontWeight: 600, cursor: 'pointer',
              }}
            >
              {preset.label}
            </button>
          ))}
        </div>
      </div>

      {/* Editor & Target Text */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '14px' }}>
        <div>
          <div className="font-label-caps text-on-surface-variant" style={{ fontSize: '10px', marginBottom: '6px' }}>YARA Rule Code:</div>
          <textarea
            value={ruleText}
            onChange={(e) => setRuleText(e.target.value)}
            className="font-data-mono"
            style={{
              width: '100%', height: '160px', background: 'rgba(0,0,0,0.4)',
              border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px',
              padding: '12px', color: 'var(--primary)', fontSize: '12px', resize: 'vertical',
            }}
          />
        </div>

        <div>
          <div className="font-label-caps text-on-surface-variant" style={{ fontSize: '10px', marginBottom: '6px' }}>Test Buffer / Extracted Strings:</div>
          <textarea
            value={testContent}
            onChange={(e) => setTestContent(e.target.value)}
            placeholder="Paste text, extracted PE strings, or script contents to evaluate against the YARA rule..."
            className="font-data-mono"
            style={{
              width: '100%', height: '160px', background: 'rgba(0,0,0,0.4)',
              border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px',
              padding: '12px', color: 'var(--on-surface)', fontSize: '12px', resize: 'vertical',
            }}
          />
        </div>
      </div>

      <div style={{ marginTop: '14px', display: 'flex', justifyContent: 'flex-end', gap: '12px', alignItems: 'center' }}>
        <button
          type="button"
          onClick={handleTestRule}
          disabled={!testContent.trim()}
          style={{
            padding: '10px 24px', borderRadius: '8px', background: 'var(--primary)',
            border: 'none', color: '#000000', fontFamily: 'var(--font-mono)',
            fontSize: '12px', fontWeight: 700, cursor: testContent.trim() ? 'pointer' : 'not-allowed',
            display: 'flex', alignItems: 'center', gap: '6px',
          }}
        >
          <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>rule</span>
          <span>EVALUATE YARA RULE</span>
        </button>
      </div>

      {/* Results Box */}
      {scanned && (
        <div style={{ marginTop: '16px', padding: '16px', borderRadius: '8px', background: 'rgba(0,0,0,0.5)', border: '1px solid rgba(255,255,255,0.08)' }}>
          <div className="font-label-caps text-on-surface-variant" style={{ fontSize: '11px', marginBottom: '8px' }}>Evaluation Results:</div>
          {results.map((r, i) => (
            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 12px', borderRadius: '6px', background: r.verdict === 'MATCH' ? 'rgba(255,0,60,0.12)' : 'rgba(0,255,163,0.08)', border: `1px solid ${r.verdict === 'MATCH' ? 'rgba(255,0,60,0.35)' : 'rgba(0,255,163,0.3)'}` }}>
              <div>
                <span className="font-data-mono text-on-surface" style={{ fontSize: '13px', fontWeight: 700 }}>{r.ruleName}</span>
                {r.matchedStrings.length > 0 && (
                  <div className="font-code-sm text-on-surface-variant" style={{ fontSize: '11px', marginTop: '2px' }}>
                    Matched strings: {r.matchedStrings.map(s => s.name).join(', ')}
                  </div>
                )}
              </div>
              <span style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', fontWeight: 800, color: r.verdict === 'MATCH' ? 'var(--secondary)' : 'var(--success)' }}>
                {r.verdict === 'MATCH' ? '🚨 SIGNATURE MATCHED' : '✅ CLEAN / NO MATCH'}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
