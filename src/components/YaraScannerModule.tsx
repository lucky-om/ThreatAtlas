import React, { useState } from 'react';

// ── Built-in YARA Rule Presets (Industry Standard Threat Ruleset) ────────────
export const EXAMPLE_YARA_RULES = [
  {
    name: 'eicar_av_test',
    label: 'EICAR Antivirus Test Signature',
    rule: `rule EICAR_Test_File {
  meta:
    description = "Standard EICAR Antivirus verification test pattern"
    author = "EICAR / ThreatAtlas"
    severity = "low"
  strings:
    $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    $eicar_tag = "eicar" nocase
  condition:
    $eicar or $eicar_tag
}`
  },
  {
    name: 'wannacry_ransomware',
    label: 'WannaCry / WanaCrypt0r Ransomware',
    rule: `rule Ransomware_WannaCry {
  meta:
    description = "Detects WannaCry ransomware extortion payloads and mutexes"
    author = "ThreatAtlas YARA Core"
    severity = "critical"
  strings:
    $w1 = "WanaCrypt0r" nocase
    $w2 = "WNCRY" nocase
    $w3 = "Global\\\\MsWinZonesCacheCounterMutexA" nocase
    $w4 = "wannacry" nocase
    $w5 = "msg/m_bulgarian.wnry" nocase
  condition:
    1 of them
}`
  },
  {
    name: 'cobalt_strike_beacon',
    label: 'Cobalt Strike Beacon & C2',
    rule: `rule CobaltStrike_Beacon {
  meta:
    description = "Detects Cobalt Strike Beacon in-memory artifacts and reflective loaders"
    author = "ThreatAtlas YARA Core"
    severity = "critical"
  strings:
    $cs1 = "beacon.x64.dll" nocase
    $cs2 = "beacon.dll" nocase
    $cs3 = "%d is an x64 process" nocase
    $cs4 = "ReflectiveDll.x64.dll" nocase
    $cs5 = "cobalt" nocase
  condition:
    1 of them
}`
  },
  {
    name: 'mimikatz_dump',
    label: 'Mimikatz Credential Dumper',
    rule: `rule Mimikatz_Generic {
  meta:
    description = "Detects Mimikatz credential dumping and LSASS injection artifacts"
    author = "ThreatAtlas YARA Core"
    severity = "high"
  strings:
    $m1 = "mimikatz" nocase
    $m2 = "sekurlsa::" nocase
    $m3 = "lsadump::" nocase
    $m4 = "privilege::debug" nocase
    $m5 = "Pass-the-Hash" nocase
    $m6 = "crypto::hash" nocase
  condition:
    1 of them
}`
  },
  {
    name: 'redline_stealer',
    label: 'RedLine / Infostealer Token Harvester',
    rule: `rule RedLine_Stealer_Generic {
  meta:
    description = "Detects RedLine, Vidar, and Lumma browser credential harvest indicators"
    author = "ThreatAtlas YARA Core"
    severity = "high"
  strings:
    $r1 = "redline" nocase
    $r2 = "vidar" nocase
    $r3 = "lumma" nocase
    $r4 = "\\\\Google\\\\Chrome\\\\User Data\\\\Default\\\\Login Data" nocase
    $r5 = "SELECT action_url, username_value, password_value FROM logins" nocase
    $r6 = "stealer" nocase
  condition:
    1 of them
}`
  },
  {
    name: 'xmrig_coinminer',
    label: 'XMRig / Monero CPU Cryptominer',
    rule: `rule Cryptominer_XMRig {
  meta:
    description = "Detects unauthorized XMRig / Stratum protocol coinminers"
    author = "ThreatAtlas YARA Core"
    severity = "high"
  strings:
    $x1 = "xmrig" nocase
    $x2 = "stratum+tcp://" nocase
    $x3 = "stratum+ssl://" nocase
    $x4 = "cryptonight" nocase
    $x5 = "monero" nocase
    $x6 = "coinminer" nocase
  condition:
    1 of them
}`
  },
  {
    name: 'emotet_dropper',
    label: 'Emotet / TrickBot Banking Trojan',
    rule: `rule Trojan_Emotet_Trickbot {
  meta:
    description = "Detects Emotet and TrickBot modular banking trojan droppers"
    author = "ThreatAtlas YARA Core"
    severity = "critical"
  strings:
    $e1 = "emotet" nocase
    $e2 = "trickbot" nocase
    $e3 = "heodo" nocase
    $e4 = "geodo" nocase
    $e5 = "banker" nocase
  condition:
    1 of them
}`
  },
  {
    name: 'php_webshell',
    label: 'PHP Web Shell & Backdoor',
    rule: `rule PHP_Webshell {
  meta:
    description = "Detects obfuscated PHP web shells, evaluators, and system execution"
    author = "ThreatAtlas YARA Core"
    severity = "high"
  strings:
    $p1 = "eval(base64_decode" nocase
    $p2 = "system($_" nocase
    $p3 = "passthru($_" nocase
    $p4 = "exec($_GET" nocase
    $p5 = "shell_exec(" nocase
    $p6 = "@eval(" nocase
    $p7 = "c99shell" nocase
    $p8 = "r57shell" nocase
  condition:
    1 of them
}`
  },
  {
    name: 'powershell_obfuscated',
    label: 'Obfuscated PowerShell Download Cradle',
    rule: `rule PowerShell_Download_Cradle {
  meta:
    description = "Detects hidden or encoded PowerShell download and execute cradles"
    author = "ThreatAtlas YARA Core"
    severity = "high"
  strings:
    $ps1 = "powershell" nocase
    $ps2 = "-enc" nocase
    $ps3 = "-encodedcommand" nocase
    $ps4 = "downloadstring" nocase
    $ps5 = "downloadfile" nocase
    $ps6 = "iex(" nocase
    $ps7 = "invoke-expression" nocase
    $ps8 = "-windowstyle hidden" nocase
  condition:
    $ps1 and (1 of ($ps2, $ps3, $ps4, $ps5, $ps6, $ps7, $ps8))
}`
  },
  {
    name: 'macro_malware',
    label: 'Office VBA Malicious Macro',
    rule: `rule OfficeMacro_Malware {
  meta:
    description = "Detects malicious VBA Office macros and execution routines"
    author = "ThreatAtlas YARA Core"
    severity = "medium"
  strings:
    $macro1 = "AutoOpen" nocase
    $macro2 = "Document_Open" nocase
    $macro3 = "Auto_Open" nocase
    $macro4 = "Shell(" nocase
    $macro5 = "WScript.Shell" nocase
    $macro6 = "CreateObject" nocase
    $macro7 = "vba" nocase
  condition:
    1 of ($macro1, $macro2, $macro3) or (2 of ($macro4, $macro5, $macro6, $macro7))
}`
  },
  {
    name: 'process_injection_api',
    label: 'Process Injection & Thread Hijacking',
    rule: `rule Process_Injection_APIs {
  meta:
    description = "Detects Win32 memory allocation and remote thread injection APIs"
    author = "ThreatAtlas YARA Core"
    severity = "high"
  strings:
    $api1 = "VirtualAllocEx" nocase
    $api2 = "WriteProcessMemory" nocase
    $api3 = "CreateRemoteThread" nocase
    $api4 = "QueueUserAPC" nocase
    $api5 = "SetThreadContext" nocase
    $api6 = "NtUnmapViewOfSection" nocase
  condition:
    2 of them
}`
  },
  {
    name: 'anti_analysis_debugger',
    label: 'Anti-Analysis & Sandbox Evasion',
    rule: `rule Anti_Analysis_Sandbox_Evasion {
  meta:
    description = "Detects debugger detection, sandbox checks, and sleep acceleration"
    author = "ThreatAtlas YARA Core"
    severity = "medium"
  strings:
    $aa1 = "IsDebuggerPresent" nocase
    $aa2 = "CheckRemoteDebuggerPresent" nocase
    $aa3 = "NtQueryInformationProcess" nocase
    $aa4 = "OutputDebugString" nocase
    $aa5 = "GetTickCount" nocase
  condition:
    2 of them
}`
  },
  {
    name: 'upx_packed_binary',
    label: 'UPX / High-Entropy Packed Binary',
    rule: `rule Packed_UPX_Section {
  meta:
    description = "Detects UPX and ASPack packed binary sections"
    author = "ThreatAtlas YARA Core"
    severity = "medium"
  strings:
    $upx1 = "UPX0" nocase
    $upx2 = "UPX1" nocase
    $upx3 = "UPX!" nocase
    $upx4 = "aspack" nocase
    $upx5 = "upx" nocase
  condition:
    1 of them
}`
  },
  {
    name: 'stego_polyglot_payload',
    label: 'Steganography / Image Polyglot Payload',
    rule: `rule Stego_Image_Polyglot {
  meta:
    description = "Detects hidden script injections or archive polyglots appended to media"
    author = "ThreatAtlas YARA Core"
    severity = "high"
  strings:
    $stego1 = "<?php" nocase
    $stego2 = "<script" nocase
    $stego3 = "eval(base64" nocase
    $stego4 = "appended data" nocase
    $stego5 = "trailer" nocase
    $stego6 = "polyglot" nocase
  condition:
    1 of them
}`
  },
  {
    name: 'reverse_shell_payload',
    label: 'Reverse Shell / Meterpreter Payload',
    rule: `rule Reverse_Shell_Meterpreter {
  meta:
    description = "Detects interactive reverse shell connectors and Meterpreter stages"
    author = "ThreatAtlas YARA Core"
    severity = "critical"
  strings:
    $rs1 = "meterpreter" nocase
    $rs2 = "/bin/sh -i" nocase
    $rs3 = "/bin/bash -i" nocase
    $rs4 = "nc -e /bin" nocase
    $rs5 = "0>&1 2>&1" nocase
    $rs6 = "reverse_tcp" nocase
  condition:
    1 of them
}`
  }
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
