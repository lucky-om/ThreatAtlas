import React from 'react';
import { EXAMPLE_YARA_RULES } from './YaraScannerModule';
import { CrowdsourcedYaraRule, NormalizedFile } from '../services/api';

interface AutomaticYaraProps {
  fileResult?: NormalizedFile | null;
  crowdsourcedYara?: CrowdsourcedYaraRule[];
}

export interface EvaluatedRule {
  name: string;
  source: 'Crowdsourced' | 'Built-in Engine';
  author: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  matched: boolean;
  matchedStrings: string[];
}

export const AutomaticYaraCard: React.FC<AutomaticYaraProps> = ({ fileResult, crowdsourcedYara }) => {
  // Aggregate searchable strings from all file attributes for automatic YARA evaluation
  const searchableParts: string[] = [];
  if (fileResult) {
    if (fileResult.name) searchableParts.push(fileResult.name);
    if (fileResult.names) searchableParts.push(...fileResult.names);
    if (fileResult.type) searchableParts.push(fileResult.type);
    if (fileResult.mimeType) searchableParts.push(fileResult.mimeType);
    if (fileResult.tags) searchableParts.push(...fileResult.tags);
    if (fileResult.extended?.magic) searchableParts.push(fileResult.extended.magic);
    if (fileResult.extended?.packers) searchableParts.push(...Object.values(fileResult.extended.packers));
    if (fileResult.extended?.mitreAttack) {
      fileResult.extended.mitreAttack.forEach(m => searchableParts.push(m.id, m.signature_description, m.tactic));
    }
    if (fileResult.extended?.peInfo?.import_list) {
      fileResult.extended.peInfo.import_list.forEach(imp => {
        searchableParts.push(imp.library_name, ...imp.imported_functions);
      });
    }
    if (fileResult.extended?.exiftool) {
      searchableParts.push(...Object.values(fileResult.extended.exiftool).map(v => String(v)));
    }
    if (fileResult.engines && Array.isArray(fileResult.engines)) {
      fileResult.engines.forEach(e => {
        if (e.result) searchableParts.push(e.result);
      });
    }
  }

  const combinedContent = searchableParts.join('\n').toLowerCase();

  // 1. Evaluate Built-in Rules
  const evaluatedRules: EvaluatedRule[] = [];

  // Add crowdsourced VT rules if present
  if (crowdsourcedYara && crowdsourcedYara.length > 0) {
    crowdsourcedYara.forEach(cy => {
      evaluatedRules.push({
        name: cy.rule_name || cy.ruleset_name || 'Generic_VT_Rule',
        source: 'Crowdsourced',
        author: cy.author || 'VirusTotal Community',
        severity: 'high',
        description: cy.description || 'Community YARA detection rule matched by VirusTotal pipeline.',
        matched: true,
        matchedStrings: cy.match_data ? [JSON.stringify(cy.match_data)] : ['Matched on VT ingestion'],
      });
    });
  }

  // Evaluate each built-in preset
  EXAMPLE_YARA_RULES.forEach(rulePreset => {
    let matched = false;
    const matchedStrings: string[] = [];

    // Parse simple string patterns from rule text
    const strMatches = rulePreset.rule.matchAll(/\$(\w+)\s*=\s*"([^"]*)"/g);
    for (const sm of strMatches) {
      const pattern = sm[2].toLowerCase();
      if (combinedContent.includes(pattern)) {
        matched = true;
        matchedStrings.push(`$${sm[1]} = "${sm[2]}"`);
      }
    }

    const severity = rulePreset.name.includes('ransomware') || rulePreset.name.includes('cobalt')
      ? 'critical'
      : rulePreset.name.includes('mimikatz') || rulePreset.name.includes('webshell')
      ? 'high'
      : 'medium';

    const descMatch = rulePreset.rule.match(/description\s*=\s*"([^"]*)"/);
    const description = descMatch ? descMatch[1] : rulePreset.label;

    evaluatedRules.push({
      name: rulePreset.name,
      source: 'Built-in Engine',
      author: 'ThreatAtlas YARA Core',
      severity: severity as any,
      description,
      matched,
      matchedStrings,
    });
  });

  const totalEvaluated = evaluatedRules.length;
  const matchCount = evaluatedRules.filter(r => r.matched).length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Header Summary */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span className="material-symbols-outlined" style={{ color: matchCount > 0 ? '#ff2a5f' : '#00ffa3', fontSize: '20px' }}>
            {matchCount > 0 ? 'warning' : 'verified_user'}
          </span>
          <span style={{ fontSize: '14px', fontWeight: 600, color: '#f1f5f9' }}>
            {matchCount > 0
              ? `${matchCount} YARA signature match${matchCount > 1 ? 'es' : ''} detected`
              : 'All YARA rules evaluated — 0 matches (Clean)'}
          </span>
        </div>

        <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
          {totalEvaluated} rules automatically scanned
        </div>
      </div>

      {/* Rules Table */}
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid #334155', color: '#64748b' }}>
              <th style={{ padding: '10px 12px' }}>Rule Name</th>
              <th style={{ padding: '10px 12px' }}>Source / Author</th>
              <th style={{ padding: '10px 12px' }}>Severity</th>
              <th style={{ padding: '10px 12px' }}>Status</th>
              <th style={{ padding: '10px 12px' }}>Description</th>
            </tr>
          </thead>
          <tbody>
            {evaluatedRules.map((rule, idx) => {
              const severityColor = rule.severity === 'critical' ? '#ff2a5f' : rule.severity === 'high' ? '#fb923c' : '#38bdf8';
              return (
                <tr 
                  key={idx} 
                  style={{ 
                    borderBottom: '1px solid rgba(255,255,255,0.03)',
                    background: rule.matched ? 'rgba(255, 42, 95, 0.04)' : 'transparent',
                    transition: 'background 0.15s ease'
                  }}
                >
                  <td style={{ padding: '10px 12px', color: rule.matched ? '#ff2a5f' : '#e2e8f0', fontWeight: 600 }}>
                    {rule.name}
                  </td>
                  <td style={{ padding: '10px 12px', color: '#94a3b8' }}>
                    {rule.author}
                  </td>
                  <td style={{ padding: '10px 12px' }}>
                    <span 
                      style={{ 
                        background: `${severityColor}15`, 
                        border: `1px solid ${severityColor}40`, 
                        color: severityColor, 
                        padding: '2px 6px', 
                        borderRadius: '4px', 
                        fontSize: '10px', 
                        fontWeight: 700 
                      }}
                    >
                      {rule.severity.toUpperCase()}
                    </span>
                  </td>
                  <td style={{ padding: '10px 12px' }}>
                    {rule.matched ? (
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', color: '#ff2a5f', fontWeight: 700 }}>
                        <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>error</span>
                        MATCHED
                      </span>
                    ) : (
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', color: '#64748b' }}>
                        <span className="material-symbols-outlined" style={{ fontSize: '14px', color: '#00ffa3' }}>check_circle</span>
                        PASSED
                      </span>
                    )}
                  </td>
                  <td style={{ padding: '10px 12px', color: '#cbd5e1', maxWidth: '300px' }}>
                    <div>{rule.description}</div>
                    {rule.matched && rule.matchedStrings.length > 0 && (
                      <div style={{ marginTop: '4px', color: '#ff2a5f', fontSize: '11px' }}>
                        {rule.matchedStrings.join(', ')}
                      </div>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
