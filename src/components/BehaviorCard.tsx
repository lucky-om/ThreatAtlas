import React from 'react';
import { MitreAttackTechnique } from '../services/api';

interface BehaviorCardProps {
  mitreAttack?: MitreAttackTechnique[];
}

export const BehaviorCard: React.FC<BehaviorCardProps> = ({ mitreAttack }) => {
  if (!mitreAttack || mitreAttack.length === 0) {
    return (
      <div className="glass-card animate-fade-in-up" style={{ padding: '48px', textAlign: 'center' }}>
        <span className="material-symbols-outlined text-on-surface-variant" style={{ fontSize: '48px', marginBottom: '16px' }}>psychology_alt</span>
        <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '8px' }}>No Behavioral Data</h3>
        <p className="font-body-md text-on-surface-variant">Sandbox execution did not produce MITRE ATT&CK technique signatures for this item.</p>
      </div>
    );
  }

  return (
    <div className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
      <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '24px', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <span className="material-symbols-outlined text-primary">account_tree</span>
        MITRE ATT&CK® Tactical Matrix
      </h3>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '16px' }}>
        {mitreAttack.map((tech, i) => (
          <div key={i} style={{ padding: '16px', background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '6px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <span className="font-code-sm text-primary" style={{ padding: '2px 6px', background: 'rgba(0,242,255,0.1)', borderRadius: '4px', border: '1px solid rgba(0,242,255,0.3)' }}>
                {tech.id}
              </span>
              <span className="font-label-caps text-secondary" style={{ fontSize: '11px' }}>
                {tech.tactic}
              </span>
            </div>
            <div className="font-body-md text-on-surface" style={{ fontWeight: 600 }}>{tech.signature_description}</div>
          </div>
        ))}
      </div>
    </div>
  );
};
