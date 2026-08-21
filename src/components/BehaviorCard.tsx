import React, { useState } from 'react';
import { MitreAttackTechnique } from '../services/api';

interface SandboxBehavior {
  attributes?: {
    sandbox_name?: string;
    processes_created?: string[];
    files_opened?: string[];
    files_written?: string[];
    files_deleted?: string[];
    registry_keys_opened?: string[];
    registry_keys_set?: Array<{ key: string; value: string }>;
    ip_traffic?: Array<{ destination_ip: string; destination_port: number; transport_layer_protocol: string }>;
    http_conversations?: Array<{ url: string; request_method: string; response_status_code: number }>;
    dns_lookups?: Array<{ hostname: string; resolved_ips: string[] }>;
    mutexes_created?: string[];
    mitre_attack_techniques?: MitreAttackTechnique[];
  };
}

interface BehaviorCardProps {
  mitreAttack?: MitreAttackTechnique[];
  behaviorData?: { data?: SandboxBehavior[] } | null;
}

const Pill: React.FC<{ children: React.ReactNode; color?: string }> = ({ children, color = 'rgba(255,255,255,0.06)' }) => (
  <span style={{
    display: 'inline-block',
    padding: '2px 8px',
    background: color,
    border: '1px solid rgba(255,255,255,0.1)',
    borderRadius: '4px',
    fontFamily: 'var(--font-mono)',
    fontSize: '12px',
    color: 'var(--on-surface)',
    wordBreak: 'break-all'
  }}>{children}</span>
);

const Section: React.FC<{ icon: string; title: string; count: number; children: React.ReactNode }> = ({ icon, title, count, children }) => {
  const [open, setOpen] = useState(false);
  if (count === 0) return null;
  return (
    <div style={{ borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '16px' }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          width: '100%', display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          background: 'none', border: 'none', cursor: 'pointer', padding: '12px 0', color: 'inherit'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span className="material-symbols-outlined text-primary" style={{ fontSize: '20px' }}>{icon}</span>
          <span className="font-headline-sm text-on-surface">{title}</span>
          <span style={{ fontSize: '12px', padding: '1px 8px', background: 'rgba(185,66,255,0.15)', border: '1px solid rgba(185,66,255,0.3)', borderRadius: '999px', color: 'var(--primary)', fontFamily: 'var(--font-mono)' }}>
            {count}
          </span>
        </div>
        <span className="material-symbols-outlined text-on-surface-variant" style={{ fontSize: '20px' }}>
          {open ? 'expand_less' : 'expand_more'}
        </span>
      </button>
      {open && <div style={{ paddingTop: '12px', paddingLeft: '30px' }}>{children}</div>}
    </div>
  );
};

export const BehaviorCard: React.FC<BehaviorCardProps> = ({ mitreAttack, behaviorData }) => {
  const sandboxes = behaviorData?.data || [];

  // Aggregate all MITRE techniques from both static file analysis and sandbox reports
  const allMitre: MitreAttackTechnique[] = [
    ...(mitreAttack || []),
    ...sandboxes.flatMap(s => s.attributes?.mitre_attack_techniques || [])
  ];

  // Remove duplicates by technique ID
  const uniqueMitre = Array.from(new Map(allMitre.map(t => [t.id, t])).values());

  if (sandboxes.length === 0 && uniqueMitre.length === 0) {
    return (
      <div className="glass-card animate-fade-in-up" style={{ padding: '48px', textAlign: 'center' }}>
        <span className="material-symbols-outlined text-on-surface-variant" style={{ fontSize: '48px', marginBottom: '16px' }}>psychology_alt</span>
        <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '8px' }}>No Behavioral Data</h3>
        <p className="font-body-md text-on-surface-variant">Sandbox execution data is not available for this item. This may be a new submission or a file type without sandbox support.</p>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* MITRE ATT&CK Matrix */}
      {uniqueMitre.length > 0 && (
        <div className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
          <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '24px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="material-symbols-outlined text-primary">account_tree</span>
            MITRE ATT&CK® Tactical Matrix
            <span style={{ fontSize: '12px', padding: '2px 10px', background: 'rgba(185,66,255,0.15)', border: '1px solid rgba(185,66,255,0.3)', borderRadius: '999px', color: 'var(--primary)', fontFamily: 'var(--font-mono)' }}>
              {uniqueMitre.length} techniques
            </span>
          </h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '12px' }}>
            {uniqueMitre.map((tech, i) => (
              <div key={i} style={{ padding: '16px', background: 'rgba(255,0,60,0.04)', border: '1px solid rgba(255,0,60,0.15)', borderRadius: '8px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <span className="font-code-sm text-secondary" style={{ padding: '2px 8px', background: 'rgba(255,0,60,0.1)', borderRadius: '4px', border: '1px solid rgba(255,0,60,0.3)' }}>
                    {tech.id}
                  </span>
                  <span className="font-label-caps" style={{ fontSize: '10px', color: 'var(--on-surface-variant)' }}>
                    {tech.tactic}
                  </span>
                </div>
                <div className="font-body-md text-on-surface" style={{ fontWeight: 500, fontSize: '14px' }}>{tech.signature_description}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Per-Sandbox Reports */}
      {sandboxes.map((sb, idx) => {
        const attrs = sb.attributes || {};
        const processes = attrs.processes_created || [];
        const filesWritten = attrs.files_written || [];
        const filesDeleted = attrs.files_deleted || [];
        const regKeys = attrs.registry_keys_set || [];
        const ipTraffic = attrs.ip_traffic || [];
        const httpConv = attrs.http_conversations || [];
        const dnsLookups = attrs.dns_lookups || [];
        const mutexes = attrs.mutexes_created || [];

        const totalArtifacts = processes.length + filesWritten.length + filesDeleted.length +
          regKeys.length + ipTraffic.length + httpConv.length + dnsLookups.length + mutexes.length;

        return (
          <div key={idx} className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '24px' }}>
              <span className="material-symbols-outlined text-primary" style={{ fontSize: '24px' }}>smart_toy</span>
              <div>
                <div className="font-headline-sm text-on-surface">{attrs.sandbox_name || `Sandbox Report #${idx + 1}`}</div>
                <div className="font-code-sm text-on-surface-variant">{totalArtifacts} behavioral artifacts collected</div>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              <Section icon="terminal" title="Processes Created" count={processes.length}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {processes.map((p, i) => <Pill key={i}>{p}</Pill>)}
                </div>
              </Section>

              <Section icon="edit_document" title="Files Written" count={filesWritten.length}>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                  {filesWritten.map((f, i) => <Pill key={i}>{f}</Pill>)}
                </div>
              </Section>

              <Section icon="delete" title="Files Deleted" count={filesDeleted.length}>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                  {filesDeleted.map((f, i) => <Pill key={i} color="rgba(255,0,60,0.06)">{f}</Pill>)}
                </div>
              </Section>

              <Section icon="app_registration" title="Registry Keys Modified" count={regKeys.length}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {regKeys.map((r, i) => (
                    <div key={i} style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                      <Pill color="rgba(255,179,0,0.06)">{r.key}</Pill>
                      <span style={{ color: 'var(--on-surface-variant)', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>→ {r.value}</span>
                    </div>
                  ))}
                </div>
              </Section>

              <Section icon="network_node" title="Network Connections" count={ipTraffic.length}>
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
                        {['Destination IP', 'Port', 'Protocol'].map(h => (
                          <th key={h} className="font-label-caps text-on-surface-variant" style={{ padding: '8px 12px' }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {ipTraffic.map((c, i) => (
                        <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                          <td className="font-data-mono text-primary" style={{ padding: '8px 12px' }}>{c.destination_ip}</td>
                          <td className="font-data-mono text-on-surface" style={{ padding: '8px 12px' }}>{c.destination_port}</td>
                          <td className="font-data-mono text-on-surface-variant" style={{ padding: '8px 12px' }}>{c.transport_layer_protocol}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Section>

              <Section icon="http" title="HTTP Conversations" count={httpConv.length}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {httpConv.map((c, i) => (
                    <div key={i} style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
                      <span style={{ padding: '2px 6px', borderRadius: '4px', background: 'rgba(0,255,163,0.1)', color: 'var(--success)', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>{c.request_method}</span>
                      <span className="font-code-sm text-on-surface" style={{ wordBreak: 'break-all' }}>{c.url}</span>
                      <span style={{ color: c.response_status_code < 400 ? 'var(--success)' : 'var(--secondary)', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>{c.response_status_code}</span>
                    </div>
                  ))}
                </div>
              </Section>

              <Section icon="dns" title="DNS Lookups" count={dnsLookups.length}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {dnsLookups.map((d, i) => (
                    <div key={i} style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' }}>
                      <Pill>{d.hostname}</Pill>
                      <span style={{ color: 'var(--on-surface-variant)', fontSize: '12px' }}>→ {(d.resolved_ips || []).join(', ')}</span>
                    </div>
                  ))}
                </div>
              </Section>

              <Section icon="lock" title="Mutexes Created" count={mutexes.length}>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                  {mutexes.map((m, i) => <Pill key={i} color="rgba(185,66,255,0.06)">{m}</Pill>)}
                </div>
              </Section>
            </div>
          </div>
        );
      })}
    </div>
  );
};
