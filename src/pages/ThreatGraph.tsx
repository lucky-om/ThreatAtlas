import React from 'react';

export const ThreatGraph: React.FC = () => {
  return (
    <div className="module-page">
      <div className="digital-grid" />
      <div style={{ position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 0, background: 'radial-gradient(circle at 50% 50%, rgba(129,140,248,0.07) 0%, transparent 50%)' }} />

      <div className="container" style={{ position: 'relative', zIndex: 10, maxWidth: '1100px', width: '100%', textAlign: 'center' }}>
        <div className="module-badge" style={{ background: 'var(--module-graph-dim)', border: '1px solid rgba(129,140,248,0.3)', color: 'var(--module-graph)' }}>
          <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>hub</span>
          Threat Graph — 3D Interactive
        </div>
        <h1 className="font-display-lg text-on-surface" style={{ fontSize: '48px', margin: '16px 0 12px' }}>
          3D <span style={{ color: 'var(--module-graph)' }}>Threat</span> Graph
        </h1>
        <p className="font-body-md text-on-surface-variant" style={{ maxWidth: '560px', margin: '0 auto 48px' }}>
          Interactive 3D force-directed graph of entity relationships — files, IPs, domains, URLs — with full OSINT linking. Coming in Phase 5.
        </p>

        <div className="glass-card animate-fade-in-up" style={{ padding: '64px', position: 'relative', overflow: 'hidden' }}>
          {/* Animated placeholder graph preview */}
          <svg width="100%" height="300" viewBox="0 0 600 300" style={{ opacity: 0.4 }}>
            {/* Nodes */}
            {[
              { x: 300, y: 150, r: 20, color: '#818cf8', label: 'Domain' },
              { x: 150, y: 80, r: 14, color: '#ff2a5f', label: 'File' },
              { x: 450, y: 80, r: 14, color: '#fb923c', label: 'IP' },
              { x: 100, y: 220, r: 12, color: '#ff2a5f', label: 'File' },
              { x: 200, y: 230, r: 10, color: '#22d3ee', label: 'URL' },
              { x: 500, y: 200, r: 12, color: '#fb923c', label: 'IP' },
              { x: 400, y: 240, r: 10, color: '#818cf8', label: 'Domain' },
            ].map((node, i) => (
              <g key={i}>
                <circle cx={node.x} cy={node.y} r={node.r + 8} fill={node.color} opacity="0.15" />
                <circle cx={node.x} cy={node.y} r={node.r} fill={node.color} opacity="0.7" />
                <text x={node.x} y={node.y + node.r + 14} textAnchor="middle" fill="white" fontSize="10" fontFamily="monospace" opacity="0.8">{node.label}</text>
              </g>
            ))}
            {/* Edges */}
            {[
              [300, 150, 150, 80], [300, 150, 450, 80], [300, 150, 200, 230],
              [150, 80, 100, 220], [150, 80, 200, 230], [450, 80, 500, 200],
              [450, 80, 400, 240], [300, 150, 400, 240],
            ].map(([x1, y1, x2, y2], i) => (
              <line key={i} x1={x1} y1={y1} x2={x2} y2={y2} stroke="rgba(129,140,248,0.3)" strokeWidth="1.5" />
            ))}
          </svg>

          <div style={{ marginTop: '32px' }}>
            <span style={{ padding: '8px 24px', borderRadius: '999px', background: 'rgba(129,140,248,0.12)', border: '1px solid rgba(129,140,248,0.3)', fontFamily: 'var(--font-mono)', fontSize: '13px', color: 'var(--module-graph)', fontWeight: 700 }}>
              🔧 Phase 5 — Powered by three.js + 3d-force-graph
            </span>
          </div>

          <div style={{ marginTop: '24px', display: 'flex', gap: '16px', flexWrap: 'wrap', justifyContent: 'center' }}>
            {['Files', 'IP Addresses', 'Domains', 'URLs', 'MITRE Nodes', 'Real-time Layout', 'Click-to-Investigate'].map(f => (
              <span key={f} style={{ padding: '5px 14px', borderRadius: '999px', background: 'rgba(129,140,248,0.06)', border: '1px solid rgba(129,140,248,0.15)', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--module-graph)' }}>
                {f}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
