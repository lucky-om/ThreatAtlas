import React, { useState } from 'react';
import { EngineResult } from '../services/api';

interface EngineGridProps {
  results: EngineResult[];
}

export const EngineGrid: React.FC<EngineGridProps> = ({ results }) => {
  const [filter, setFilter] = useState<'all' | 'malicious' | 'clean' | 'unrated'>('all');

  const engineList = results || [];
  
  const maliciousCount = engineList.filter(r => r.category === 'malicious').length;
  const cleanCount = engineList.filter(r => r.category === 'undetected' || r.category === 'harmless').length;
  const unratedCount = engineList.length - maliciousCount - cleanCount;

  const filteredResults = engineList.filter(r => {
    if (filter === 'all') return true;
    if (filter === 'malicious') return r.category === 'malicious';
    if (filter === 'clean') return r.category === 'undetected' || r.category === 'harmless';
    return r.category !== 'malicious' && r.category !== 'undetected' && r.category !== 'harmless';
  });

  return (
    <div>
      <div style={{ display: 'flex', gap: '8px', marginBottom: '24px', flexWrap: 'wrap' }}>
        <button 
          className={`btn-primary ${filter === 'all' ? '' : 'inactive'}`}
          style={{ background: filter === 'all' ? 'var(--primary)' : 'rgba(255,255,255,0.05)', color: filter === 'all' ? '#00363a' : 'var(--on-surface)' }}
          onClick={() => setFilter('all')}
        >
          All ({engineList.length})
        </button>
        <button 
          className="btn-primary"
          style={{ background: filter === 'malicious' ? 'var(--secondary)' : 'rgba(255,255,255,0.05)', color: filter === 'malicious' ? '#fff' : 'var(--on-surface)', boxShadow: filter === 'malicious' ? '0 0 15px rgba(255,0,60,0.5)' : 'none' }}
          onClick={() => setFilter('malicious')}
        >
          Malicious ({maliciousCount})
        </button>
        <button 
          className="btn-primary"
          style={{ background: filter === 'clean' ? 'var(--primary)' : 'rgba(255,255,255,0.05)', color: filter === 'clean' ? '#00363a' : 'var(--on-surface)' }}
          onClick={() => setFilter('clean')}
        >
          Clean ({cleanCount})
        </button>
        <button 
          className="btn-primary"
          style={{ background: filter === 'unrated' ? 'rgba(255,255,255,0.2)' : 'rgba(255,255,255,0.05)', color: 'var(--on-surface)' }}
          onClick={() => setFilter('unrated')}
        >
          Unrated ({unratedCount})
        </button>
      </div>

      <div className="engine-grid">
        {filteredResults.map((item, i) => {
          const isMalicious = item.category === 'malicious';
          const isClean = item.category === 'undetected' || item.category === 'harmless';
          
          let icon = 'help';
          let iconColor = 'var(--on-surface-variant)';
          let statusText = 'Unrated';
          let statusClass = 'status-unrated';
          let border = '1px solid rgba(255,255,255,0.1)';
          let shadow = 'none';

          if (isMalicious) {
            icon = 'warning';
            iconColor = 'var(--secondary)';
            statusText = item.result || 'Malicious';
            statusClass = 'status-malicious';
            border = '1px solid rgba(255,0,60,0.3)';
            shadow = '0 0 10px rgba(255,0,60,0.1)';
          } else if (isClean) {
            icon = 'check_circle';
            iconColor = 'var(--primary)';
            statusText = 'Clean';
            statusClass = 'status-clean';
            border = '1px solid rgba(0,242,255,0.1)';
          }

          return (
            <div key={i} className="engine-item" style={{ border, boxShadow: shadow }}>
              <span className="font-data-mono">{item.engine}</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className={`engine-status-text font-code-sm ${statusClass}`} style={{ color: iconColor }}>{statusText}</span>
                <span className="material-symbols-outlined" style={{ color: iconColor, fontSize: '18px' }}>{icon}</span>
              </div>
            </div>
          );
        })}
        {filteredResults.length === 0 && (
          <div style={{ gridColumn: '1 / -1', textAlign: 'center', padding: '32px', color: 'var(--on-surface-variant)' }}>
            No engines found matching this filter.
          </div>
        )}
      </div>
    </div>
  );
};
