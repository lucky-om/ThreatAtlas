import React, { useState } from 'react';
import { EngineResult } from '../services/api';

interface EngineGridProps {
  results: EngineResult[];
}

export const EngineGrid: React.FC<EngineGridProps> = ({ results }) => {
  const [filter, setFilter] = useState<'all' | 'malicious' | 'clean' | 'unrated'>('all');
  const [searchQuery, setSearchQuery] = useState('');

  const engineList = results || [];
  
  const maliciousCount = engineList.filter(r => r.category === 'malicious').length;
  const cleanCount = engineList.filter(r => r.category === 'undetected' || r.category === 'harmless').length;
  const unratedCount = engineList.length - maliciousCount - cleanCount;

  const filteredResults = engineList.filter(r => {
    const matchesSearch = searchQuery === '' || 
      r.engine.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (r.result && r.result.toLowerCase().includes(searchQuery.toLowerCase()));

    if (!matchesSearch) return false;

    if (filter === 'all') return true;
    if (filter === 'malicious') return r.category === 'malicious';
    if (filter === 'clean') return r.category === 'undetected' || r.category === 'harmless';
    return r.category !== 'malicious' && r.category !== 'undetected' && r.category !== 'harmless';
  });

  return (
    <div>
      {/* Controls & Filter Bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          <button 
            className="font-label-caps"
            style={{ 
              padding: '6px 14px', 
              borderRadius: '6px', 
              cursor: 'pointer',
              border: filter === 'all' ? '1px solid var(--primary)' : '1px solid rgba(255,255,255,0.08)',
              background: filter === 'all' ? 'rgba(255, 69, 0, 0.12)' : 'rgba(255,255,255,0.02)', 
              color: filter === 'all' ? 'var(--primary)' : 'var(--on-surface-variant)',
              transition: 'all 0.2s ease'
            }}
            onClick={() => setFilter('all')}
          >
            All ({engineList.length})
          </button>
          
          <button 
            className="font-label-caps"
            style={{ 
              padding: '6px 14px', 
              borderRadius: '6px', 
              cursor: 'pointer',
              border: filter === 'malicious' ? '1px solid var(--secondary)' : '1px solid rgba(255,255,255,0.08)',
              background: filter === 'malicious' ? 'rgba(255, 42, 95, 0.15)' : 'rgba(255,255,255,0.02)', 
              color: filter === 'malicious' ? 'var(--secondary)' : 'var(--on-surface-variant)',
              transition: 'all 0.2s ease'
            }}
            onClick={() => setFilter('malicious')}
          >
            Malicious ({maliciousCount})
          </button>
          
          <button 
            className="font-label-caps"
            style={{ 
              padding: '6px 14px', 
              borderRadius: '6px', 
              cursor: 'pointer',
              border: filter === 'clean' ? '1px solid #00ffa3' : '1px solid rgba(255,255,255,0.08)',
              background: filter === 'clean' ? 'rgba(0, 255, 163, 0.12)' : 'rgba(255,255,255,0.02)', 
              color: filter === 'clean' ? 'var(--brand-amber)' : 'var(--on-surface-variant)',
              transition: 'all 0.2s ease'
            }}
            onClick={() => setFilter('clean')}
          >
            Clean ({cleanCount})
          </button>

          {unratedCount > 0 && (
            <button 
              className="font-label-caps"
              style={{ 
                padding: '6px 14px', 
                borderRadius: '6px', 
                cursor: 'pointer',
                border: filter === 'unrated' ? '1px solid rgba(255,255,255,0.3)' : '1px solid rgba(255,255,255,0.08)',
                background: filter === 'unrated' ? 'rgba(255,255,255,0.1)' : 'rgba(255,255,255,0.02)', 
                color: filter === 'unrated' ? '#fff' : 'var(--on-surface-variant)',
                transition: 'all 0.2s ease'
              }}
              onClick={() => setFilter('unrated')}
            >
              Unrated ({unratedCount})
            </button>
          )}
        </div>

        {/* Search Filter Input */}
        <div style={{ position: 'relative', width: '220px' }}>
          <span className="material-symbols-outlined" style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', fontSize: '16px', color: 'var(--on-surface-variant)' }}>
            search
          </span>
          <input 
            type="text" 
            placeholder="Filter vendor or malware..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              width: '100%',
              padding: '6px 12px 6px 32px',
              background: 'rgba(0, 0, 0, 0.3)',
              border: '1px solid rgba(255, 255, 255, 0.1)',
              borderRadius: '6px',
              color: '#fff',
              fontSize: '12px',
              fontFamily: 'var(--font-mono)',
              outline: 'none',
            }}
          />
        </div>
      </div>

      {/* 2-Column Scanner-Style Engine Rows */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
        gap: '0 32px',
      }}>
        {filteredResults.map((item, i) => {
          const isMalicious = item.category === 'malicious';
          const isClean = item.category === 'undetected' || item.category === 'harmless';
          
          let icon = 'help_outline';
          let iconColor = '#6b7280';
          let statusText = item.result || 'Unrated';
          let statusColor = '#9ca3af';

          if (isMalicious) {
            icon = 'cancel';
            iconColor = '#ff2a5f';
            statusText = item.result || 'Malicious';
            statusColor = '#ff2a5f';
          } else if (isClean) {
            icon = 'check_circle';
            iconColor = '#00e5a3';
            statusText = 'Undetected';
            statusColor = '#d1d5db';
          }

          return (
            <div 
              key={i} 
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '12px 14px',
                borderBottom: '1px solid rgba(255, 255, 255, 0.04)',
                transition: 'background 0.15s ease',
              }}
              onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.02)'; }}
              onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; }}
            >
              <span className="font-data-mono" style={{ fontSize: '13px', color: '#e2e8f0', fontWeight: 500 }}>
                {item.engine}
              </span>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined" style={{ color: iconColor, fontSize: '18px' }}>
                  {icon}
                </span>
                <span 
                  className="font-code-sm" 
                  style={{ 
                    color: statusColor, 
                    fontWeight: isMalicious ? 600 : 400,
                    fontSize: '13px',
                    maxWidth: '200px',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap'
                  }}
                  title={statusText}
                >
                  {statusText}
                </span>
              </div>
            </div>
          );
        })}

        {filteredResults.length === 0 && (
          <div style={{ gridColumn: '1 / -1', textAlign: 'center', padding: '48px', color: 'var(--on-surface-variant)' }} className="font-data-mono">
            No security engines match your search or filter.
          </div>
        )}
      </div>
    </div>
  );
};
