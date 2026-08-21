import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useScanHistory, HistoryItem } from '../services/historyStore';
import { formatRelativeTime } from '../utils/sanitize';

interface ScanHistoryDrawerProps {
  isOpen: boolean;
  onClose: () => void;
}

export const ScanHistoryDrawer: React.FC<ScanHistoryDrawerProps> = ({ isOpen, onClose }) => {
  const { history, removeItem, clearHistory, exportJson, exportCsv } = useScanHistory();
  const [filterType, setFilterType] = useState<'all' | 'file' | 'url' | 'domain' | 'ip'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const navigate = useNavigate();

  if (!isOpen) return null;

  const filteredHistory = history.filter(item => {
    const matchesType = filterType === 'all' || item.type === filterType;
    const matchesSearch = !searchQuery || 
      item.target.toLowerCase().includes(searchQuery.toLowerCase()) || 
      (item.name && item.name.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (item.hash && item.hash.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesType && matchesSearch;
  });

  const handleOpenItem = (item: HistoryItem) => {
    onClose();
    if (item.type === 'file') {
      navigate(`/file/${item.hash || item.target || item.id}`);
    } else if (item.type === 'url') {
      navigate(`/url/${item.id || encodeURIComponent(item.target)}`);
    } else if (item.type === 'ip') {
      navigate(`/ip-address/${item.target}`);
    } else if (item.type === 'domain') {
      navigate(`/domain/${encodeURIComponent(item.target)}`);
    } else {
      navigate(`/search?query=${encodeURIComponent(item.target)}`);
    }
  };

  const getTypeIcon = (type: HistoryItem['type']) => {
    switch (type) {
      case 'file': return 'description';
      case 'url': return 'link';
      case 'domain': return 'language';
      case 'ip': return 'router';
      default: return 'search';
    }
  };

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 1000, display: 'flex', justifyContent: 'flex-end', background: 'rgba(0, 0, 0, 0.7)', backdropFilter: 'blur(6px)', animation: 'fadeIn 0.2s ease' }}>
      
      {/* Click outside backdrop to close */}
      <div style={{ position: 'absolute', inset: 0 }} onClick={onClose}></div>

      {/* Drawer Body */}
      <div style={{
        position: 'relative',
        width: '100%',
        maxWidth: '480px',
        height: '100%',
        background: '#0c1322',
        borderLeft: '1px solid #1e293b',
        boxShadow: '-10px 0 40px rgba(0,0,0,0.8)',
        display: 'flex',
        flexDirection: 'column',
        zIndex: 1001,
        animation: 'slideLeft 0.25s cubic-bezier(0.16, 1, 0.3, 1)'
      }}>

        {/* Top Header */}
        <div style={{ padding: '20px 24px', borderBottom: '1px solid #1e293b', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span className="material-symbols-outlined" style={{ color: '#00f2ff', fontSize: '24px' }}>history</span>
            <div>
              <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 700, color: '#f1f5f9' }}>
                Scan History
              </h3>
              <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
                {history.length} persistent scan records
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <button
              onClick={exportJson}
              title="Export History as JSON"
              style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid #334155', color: '#94a3b8', padding: '5px 8px', borderRadius: '6px', cursor: 'pointer', fontSize: '11px', fontFamily: 'var(--font-mono)' }}
            >
              JSON
            </button>
            <button
              onClick={exportCsv}
              title="Export History as CSV"
              style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid #334155', color: '#94a3b8', padding: '5px 8px', borderRadius: '6px', cursor: 'pointer', fontSize: '11px', fontFamily: 'var(--font-mono)' }}
            >
              CSV
            </button>
            <button
              onClick={onClose}
              style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', display: 'flex', padding: '4px' }}
            >
              <span className="material-symbols-outlined" style={{ fontSize: '22px' }}>close</span>
            </button>
          </div>
        </div>

        {/* Search & Category Filter */}
        <div style={{ padding: '16px 24px', borderBottom: '1px solid rgba(255,255,255,0.04)', display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <input
            type="text"
            placeholder="Search scans by hash, name, url..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              width: '100%',
              background: 'rgba(0,0,0,0.4)',
              border: '1px solid #334155',
              borderRadius: '8px',
              padding: '8px 14px',
              color: '#fff',
              fontSize: '13px',
              fontFamily: 'var(--font-mono)',
              outline: 'none'
            }}
          />

          {/* Filter Badges */}
          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
            {(['all', 'file', 'url', 'domain', 'ip'] as const).map((cat) => {
              const count = cat === 'all' ? history.length : history.filter(h => h.type === cat).length;
              const isActive = filterType === cat;
              return (
                <button
                  key={cat}
                  onClick={() => setFilterType(cat)}
                  style={{
                    background: isActive ? 'rgba(0, 242, 255, 0.15)' : 'rgba(255,255,255,0.03)',
                    border: isActive ? '1px solid #00f2ff' : '1px solid rgba(255,255,255,0.06)',
                    color: isActive ? '#00f2ff' : '#94a3b8',
                    padding: '3px 10px',
                    borderRadius: '6px',
                    fontSize: '11px',
                    fontFamily: 'var(--font-mono)',
                    cursor: 'pointer',
                    textTransform: 'uppercase',
                    fontWeight: isActive ? 700 : 500
                  }}
                >
                  {cat} ({count})
                </button>
              );
            })}
          </div>
        </div>

        {/* History List */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '16px 24px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {filteredHistory.length > 0 ? (
            filteredHistory.map((item) => {
              const isMal = item.maliciousCount > 0 || item.threatScore > 0;
              const badgeColor = isMal ? '#ff2a5f' : '#00ffa3';
              return (
                <div
                  key={item.timestamp + item.target}
                  onClick={() => handleOpenItem(item)}
                  style={{
                    background: 'rgba(255,255,255,0.02)',
                    border: '1px solid #1e293b',
                    borderRadius: '8px',
                    padding: '12px 14px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '8px',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease'
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.borderColor = '#00f2ff'; e.currentTarget.style.background = 'rgba(0,242,255,0.03)'; }}
                  onMouseLeave={(e) => { e.currentTarget.style.borderColor = '#1e293b'; e.currentTarget.style.background = 'rgba(255,255,255,0.02)'; }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className="material-symbols-outlined" style={{ fontSize: '18px', color: '#38bdf8' }}>
                        {getTypeIcon(item.type)}
                      </span>
                      <span style={{ fontSize: '13px', fontWeight: 600, color: '#f1f5f9', maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {item.name || item.target}
                      </span>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span style={{
                        background: `${badgeColor}15`,
                        border: `1px solid ${badgeColor}40`,
                        color: badgeColor,
                        padding: '2px 6px',
                        borderRadius: '4px',
                        fontSize: '10px',
                        fontWeight: 700,
                        fontFamily: 'var(--font-mono)'
                      }}>
                        {item.maliciousCount > 0 ? `${item.maliciousCount}/${item.totalEngines}` : 'CLEAN'}
                      </span>

                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          removeItem(item.id);
                        }}
                        style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', display: 'flex', padding: '2px' }}
                        title="Delete from history"
                      >
                        <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>delete</span>
                      </button>
                    </div>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
                    <span style={{ maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {item.hash || item.target}
                    </span>
                    <span>
                      {formatRelativeTime(Math.floor(item.timestamp / 1000))}
                    </span>
                  </div>
                </div>
              );
            })
          ) : (
            <div style={{ textAlign: 'center', padding: '48px 16px', color: '#64748b' }} className="font-data-mono">
              <span className="material-symbols-outlined" style={{ fontSize: '40px', color: '#334155', marginBottom: '8px' }}>manage_search</span>
              <div>No scan records found.</div>
            </div>
          )}
        </div>

        {/* Bottom Actions */}
        {history.length > 0 && (
          <div style={{ padding: '16px 24px', borderTop: '1px solid #1e293b', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <button
              onClick={clearHistory}
              style={{ background: 'none', border: 'none', color: '#ff2a5f', cursor: 'pointer', fontSize: '12px', fontFamily: 'var(--font-mono)', display: 'flex', alignItems: 'center', gap: '4px' }}
            >
              <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>delete_sweep</span>
              Clear All History
            </button>

            <span style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
              Saved locally
            </span>
          </div>
        )}

      </div>
    </div>
  );
};
