import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  History, 
  X, 
  Search, 
  FileText, 
  Link as LinkIcon, 
  Globe, 
  Network, 
  Trash2, 
  Download, 
  Clock, 
  ShieldCheck, 
  AlertTriangle,
  ArrowUpRight
} from 'lucide-react';
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
      case 'file': return <FileText size={15} style={{ color: 'var(--scan-file)' }} />;
      case 'url': return <LinkIcon size={15} style={{ color: 'var(--scan-url)' }} />;
      case 'domain': return <Globe size={15} style={{ color: 'var(--scan-domain)' }} />;
      case 'ip': return <Network size={15} style={{ color: 'var(--scan-ip)' }} />;
      default: return <Search size={15} style={{ color: 'var(--accent)' }} />;
    }
  };

  const getScanTypeColor = (type: HistoryItem['type']) => {
    switch (type) {
      case 'file': return 'var(--scan-file)';
      case 'url': return 'var(--scan-url)';
      case 'domain': return 'var(--scan-domain)';
      case 'ip': return 'var(--scan-ip)';
      default: return 'var(--accent)';
    }
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <div style={{ position: 'fixed', inset: 0, zIndex: 1000, display: 'flex', justifyContent: 'flex-end' }}>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            onClick={onClose}
            style={{
              position: 'absolute',
              inset: 0,
              background: 'rgba(6, 8, 9, 0.75)',
              backdropFilter: 'blur(8px)',
              WebkitBackdropFilter: 'blur(8px)',
            }}
          />

          {/* Drawer Body */}
          <motion.div
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', damping: 28, stiffness: 280 }}
            style={{
              position: 'relative',
              width: '100%',
              maxWidth: '480px',
              height: '100%',
              background: 'var(--surface)',
              borderLeft: '1px solid var(--border)',
              boxShadow: '-12px 0 48px rgba(0, 0, 0, 0.7)',
              display: 'flex',
              flexDirection: 'column',
              zIndex: 1001,
            }}
          >
            {/* Top Header */}
            <div style={{
              padding: '20px 24px',
              borderBottom: '1px solid var(--border)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              background: 'var(--surface-2)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{
                  width: '36px',
                  height: '36px',
                  borderRadius: '8px',
                  background: 'var(--primary-dim)',
                  border: '1px solid var(--primary-border)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: 'var(--primary)',
                }}>
                  <History size={18} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--text)', fontFamily: 'var(--font-display)' }}>
                    Scan History
                  </h3>
                  <div style={{ fontSize: '11px', color: 'var(--text-2)', fontFamily: 'var(--font-mono)', marginTop: '2px' }}>
                    {history.length} persistent scan {history.length === 1 ? 'record' : 'records'}
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <button
                  onClick={exportJson}
                  title="Export History as JSON"
                  className="btn-ghost"
                  style={{ padding: '5px 9px', fontSize: '11px', fontFamily: 'var(--font-mono)', gap: '4px' }}
                >
                  <Download size={12} /> JSON
                </button>
                <button
                  onClick={exportCsv}
                  title="Export History as CSV"
                  className="btn-ghost"
                  style={{ padding: '5px 9px', fontSize: '11px', fontFamily: 'var(--font-mono)', gap: '4px' }}
                >
                  <Download size={12} /> CSV
                </button>
                <button
                  onClick={onClose}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: 'var(--text-2)',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    padding: '6px',
                    borderRadius: '6px',
                    transition: 'all var(--t-fast)',
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.color = 'var(--text)';
                    e.currentTarget.style.backgroundColor = 'var(--surface-hover)';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.color = 'var(--text-2)';
                    e.currentTarget.style.backgroundColor = 'transparent';
                  }}
                  title="Close History"
                >
                  <X size={18} />
                </button>
              </div>
            </div>

            {/* Search & Category Filter */}
            <div style={{
              padding: '16px 24px',
              borderBottom: '1px solid var(--border)',
              display: 'flex',
              flexDirection: 'column',
              gap: '12px',
              background: 'var(--surface)',
            }}>
              {/* Search Box */}
              <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                <Search size={14} style={{ position: 'absolute', left: '12px', color: 'var(--text-3)' }} />
                <input
                  type="text"
                  placeholder="Filter by hash, target, or file name..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  style={{
                    width: '100%',
                    background: 'var(--surface-2)',
                    border: '1px solid var(--border)',
                    borderRadius: 'var(--radius-md)',
                    padding: '8px 12px 8px 34px',
                    color: 'var(--text)',
                    fontSize: '12px',
                    fontFamily: 'var(--font-mono)',
                    outline: 'none',
                    transition: 'border-color var(--t-fast)',
                  }}
                  onFocus={(e) => { e.currentTarget.style.borderColor = 'var(--border-focus)'; }}
                  onBlur={(e) => { e.currentTarget.style.borderColor = 'var(--border)'; }}
                />
              </div>

              {/* Filter Pills */}
              <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                {(['all', 'file', 'url', 'domain', 'ip'] as const).map((cat) => {
                  const count = cat === 'all' ? history.length : history.filter(h => h.type === cat).length;
                  const isActive = filterType === cat;
                  const accentColor = cat === 'all' ? 'var(--primary)' : getScanTypeColor(cat);

                  return (
                    <button
                      key={cat}
                      onClick={() => setFilterType(cat)}
                      style={{
                        background: isActive ? `${accentColor}18` : 'var(--surface-2)',
                        border: `1px solid ${isActive ? accentColor : 'var(--border)'}`,
                        color: isActive ? 'var(--text)' : 'var(--text-2)',
                        padding: '4px 10px',
                        borderRadius: 'var(--radius-sm)',
                        fontSize: '11px',
                        fontFamily: 'var(--font-display)',
                        cursor: 'pointer',
                        fontWeight: isActive ? 600 : 500,
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px',
                        transition: 'all var(--t-fast)',
                      }}
                      onMouseEnter={(e) => {
                        if (!isActive) {
                          e.currentTarget.style.borderColor = 'var(--border-strong)';
                          e.currentTarget.style.color = 'var(--text)';
                        }
                      }}
                      onMouseLeave={(e) => {
                        if (!isActive) {
                          e.currentTarget.style.borderColor = 'var(--border)';
                          e.currentTarget.style.color = 'var(--text-2)';
                        }
                      }}
                    >
                      <span style={{ textTransform: 'capitalize' }}>{cat === 'all' ? 'All Scans' : cat.toUpperCase()}</span>
                      <span style={{
                        background: isActive ? accentColor : 'var(--surface-3)',
                        color: isActive ? '#fff' : 'var(--text-3)',
                        padding: '0 5px',
                        borderRadius: '999px',
                        fontSize: '10px',
                        fontFamily: 'var(--font-mono)',
                        lineHeight: '14px',
                      }}>
                        {count}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* History List */}
            <div style={{
              flex: 1,
              overflowY: 'auto',
              padding: '16px 24px',
              display: 'flex',
              flexDirection: 'column',
              gap: '10px',
            }}>
              {filteredHistory.length > 0 ? (
                filteredHistory.map((item) => {
                  const isMal = item.maliciousCount > 0 || item.threatScore > 0;
                  const badgeColor = isMal ? 'var(--danger)' : 'var(--success)';
                  const badgeBg = isMal ? 'var(--danger-dim)' : 'var(--success-dim)';
                  const badgeBorder = isMal ? 'var(--danger-border)' : 'var(--success-border)';

                  return (
                    <motion.div
                      key={item.timestamp + item.target}
                      whileHover={{ y: -1 }}
                      onClick={() => handleOpenItem(item)}
                      style={{
                        background: 'var(--surface-2)',
                        border: '1px solid var(--border)',
                        borderRadius: 'var(--radius-md)',
                        padding: '12px 14px',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '8px',
                        cursor: 'pointer',
                        transition: 'border-color var(--t-fast), box-shadow var(--t-fast)',
                        position: 'relative',
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.borderColor = 'var(--border-strong)';
                        e.currentTarget.style.boxShadow = '0 4px 12px rgba(0, 0, 0, 0.3)';
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.borderColor = 'var(--border)';
                        e.currentTarget.style.boxShadow = 'none';
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
                          <div style={{
                            width: '24px',
                            height: '24px',
                            borderRadius: '6px',
                            background: 'var(--surface-3)',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            flexShrink: 0,
                          }}>
                            {getTypeIcon(item.type)}
                          </div>
                          <span style={{
                            fontSize: '13px',
                            fontWeight: 600,
                            color: 'var(--text)',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                            fontFamily: 'var(--font-display)',
                          }}>
                            {item.name || item.target}
                          </span>
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
                          <span style={{
                            background: badgeBg,
                            border: `1px solid ${badgeBorder}`,
                            color: badgeColor,
                            padding: '2px 8px',
                            borderRadius: '999px',
                            fontSize: '10px',
                            fontWeight: 700,
                            fontFamily: 'var(--font-mono)',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '4px',
                          }}>
                            {isMal ? (
                              <>
                                <AlertTriangle size={10} />
                                {item.maliciousCount > 0 ? `${item.maliciousCount}/${item.totalEngines}` : 'MALICIOUS'}
                              </>
                            ) : (
                              <>
                                <ShieldCheck size={10} />
                                CLEAN
                              </>
                            )}
                          </span>

                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              removeItem(item.id);
                            }}
                            style={{
                              background: 'none',
                              border: 'none',
                              color: 'var(--text-3)',
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              padding: '4px',
                              borderRadius: '4px',
                              transition: 'all var(--t-fast)',
                            }}
                            onMouseEnter={(e) => {
                              e.currentTarget.style.color = 'var(--danger)';
                              e.currentTarget.style.backgroundColor = 'var(--danger-dim)';
                            }}
                            onMouseLeave={(e) => {
                              e.currentTarget.style.color = 'var(--text-3)';
                              e.currentTarget.style.backgroundColor = 'transparent';
                            }}
                            title="Delete from history"
                          >
                            <Trash2 size={13} />
                          </button>
                        </div>
                      </div>

                      <div style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        fontSize: '11px',
                        color: 'var(--text-3)',
                        fontFamily: 'var(--font-mono)',
                      }}>
                        <span style={{
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                          maxWidth: '260px',
                        }}>
                          {item.hash || item.target}
                        </span>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '4px', flexShrink: 0 }}>
                          <Clock size={10} />
                          <span>{formatRelativeTime(Math.floor(item.timestamp / 1000))}</span>
                          <ArrowUpRight size={11} style={{ opacity: 0.6 }} />
                        </div>
                      </div>
                    </motion.div>
                  );
                })
              ) : (
                <div style={{
                  textAlign: 'center',
                  padding: '60px 20px',
                  color: 'var(--text-3)',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  gap: '12px',
                }}>
                  <div style={{
                    width: '48px',
                    height: '48px',
                    borderRadius: '12px',
                    background: 'var(--surface-2)',
                    border: '1px solid var(--border)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: 'var(--text-3)',
                  }}>
                    <History size={24} />
                  </div>
                  <div>
                    <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-2)', fontFamily: 'var(--font-display)' }}>
                      No scan records found
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-3)', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
                      {searchQuery ? 'Try adjusting your search filter' : 'Scanned files, URLs, IPs and domains will be saved here'}
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Bottom Actions */}
            {history.length > 0 && (
              <div style={{
                padding: '14px 24px',
                borderTop: '1px solid var(--border)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                background: 'var(--surface-2)',
              }}>
                <button
                  onClick={clearHistory}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: 'var(--danger)',
                    cursor: 'pointer',
                    fontSize: '12px',
                    fontFamily: 'var(--font-display)',
                    fontWeight: 500,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    padding: '4px 8px',
                    borderRadius: 'var(--radius-sm)',
                    transition: 'all var(--t-fast)',
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--danger-dim)'; }}
                  onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; }}
                >
                  <Trash2 size={13} />
                  Clear All History
                </button>

                <span style={{ fontSize: '11px', color: 'var(--text-3)', fontFamily: 'var(--font-mono)' }}>
                  Persisted in local storage
                </span>
              </div>
            )}
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
};
