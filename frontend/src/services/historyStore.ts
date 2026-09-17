/**
 * historyStore.ts — Persistent User Scan History Engine
 * Automatically tracks and indexes scanned files, URLs, domains, and IPs.
 * Provides real-time reactive hooks, category filters, and 1-click JSON/CSV exports.
 */

import { useState, useEffect } from 'react';

export interface HistoryItem {
  id: string;
  target: string;
  type: 'file' | 'url' | 'domain' | 'ip';
  name?: string;
  hash?: string;
  verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  threatScore: number;
  maliciousCount: number;
  totalEngines: number;
  fileSize?: number;
  timestamp: number; // ms
}

const HISTORY_STORAGE_KEY = 'ta_user_scan_history_v1';
const MAX_HISTORY_ITEMS = 100;

// Internal event emitter for live multi-component sync
type HistoryListener = () => void;
const listeners = new Set<HistoryListener>();

function notifyListeners() {
  listeners.forEach(cb => cb());
}

export function getScanHistory(): HistoryItem[] {
  try {
    const raw = localStorage.getItem(HISTORY_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (_) {
    return [];
  }
}

export function addScanHistoryItem(item: Omit<HistoryItem, 'timestamp'>): void {
  try {
    const history = getScanHistory();
    // Remove if already exists with same target to push to top
    const filtered = history.filter(h => h.target.toLowerCase() !== item.target.toLowerCase() && h.id !== item.id);
    
    const newItem: HistoryItem = {
      ...item,
      timestamp: Date.now()
    };

    const updated = [newItem, ...filtered].slice(0, MAX_HISTORY_ITEMS);
    localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(updated));
    notifyListeners();
  } catch (_) { /* localStorage unavailable — skip history write */ }
}

export function removeScanHistoryItem(id: string): void {
  try {
    const history = getScanHistory();
    const updated = history.filter(h => h.id !== id && h.target !== id);
    localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(updated));
    notifyListeners();
  } catch (_) { /* localStorage unavailable — skip history update */ }
}

export function clearScanHistory(): void {
  try {
    localStorage.removeItem(HISTORY_STORAGE_KEY);
    notifyListeners();
  } catch (_) { /* localStorage unavailable — skip clear */ }
}

export function exportHistoryAsJson(): void {
  const history = getScanHistory();
  const blob = new Blob([JSON.stringify(history, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `ThreatAtlas_Scan_History_${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

export function exportHistoryAsCsv(): void {
  const history = getScanHistory();
  const headers = ['Timestamp', 'Type', 'Target', 'Name', 'Verdict', 'Threat Score', 'Malicious Detections', 'Total Engines', 'Hash'];
  const rows = history.map(h => [
    new Date(h.timestamp).toISOString(),
    h.type,
    `"${h.target.replace(/"/g, '""')}"`,
    `"${(h.name || '').replace(/"/g, '""')}"`,
    h.verdict,
    h.threatScore,
    h.maliciousCount,
    h.totalEngines,
    h.hash || ''
  ]);

  const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `ThreatAtlas_Scan_History_${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

/**
 * React Hook for consuming reactive scan history.
 */
export function useScanHistory() {
  const [history, setHistory] = useState<HistoryItem[]>(getScanHistory);

  useEffect(() => {
    const update = () => setHistory(getScanHistory());
    listeners.add(update);
    return () => {
      listeners.delete(update);
    };
  }, []);

  return {
    history,
    addItem: addScanHistoryItem,
    removeItem: removeScanHistoryItem,
    clearHistory: clearScanHistory,
    exportJson: exportHistoryAsJson,
    exportCsv: exportHistoryAsCsv
  };
}
