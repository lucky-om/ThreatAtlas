/**
 * cache.ts — High-Performance Client & Memory Caching Engine
 * Provides instant in-memory and local storage memoization for scan results,
 * relations, and threat intelligence lookups to achieve sub-10ms response times.
 */

const MEMORY_CACHE = new Map<string, { data: any; timestamp: number }>();
const DEFAULT_TTL_MS = 10 * 60 * 1000; // 10 minutes cache TTL

export function getCachedItem<T = any>(key: string, ttlMs = DEFAULT_TTL_MS): T | null {
  const cleanKey = `ta_cache_${key.trim().toLowerCase()}`;

  // 1. Check in-memory Map first (Fastest)
  const memItem = MEMORY_CACHE.get(cleanKey);
  if (memItem) {
    if (Date.now() - memItem.timestamp < ttlMs) {
      return memItem.data as T;
    }
    MEMORY_CACHE.delete(cleanKey);
  }

  // 2. Check localStorage (Persistent across page reloads)
  try {
    const stored = localStorage.getItem(cleanKey);
    if (stored) {
      const parsed = JSON.parse(stored);
      if (Date.now() - parsed.timestamp < ttlMs) {
        // Populate memory cache for subsequent calls
        MEMORY_CACHE.set(cleanKey, parsed);
        return parsed.data as T;
      }
      localStorage.removeItem(cleanKey);
    }
  } catch (_) {}

  return null;
}

export function setCachedItem<T = any>(key: string, data: T): void {
  if (!key || !data) return;
  const cleanKey = `ta_cache_${key.trim().toLowerCase()}`;
  const entry = { data, timestamp: Date.now() };

  // Store in memory
  MEMORY_CACHE.set(cleanKey, entry);

  // Store in localStorage
  try {
    localStorage.setItem(cleanKey, JSON.stringify(entry));
  } catch (_) {
    // If storage is full, prune oldest cache entries
    try {
      pruneOldCache();
      localStorage.setItem(cleanKey, JSON.stringify(entry));
    } catch (_) {}
  }
}

export function clearCache(): void {
  MEMORY_CACHE.clear();
  try {
    const keysToRemove: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && k.startsWith('ta_cache_')) {
        keysToRemove.push(k);
      }
    }
    keysToRemove.forEach(k => localStorage.removeItem(k));
  } catch (_) {}
}

function pruneOldCache(): void {
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && k.startsWith('ta_cache_')) {
        localStorage.removeItem(k);
      }
    }
  } catch (_) {}
}
