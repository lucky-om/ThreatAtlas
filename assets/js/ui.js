/**
 * ThreatAtlas — UI Component Library
 * Renders threat gauges, engine grids, detection tables, toasts, etc.
 */

/* ── Threat Gauge ─────────────────────────────────────────────────────────── */
function renderGauge(containerId, score, verdict) {
  const el = document.getElementById(containerId);
  if (!el) return;

  const r         = 54;
  const cx        = 70;
  const cy        = 70;
  const circ      = 2 * Math.PI * r;
  const fillPct   = Math.max(0, Math.min(100, score)) / 100;
  const dashArray = `${fillPct * circ} ${circ}`;

  const colorMap = {
    malicious:  '#ef4444',
    suspicious: '#f59e0b',
    clean:      '#00bfa0',
    unknown:    '#64748b',
  };

  const color = colorMap[verdict] || colorMap.unknown;

  el.innerHTML = `
    <svg class="gauge-svg" width="140" height="140" viewBox="0 0 140 140" role="img" aria-label="Threat score: ${score}">
      <circle class="gauge-track" cx="${cx}" cy="${cy}" r="${r}" />
      <circle
        class="gauge-fill"
        cx="${cx}" cy="${cy}" r="${r}"
        stroke="${color}"
        stroke-dasharray="0 ${circ}"
        id="gauge-fill-${containerId}"
      />
      <text class="gauge-score" x="${cx}" y="${cy - 8}" fill="${color}">${score}</text>
      <text class="gauge-label" x="${cx}" y="${cy + 14}" fill="var(--text-muted)">/ 100</text>
    </svg>
  `;

  // Animate after render
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      const fill = document.getElementById(`gauge-fill-${containerId}`);
      if (fill) fill.setAttribute('stroke-dasharray', dashArray);
    });
  });
}

/* ── Verdict Badge ────────────────────────────────────────────────────────── */
function verdictBadge(verdict, count) {
  const map = {
    malicious:  { cls: 'badge-malicious', label: 'Malicious' },
    suspicious: { cls: 'badge-suspicious', label: 'Suspicious' },
    clean:      { cls: 'badge-clean',      label: 'Clean' },
    unknown:    { cls: 'badge-unknown',    label: 'Unknown' },
    undetected: { cls: 'badge-undetected', label: 'Undetected' },
  };

  const m     = map[verdict] || map.unknown;
  const label = count !== undefined ? `${count} ${m.label}` : m.label;

  return `<span class="badge ${m.cls}">${label}</span>`;
}

/* ── Stats Summary Bar ────────────────────────────────────────────────────── */
function renderStatsSummary(containerId, stats) {
  const el = document.getElementById(containerId);
  if (!el || !stats) return;

  const { malicious = 0, suspicious = 0, harmless = 0, undetected = 0 } = stats;
  const total = malicious + suspicious + harmless + undetected;

  el.innerHTML = `
    <div class="result-stats-grid">
      <div class="result-stat result-stat--malicious">
        <span class="result-stat-num">${malicious}</span>
        <span class="result-stat-label">Malicious</span>
      </div>
      <div class="result-stat result-stat--suspicious">
        <span class="result-stat-num">${suspicious}</span>
        <span class="result-stat-label">Suspicious</span>
      </div>
      <div class="result-stat result-stat--clean">
        <span class="result-stat-num">${harmless}</span>
        <span class="result-stat-label">Harmless</span>
      </div>
      <div class="result-stat result-stat--undetected">
        <span class="result-stat-num">${undetected}</span>
        <span class="result-stat-label">Undetected</span>
      </div>
      <div class="result-stat result-stat--total">
        <span class="result-stat-num">${total}</span>
        <span class="result-stat-label">Total Engines</span>
      </div>
    </div>
  `;
}

/* ── Engine Results Grid ──────────────────────────────────────────────────── */
function renderEngineGrid(containerId, engines, filter = 'all') {
  const el = document.getElementById(containerId);
  if (!el) return;

  let filtered = engines;
  if (filter === 'detected')   filtered = engines.filter(e => e.detected);
  if (filter === 'clean')      filtered = engines.filter(e => !e.detected && e.category !== 'timeout');
  if (filter === 'timeout')    filtered = engines.filter(e => e.category === 'timeout');

  if (filtered.length === 0) {
    el.innerHTML = `<p class="text-muted text-center" style="padding:2rem">No engines in this category.</p>`;
    return;
  }

  el.innerHTML = `
    <div class="engine-grid">
      ${filtered.map(e => `
        <div class="engine-row ${e.detected ? 'detected' : ''}">
          <span class="engine-name">${escHtml(e.engine)}</span>
          <span class="engine-result">${
            e.detected
              ? escHtml(e.result || e.category)
              : `<span style="color:var(--text-muted)">${escHtml(e.category || 'clean')}</span>`
          }</span>
        </div>
      `).join('')}
    </div>
  `;
}

/* ── Detail Panel ─────────────────────────────────────────────────────────── */
function renderDetailRows(containerId, rows) {
  const el = document.getElementById(containerId);
  if (!el) return;

  el.innerHTML = rows
    .filter(r => r.value !== undefined && r.value !== null && r.value !== '')
    .map(r => `
      <div class="detail-row">
        <span class="detail-key">${escHtml(r.key)}</span>
        <span class="detail-value ${r.mono !== false ? 'mono' : ''}">${
          r.html ? r.value : escHtml(String(r.value))
        }</span>
      </div>
    `).join('');
}

/* ── Toast Notifications ──────────────────────────────────────────────────── */
let toastContainer = null;

function getToastContainer() {
  if (!toastContainer) {
    toastContainer = document.createElement('div');
    toastContainer.className = 'toast-container';
    toastContainer.setAttribute('role', 'status');
    toastContainer.setAttribute('aria-live', 'polite');
    document.body.appendChild(toastContainer);
  }
  return toastContainer;
}

function showToast(message, type = 'info', duration = 4000) {
  const container = getToastContainer();
  const iconMap = {
    success: `<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="7" stroke="#00bfa0" stroke-width="1.5"/><path d="M5 8l2 2 4-4" stroke="#00bfa0" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
    danger:  `<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="7" stroke="#ef4444" stroke-width="1.5"/><path d="M8 5v3.5M8 11h.01" stroke="#ef4444" stroke-width="1.5" stroke-linecap="round"/></svg>`,
    warning: `<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M8 2L14 13H2L8 2z" stroke="#f59e0b" stroke-width="1.5" stroke-linejoin="round"/><path d="M8 6v3.5M8 11h.01" stroke="#f59e0b" stroke-width="1.5" stroke-linecap="round"/></svg>`,
    info:    `<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="7" stroke="#60a5fa" stroke-width="1.5"/><path d="M8 7.5v4M8 5.5h.01" stroke="#60a5fa" stroke-width="1.5" stroke-linecap="round"/></svg>`,
  };

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `
    <span class="toast-icon">${iconMap[type] || iconMap.info}</span>
    <span>${escHtml(message)}</span>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(8px)';
    toast.style.transition = 'all 0.25s ease';
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

/* ── Scan Progress UI ─────────────────────────────────────────────────────── */
function showScanProgress(containerId, status, attempt, maxAttempts) {
  const el = document.getElementById(containerId);
  if (!el) return;

  const pct = Math.round((attempt / maxAttempts) * 100);
  const statusLabel = {
    queued:       'Queued — waiting for analysis engines…',
    'in-progress': `Scanning… (${attempt}/${maxAttempts})`,
    completed:    'Analysis complete.',
  }[status] || status;

  el.innerHTML = `
    <div class="scan-progress-wrap">
      <div class="scan-progress-anim">
        <div class="spinner spinner-lg"></div>
        <div class="scan-line-anim"></div>
      </div>
      <p class="scan-status-label">${escHtml(statusLabel)}</p>
      <div class="scan-progress-bar-wrap" role="progressbar" aria-valuenow="${pct}" aria-valuemin="0" aria-valuemax="100">
        <div class="scan-progress-bar" style="width:${pct}%"></div>
      </div>
      <p class="scan-progress-pct text-muted">${pct}%</p>
    </div>
  `;
}

/* ── Format Helpers ───────────────────────────────────────────────────────── */
function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatBytes(bytes) {
  if (bytes === undefined || bytes === null) return '—';
  if (bytes === 0) return '0 B';
  const k     = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i     = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

function formatDate(ts) {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleString('en-US', {
    year:   'numeric',
    month:  'short',
    day:    'numeric',
    hour:   '2-digit',
    minute: '2-digit',
    timeZoneName: 'short',
  });
}

function formatHashShort(hash, len = 12) {
  if (!hash) return '—';
  return `${hash.slice(0, len)}…${hash.slice(-6)}`;
}

function copyToClipboard(text, label = 'Value') {
  navigator.clipboard.writeText(text)
    .then(() => showToast(`${label} copied to clipboard.`, 'success', 2500))
    .catch(() => showToast('Copy failed — please copy manually.', 'warning'));
}

/* ── Navigation Active State ──────────────────────────────────────────────── */
function setActiveNav() {
  const path = window.location.pathname.split('/').pop() || 'index.html';
  document.querySelectorAll('.nav-link').forEach(link => {
    const href = link.getAttribute('href') || '';
    if (href === path || (path === 'index.html' && href === './') || href === path.replace('.html', '')) {
      link.classList.add('active');
    }
  });
}

/* ── Nav Scroll Behavior ──────────────────────────────────────────────────── */
function initNav() {
  const nav = document.querySelector('.nav');
  if (!nav) return;

  const onScroll = () => {
    nav.classList.toggle('scrolled', window.scrollY > 20);
  };
  window.addEventListener('scroll', onScroll, { passive: true });

  // Mobile hamburger
  const hamburger = document.querySelector('.nav-hamburger');
  const mobile    = document.querySelector('.nav-mobile');
  if (hamburger && mobile) {
    hamburger.addEventListener('click', () => {
      const open = mobile.classList.toggle('open');
      hamburger.setAttribute('aria-expanded', String(open));
      document.body.style.overflow = open ? 'hidden' : '';
    });

    // Close on link click
    mobile.querySelectorAll('.nav-link').forEach(link => {
      link.addEventListener('click', () => {
        mobile.classList.remove('open');
        document.body.style.overflow = '';
      });
    });
  }

  setActiveNav();
}

/* ── Counter Animation ────────────────────────────────────────────────────── */
function animateCounter(el, target, duration = 2000, suffix = '') {
  const start    = 0;
  const step     = (timestamp) => {
    if (!startTime) startTime = timestamp;
    const elapsed = timestamp - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const eased    = 1 - Math.pow(1 - progress, 3); // ease-out cubic
    const current  = Math.round(start + (target - start) * eased);
    el.textContent = current.toLocaleString() + suffix;
    if (progress < 1) requestAnimationFrame(step);
  };
  let startTime = null;
  requestAnimationFrame(step);
}

function initCounters() {
  const els = document.querySelectorAll('[data-counter]');
  if (!els.length) return;

  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const el     = entry.target;
        const target = parseInt(el.dataset.counter, 10);
        const suffix = el.dataset.suffix || '';
        animateCounter(el, target, 2200, suffix);
        observer.unobserve(el);
      }
    });
  }, { threshold: 0.3 });

  els.forEach(el => observer.observe(el));
}

/* ── Skeleton Loaders ─────────────────────────────────────────────────────── */
function showSkeletons(containerId, count = 5, height = 48) {
  const el = document.getElementById(containerId);
  if (!el) return;
  el.innerHTML = Array(count).fill(0).map(() =>
    `<div class="skeleton" style="height:${height}px;margin-bottom:8px;border-radius:6px"></div>`
  ).join('');
}

/* ── Tab Controller ───────────────────────────────────────────────────────── */
function initTabs(containerEl) {
  const buttons = containerEl.querySelectorAll('.tab-btn');
  const panes   = containerEl.querySelectorAll('.tab-pane');

  buttons.forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.tab;
      buttons.forEach(b => b.classList.toggle('active', b === btn));
      panes.forEach(p => p.classList.toggle('active', p.id === target));
    });
  });

  // Activate first
  if (buttons[0]) buttons[0].click();
}

/* ── Expose globals ───────────────────────────────────────────────────────── */
window.ThreatAtlasUI = {
  renderGauge,
  verdictBadge,
  renderStatsSummary,
  renderEngineGrid,
  renderDetailRows,
  showToast,
  showScanProgress,
  escHtml,
  formatBytes,
  formatDate,
  formatHashShort,
  copyToClipboard,
  initNav,
  initCounters,
  showSkeletons,
  initTabs,
};
