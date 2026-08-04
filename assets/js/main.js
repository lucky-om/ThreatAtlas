/**
 * ThreatAtlas — Main Page Controller
 * Handles home page scanner, routing to results, and shared page setup.
 */

(function () {
  'use strict';

  const API = window.ThreatAtlasAPI;
  const UI  = window.ThreatAtlasUI;

  // ── Init on DOM ready ───────────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', () => {
    UI.initNav();
    UI.initCounters();
    initScanner();
    initDropZone();
    initRecentScansDemo();
    initFeatureCards();
  });

  // ── Scanner Bar ─────────────────────────────────────────────────────────
  function initScanner() {
    const form       = document.getElementById('scanner-form');
    const input      = document.getElementById('scanner-input');
    const tabBtns    = document.querySelectorAll('.scanner-tab');
    const scanBtn    = document.getElementById('scan-btn');
    const fileInput  = document.getElementById('file-input');
    const fileTab    = document.querySelector('[data-tab="file"]');

    if (!form) return;

    let activeTab = 'url';

    // Tab switching
    tabBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        tabBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        activeTab = btn.dataset.tab;

        // Toggle file vs text input
        const inputRow  = document.getElementById('scanner-input-row');
        const dropArea  = document.getElementById('scanner-drop');

        if (activeTab === 'file') {
          inputRow && (inputRow.style.display = 'none');
          dropArea && (dropArea.style.display = 'block');
        } else {
          inputRow && (inputRow.style.display = 'flex');
          dropArea && (dropArea.style.display = 'none');

          // Update placeholder
          const placeholders = {
            url:    'Enter a URL — https://example.com/suspicious',
            ip:     'Enter an IP address — 192.168.1.1',
            domain: 'Enter a domain — malicious-site.com',
            hash:   'Enter SHA256, SHA1, or MD5 hash',
          };
          if (input) input.placeholder = placeholders[activeTab] || '';
        }
      });
    });

    // Form submission
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const value = input ? input.value.trim() : '';
      if (!value && activeTab !== 'file') {
        UI.showToast('Please enter a value to scan.', 'warning');
        input && input.focus();
        return;
      }
      await handleTextScan(value, activeTab, scanBtn);
    });

    // File input change (from drop zone browse click)
    if (fileInput) {
      fileInput.addEventListener('change', async () => {
        const file = fileInput.files[0];
        if (file) await handleFileScan(file);
      });
    }
  }

  async function handleTextScan(value, activeTab, btn) {
    if (btn) setLoading(btn, true);

    // Auto-detect type if not file
    let type = activeTab;
    if (activeTab === 'url' || activeTab === 'domain' || activeTab === 'ip' || activeTab === 'hash') {
      // Trust user selection but fall back to auto-detect
      const detected = API.detectInputType(value);
      if (activeTab === 'url' && detected === 'hash') type = 'hash';
    }

    try {
      let redirectUrl = '';

      if (type === 'hash') {
        redirectUrl = `results.html?type=hash&q=${encodeURIComponent(value)}`;
      } else if (type === 'ip') {
        redirectUrl = `lookup.html?type=ip&q=${encodeURIComponent(value)}`;
      } else if (type === 'domain') {
        redirectUrl = `lookup.html?type=domain&q=${encodeURIComponent(value)}`;
      } else {
        // URL — submit and redirect
        redirectUrl = `results.html?type=url&q=${encodeURIComponent(value)}`;
      }

      window.location.href = redirectUrl;
    } catch (err) {
      UI.showToast(err.message || 'Scan failed. Please try again.', 'danger');
      if (btn) setLoading(btn, false);
    }
  }

  async function handleFileScan(file) {
    // Redirect to results with file indicator; actual scan happens on results.html
    sessionStorage.setItem('ta_pending_file_name', file.name);
    sessionStorage.setItem('ta_pending_file_size', file.size);

    // We need to read file as data URL for cross-page persistence
    // For files < 5MB, store in sessionStorage; otherwise warn
    if (file.size > 5 * 1024 * 1024) {
      UI.showToast('Large file detected. Opening scanner — please re-drop the file on the results page.', 'warning', 5000);
      window.location.href = `results.html?type=file&q=${encodeURIComponent(file.name)}`;
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        sessionStorage.setItem('ta_pending_file_data', e.target.result);
        sessionStorage.setItem('ta_pending_file_type', file.type);
        window.location.href = `results.html?type=file&q=${encodeURIComponent(file.name)}`;
      } catch (storageErr) {
        // Storage quota exceeded
        UI.showToast('File too large for direct transfer. Please re-upload on the results page.', 'warning', 5000);
        window.location.href = `results.html?type=file&q=${encodeURIComponent(file.name)}`;
      }
    };
    reader.readAsDataURL(file);
  }

  function setLoading(btn, loading) {
    btn.disabled = loading;
    btn.innerHTML = loading
      ? `<span class="spinner" style="width:16px;height:16px;border-width:2px"></span> Scanning…`
      : `<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M15 1L8 8M15 1H10M15 1V6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/><path d="M6 3H3a2 2 0 00-2 2v8a2 2 0 002 2h8a2 2 0 002-2v-3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg> Scan Now`;
  }

  // ── Drop Zone ───────────────────────────────────────────────────────────
  function initDropZone() {
    const zone      = document.getElementById('scanner-drop');
    const fileInput = document.getElementById('file-input');
    if (!zone) return;

    zone.addEventListener('click', () => fileInput && fileInput.click());

    zone.addEventListener('dragover', (e) => {
      e.preventDefault();
      zone.classList.add('drag-over');
    });

    zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));

    zone.addEventListener('drop', async (e) => {
      e.preventDefault();
      zone.classList.remove('drag-over');
      const file = e.dataTransfer.files[0];
      if (file) await handleFileScan(file);
    });
  }

  // ── Recent Scans Demo Data ──────────────────────────────────────────────
  const DEMO_SCANS = [
    {
      type: 'URL',
      value: 'hxxps://malware-drop.xyz/payload.exe',
      engines: '47/90',
      verdict: 'malicious',
      date: '2 min ago',
      score: 89
    },
    {
      type: 'File',
      value: 'invoice_march2026.pdf.exe',
      engines: '32/90',
      verdict: 'malicious',
      date: '11 min ago',
      score: 71
    },
    {
      type: 'IP',
      value: '185.220.101.47',
      engines: '18/90',
      verdict: 'suspicious',
      date: '28 min ago',
      score: 38
    },
    {
      type: 'Hash',
      value: 'a3f1e2d4b8c9…7a2d',
      engines: '0/90',
      verdict: 'clean',
      date: '45 min ago',
      score: 0
    },
    {
      type: 'Domain',
      value: 'cdn-update-service.net',
      engines: '12/90',
      verdict: 'suspicious',
      date: '1h ago',
      score: 28
    },
    {
      type: 'URL',
      value: 'hxxps://phish-bank-secure.com/login',
      engines: '61/90',
      verdict: 'malicious',
      date: '1h 20m ago',
      score: 96
    },
    {
      type: 'File',
      value: 'windows_update_patch.bat',
      engines: '5/90',
      verdict: 'suspicious',
      date: '2h ago',
      score: 14
    },
    {
      type: 'Hash',
      value: '5d41402abc4b…f2f6',
      engines: '0/90',
      verdict: 'clean',
      date: '3h ago',
      score: 0
    },
  ];

  function initRecentScansDemo() {
    const tbody = document.getElementById('recent-scans-tbody');
    if (!tbody) return;

    tbody.innerHTML = DEMO_SCANS.map(scan => {
      const verdictMap = {
        malicious:  { cls: 'badge-malicious', label: 'Malicious' },
        suspicious: { cls: 'badge-suspicious', label: 'Suspicious' },
        clean:      { cls: 'badge-clean',      label: 'Clean' },
      };
      const v = verdictMap[scan.verdict] || verdictMap.clean;

      const typeIcon = {
        URL: `<svg width="12" height="12" fill="none" viewBox="0 0 16 16"><path d="M6 10l-3.5 3.5M9 6l3.5-3.5M6.5 9.5l3-3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><circle cx="4.5" cy="11.5" r="2.5" stroke="currentColor" stroke-width="1.5"/><circle cx="11.5" cy="4.5" r="2.5" stroke="currentColor" stroke-width="1.5"/></svg>`,
        File: `<svg width="12" height="12" fill="none" viewBox="0 0 16 16"><path d="M10 2H4a1 1 0 00-1 1v10a1 1 0 001 1h8a1 1 0 001-1V6l-3-4z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M10 2v4h4" stroke="currentColor" stroke-width="1.5"/></svg>`,
        IP: `<svg width="12" height="12" fill="none" viewBox="0 0 16 16"><circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="1.5"/><path d="M2 8h12M8 2c-2 2-3 4-3 6s1 4 3 6M8 2c2 2 3 4 3 6s-1 4-3 6" stroke="currentColor" stroke-width="1.5"/></svg>`,
        Domain: `<svg width="12" height="12" fill="none" viewBox="0 0 16 16"><rect x="2" y="4" width="12" height="9" rx="1" stroke="currentColor" stroke-width="1.5"/><path d="M2 7h12M5 4V3a1 1 0 011-1h4a1 1 0 011 1v1" stroke="currentColor" stroke-width="1.5"/></svg>`,
        Hash: `<svg width="12" height="12" fill="none" viewBox="0 0 16 16"><path d="M6 3v10M10 3v10M3 6h10M3 10h10" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`,
      };

      return `
        <tr>
          <td>
            <span class="type-pill" style="display:inline-flex;align-items:center;gap:5px;padding:3px 8px;font-size:0.7rem;font-family:var(--font-mono);border-radius:4px;background:var(--bg-elevated);border:1px solid var(--border);color:var(--text-muted)">
              ${typeIcon[scan.type] || ''}${scan.type}
            </span>
          </td>
          <td class="mono-cell truncate" style="max-width:280px" title="${UI.escHtml(scan.value)}">${UI.escHtml(scan.value)}</td>
          <td style="color:var(--text-muted);font-family:var(--font-mono);font-size:0.8rem">${scan.engines}</td>
          <td><span class="badge ${v.cls}">${v.label}</span></td>
          <td style="color:var(--text-muted);font-size:0.8125rem">${scan.date}</td>
        </tr>
      `;
    }).join('');
  }

  // ── Feature Cards Animate In ────────────────────────────────────────────
  function initFeatureCards() {
    const cards = document.querySelectorAll('.feature-card');
    if (!cards.length) return;

    const observer = new IntersectionObserver(entries => {
      entries.forEach((entry, i) => {
        if (entry.isIntersecting) {
          setTimeout(() => {
            entry.target.style.opacity = '1';
            entry.target.style.transform = 'translateY(0)';
          }, i * 80);
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.1 });

    cards.forEach(card => {
      card.style.opacity = '0';
      card.style.transform = 'translateY(24px)';
      card.style.transition = 'opacity 0.45s ease, transform 0.45s ease';
      observer.observe(card);
    });
  }

})();
