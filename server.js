const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const path = require('path');
const { Queue, QueueEvents } = require('bullmq');
const { randomUUID } = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Load environment variables from .env file
require('dotenv').config();

// API Keys
const VT_API_KEY = process.env.VT_API_KEY || '';
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || '';
const GROQ_API_KEY = process.env.GROQ_API_KEY || '';
const REDIS_URL = process.env.REDIS_URL || 'redis://127.0.0.1:6379';

// ─────────────────────────────────────────────────────────────────────────────
// BullMQ Queue — file-scan
// Redis connection is optional: if Redis is unavailable the API falls back
// to direct synchronous VT scanning so the app still works without Docker.
// ─────────────────────────────────────────────────────────────────────────────
let fileScanQueue = null;
let queueEvents = null;

try {
  fileScanQueue = new Queue('file-scan', {
    connection: { url: REDIS_URL },
    defaultJobOptions: {
      attempts: 2,
      backoff: { type: 'exponential', delay: 3000 },
      removeOnComplete: { count: 200, age: 3600 },
      removeOnFail: { count: 100 },
    },
  });

  queueEvents = new QueueEvents('file-scan', { connection: { url: REDIS_URL } });

  fileScanQueue.on('error', (err) => {
    console.warn('[Queue] Redis unavailable — falling back to direct scan mode:', err.message);
    fileScanQueue = null;
  });

  console.log('[Queue] BullMQ file-scan queue connected to Redis');
} catch (err) {
  console.warn('[Queue] BullMQ init failed — Redis may not be running. Direct scan mode active.', err.message);
}

// Security Headers Middleware
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// Body parsing — 40MB limit for base64-encoded file uploads via queue API
app.use(express.json({ limit: '40mb' }));
app.use(express.urlencoded({ extended: true, limit: '40mb' }));

// ─────────────────────────────────────────────────────────────────────────────
// Unified AI Chatbot endpoint — Groq with Gemini Fallback
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/ai/chat', async (req, res) => {
  let { messages } = req.body || { messages: [] };
  if (!Array.isArray(messages)) messages = [];

  // Sanitize & bound messages to prevent memory/token abuse
  const sanitizedMessages = messages.slice(-15).map(m => ({
    role: m.role === 'assistant' ? 'assistant' : m.role === 'system' ? 'system' : 'user',
    content: typeof m.content === 'string' ? m.content.slice(0, 4000) : ''
  })).filter(m => m.content.trim().length > 0);

  try {
    if (GROQ_API_KEY) {
      try {
        const groqRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${GROQ_API_KEY}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            model: 'openai/gpt-oss-120b',
            messages: sanitizedMessages,
            max_tokens: 800,
            temperature: 0.7,
          })
        });

        if (groqRes.ok) {
          const groqData = await groqRes.json();
          let reply = groqData.choices?.[0]?.message?.content || '';
          reply = reply.replace(/<think>[\s\S]*?(<\/think>|$)/g, '').trim();
          if (reply) {
            return res.json({ reply });
          }
        }
      } catch (e) {
        console.warn('[Server AI] Groq attempt failed, falling back to Gemini:', e);
      }
    }

    if (GEMINI_API_KEY) {
      const lastUserMsg = sanitizedMessages.filter(m => m.role === 'user').pop()?.content || '';
      const geminiRes = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${GEMINI_API_KEY}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: lastUserMsg }] }],
          generationConfig: { maxOutputTokens: 600, temperature: 0.6 }
        })
      });

      if (geminiRes.ok) {
        const geminiData = await geminiRes.json();
        const reply = geminiData.candidates?.[0]?.content?.parts?.[0]?.text || '';
        return res.json({ reply });
      }
    }

    res.status(500).json({ error: 'AI services unavailable' });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Internal AI Error' });
  }
});

// Serve static files from dist (for production)
app.use(express.static(path.join(__dirname, 'dist')));

// ─────────────────────────────────────────────────────────────────────────────
// Task Queue Endpoints — /api/scan/*
// ─────────────────────────────────────────────────────────────────────────────

const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 33 * 1024 * 1024 } });

// In-memory fallback store with TTL cleanup to prevent memory leaks
const pendingTasks = new Map(); // taskId → { status, progress, report?, error?, analysisId?, createdAtTime }

// Clean up pendingTasks older than 2 hours every 30 minutes
setInterval(() => {
  const now = Date.now();
  const TWO_HOURS = 2 * 60 * 60 * 1000;
  for (const [id, task] of pendingTasks.entries()) {
    if (task.createdAtTime && (now - task.createdAtTime > TWO_HOURS)) {
      pendingTasks.delete(id);
    }
  }
}, 30 * 60 * 1000).unref();

app.post('/api/scan/file', upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file provided. Use field name \'file\'.' });

  const taskId = randomUUID();
  const createdAt = new Date().toISOString();
  const { originalname: fileName, mimetype: mimeType, buffer } = req.file;

  // ── Mode 1: BullMQ queue (Redis available) ────────────────────────────────
  if (fileScanQueue) {
    try {
      const job = await fileScanQueue.add(
        'scan',
        {
          taskId,
          fileName,
          mimeType,
          fileBase64: buffer.toString('base64'),
          fileSize: buffer.length,
          createdAt,
        },
        { jobId: taskId }
      );

      return res.status(202).json({
        task_id: taskId,
        job_id: job.id,
        status: 'queued',
        message: `File "${fileName}" queued for scanning.`,
        poll_url: `/api/scan/status/${taskId}`,
        report_url: `/api/report/${taskId}`,
        created_at: createdAt,
      });
    } catch (err) {
      console.warn('[Queue] Failed to enqueue — falling back to direct mode:', err.message);
    }
  }

  // ── Mode 2: Direct fallback (no Redis) ───────────────────────────────────
  pendingTasks.set(taskId, { status: 'queued', progress: 0, createdAt, fileName });

  // Run the VT upload asynchronously and store result in pendingTasks
  (async () => {
    try {
      pendingTasks.set(taskId, { status: 'in_progress', progress: 15, createdAt, fileName });

      // Upload to VT
      const form = new (require('form-data'))();
      form.append('file', buffer, { filename: fileName, contentType: mimeType });

      const uploadRes = await fetch('https://www.virustotal.com/api/v3/files', {
        method: 'POST',
        headers: { 'x-apikey': VT_API_KEY, ...form.getHeaders() },
        body: form,
      });

      if (!uploadRes.ok) throw new Error(`VT upload ${uploadRes.status}`);
      const uploadData = await uploadRes.json();
      const analysisId = uploadData?.data?.id;
      if (!analysisId) throw new Error('No analysis ID from VT');

      pendingTasks.set(taskId, { status: 'in_progress', progress: 30, createdAt, fileName, analysisId });

      // Poll until complete
      let attempts = 0;
      while (attempts < 24) {
        attempts++;
        await new Promise(r => setTimeout(r, 2500));
        try {
          const pollRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
            headers: { 'x-apikey': VT_API_KEY }
          });
          if (!pollRes.ok) continue;
          const pollData = await pollRes.json();
          const status = pollData?.data?.attributes?.status || 'queued';
          const progress = status === 'completed' ? 90 : Math.min(30 + attempts * 3, 85);
          pendingTasks.set(taskId, { status: 'in_progress', progress, createdAt, fileName, analysisId, _latest: pollData });

          if (status === 'completed') {
            // Try to get full enriched file report
            const sha256 = pollData?.data?.attributes?.sha256
              || pollData?.meta?.file_info?.sha256
              || pollData?.data?.meta?.file_info?.sha256;

            let fileReport = pollData;
            if (sha256) {
              try {
                const fr = await fetch(`https://www.virustotal.com/api/v3/files/${sha256}`, {
                  headers: { 'x-apikey': VT_API_KEY }
                });
                if (fr.ok) fileReport = await fr.json();
              } catch (_) {}
            }

            // Build minimal ThreatReport
            const fa = fileReport?.data?.attributes || {};
            const stats = fa.last_analysis_stats || pollData?.data?.attributes?.stats || {};
            const results = fa.last_analysis_results || pollData?.data?.attributes?.results || {};
            const m = stats.malicious || 0, s = stats.suspicious || 0,
              h = stats.harmless || 0, u = stats.undetected || 0, total = m + s + h + u;

            const report = {
              schema_version: '1.0',
              task_id: taskId,
              scan_type: 'file',
              target: fa.sha256 || sha256 || taskId,
              status: 'completed',
              created_at: createdAt,
              completed_at: new Date().toISOString(),
              verdict: m > 0 ? 'malicious' : s > 0 ? 'suspicious' : 'clean',
              threat_score: total > 0 ? Math.round((m + s) / total * 100) : 0,
              stats: { malicious: m, suspicious: s, harmless: h, undetected: u, total },
              engines: Object.entries(results).map(([engine, r]) => ({
                engine,
                category: r.category || 'undetected',
                result: r.result || null,
                detected: r.category === 'malicious' || r.category === 'suspicious',
              })),
              file_meta: {
                sha256: fa.sha256 || '', sha1: fa.sha1 || '', md5: fa.md5 || '',
                name: (fa.names || [])[0] || fa.meaningful_name || fileName,
                names: fa.names || [], size: fa.size || buffer.length,
                type: fa.type_description || mimeType, mime_type: fa.type_tag || mimeType,
                first_seen: fa.first_submission_date || null, last_seen: fa.last_analysis_date || null,
                times_submitted: fa.times_submitted || 1, tags: fa.tags || [],
                magic: fa.magic,
              },
            };

            pendingTasks.set(taskId, { status: 'completed', progress: 100, createdAt, fileName, report });
            return;
          }
        } catch (_) {}
      }

      // Timeout
      const t = pendingTasks.get(taskId) || {};
      pendingTasks.set(taskId, { ...t, status: 'failed', error: 'Analysis timed out. Check VT directly.' });
    } catch (err) {
      const t = pendingTasks.get(taskId) || {};
      pendingTasks.set(taskId, { ...t, status: 'failed', error: err.message });
    }
  })();

  return res.status(202).json({
    task_id: taskId,
    status: 'queued',
    message: `File "${fileName}" submitted for scanning (direct mode — Redis offline).`,
    poll_url: `/api/scan/status/${taskId}`,
    report_url: `/api/report/${taskId}`,
    created_at: createdAt,
  });
});

/**
 * GET /api/scan/status/:taskId
 * Returns: { task_id, status, progress, created_at, completed_at?, report?, error? }
 */
app.get('/api/scan/status/:taskId', async (req, res) => {
  const { taskId } = req.params;

  // ── BullMQ mode ──────────────────────────────────────────────────────────
  if (fileScanQueue) {
    try {
      const job = await fileScanQueue.getJob(taskId);
      if (!job) {
        // Fallback: might be in pendingTasks if queue switched modes mid-session
        const t = pendingTasks.get(taskId);
        if (t) return res.json({ task_id: taskId, ...t });
        return res.status(404).json({ error: 'Task not found', task_id: taskId });
      }

      const state = await job.getState();
      const progress = job.progress || {};
      const returnValue = job.returnvalue;

      const statusMap = { waiting: 'queued', active: 'in_progress', completed: 'completed', failed: 'failed', delayed: 'queued' };
      const status = statusMap[state] || state;

      return res.json({
        task_id: taskId,
        job_id: job.id,
        status,
        progress: typeof progress === 'object' ? (progress.percent || 0) : (progress || 0),
        stage: typeof progress === 'object' ? progress.stage : undefined,
        message: typeof progress === 'object' ? progress.message : undefined,
        created_at: job.data?.createdAt || new Date(job.timestamp).toISOString(),
        completed_at: returnValue ? new Date().toISOString() : null,
        report: returnValue || undefined,
        error: state === 'failed' ? (job.failedReason || 'Unknown error') : undefined,
      });
    } catch (err) {
      console.warn('[Queue] Status lookup failed:', err.message);
    }
  }

  // ── Direct fallback mode ─────────────────────────────────────────────────
  const task = pendingTasks.get(taskId);
  if (!task) return res.status(404).json({ error: 'Task not found', task_id: taskId });

  return res.json({
    task_id: taskId,
    status: task.status,
    progress: task.progress || 0,
    created_at: task.createdAt,
    completed_at: task.status === 'completed' ? task.report?.completed_at || null : null,
    report: task.report || undefined,
    error: task.error || undefined,
  });
});

/**
 * GET /api/report/:taskId
 * Returns the full ThreatReport v1.0 JSON once the scan is complete.
 */
app.get('/api/report/:taskId', async (req, res) => {
  const { taskId } = req.params;

  // ── BullMQ mode ──────────────────────────────────────────────────────────
  if (fileScanQueue) {
    try {
      const job = await fileScanQueue.getJob(taskId);
      if (job) {
        const state = await job.getState();
        if (state !== 'completed') {
          return res.status(202).json({
            error: 'Report not ready yet.',
            status: state === 'failed' ? 'failed' : 'in_progress',
            task_id: taskId,
            poll_url: `/api/scan/status/${taskId}`,
          });
        }
        return res.json(job.returnvalue);
      }
    } catch (err) {
      console.warn('[Queue] Report fetch failed:', err.message);
    }
  }

  // ── Direct fallback mode ─────────────────────────────────────────────────
  const task = pendingTasks.get(taskId);
  if (!task) return res.status(404).json({ error: 'Task not found', task_id: taskId });
  if (task.status !== 'completed') {
    return res.status(202).json({ error: 'Report not ready yet.', status: task.status, task_id: taskId });
  }
  return res.json(task.report);
});

/**
 * GET /api/scan/queue-health
 * Returns queue stats for monitoring / health checks.
 */
app.get('/api/scan/queue-health', async (req, res) => {
  if (!fileScanQueue) {
    return res.json({ mode: 'direct', redis: 'offline', queue: null });
  }
  try {
    const counts = await fileScanQueue.getJobCounts('waiting', 'active', 'completed', 'failed', 'delayed');
    return res.json({ mode: 'queue', redis: 'online', queue: { name: 'file-scan', ...counts } });
  } catch (err) {
    return res.status(503).json({ mode: 'error', error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Geolocation Proxy — ip-api.com (handles HTTP→HTTPS mixed content)
// FIX: Properly extract IP from /geo-ip/:ip and forward to ip-api.com/json/:ip
// ─────────────────────────────────────────────────────────────────────────────
app.get('/geo-ip/:ip', async (req, res) => {
  const ip = (req.params.ip || '').trim();
  if (!/^([0-9a-fA-F:.]+)$/.test(ip)) {
    return res.status(400).json({ error: 'Invalid IP address parameter' });
  }
  try {
    const response = await fetch(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query`);
    const data = await response.json();
    res.json(data);
  } catch (err) {
    console.error(`[GeoIP Error] Failed to fetch geolocation for ${ip}:`, err);
    res.status(500).json({ error: 'Failed to retrieve Geolocation data from ip-api' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VirusTotal API Proxy — /api/vt/*  → https://www.virustotal.com/api/v3/*
// ─────────────────────────────────────────────────────────────────────────────
app.use(
  '/api/vt',
  createProxyMiddleware({
    target: 'https://www.virustotal.com/api/v3',
    changeOrigin: true,
    pathRewrite: { '^/api/vt': '' },
    on: {
      proxyReq: (proxyReq) => {
        proxyReq.setHeader('x-apikey', VT_API_KEY);
      },
      proxyRes: (proxyRes) => {
        proxyRes.headers['Access-Control-Allow-Origin'] = '*';
        proxyRes.headers['Access-Control-Allow-Headers'] = 'Content-Type, x-apikey';
        proxyRes.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS';
      }
    }
  })
);

// ─────────────────────────────────────────────────────────────────────────────
// Gemini API Proxy — /api/gemini/*  → https://generativelanguage.googleapis.com/*
// ─────────────────────────────────────────────────────────────────────────────
app.use(
  '/api/gemini',
  createProxyMiddleware({
    target: 'https://generativelanguage.googleapis.com',
    changeOrigin: true,
    pathRewrite: { '^/api/gemini': '' },
    on: {
      proxyReq: (proxyReq) => {
        proxyReq.setHeader('x-goog-api-key', GEMINI_API_KEY);
      },
      proxyRes: (proxyRes) => {
        proxyRes.headers['Access-Control-Allow-Origin'] = '*';
        proxyRes.headers['Access-Control-Allow-Headers'] = 'Content-Type, x-goog-api-key';
        proxyRes.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS';
      }
    }
  })
);

// ─────────────────────────────────────────────────────────────────────────────
// DNS over HTTPS Proxy — /api/dns?name=...&type=...  → dns.google
// Used by WebScan module for DNS record lookups
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/dns', async (req, res) => {
  const name = (req.query.name || '').toString().trim();
  const rawType = (req.query.type || 'A').toString().toUpperCase().trim();
  const allowedTypes = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'PTR', 'CAA'];
  const type = allowedTypes.includes(rawType) ? rawType : 'A';

  if (!name || !/^[a-zA-Z0-9.-]+$/.test(name)) {
    return res.status(400).json({ error: 'Invalid or missing name parameter' });
  }
  try {
    const response = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`, {
      headers: { 'Accept': 'application/dns-json' }
    });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    console.error('[DNS Error]', err);
    res.status(500).json({ error: 'DNS lookup failed' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// RDAP WHOIS Proxy — /api/rdap/:domain  → rdap.org
// Used by WebScan module for WHOIS data
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/rdap/:domain', async (req, res) => {
  const domain = (req.params.domain || '').trim();
  if (!domain || !/^[a-zA-Z0-9.-]+$/.test(domain)) {
    return res.status(400).json({ error: 'Invalid domain parameter' });
  }
  try {
    const response = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: { 'Accept': 'application/rdap+json' }
    });
    if (!response.ok) throw new Error(`RDAP returned ${response.status}`);
    const data = await response.json();
    res.json(data);
  } catch (err) {
    console.error('[RDAP Error]', err);
    res.status(500).json({ error: 'WHOIS/RDAP lookup failed' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Certificate Transparency Proxy — /api/certsh/:domain  → crt.sh
// Used by WebScan module to fetch known certificates for a domain
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/certsh/:domain', async (req, res) => {
  const domain = (req.params.domain || '').trim();
  if (!domain || !/^[a-zA-Z0-9.-]+$/.test(domain)) {
    return res.status(400).json({ error: 'Invalid domain parameter' });
  }
  try {
    const response = await fetch(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`);
    if (!response.ok) throw new Error(`crt.sh returned ${response.status}`);
    const data = await response.json();
    res.json(data);
  } catch (err) {
    console.error('[crt.sh Error]', err);
    res.status(500).json({ error: 'Certificate transparency lookup failed' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// URLhaus Lookup Proxy — /api/urlhaus  → abuse.ch URLhaus API
// Used by IOC Hunter for malicious URL/domain intelligence
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/urlhaus', async (req, res) => {
  const { url, host } = req.body;
  try {
    const formData = new URLSearchParams();
    if (url) formData.append('url', url);
    if (host) formData.append('host', host);

    const endpoint = url
      ? 'https://urlhaus-api.abuse.ch/v1/url/'
      : 'https://urlhaus-api.abuse.ch/v1/host/';

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData.toString()
    });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    console.error('[URLhaus Error]', err);
    res.status(500).json({ error: 'URLhaus lookup failed' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// MalwareBazaar Proxy — /api/malwarebazaar  → MalwareBazaar API
// Used by IOC Hunter for file hash intelligence
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/malwarebazaar', async (req, res) => {
  const body = req.body;
  try {
    const response = await fetch('https://mb-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    console.error('[MalwareBazaar Error]', err);
    res.status(500).json({ error: 'MalwareBazaar lookup failed' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// AlienVault OTX Proxy — /api/otx/*  → otx.alienvault.com
// Used by IOC Hunter for open threat exchange intelligence
// ─────────────────────────────────────────────────────────────────────────────
app.use(
  '/api/otx',
  createProxyMiddleware({
    target: 'https://otx.alienvault.com',
    changeOrigin: true,
    pathRewrite: { '^/api/otx': '' },
    on: {
      proxyRes: (proxyRes) => {
        proxyRes.headers['Access-Control-Allow-Origin'] = '*';
      }
    }
  })
);

// ─────────────────────────────────────────────────────────────────────────────
// SPA Fallback — serve index.html for all React routes in production
// FIX: No longer references a missing 404.html file
// ─────────────────────────────────────────────────────────────────────────────
app.use((req, res) => {
  // If request is for a static asset (has extension), return 404 JSON
  if (req.path.includes('.') && !req.path.endsWith('.html')) {
    return res.status(404).json({ error: 'Not found', path: req.path });
  }
  // Otherwise serve React SPA for client-side routing
  const indexPath = path.join(__dirname, 'dist', 'index.html');
  res.sendFile(indexPath, (err) => {
    if (err) {
      // In dev mode, dist/ may not exist — just send a JSON fallback
      res.status(200).json({ message: 'ThreatAtlas API server running. Start frontend with: npm run dev' });
    }
  });
});

app.listen(PORT, () => {
  console.log(`\n==================================================`);
  console.log(` ThreatAtlas Server v2.0`);
  console.log(` URL: http://localhost:${PORT}`);
  console.log(` VT API Key: ${VT_API_KEY ? '✓ Configured' : '✗ MISSING'}`);
  console.log(` Gemini Key: ${GEMINI_API_KEY ? '✓ Configured' : '✗ MISSING'}`);
  console.log(`==================================================\n`);
});
