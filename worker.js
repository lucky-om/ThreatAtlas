/**
 * ThreatAtlas — BullMQ Worker Process (worker.js)
 *
 * Runs as a separate process alongside server.js.
 * Picks up "file-scan" jobs from Redis, runs VirusTotal upload + polling,
 * normalises the result into ThreatReport v1.0 JSON, stores it back in Redis.
 *
 * Start:  node worker.js
 * Docker: defined as the `worker` service in docker-compose.yml
 */

require('dotenv').config();

const { Worker, QueueEvents } = require('bullmq');
const { createClient } = require('redis');
const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args)).catch(() => global.fetch(...args));

// ─────────────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────────────
const VT_API_KEY = process.env.VT_API_KEY || '';
const REDIS_URL = process.env.REDIS_URL || 'redis://127.0.0.1:6379';
const VT_BASE = 'https://www.virustotal.com/api/v3';
const POLL_INTERVAL_MS = 2500;
const MAX_POLL_ATTEMPTS = 24;  // 60 seconds total

const redisConnection = {
  url: REDIS_URL,
};

// ─────────────────────────────────────────────────────────────────────────────
// Helper: VT API fetch
// ─────────────────────────────────────────────────────────────────────────────
async function vtFetch(path, options = {}) {
  const url = `${VT_BASE}${path}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      'x-apikey': VT_API_KEY,
      ...(options.headers || {}),
    },
  });

  if (!res.ok) {
    let msg = `VT API error ${res.status}`;
    try { const d = await res.json(); msg = d?.error?.message || msg; } catch (_) {}
    throw new Error(msg);
  }

  const ct = res.headers.get('content-type') || '';
  return ct.includes('application/json') ? res.json() : res.text();
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: Normalize VT analysis response → ThreatReport shape
// ─────────────────────────────────────────────────────────────────────────────
function calcThreatScore(stats) {
  const total = (stats.malicious || 0) + (stats.suspicious || 0) +
    (stats.harmless || 0) + (stats.undetected || 0);
  if (total === 0) return 0;
  return Math.round(((stats.malicious || 0) + (stats.suspicious || 0)) / total * 100);
}

function calcVerdict(stats) {
  if ((stats.malicious || 0) > 0) return 'malicious';
  if ((stats.suspicious || 0) > 0) return 'suspicious';
  return 'clean';
}

function normalizeEngines(results = {}) {
  return Object.entries(results).map(([engine, res]) => ({
    engine,
    category: res.category || 'undetected',
    result: res.result || null,
    method: res.method,
    detected: res.category === 'malicious' || res.category === 'suspicious',
  }));
}

function buildFileThreatReport(taskId, fileData, analysisData, createdAt) {
  const fa = fileData?.data?.attributes || {};
  const aa = analysisData?.data?.attributes || {};

  // Merge stats: prefer file report (last_analysis_stats) over analysis stats
  const stats = fa.last_analysis_stats || aa.stats || {};
  const results = fa.last_analysis_results || aa.results || {};

  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const harmless = stats.harmless || 0;
  const undetected = stats.undetected || 0;
  const total = malicious + suspicious + harmless + undetected;

  return {
    schema_version: '1.0',
    task_id: taskId,
    scan_type: 'file',
    target: fa.sha256 || fileData?.data?.id || taskId,
    status: 'completed',
    created_at: createdAt,
    completed_at: new Date().toISOString(),
    verdict: calcVerdict(stats),
    threat_score: calcThreatScore(stats),
    stats: { malicious, suspicious, harmless, undetected, total },
    engines: normalizeEngines(results),
    file_meta: {
      sha256: fa.sha256 || '',
      sha1: fa.sha1 || '',
      md5: fa.md5 || '',
      name: (fa.names || [])[0] || fa.meaningful_name || 'Unknown',
      names: fa.names || [],
      size: fa.size || 0,
      type: fa.type_description || 'Unknown',
      mime_type: fa.type_tag || '',
      first_seen: fa.first_submission_date || null,
      last_seen: fa.last_analysis_date || null,
      times_submitted: fa.times_submitted || 0,
      tags: fa.tags || [],
      magic: fa.magic,
      pe_info: fa.pe_info ? {
        imphash: fa.pe_info.imphash,
        entry_point: fa.pe_info.entry_point,
        machine_type: fa.pe_info.machine_type,
        sections: fa.pe_info.sections,
        import_list: fa.pe_info.import_list,
      } : undefined,
      mitre_attack: (fa.mitre_attack_techniques || []).map(m => ({
        id: m.id || m.technique_id,
        description: m.signature_description || m.technique_name,
        tactic: m.tactic || m.tactic_name,
      })),
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: Upload file buffer to VirusTotal
// ─────────────────────────────────────────────────────────────────────────────
async function uploadFileToVT(fileBuffer, fileName, mimeType) {
  const { FormData, Blob } = await import('node-fetch').then(m => m).catch(() => global);
  const form = new FormData();
  form.append('file', new Blob([fileBuffer], { type: mimeType }), fileName);

  const res = await fetch(`${VT_BASE}/files`, {
    method: 'POST',
    headers: { 'x-apikey': VT_API_KEY },
    body: form,
  });

  if (!res.ok) {
    let msg = `VT upload failed: ${res.status}`;
    try { const d = await res.json(); msg = d?.error?.message || msg; } catch (_) {}
    throw new Error(msg);
  }
  return res.json();
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: Poll analysis until completed
// ─────────────────────────────────────────────────────────────────────────────
async function pollAnalysis(analysisId, onProgress) {
  let attempts = 0;
  let latestRaw = null;

  while (attempts < MAX_POLL_ATTEMPTS) {
    attempts++;
    try {
      const res = await vtFetch(`/analyses/${analysisId}`);
      latestRaw = res;
      const status = res?.data?.attributes?.status || 'queued';

      const progress = status === 'completed'
        ? 90
        : Math.min(30 + attempts * 5, 85);
      onProgress(progress, status, res);

      if (status === 'completed') {
        return res;
      }
    } catch (err) {
      console.warn(`[Worker] Poll attempt ${attempts} failed:`, err.message);
      if (latestRaw && attempts >= MAX_POLL_ATTEMPTS - 1) return latestRaw;
    }
    await new Promise(r => setTimeout(r, POLL_INTERVAL_MS));
  }

  return latestRaw;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: Fetch full file report from VT (after scan completes)
// ─────────────────────────────────────────────────────────────────────────────
async function fetchFileReport(sha256) {
  try {
    return await vtFetch(`/files/${sha256}`);
  } catch (_) {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// BullMQ Worker — processes "file-scan" jobs
// ─────────────────────────────────────────────────────────────────────────────
const worker = new Worker(
  'file-scan',
  async (job) => {
    const { taskId, fileName, mimeType, fileBase64, fileSize, createdAt } = job.data;
    console.log(`[Worker] Processing job ${job.id} — file: "${fileName}" (${fileSize} bytes)`);

    if (!VT_API_KEY) {
      throw new Error('VT_API_KEY is not configured. Set it in your .env file.');
    }

    // ── Step 1: Upload file to VirusTotal (10% progress) ────────────────────
    await job.updateProgress({ percent: 10, stage: 'uploading', message: 'Uploading to VirusTotal…' });

    const fileBuffer = Buffer.from(fileBase64, 'base64');
    let scanResponse;
    try {
      scanResponse = await uploadFileToVT(fileBuffer, fileName, mimeType);
    } catch (err) {
      throw new Error(`Upload failed: ${err.message}`);
    }

    const analysisId = scanResponse?.data?.id;
    if (!analysisId) throw new Error('No analysis ID returned from VirusTotal upload');

    await job.updateProgress({ percent: 20, stage: 'queued', message: 'File queued for analysis…' });
    console.log(`[Worker] Analysis ID: ${analysisId}`);

    // ── Step 2: Poll analysis until completed (20–90% progress) ─────────────
    const analysisData = await pollAnalysis(analysisId, async (percent, stage, raw) => {
      await job.updateProgress({
        percent,
        stage,
        message: stage === 'completed' ? 'Analysis complete, building report…' : `Scanning (${percent}%)…`,
      });
    });

    await job.updateProgress({ percent: 90, stage: 'normalizing', message: 'Building threat report…' });

    // ── Step 3: Fetch full enriched file report from VT ─────────────────────
    const sha256 = analysisData?.data?.attributes?.sha256
      || analysisData?.meta?.file_info?.sha256
      || analysisData?.data?.meta?.file_info?.sha256;

    let fileReportData = null;
    if (sha256) {
      fileReportData = await fetchFileReport(sha256);
    }

    // ── Step 4: Build ThreatReport v1.0 ─────────────────────────────────────
    const report = buildFileThreatReport(taskId, fileReportData, analysisData, createdAt);

    await job.updateProgress({ percent: 100, stage: 'completed', message: 'Scan complete!' });
    console.log(`[Worker] Job ${job.id} complete — verdict: ${report.verdict}, score: ${report.threat_score}`);

    return report;
  },
  {
    connection: redisConnection,
    concurrency: 3,
  }
);

// ─────────────────────────────────────────────────────────────────────────────
// Event Listeners
// ─────────────────────────────────────────────────────────────────────────────
worker.on('completed', (job, result) => {
  console.log(`[Worker] ✓ Job ${job.id} completed — ${result.verdict} (score: ${result.threat_score})`);
});

worker.on('failed', (job, err) => {
  console.error(`[Worker] ✗ Job ${job?.id} failed:`, err.message);
});

worker.on('error', (err) => {
  console.error('[Worker] Worker error:', err);
});

worker.on('progress', (job, progress) => {
  console.log(`[Worker] Job ${job.id} progress: ${progress?.percent}% (${progress?.stage})`);
});

console.log('\n==================================================');
console.log(' ThreatAtlas Worker v1.0');
console.log(' Queue: file-scan');
console.log(` Redis: ${REDIS_URL}`);
console.log(` VT Key: ${VT_API_KEY ? '✓ Configured' : '✗ MISSING — scans will fail'}`);
console.log(' Concurrency: 3');
console.log('==================================================\n');

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('[Worker] Shutting down gracefully…');
  await worker.close();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('[Worker] Shutting down gracefully…');
  await worker.close();
  process.exit(0);
});
