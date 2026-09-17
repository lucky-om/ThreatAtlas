import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import multer from 'multer';
import dns from 'dns/promises';
import tls from 'tls';
import whois from 'whois-json';
import exifr from 'exifr';
import ffmpeg from 'fluent-ffmpeg';
import fs from 'fs';
import crypto from 'crypto';

dotenv.config();

const app = express();
const port = process.env.PORT || 3001;

// ── CORS: allow only configured origins ───────────────────────────────────────
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:3002')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (e.g., Render health checks, curl)
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS: origin ${origin} not allowed`));
    }
  },
  credentials: true,
}));
app.use(express.json());

const upload = multer({ 
  dest: 'uploads/',
  limits: { fileSize: 32 * 1024 * 1024 } // 32 MB limit
});

// --- HEALTH CHECK ---
app.get('/api/ping', (req, res) => {
  res.json({ status: 'ok', message: 'ThreatAtlas Backend Engine V2.0 Active' });
});

// --- WEBFOX ENGINE ---
app.get('/api/webfox/dns', async (req, res) => {
  const { domain } = req.query;
  if (!domain || typeof domain !== 'string') return res.status(400).json({ error: 'Domain required' });

  try {
    const results: any = {};
    const recordTypes = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA'];
    
    for (const type of recordTypes) {
      try {
        const records = await dns.resolve(domain, type as any);
        if (records && records.length > 0) {
          results[type] = records;
        }
      } catch (e) {
        // Ignore resolution errors for specific record types
      }
    }
    res.json(results);
  } catch (error: any) {
    res.status(500).json({ error: 'DNS resolution failed', details: error.message });
  }
});

app.get('/api/webfox/whois', async (req, res) => {
  const { query } = req.query;
  if (!query || typeof query !== 'string') return res.status(400).json({ error: 'Query required' });

  try {
    const results = await whois(query);
    res.json(results);
  } catch (error: any) {
    res.status(500).json({ error: 'WHOIS lookup failed', details: error.message });
  }
});

app.get('/api/webfox/tls', (req, res) => {
  const { host } = req.query;
  if (!host || typeof host !== 'string') return res.status(400).json({ error: 'Host required' });

  const socket = tls.connect(443, host, { servername: host, rejectUnauthorized: false }, () => {
    const cert = socket.getPeerCertificate(true);
    socket.end();
    if (!cert || Object.keys(cert).length === 0) {
      return res.status(404).json({ error: 'No certificate found' });
    }
    res.json({
      subject: cert.subject,
      issuer: cert.issuer,
      valid_from: cert.valid_from,
      valid_to: cert.valid_to,
      fingerprint: cert.fingerprint,
      fingerprint256: cert.fingerprint256,
      serialNumber: cert.serialNumber
    });
  });

  socket.on('error', (error) => {
    res.status(500).json({ error: 'TLS scan failed', details: error.message });
  });
});

app.get('/api/ipgeo', async (req, res) => {
  const { query } = req.query;
  if (!query || typeof query !== 'string') return res.status(400).json({ error: 'Query required' });
  
  try {
    const targetUrl = `http://ip-api.com/json/${encodeURIComponent(query)}`;
    const response = await fetch(targetUrl);
    const data = await response.json();
    res.json(data);
  } catch (error: any) {
    res.status(500).json({ error: 'IP Geolocation failed', details: error.message });
  }
});

// Proxy for VirusTotal file uploads to avoid CORS issues in the browser
app.post('/api/vt/files', upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const apiKey = req.headers['x-apikey'];
  
  if (!apiKey || typeof apiKey !== 'string') {
    fs.unlinkSync(req.file.path);
    return res.status(401).json({ error: 'API key required in x-apikey header' });
  }

  try {
    const buffer = fs.readFileSync(req.file.path);
    const blob = new Blob([buffer], { type: req.file.mimetype });
    const formData = new FormData();
    formData.append('file', blob, req.file.originalname || 'upload.bin');

    const response = await fetch('https://www.virustotal.com/api/v3/files', {
      method: 'POST',
      headers: {
        'x-apikey': apiKey
      },
      body: formData
    });

    const data = await response.json();
    fs.unlinkSync(req.file.path);
    
    if (!response.ok) {
      return res.status(response.status).json(data);
    }
    res.json(data);
  } catch (error: any) {
    if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    res.status(500).json({ error: 'VT proxy failed', details: error.message });
  }
});




// --- FORENSICS ENGINE ---
app.post('/api/forensics/image/exif', upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  try {
    const exifData = await exifr.parse(req.file.path, true);
    fs.unlinkSync(req.file.path); // cleanup
    res.json(exifData || { message: 'No EXIF metadata found' });
  } catch (error: any) {
    if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    res.status(500).json({ error: 'Image parsing failed', details: error.message });
  }
});

app.post('/api/forensics/media/metadata', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  ffmpeg.ffprobe(req.file.path, (err, metadata) => {
    if (fs.existsSync(req.file!.path)) fs.unlinkSync(req.file!.path);
    if (err) {
      return res.status(500).json({ error: 'FFprobe failed', details: err.message });
    }
    res.json(metadata);
  });
});

app.post('/api/forensics/file/analyze', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  try {
    const buffer = fs.readFileSync(req.file.path);
    const md5 = crypto.createHash('md5').update(buffer).digest('hex');
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
    const magic = buffer.toString('hex', 0, 8); // First 8 bytes
    
    fs.unlinkSync(req.file.path);
    
    res.json({
      size: buffer.length,
      md5,
      sha256,
      magic,
    });
  } catch (error: any) {
    if (fs.existsSync(req.file!.path)) fs.unlinkSync(req.file!.path);
    res.status(500).json({ error: 'File analysis failed', details: error.message });
  }
});
app.post('/api/forensics/pdf/analyze', upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  try {
    const pdfParse = require('pdf-parse') as (buf: Buffer) => Promise<{ numpages: number; info: Record<string, unknown>; metadata: unknown; text: string }>;
    const buffer = fs.readFileSync(req.file.path);
    const data = await pdfParse(buffer);
    
    const bufferStr = buffer.toString('binary');
    const anomalies: string[] = [];
    if (bufferStr.includes('/JavaScript') || bufferStr.includes('/JS')) anomalies.push('Embedded JavaScript detected');
    if (bufferStr.includes('/OpenAction') || bufferStr.includes('/AA')) anomalies.push('Auto-launch action (OpenAction/AA) detected');
    if (bufferStr.includes('/Launch')) anomalies.push('Launch action detected');
    if (bufferStr.includes('/SubmitForm')) anomalies.push('SubmitForm action detected');
    if (bufferStr.includes('/ObjStm')) anomalies.push('Object streams detected (potentially obfuscated)');
    
    const md5 = crypto.createHash('md5').update(buffer).digest('hex');
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');

    fs.unlinkSync(req.file.path);

    res.json({
      pageCount: data.numpages,
      info: data.info,
      metadata: data.metadata,
      textPreview: data.text.substring(0, 1000).trim(),
      anomalies,
      md5,
      sha256,
      size: buffer.length
    });
  } catch (error: any) {
    if (fs.existsSync(req.file!.path)) fs.unlinkSync(req.file!.path);
    res.status(500).json({ error: 'PDF parsing failed', details: error.message });
  }
});
let openPhishCache: Set<string> | null = null;
let lastOpenPhishFetch = 0;

app.get('/api/phishguard/intel', async (req, res) => {
  const url = req.query.url;
  if (!url || typeof url !== 'string') return res.status(400).json({ error: 'URL required' });
  
  try {
    // Refresh cache every hour
    if (!openPhishCache || Date.now() - lastOpenPhishFetch > 3600000) {
      const response = await fetch('https://openphish.com/feed.txt');
      if (response.ok) {
        const text = await response.text();
        openPhishCache = new Set(text.split('\n').map(line => line.trim()).filter(Boolean));
        lastOpenPhishFetch = Date.now();
      }
    }
    
    let isOpenPhishBlacklisted = false;
    if (openPhishCache) {
      try {
        const parsedUrl = new URL(url.startsWith('http') ? url : `https://${url}`);
        if (openPhishCache.has(url) || openPhishCache.has(parsedUrl.hostname) || openPhishCache.has(parsedUrl.hostname + parsedUrl.pathname)) {
          isOpenPhishBlacklisted = true;
        }
      } catch {
        if (openPhishCache.has(url)) isOpenPhishBlacklisted = true;
      }
    }
    
    res.json({ isOpenPhishBlacklisted });
  } catch (error: any) {
    res.status(500).json({ error: 'Intel fetch failed', details: error.message });
  }
});

app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ error: 'File too large. Maximum size is 32 MB.' });
  }
  if (err) {
    return res.status(500).json({ error: 'Server error', details: err.message });
  }
  next();
});


app.listen(port, () => {
  console.log(`[ThreatAtlas] Backend engine listening on port ${port}`);

  // ── Self-Ping Keepalive (prevents Render free-tier spin-down) ────────────────
  // Pings /api/ping every 14 minutes. Works alongside UptimeRobot as a backup.
  // Only active in production (RENDER env is set automatically by Render).
  if (process.env.RENDER) {
    const SELF_URL = `https://${process.env.RENDER_EXTERNAL_HOSTNAME}/api/ping`;
    const INTERVAL_MS = 14 * 60 * 1000; // 14 minutes

    setInterval(async () => {
      try {
        const res = await fetch(SELF_URL);
        const data = await res.json() as { status?: string };
        console.log(`[Keepalive] Self-ping OK — status: ${data?.status ?? 'unknown'}`);
      } catch (err) {
        console.warn('[Keepalive] Self-ping failed:', err);
      }
    }, INTERVAL_MS);

    console.log(`[Keepalive] Self-ping active → ${SELF_URL} (every 14 min)`);
  }
});
