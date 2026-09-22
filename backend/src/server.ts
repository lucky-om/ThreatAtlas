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

app.use(cors({
  origin: '*', // Allow absolutely anything
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-apikey', 'Authorization', 'Access-Control-Allow-Private-Network']
}));

// Support Private Network Access (Chrome CORS requirement for public -> localhost)
app.use((req, res, next) => {
  if (req.headers['access-control-request-private-network']) {
    res.setHeader('Access-Control-Allow-Private-Network', 'true');
  }
  next();
});

app.use(express.json());

const upload = multer({ 
  dest: 'uploads/',
  limits: { fileSize: 32 * 1024 * 1024 } // 32 MB limit
});

// --- ROOT ROUTE (Friendly landing) ---
app.get('/', (_req, res) => {
  res.json({
    name: 'ThreatAtlas Backend Engine',
    version: '2.0',
    status: 'online',
    docs: '/api/status',
    ping: '/api/ping',
  });
});

// --- HEALTH CHECK ---
app.get('/api/ping', (_req, res) => {
  res.json({ status: 'ok', message: 'ThreatAtlas Backend Engine V2.0 Active' });
});

// --- DIAGNOSTIC STATUS (shows what backend sees) ---
app.get('/api/status', (req, res) => {
  res.json({
    status: 'ok',
    version: '2.0',
    origin: req.headers.origin || 'none',
    allowedOrigins,
    vtKeyConfigured: Boolean(process.env.VT_API_KEY || process.env.VITE_VT_API_KEY),
    atlasKeyConfigured: Boolean(process.env.ATLAS_API_KEY),
    timestamp: new Date().toISOString(),
  });
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

// Generic CORS proxy for frontend
app.all('/api/proxy', async (req, res) => {
  const { url } = req.query;
  if (!url || typeof url !== 'string') return res.status(400).json({ error: 'URL required' });
  
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 12000);
    const target = url.startsWith('http') ? url : `https://${url}`;
    
    const fetchOptions: RequestInit = {
      method: req.method,
      signal: controller.signal,
      headers: { ...req.headers } as Record<string, string>,
    };
    
    // Clean up restricted headers
    delete fetchOptions.headers['host'];
    delete fetchOptions.headers['origin'];
    delete fetchOptions.headers['referer'];
    
    if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
      // For simple proxying, we can use the raw body if we add raw body parsing
      // But express.json() / urlencoded is applied, so we serialize it back
      if (req.is('json')) fetchOptions.body = JSON.stringify(req.body);
      else if (req.is('urlencoded')) fetchOptions.body = new URLSearchParams(req.body).toString();
      else fetchOptions.body = req.body;
    }
    
    const response = await fetch(target, fetchOptions);
    clearTimeout(timeout);
    
    const headers: Record<string, string> = {};
    response.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    
    const bodyText = await response.text().catch(() => '');
    
    res.json({
      headers,
      body: bodyText.slice(0, 40000)
    });
  } catch (error: any) {
    res.status(500).json({ error: 'Proxy fetch failed', details: error.message });
  }
});

// Old endpoint to not break existing code
app.get('/api/webfox/proxy', async (req, res) => {
  const { url } = req.query;
  if (!url || typeof url !== 'string') return res.status(400).json({ error: 'URL required' });
  
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const target = url.startsWith('http') ? url : `https://${url}`;
    
    const response = await fetch(target, { signal: controller.signal });
    clearTimeout(timeout);
    
    const headers: Record<string, string> = {};
    response.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    
    const bodyText = await response.text().catch(() => '');
    
    res.json({
      headers,
      body: bodyText.slice(0, 40000)
    });
  } catch (error: any) {
    res.status(500).json({ error: 'Fetch failed', details: error.message });
  }
});

// Proxy for VirusTotal file uploads to avoid CORS issues in the browser
app.post('/api/vt/files', upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  // Use client key or fall back to server env var
  const apiKey = (req.headers['x-apikey'] as string) || process.env.VT_API_KEY || '';
  
  if (!apiKey) {
    fs.unlinkSync(req.file.path);
    return res.status(401).json({ error: 'VirusTotal API key not configured. Set VT_API_KEY in backend .env file.' });
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

// Proxy for VirusTotal URL scanning to avoid CORS issues in the browser
app.post('/api/vt/urls', async (req, res) => {
  // Use client key or fall back to server env var
  const apiKey = (req.headers['x-apikey'] as string) || process.env.VT_API_KEY || '';
  if (!apiKey) {
    return res.status(401).json({ error: 'VirusTotal API key not configured. Set VT_API_KEY in backend .env file.' });
  }

  const { url } = req.body;
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'URL required in request body' });
  }

  try {
    const formData = new URLSearchParams();
    formData.append('url', url);

    const response = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: {
        'x-apikey': apiKey,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: formData.toString(),
    });

    const data = await response.json();
    if (!response.ok) return res.status(response.status).json(data);
    res.json(data);
  } catch (error: any) {
    res.status(500).json({ error: 'VT URL proxy failed', details: error.message });
  }
});

// Generic proxy for VT GET requests (hash lookups, IP/domain queries, analysis polling, relations)
// Supports both client-passed x-apikey and server-side VT_API_KEY env var as fallback
app.get('/api/vt/proxy', async (req, res) => {
  // Use client-provided key or fall back to server env var
  const apiKey = (req.headers['x-apikey'] as string) || process.env.VT_API_KEY || '';
  if (!apiKey) {
    return res.status(401).json({ error: 'VirusTotal API key not configured. Set VT_API_KEY in backend .env file.' });
  }

  const { path: vtPath } = req.query;
  if (!vtPath || typeof vtPath !== 'string') {
    return res.status(400).json({ error: 'path query param required (e.g. /files/abc123)' });
  }

  // Security: only allow VT API v3 paths
  if (!vtPath.startsWith('/')) {
    return res.status(400).json({ error: 'path must start with /' });
  }

  try {
    const vtUrl = `https://www.virustotal.com/api/v3${vtPath}`;
    console.log(`[VT Proxy] GET ${vtPath}`);
    const response = await fetch(vtUrl, {
      headers: { 'x-apikey': apiKey },
    });
    const data = await response.json();
    // Forward exact VT status code so client can handle 404, 429, etc.
    return res.status(response.status).json(data);
  } catch (error: any) {
    console.error('[VT Proxy] Error:', error.message);
    res.status(500).json({ error: 'VT proxy failed', details: error.message });
  }
});


// --- ATLAS AI PROXY (Atlas Intelligence Engine) ---
// Proxies Atlas API requests server-side so ATLAS_API_KEY stays off the browser
app.post('/api/atlas/chat', async (req, res) => {
  const atlasKey = process.env.ATLAS_API_KEY || '';
  if (!atlasKey) {
    return res.status(401).json({ error: 'ATLAS_API_KEY not configured. Add it to backend .env file.' });
  }

  const { messages, max_tokens = 800, temperature = 0.7 } = req.body;
  if (!messages || !Array.isArray(messages)) {
    return res.status(400).json({ error: 'messages array required' });
  }

  try {
    console.log('[Atlas Proxy] Chat request →', messages.length, 'messages');
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${atlasKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'openai/gpt-oss-20b',
        messages,
        max_tokens,
        temperature,
      }),
    });

    const data = await response.json();
    if (!response.ok) {
      console.error('[Atlas Proxy] Error:', response.status, data);
      return res.status(response.status).json(data);
    }
    res.json(data);
  } catch (error: any) {
    console.error('[Atlas Proxy] Failed:', error.message);
    res.status(500).json({ error: 'Atlas proxy failed', details: error.message });
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
});
