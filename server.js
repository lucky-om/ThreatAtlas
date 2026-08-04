const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Load environment variables from .env file
require('dotenv').config();

// VirusTotal API Key provided by user
const VT_API_KEY = process.env.VT_API_KEY || '';

// Gemini API Key provided by user
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || '';

// Serve static files
app.use(express.static(path.join(__dirname)));

// Geolocation Proxy for ip-api.com (handles mixed content issues on HTTPS origins)
app.get('/geo-ip/:ip', async (req, res) => {
  const ip = req.params.ip;
  try {
    // Using Node's global fetch (supported in Node v18+)
    const response = await fetch(`http://ip-api.com/json/${encodeURIComponent(ip)}`);
    const data = await response.json();
    res.json(data);
  } catch (err) {
    console.error(`[GeoIP Error] Failed to fetch geolocation for ${ip}:`, err);
    res.status(500).json({ error: 'Failed to retrieve Geolocation data from ip-api' });
  }
});

// Proxy endpoint for VirusTotal API
// All client requests to /api/vt/* will be forwarded to https://www.virustotal.com/api/v3/*
app.use(
  '/api/vt',
  createProxyMiddleware({
    target: 'https://www.virustotal.com/api/v3',
    changeOrigin: true,
    pathRewrite: {
      '^/api/vt': '', // Remove /api/vt prefix when forwarding to VirusTotal
    },
    on: {
      proxyReq: (proxyReq, req, res) => {
        // Inject the VirusTotal API key into the request header
        proxyReq.setHeader('x-apikey', VT_API_KEY);
      },
      proxyRes: (proxyRes, req, res) => {
        // Add CORS headers to allow cross-origin requests
        proxyRes.headers['Access-Control-Allow-Origin'] = '*';
        proxyRes.headers['Access-Control-Allow-Headers'] = 'Content-Type, x-apikey';
        proxyRes.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS';
      }
    }
  })
);

// Proxy endpoint for Gemini API
app.use(
  '/api/gemini',
  createProxyMiddleware({
    target: 'https://generativelanguage.googleapis.com',
    changeOrigin: true,
    pathRewrite: {
      '^/api/gemini': '', // Remove /api/gemini prefix
    },
    on: {
      proxyReq: (proxyReq, req, res) => {
        // Inject the Gemini API key into the request header
        proxyReq.setHeader('x-goog-api-key', GEMINI_API_KEY);
      },
      proxyRes: (proxyRes, req, res) => {
        proxyRes.headers['Access-Control-Allow-Origin'] = '*';
        proxyRes.headers['Access-Control-Allow-Headers'] = 'Content-Type, x-goog-api-key';
        proxyRes.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS';
      }
    }
  })
);

// Fallback to custom 404 page
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, '404.html'));
});

app.listen(PORT, () => {
  console.log(`\n==================================================`);
  console.log(` ThreatAtlas Local Server Running`);
  console.log(` URL: http://localhost:${PORT}`);
  console.log(` Proxying API calls to VirusTotal & ip-api`);
  console.log(`==================================================\n`);
});
