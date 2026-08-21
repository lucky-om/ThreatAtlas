import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const VT_API_KEY = env.VT_API_KEY || '';
  const GEMINI_API_KEY = env.GEMINI_API_KEY || '';
  const GROQ_API_KEY = env.GROQ_API_KEY || '';

  return {
    plugins: [
      react(),
      {
        name: 'threatatlas-api-middleware',
        configureServer(server) {
          // Custom middleware to handle API endpoints in Vite dev mode seamlessly
          server.middlewares.use(async (req, res, next) => {
            const url = new URL(req.url || '', `http://${req.headers.host}`);

            // 0. Unified AI Chatbot endpoint (Groq with Gemini Fallback)
            if (url.pathname === '/api/ai/chat' && req.method === 'POST') {
              let body = '';
              req.on('data', chunk => { body += chunk; });
              req.on('end', async () => {
                try {
                  const { messages } = body ? JSON.parse(body) : { messages: [] };

                  // Attempt Groq first if key available
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
                          messages: messages,
                          max_tokens: 800,
                          temperature: 0.7,
                        })
                      });

                      if (groqRes.ok) {
                        const groqData = await groqRes.json();
                        let reply = groqData.choices?.[0]?.message?.content || '';
                        reply = reply.replace(/<think>[\s\S]*?(<\/think>|$)/g, '').trim();
                        if (reply) {
                          res.setHeader('Content-Type', 'application/json');
                          return res.end(JSON.stringify({ reply }));
                        }
                      }
                    } catch (groqErr) {
                      console.warn('[AI] Groq failed, falling back to Gemini:', groqErr);
                    }
                  }

                  // Fallback to Gemini
                  if (GEMINI_API_KEY) {
                    const lastUserMsg = messages.filter((m: any) => m.role === 'user').pop()?.content || '';
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
                      res.setHeader('Content-Type', 'application/json');
                      return res.end(JSON.stringify({ reply }));
                    }
                  }

                  res.statusCode = 500;
                  res.end(JSON.stringify({ error: 'No AI backend available or keys invalid' }));
                } catch (err: any) {
                  res.statusCode = 500;
                  res.end(JSON.stringify({ error: err.message || 'AI request failed' }));
                }
              });
              return;
            }

            // 1. URLhaus proxy (POST)
            if (url.pathname === '/api/urlhaus' && req.method === 'POST') {
              let body = '';
              req.on('data', chunk => { body += chunk; });
              req.on('end', async () => {
                try {
                  const parsed = body ? JSON.parse(body) : {};
                  const formData = new URLSearchParams();
                  if (parsed.url) formData.append('url', parsed.url);
                  if (parsed.host) formData.append('host', parsed.host);

                  const endpoint = parsed.url
                    ? 'https://urlhaus-api.abuse.ch/v1/url/'
                    : 'https://urlhaus-api.abuse.ch/v1/host/';

                  const apiRes = await fetch(endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: formData.toString()
                  });
                  const data = await apiRes.json();
                  res.setHeader('Content-Type', 'application/json');
                  res.end(JSON.stringify(data));
                } catch (err: any) {
                  res.statusCode = 500;
                  res.end(JSON.stringify({ error: err.message || 'URLhaus failed' }));
                }
              });
              return;
            }

            // 2. MalwareBazaar proxy (POST)
            if (url.pathname === '/api/malwarebazaar' && req.method === 'POST') {
              let body = '';
              req.on('data', chunk => { body += chunk; });
              req.on('end', async () => {
                try {
                  const parsed = body ? JSON.parse(body) : {};
                  const apiRes = await fetch('https://mb-api.abuse.ch/api/v1/', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(parsed)
                  });
                  const data = await apiRes.json();
                  res.setHeader('Content-Type', 'application/json');
                  res.end(JSON.stringify(data));
                } catch (err: any) {
                  res.statusCode = 500;
                  res.end(JSON.stringify({ error: err.message || 'MalwareBazaar failed' }));
                }
              });
              return;
            }

            // 3. DNS over HTTPS
            if (url.pathname === '/api/dns' && req.method === 'GET') {
              const name = url.searchParams.get('name');
              const type = url.searchParams.get('type') || 'A';
              if (!name) {
                res.statusCode = 400;
                return res.end(JSON.stringify({ error: 'Missing name' }));
              }
              try {
                const apiRes = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`, {
                  headers: { Accept: 'application/dns-json' }
                });
                const data = await apiRes.json();
                res.setHeader('Content-Type', 'application/json');
                res.end(JSON.stringify(data));
              } catch (err: any) {
                res.statusCode = 500;
                res.end(JSON.stringify({ error: 'DNS resolution failed' }));
              }
              return;
            }

            // 4. RDAP WHOIS
            if (url.pathname.startsWith('/api/rdap/') && req.method === 'GET') {
              const domain = url.pathname.replace('/api/rdap/', '');
              try {
                const apiRes = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
                  headers: { Accept: 'application/rdap+json' }
                });
                const data = await apiRes.json();
                res.setHeader('Content-Type', 'application/json');
                res.end(JSON.stringify(data));
              } catch (err: any) {
                res.statusCode = 500;
                res.end(JSON.stringify({ error: 'RDAP lookup failed' }));
              }
              return;
            }

            // 5. crt.sh Certificate Transparency
            if (url.pathname.startsWith('/api/certsh/') && req.method === 'GET') {
              const domain = url.pathname.replace('/api/certsh/', '');
              try {
                const apiRes = await fetch(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`);
                const data = await apiRes.json();
                res.setHeader('Content-Type', 'application/json');
                res.end(JSON.stringify(data));
              } catch (err: any) {
                res.statusCode = 500;
                res.end(JSON.stringify({ error: 'crt.sh lookup failed' }));
              }
              return;
            }

            next();
          });
        }
      }
    ],
    server: {
      port: 3000,
      proxy: {
        // Proxy VirusTotal API calls to bypass CORS locally
        '/api/vt': {
          target: 'https://www.virustotal.com/api/v3',
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api\/vt/, ''),
          configure: (proxy) => {
            proxy.on('proxyReq', (proxyReq) => {
              if (VT_API_KEY) {
                proxyReq.setHeader('x-apikey', VT_API_KEY);
              }
            });
          }
        },
        // Proxy Gemini API calls
        '/api/gemini': {
          target: 'https://generativelanguage.googleapis.com',
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api\/gemini/, ''),
          configure: (proxy) => {
            proxy.on('proxyReq', (proxyReq) => {
              if (GEMINI_API_KEY) {
                proxyReq.setHeader('x-goog-api-key', GEMINI_API_KEY);
              }
            });
          }
        },
        // Proxy IP Geolocation queries to ip-api.com
        '/geo-ip': {
          target: 'http://ip-api.com',
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/geo-ip\//, '/json/')
        }
      }
    }
  };
});
