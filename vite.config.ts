import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  return {
    plugins: [react()],
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
              if (env.VT_API_KEY) {
                proxyReq.setHeader('x-apikey', env.VT_API_KEY);
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
              if (env.GEMINI_API_KEY) {
                proxyReq.setHeader('x-goog-api-key', env.GEMINI_API_KEY);
              }
            });
          }
        },
        // Proxy IP Geolocation queries to ip-api.com
        '/geo-ip': {
          target: 'http://ip-api.com/json',
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/geo-ip/, '')
        }
      }
    }
  };
});
