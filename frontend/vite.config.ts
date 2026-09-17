import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const backendUrl = env.VITE_API_BASE_URL || 'http://localhost:3001';

  return {
    plugins: [react()],
    server: {
      port: 3002,
      strictPort: true,
      proxy: {
        '/api': {
          target: backendUrl,
          changeOrigin: true,
        },
      },
    },
    build: {
      sourcemap: false,
      chunkSizeWarningLimit: 1000,
      rollupOptions: {
        output: {
          // Deterministic chunking — avoids circular vendor chunk issue
          manualChunks: {
            'react-core':  ['react', 'react-dom'],
            'react-router': ['react-router-dom'],
            'framer':      ['framer-motion'],
            'lucide':      ['lucide-react'],
            'pdf':         ['jspdf'],
          },
        },
      },
    },
  };
});

