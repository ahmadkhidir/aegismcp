/// <reference types="vitest" />
import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

/**
 * Local development proxies `/api` to the gateway target from the environment.
 * The target defaults to the local compose stack (infra/compose) so a fresh
 * checkout reaches the gateway without an extra setting. A production build is
 * served from the gateway origin and needs no proxy; no origin is compiled into
 * the application source.
 */
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const gatewayTarget = env.VITE_GATEWAY_PROXY_TARGET?.trim() || 'http://localhost:8443';

  return {
    plugins: [react()],
    server: {
      port: 3000,
      strictPort: true,
      proxy: {
        '/api': {
          target: gatewayTarget,
          changeOrigin: true,
          secure: false,
          // The live inspector's Server-Sent Events response must stream
          // through the proxy without buffering (C-002, NFR-005).
          ws: false,
        },
      },
    },
    test: {
      globals: true,
      environment: 'jsdom',
      setupFiles: ['./src/test/setup.ts'],
      css: false,
    },
  };
});
