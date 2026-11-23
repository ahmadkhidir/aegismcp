/// <reference types="vitest" />
import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

/**
 * Local development proxies `/api` to the gateway target from the environment.
 * A production build serves the console from the gateway origin and needs no
 * proxy; no origin is compiled into the source.
 */
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const gatewayTarget = env.VITE_GATEWAY_PROXY_TARGET?.trim();

  return {
    plugins: [react()],
    server: {
      port: 3000,
      strictPort: true,
      ...(gatewayTarget
        ? {
            proxy: {
              '/api': {
                target: gatewayTarget,
                changeOrigin: true,
                secure: true,
              },
            },
          }
        : {}),
    },
    test: {
      globals: true,
      environment: 'jsdom',
      setupFiles: ['./src/test/setup.ts'],
      css: false,
    },
  };
});
