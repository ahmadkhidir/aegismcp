import '@testing-library/jest-dom';
import { webcrypto } from 'node:crypto';
import { vi } from 'vitest';

// jsdom does not implement Web Crypto's subtle interface, which the OIDC
// verifier and the test identity fixtures both use.
if (typeof window !== 'undefined' && !window.crypto?.subtle) {
  Object.defineProperty(window, 'crypto', {
    value: webcrypto,
    configurable: true,
  });
}

// A configured identity provider for tests that render the real singleton.
vi.stubEnv('VITE_OIDC_AUTHORITY', 'https://idp.test/realms/aegis');
vi.stubEnv('VITE_OIDC_CLIENT_ID', 'aegis-console');

if (typeof window !== 'undefined') {
  if (!window.URL.createObjectURL) {
    window.URL.createObjectURL = vi.fn(() => 'blob:test-url');
  }
  if (!window.URL.revokeObjectURL) {
    window.URL.revokeObjectURL = vi.fn();
  }
  // Prevent jsdom navigation error on anchor clicks.
  HTMLAnchorElement.prototype.click = vi.fn();
}
