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

// jsdom has no layout engine and does not implement Range geometry, which the
// CodeMirror policy editor reads while measuring its document. Empty rects are
// enough for the editor to render and update its lint decorations in tests.
if (typeof Range !== 'undefined') {
  const emptyRect = (): DOMRect => ({
    x: 0,
    y: 0,
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    width: 0,
    height: 0,
    toJSON: () => ({}),
  });
  Range.prototype.getClientRects = function getClientRects() {
    return Object.assign([], { item: () => null }) as unknown as DOMRectList;
  };
  Range.prototype.getBoundingClientRect = emptyRect;
}

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
