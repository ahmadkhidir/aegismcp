/**
 * Specification Anchors: FEAT-008, NFR-029
 * The gateway API base comes from configuration; the source carries no
 * environment origin of its own.
 */

import { describe, it, expect } from 'vitest';
import { readApiBase } from '../services/api';

describe('gateway API base configuration', () => {
  it('defaults to the same-origin API path that the dev server proxies', () => {
    expect(readApiBase({})).toBe('/api/v1');
  });

  it('reads an absolute gateway origin from the environment', () => {
    expect(
      readApiBase({ VITE_API_BASE_URL: 'https://aegis.example.com/api/v1' })
    ).toBe('https://aegis.example.com/api/v1');
  });

  it('trims surrounding whitespace and trailing slashes', () => {
    expect(readApiBase({ VITE_API_BASE_URL: '  https://aegis.example.com/api/v1/  ' })).toBe(
      'https://aegis.example.com/api/v1'
    );
  });

  it('falls back to the default when the setting is blank', () => {
    expect(readApiBase({ VITE_API_BASE_URL: '   ' })).toBe('/api/v1');
  });
});
