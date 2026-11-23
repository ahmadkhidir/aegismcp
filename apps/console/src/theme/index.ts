/**
 * Console theme layer.
 *
 * Import visual roles from here rather than writing shades, sizes or timings
 * at a call site. Token values live in `src/index.css`; utility names in
 * `tailwind.config.js`. The `dark` class on `document.documentElement` selects
 * the dark palette, and `index.html` applies it by default so the console
 * boots on its dark terminal surface.
 */
export {
  type,
  ink,
  surface,
  edge,
  elevation,
  radius,
  size,
  motion,
  ease,
  securityState,
  type SecurityState,
  breakpoints,
} from './tokens';
