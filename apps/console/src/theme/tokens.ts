/**
 * Semantic token vocabulary for the console.
 *
 * Every visual value the console renders is declared once in `src/index.css`
 * and exposed as a utility by `tailwind.config.js`. Screens and components do
 * not pick shades or sizes ad hoc: they pick a role from this module, so a
 * theme change lands in one file. Sources: branding.md § Design System,
 * screens.md § Shared / Common Components.
 *
 * Values here are literal utility strings, never assembled at runtime, so
 * Tailwind's content scanner can see them. If a role you need is missing, add
 * the token in `src/index.css` and the role here instead of writing a bracket
 * value at the call site.
 */

/** Typography roles from branding.md § Type Scale. */
export const type = {
  display: 'font-sans text-display font-bold',
  h1: 'font-sans text-h1 font-bold',
  h2: 'font-sans text-h2 font-semibold',
  h3: 'font-sans text-h3 font-semibold',
  bodyLarge: 'font-sans text-body-large',
  body: 'font-sans text-body',
  bodySmall: 'font-sans text-body-small',
  caption: 'font-sans text-caption font-medium',
  monoCode: 'font-mono text-mono-code',
} as const;

/** Text ink roles. `primary` and `secondary` follow screens.md wording. */
export const ink = {
  primary: 'text-grey-900',
  secondary: 'text-grey-600',
  muted: 'text-grey-500',
  disabled: 'text-grey-400',
  brand: 'text-primary-800',
  danger: 'text-error-500',
} as const;

/** Surface roles, from the page canvas down to inset code blocks. */
export const surface = {
  canvas: 'bg-grey-50',
  raised: 'bg-grey-100',
  inset: 'bg-grey-200',
  overlay: 'bg-grey-100',
} as const;

/** Border roles for dividers, inputs and focus. */
export const edge = {
  subtle: 'border-grey-300',
  strong: 'border-grey-400',
  focus: 'border-primary-500',
  invalid: 'border-error-500',
} as const;

/** Elevation roles from branding.md § Shadows & Elevation. */
export const elevation = {
  none: 'shadow-none',
  low: 'shadow-sm',
  mid: 'shadow-md',
  high: 'shadow-lg',
  overlay: 'shadow-xl',
} as const;

/** Corner roles from branding.md § Sizing (Fixed). */
export const radius = {
  sm: 'rounded-radius-sm',
  md: 'rounded-radius-md',
  lg: 'rounded-radius-lg',
  full: 'rounded-radius-full',
} as const;

/** Control sizing roles from branding.md § Sizing (Scales by device). */
export const size = {
  button: 'h-button-height',
  input: 'h-input-height',
  iconSm: 'size-icon-sm',
  iconMd: 'size-icon-md',
  iconLg: 'size-icon-lg',
} as const;

/** Motion roles: instant and mechanical, per the brand motion character. */
export const motion = {
  instant: 'duration-instant',
  fast: 'duration-fast',
  base: 'duration-base',
  slow: 'duration-slow',
  deliberate: 'duration-deliberate',
} as const;

/** Easing roles that pair with the motion durations. */
export const ease = {
  standard: 'ease-standard',
  entrance: 'ease-entrance',
  exit: 'ease-exit',
  mechanical: 'ease-mechanical',
} as const;

export type SecurityState = 'allowed' | 'blocked' | 'pending' | 'quarantined';

/**
 * Security-state roles from branding.md § Status Badges. Colour never carries
 * the state alone: callers pair these classes with an icon and a text label.
 */
export const securityState: Record<
  SecurityState,
  { badge: string; icon: string; label: string }
> = {
  allowed: {
    badge: 'bg-success-100 text-success-900 border border-success-300',
    icon: 'text-success-500',
    label: 'ALLOWED',
  },
  blocked: {
    badge: 'bg-error-100 text-error-900 border border-error-300',
    icon: 'text-error-500',
    label: 'BLOCKED',
  },
  pending: {
    badge: 'bg-warning-100 text-warning-900 border border-warning-300',
    icon: 'text-warning-500',
    label: 'PENDING HITL',
  },
  quarantined: {
    badge: 'bg-error-900 text-error-100 border border-error-500',
    icon: 'text-error-300',
    label: 'QUARANTINED',
  },
};

/**
 * Device classes from branding.md § Responsive & Device Targets. Mirrors the
 * `tablet` / `desktop` / `wide` screens in `tailwind.config.js` and the media
 * queries in `src/index.css` for code that needs a media query in JavaScript.
 */
export const breakpoints = {
  tablet: '600px',
  desktop: '1024px',
  wide: '1440px',
} as const;
