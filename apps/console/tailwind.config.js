/**
 * Tailwind mapping for the console design tokens.
 *
 * Values are declared once in `src/index.css`; this file only names them so
 * components can consume a utility instead of a raw hex, pixel or timing.
 * Colours are rendered as `rgb(var(--token) / <alpha-value>)` to keep opacity
 * modifiers (`bg-error-500/10`) working from the same channel triplet.
 *
 * @type {import('tailwindcss').Config}
 */
/**
 * Builds a colour scale object whose keys map to `--color-<scale>-<shade>`.
 * @param {string} scale
 * @param {number[]} shades
 */
const scale = (scale, shades) =>
  Object.fromEntries(shades.map((shade) => [shade, `rgb(var(--color-${scale}-${shade}) / <alpha-value>)`]));

export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      screens: {
        /* Device classes from branding.md § Responsive & Device Targets. */
        tablet: '600px',
        desktop: '1024px',
        wide: '1440px',
      },
      colors: {
        primary: scale('primary', [900, 800, 700, 600, 500, 400, 300, 200, 100]),
        grey: scale('grey', [900, 800, 700, 600, 500, 400, 300, 200, 100, 50]),
        success: scale('success', [900, 700, 500, 300, 100]),
        warning: scale('warning', [900, 700, 500, 300, 100]),
        error: scale('error', [900, 700, 500, 300, 100]),
        info: scale('info', [900, 700, 500, 300, 100]),
        accent: scale('accent', [900, 700, 500, 300, 100]),
      },
      fontFamily: {
        sans: 'var(--font-family-sans)',
        mono: 'var(--font-family-mono)',
      },
      fontSize: {
        /* Role names from branding.md § Type Scale; size and leading are both
           token-backed and switch by device class in `src/index.css`. */
        display: ['var(--font-size-display)', { lineHeight: 'var(--line-height-display)' }],
        h1: ['var(--font-size-h1)', { lineHeight: 'var(--line-height-h1)' }],
        h2: ['var(--font-size-h2)', { lineHeight: 'var(--line-height-h2)' }],
        h3: ['var(--font-size-h3)', { lineHeight: 'var(--line-height-h3)' }],
        'body-large': ['var(--font-size-body-large)', { lineHeight: 'var(--line-height-body-large)' }],
        body: ['var(--font-size-body)', { lineHeight: 'var(--line-height-body)' }],
        'body-small': ['var(--font-size-body-small)', { lineHeight: 'var(--line-height-body-small)' }],
        caption: ['var(--font-size-caption)', { lineHeight: 'var(--line-height-caption)' }],
        'mono-code': ['var(--font-size-mono-code)', { lineHeight: 'var(--line-height-mono-code)' }],
      },
      spacing: {
        'space-xs': 'var(--space-xs)',
        'space-sm': 'var(--space-sm)',
        'space-md': 'var(--space-md)',
        'space-lg': 'var(--space-lg)',
        'space-xl': 'var(--space-xl)',
        'space-2xl': 'var(--space-2xl)',
        'space-3xl': 'var(--space-3xl)',
        /* Sizing tokens share the spacing scale so `h-`, `w-`, `size-`, `min-h-`
           and inset utilities can all consume them by name. */
        'button-height': 'var(--size-button-height)',
        'input-height': 'var(--size-input-height)',
        'icon-sm': 'var(--size-icon-sm)',
        'icon-md': 'var(--size-icon-md)',
        'icon-lg': 'var(--size-icon-lg)',
      },
      borderRadius: {
        'radius-sm': 'var(--radius-sm)',
        'radius-md': 'var(--radius-md)',
        'radius-lg': 'var(--radius-lg)',
        'radius-full': 'var(--radius-full)',
      },
      boxShadow: {
        /* Uses Tailwind's own key names so `shadow-sm` resolves to the token
           instead of the framework's built-in rgba value. */
        none: 'var(--shadow-none)',
        sm: 'var(--shadow-sm)',
        md: 'var(--shadow-md)',
        lg: 'var(--shadow-lg)',
        xl: 'var(--shadow-xl)',
      },
      transitionDuration: {
        instant: 'var(--motion-duration-instant)',
        fast: 'var(--motion-duration-fast)',
        base: 'var(--motion-duration-base)',
        slow: 'var(--motion-duration-slow)',
        deliberate: 'var(--motion-duration-deliberate)',
      },
      transitionTimingFunction: {
        standard: 'var(--motion-ease-standard)',
        entrance: 'var(--motion-ease-entrance)',
        exit: 'var(--motion-ease-exit)',
        mechanical: 'var(--motion-ease-mechanical)',
      },
    },
  },
  plugins: [],
};
