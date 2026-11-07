/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        shield: {
          bg: '#0B100E',
          'bg-secondary': '#101713',
          surface: '#141D18',
          'surface-elevated': '#19251E',
          'surface-hover': '#1F2E26',
          accent: '#367055',
          'accent-light': '#79A98B',
          'accent-soft': '#244B3A',
          'accent-muted': 'rgba(54, 112, 85, 0.25)',
          'text-primary': '#E8EEE9',
          'text-secondary': '#9AA9A0',
          'text-muted': '#64756B',
          border: 'rgba(190, 215, 198, 0.12)',
          'border-strong': 'rgba(190, 215, 198, 0.24)',
          danger: '#D97878',
          'danger-soft': 'rgba(217, 120, 120, 0.14)',
          warning: '#D7AA62',
          'warning-soft': 'rgba(215, 170, 98, 0.14)',
          success: '#78B58D',
          'success-soft': 'rgba(120, 181, 141, 0.14)',
          info: '#91A9B7',
          'info-soft': 'rgba(145, 169, 183, 0.14)',
        },
      },
      fontFamily: {
        sans: ['Manrope', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'Menlo', 'Consolas', 'monospace'],
        arabic: ['"Noto Sans Arabic"', 'sans-serif'],
      },
      boxShadow: {
        'clay-sm': '0 2px 4px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(190, 215, 198, 0.08), inset 0 -1px 0 rgba(0, 0, 0, 0.4)',
        'clay-card': '0 8px 24px rgba(0, 0, 0, 0.45), 0 2px 6px rgba(0, 0, 0, 0.3), inset 0 1px 1px rgba(190, 215, 198, 0.12), inset 0 -2px 4px rgba(0, 0, 0, 0.4)',
        'clay-hover': '0 14px 32px rgba(0, 0, 0, 0.55), 0 4px 10px rgba(0, 0, 0, 0.35), inset 0 1px 2px rgba(121, 169, 139, 0.25), inset 0 -2px 4px rgba(0, 0, 0, 0.4)',
        'clay-input': 'inset 0 2px 5px rgba(0, 0, 0, 0.6), inset 0 1px 2px rgba(0, 0, 0, 0.4), 0 1px 0 rgba(190, 215, 198, 0.06)',
        'clay-button': '0 4px 12px rgba(16, 23, 19, 0.6), inset 0 1px 1px rgba(255, 255, 255, 0.15), inset 0 -2px 4px rgba(0, 0, 0, 0.4)',
        'clay-button-active': 'inset 0 3px 6px rgba(0, 0, 0, 0.5), inset 0 -1px 1px rgba(255, 255, 255, 0.1)',
      },
      animation: {
        'ticker-l2r': 'ticker-l2r 40s linear infinite',
        'ticker-r2l': 'ticker-r2l 40s linear infinite',
        'pulse-subtle': 'pulse-subtle 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
      keyframes: {
        'ticker-l2r': {
          '0%': { transform: 'translateX(-50%)' },
          '100%': { transform: 'translateX(0%)' },
        },
        'ticker-r2l': {
          '0%': { transform: 'translateX(0%)' },
          '100%': { transform: 'translateX(-50%)' },
        },
        'pulse-subtle': {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.65' },
        },
      },
    },
  },
  plugins: [],
}

