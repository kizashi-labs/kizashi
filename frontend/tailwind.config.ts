import type { Config } from 'tailwindcss'

const config: Config = {
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        // Falcon design system
        falcon: {
          bg:      '#080c14',  // deepest background
          surface: '#0d1220',  // sidebar / panels
          card:    '#111827',  // card backgrounds
          raised:  '#161f33',  // elevated cards
          border:  '#1e2d42',  // default borders
          hover:   '#19253d',  // hover state
          active:  '#1d2f4a',  // active state bg
          red:     '#e8002d',  // primary accent (CrowdStrike red)
          'red-dark': '#a80020',
          'red-dim':  'rgba(232,0,45,0.12)',
          blue:    '#1a6bff',
          'blue-dim': 'rgba(26,107,255,0.12)',
          cyan:    '#00b8d4',
          green:   '#00c853',
          'green-dim': 'rgba(0,200,83,0.12)',
          amber:   '#ff9800',
          'amber-dim': 'rgba(255,152,0,0.12)',
          text:    '#e2e8f4',    // primary text
          muted:   '#7d92b0',    // secondary text
          subtle:  '#3d5068',    // tertiary / placeholder
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
      boxShadow: {
        'falcon-card': '0 1px 3px rgba(0,0,0,0.4), 0 1px 2px rgba(0,0,0,0.6)',
        'falcon-modal': '0 25px 50px rgba(0,0,0,0.7), 0 10px 20px rgba(0,0,0,0.5)',
        'falcon-glow-red': '0 0 12px rgba(232,0,45,0.3)',
        'falcon-glow-blue': '0 0 12px rgba(26,107,255,0.3)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4,0,0.6,1) infinite',
        'fade-in': 'fadeIn 0.15s ease-out',
        'slide-in': 'slideIn 0.2s ease-out',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideIn: {
          '0%': { opacity: '0', transform: 'translateY(-4px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
      backgroundImage: {
        'falcon-gradient': 'linear-gradient(180deg, #0d1220 0%, #080c14 100%)',
        'falcon-card-gradient': 'linear-gradient(145deg, #111827 0%, #0d1220 100%)',
        'red-gradient': 'linear-gradient(135deg, #e8002d 0%, #a80020 100%)',
      },
    },
  },
  plugins: [],
}
export default config
