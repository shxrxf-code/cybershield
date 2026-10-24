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
        sentinel: {
          bg: '#0a0a0f',
          card: '#111118',
          border: '#1e1e2e',
          primary: '#00ff88',
          danger: '#ff4444',
          warning: '#ffaa00',
          info: '#00aaff',
        }
      }
    },
  },
  plugins: [],
}
