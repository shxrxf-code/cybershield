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
        cyber: {
          bg: '#070a10',
          card: '#111822',
          border: '#293542',
          primary: '#43f0a2',
          danger: '#fb5268',
          warning: '#f6b94a',
          info: '#48c9f2',
          accent: '#8b5cf6',
        },
        sentinel: {
          bg: '#070a10',
          card: '#111822',
          border: '#293542',
          primary: '#43f0a2',
          danger: '#fb5268',
          warning: '#f6b94a',
          info: '#48c9f2',
        }
      }
    },
  },
  plugins: [],
}
