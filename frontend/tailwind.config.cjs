/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./index.html", "./src/**/*.{vue,ts,js,jsx,tsx}"],
  // Use "class" strategy — ".theme-nightshade" activates dark: utilities.
  darkMode: ["class", ".theme-nightshade"],
  theme: {
    extend: {
      colors: {
        // Tactical Industrial accent palette
        brand: {
          blue: "#3b82f6",
          amber: "#f59e0b",
        },
      },
      fontFamily: {
        sans: ["Geist", "Inter", "system-ui", "-apple-system", "sans-serif"],
        mono: ["Geist Mono", "JetBrains Mono", "ui-monospace", "monospace"],
      },
      borderRadius: {
        DEFAULT: "0.25rem",
      },
      backdropBlur: {
        xs: "4px",
      },
    },
  },
  plugins: [],
};