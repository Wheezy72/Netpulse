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
        sans: ["Inter", "system-ui", "-apple-system", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "monospace"],
      },
      borderRadius: {
        DEFAULT: "0.25rem",
      },
    },
  },
  plugins: [],
};