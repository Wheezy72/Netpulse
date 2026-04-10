/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./index.html", "./src/**/*.{vue,ts,js,jsx,tsx}"],
  // Tailwind v3 supports an array for darkMode: the first element is the
  // strategy ("class") and subsequent elements are additional selectors that
  // also activate dark: utilities. ".theme-nightshade" enables dark: classes
  // when the Nightshade theme is active (applied to <html> by the uiStore).
  darkMode: ["class", ".theme-nightshade"],
  theme: {
    extend: {}
  },
  plugins: []
};