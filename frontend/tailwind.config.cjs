/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./index.html", "./src/**/*.{vue,ts,js,jsx,tsx}"],
  // "class" activates dark: utilities when <html> or <body> has class="dark".
  // ".theme-nightshade" also activates dark: utilities for the Nightshade theme.
  darkMode: ["class", ".theme-nightshade"],
  theme: {
    extend: {}
  },
  plugins: []
};