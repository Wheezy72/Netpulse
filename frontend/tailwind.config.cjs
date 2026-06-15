/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./index.html", "./src/**/*.{vue,ts,js,jsx,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // Eclipse – Dark Purple/Magenta palette
        surface: {
          base: "#0a0a14",
          card: "#0f0c1e",
          elevated: "#161228",
          hover: "#1c1635",
        },
        accent: {
          primary: "#d946ef",    // Fuchsia-500 — main accent
          secondary: "#a855f7",  // Purple-500
          tertiary: "#7c3aed",   // Violet-600
          muted: "#6b6894",      // Muted purple-gray
        },
        border: {
          DEFAULT: "rgba(139, 92, 246, 0.15)",
          subtle: "rgba(139, 92, 246, 0.08)",
          bright: "rgba(217, 70, 239, 0.4)",
        },
      },
      fontFamily: {
        sans: ["Geist", "Inter", "system-ui", "-apple-system", "sans-serif"],
        mono: ["Geist Mono", "JetBrains Mono", "ui-monospace", "monospace"],
      },
      borderRadius: {
        DEFAULT: "0.5rem",
      },
      backdropBlur: {
        xs: "4px",
      },
    },
  },
  plugins: [],
};