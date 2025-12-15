import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    host: "0.0.0.0",
    proxy: {
      // Forward frontend /api requests to the FastAPI backend running on :8000.
      // Use 127.0.0.1 explicitly to avoid IPv6 ::1 resolution issues.
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
        ws: true,
      },
    },
  },
  preview: {
    port: 4173,
  },
  resolve: {
    alias: {
      "@": "/src",
    },
  },
});