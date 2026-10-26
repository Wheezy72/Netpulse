import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
  plugins: [vue()],
  server: {
    host: "0.0.0.0",
    allowedHosts: true,
    // 6969 is the preferred port, but a second checkout (or a leftover Vite
    // from a previous launch) may already hold it. Vite's own fallback then
    // increments to 6970, 6971... and prints the URL it actually bound. The
    // custom probe that used to live here checked the port *before* binding
    // and set strictPort, so the same busy port made startup fail outright:
    // "Port 6969 is already in use" and no dev server at all.
    port: 6969,
    strictPort: false,
    proxy: {
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
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("node_modules")) {
            if (id.includes("echarts") || id.includes("zrender")) {
              return "vendor-echarts";
            }
            if (id.includes("@vue-flow")) {
              return "vendor-graphs";
            }
            return "vendor";
          }
        },
      },
    },
  },
});
