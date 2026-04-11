import { defineConfig, Plugin } from "vite";
import vue from "@vitejs/plugin-vue";
import net from "net";

/**
 * Returns true when the given TCP port is not currently bound on localhost.
 * A temporary server is probed and immediately closed so no port is left open.
 */
function isPortFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const probe = net.createServer();
    probe.once("error", () => resolve(false));
    probe.once("listening", () => probe.close(() => resolve(true)));
    probe.listen(port, "127.0.0.1");
  });
}

/**
 * Vite plugin: picks the first free port from `ports` and injects it into the
 * server config before Vite binds its socket.  This eliminates EADDRINUSE
 * crashes and avoids port collisions with other services (e.g. a stale Lumen
 * dev server on 5173).
 */
function portFallback(ports: number[]): Plugin {
  return {
    name: "np-port-fallback",
    async config(config) {
      for (const port of ports) {
        if (await isPortFree(port)) {
          config.server ??= {};
          config.server.port = port;
          config.server.strictPort = true;
          console.info(`[np-port-fallback] Binding to port ${port}`);
          return;
        }
        console.warn(`[np-port-fallback] Port ${port} is busy, trying next…`);
      }
      console.warn("[np-port-fallback] All preferred ports busy; Vite will fall back to its default (5173), which may also be in use.");
    },
  };
}

export default defineConfig({
  plugins: [
    vue(),
    portFallback([6969, 6970, 8888, 9999]),
  ],
  server: {
    host: "0.0.0.0",
    allowedHosts: true,
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
});
