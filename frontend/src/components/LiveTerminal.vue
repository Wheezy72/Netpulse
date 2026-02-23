<script setup lang="ts">
import { Terminal } from "xterm";
import { FitAddon } from "xterm-addon-fit";
import "xterm/css/xterm.css";

import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";

const props = defineProps<{
  title: string;
  streamUrl: string | null;
  theme: "nightshade" | "sysadmin";
}>();

const isNightshade = computed(() => props.theme === "nightshade");

const container = ref<HTMLDivElement | null>(null);
let term: Terminal | null = null;
let fitAddon: FitAddon | null = null;
let ws: WebSocket | null = null;

function disposeSocket(): void {
  try {
    ws?.close();
  } catch {
    // ignore
  }
  ws = null;
}

function initTerminal(): void {
  if (!container.value) return;

  term = new Terminal({
    disableStdin: true,
    convertEol: true,
    cursorBlink: false,
    fontFamily: isNightshade.value ? "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace" : "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace",
    fontSize: 12,
    theme: isNightshade.value
      ? {
          background: "#0b1220",
          foreground: "#d1fae5",
          cursor: "#2dd4bf",
        }
      : {
          background: "#0b1220",
          foreground: "#e5e7eb",
          cursor: "#f59e0b",
        },
  });

  fitAddon = new FitAddon();
  term.loadAddon(fitAddon);
  term.open(container.value);
  fitAddon.fit();

  term.writeln("Ready. Start a scan to stream output here...");
}

function connect(url: string): void {
  if (!term) return;

  disposeSocket();

  try {
    ws = new WebSocket(url);
  } catch (e) {
    term.writeln(`\n[error] Failed to open WebSocket: ${String(e)}\n`);
    return;
  }

  ws.onopen = () => {
    term?.writeln(`\n[connected] ${url}\n`);
  };

  ws.onmessage = (ev) => {
    const data = typeof ev.data === "string" ? ev.data : "";
    term?.write(data);
  };

  ws.onerror = () => {
    term?.writeln("\n[error] WebSocket error\n");
  };

  ws.onclose = (ev) => {
    term?.writeln(`\n[disconnected] code=${ev.code}\n`);
  };
}

function clear(): void {
  term?.clear();
  term?.writeln("Starting new stream...\n");
}

watch(
  () => props.streamUrl,
  (next) => {
    if (!term) return;
    disposeSocket();

    if (!next) {
      term.writeln("\n[idle] No active stream\n");
      return;
    }

    clear();
    connect(next);
  }
);

watch(
  () => props.theme,
  () => {
    // Recreate for consistent theming.
    if (!container.value) return;
    disposeSocket();
    term?.dispose();
    term = null;
    initTerminal();
    if (props.streamUrl) {
      connect(props.streamUrl);
    }
  }
);

function handleResize(): void {
  fitAddon?.fit();
}

onMounted(() => {
  initTerminal();
  window.addEventListener("resize", handleResize);
  if (props.streamUrl) {
    connect(props.streamUrl);
  }
});

onBeforeUnmount(() => {
  window.removeEventListener("resize", handleResize);
  disposeSocket();
  term?.dispose();
  term = null;
});
</script>

<template>
  <div class="np-panel h-full flex flex-col">
    <div class="flex items-center justify-between px-4 py-3 border-b" :style="{ borderColor: 'var(--np-border)' }">
      <h3 class="np-panel-title">{{ title }}</h3>
      <div class="text-[0.7rem] text-[var(--np-muted-text)]">Live Stream</div>
    </div>
    <div class="flex-1 p-3">
      <div ref="container" class="h-full w-full rounded-lg overflow-hidden" :style="{ background: '#0b1220' }"></div>
    </div>
  </div>
</template>
