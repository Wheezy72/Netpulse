<script setup lang="ts">
import { Terminal, type ITheme } from "xterm";
import { FitAddon } from "xterm-addon-fit";
import "xterm/css/xterm.css";

import { onBeforeUnmount, onMounted, ref, watch } from "vue";

const props = defineProps<{
  title: string;
  streamUrl: string | null;
  theme: "nightshade" | "sysadmin";
  /** Sent as the WebSocket subprotocol so it stays out of URLs and logs. */
  token?: string | null;
  /** Let the host draw the header: one title bar per panel, never two. */
  chromeless?: boolean;
}>();

const container = ref<HTMLDivElement | null>(null);
let term: Terminal | null = null;
let fitAddon: FitAddon | null = null;
let ws: WebSocket | null = null;
let resizeObserver: ResizeObserver | null = null;
let fitQueued = false;

/**
 * The console is a terminal, and terminals are dark.
 *
 * It used to derive its palette from the surrounding page, which meant light
 * mode turned a black console white: nmap output in 12px monospace on a white
 * field, and nothing like the dark IDE panels it sits beside. The surrounding
 * chrome still follows the theme; the emulator inside does not.
 */
const TERMINAL_THEME: ITheme = {
  background: "#0b0f14",
  foreground: "#e5e7eb",
  cursor: "#34d399",
  cursorAccent: "#0b0f14",
  selectionBackground: "rgba(16, 185, 129, 0.30)",
  black: "#111827",
  red: "#f87171",
  green: "#34d399",
  yellow: "#fbbf24",
  blue: "#60a5fa",
  magenta: "#c084fc",
  cyan: "#22d3ee",
  white: "#e5e7eb",
  brightBlack: "#6b7280",
  brightRed: "#fca5a5",
  brightGreen: "#6ee7b7",
  brightYellow: "#fcd34d",
  brightBlue: "#93c5fd",
  brightMagenta: "#d8b4fe",
  brightCyan: "#67e8f9",
  brightWhite: "#f9fafb",
};

function disposeSocket(): void {
  try {
    ws?.close();
  } catch {
    // ignore
  }
  ws = null;
}

/**
 * Fit the terminal to its box by measuring the grid xterm already drew.
 *
 * FitAddon reads cell metrics from xterm's private render service, and in this
 * build that reports a zero cell size, so every fit() returned silently and the
 * terminal stayed at its default 24 rows — taller than the drawer, with the
 * last lines clipped. One rendered row gives the real cell height, and the rows
 * container gives the width of a full line, so the grid can be derived from the
 * DOM instead of a private API.
 */
function fitToBox(): void {
  const host = container.value;
  if (!host || !term) return;

  // A rendered row gives the real cell height. Column count is left alone: the
  // default 80 columns already fit the drawer's width, and deriving it from the
  // rows container feeds back on itself (the container widens to the widest
  // line, which inflates the estimate, which widens it again).
  const firstRow = host.querySelector<HTMLElement>(".xterm-rows")?.firstElementChild;
  const cellHeight = firstRow?.getBoundingClientRect().height ?? 0;
  if (!cellHeight) return;

  const rows = Math.max(1, Math.floor(host.clientHeight / cellHeight));
  if (rows !== term.rows) {
    term.resize(term.cols, rows);
  }
}

function scheduleFit(): void {
  if (fitQueued) return;
  fitQueued = true;
  window.requestAnimationFrame(() => {
    fitQueued = false;
    if (!container.value || !term) return;
    fitToBox();
  });
}

function initTerminal(): void {
  if (!container.value) return;

  term = new Terminal({
    disableStdin: true,
    convertEol: true,
    cursorBlink: false,
    cursorStyle: "bar",
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace",
    fontSize: 12,
    theme: TERMINAL_THEME,
  });

  fitAddon = new FitAddon();
  term.loadAddon(fitAddon);
  term.open(container.value);

  term.writeln("Ready. Start a scan to stream output here...");
  // Fit after the first row exists: the row's height is the measurement this
  // component relies on, and an empty grid has nothing to measure.
  scheduleFit();

  // The panel is resized by the drawer opening, by the window changing, and by
  // the layout settling after a scan starts; one observer covers all three.
  resizeObserver?.disconnect();
  resizeObserver = new ResizeObserver(scheduleFit);
  resizeObserver.observe(container.value);
}

function connect(url: string): void {
  if (!term) return;

  disposeSocket();

  try {
    // "bearer.<jwt>" rides in the subprotocol list; the query string would put
    // the token into every access log along the way.
    ws = props.token
      ? new WebSocket(url, [`bearer.${props.token}`])
      : new WebSocket(url);
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

// A re-issued token (after a refresh) has to reconnect: the old socket still
// carries the old credential.
watch(
  () => props.token,
  (next, previous) => {
    if (!term || next === previous || !props.streamUrl) return;
    disposeSocket();
    connect(props.streamUrl);
  }
);

function handleResize(): void {
  scheduleFit();
}

onMounted(() => {
  initTerminal();
  // A second fit after the first paint catches a drawer that was still moving
  // when the terminal opened.
  window.setTimeout(scheduleFit, 260);

  window.addEventListener("resize", handleResize);
  if (props.streamUrl) {
    connect(props.streamUrl);
  }
});

onBeforeUnmount(() => {
  window.removeEventListener("resize", handleResize);
  resizeObserver?.disconnect();
  resizeObserver = null;

  disposeSocket();
  term?.dispose();
  term = null;
});
</script>

<template>
  <div class="np-panel h-full flex flex-col border-0 rounded-none">
    <div
      v-if="!chromeless"
      class="flex items-center justify-between px-4 py-3"
      style="border-bottom: 1px solid var(--np-border-subtle);"
    >
      <h3 class="text-sm font-semibold" style="color: var(--np-text);">{{ title }}</h3>
      <div class="text-[0.7rem]" style="color: var(--np-text-dim);">Live Stream</div>
    </div>

    <!-- min-h-0 + overflow-hidden matter: without them this flex child keeps a
         min-content height, so a terminal that was once fitted too large props
         the whole drawer open instead of being contained by it. -->
    <div class="flex-1 min-h-0 overflow-hidden p-3">
      <!-- The frame is dark in both themes: a terminal with a white field is
           the one place where following the theme hurts. -->
      <div
        ref="container"
        class="h-full w-full rounded-lg overflow-hidden"
        style="border: 1px solid rgba(255, 255, 255, 0.08); background: #0b0f14; color: #e5e7eb;"
      ></div>
    </div>
  </div>
</template>
