<script setup lang="ts">
import { Terminal, type ITheme } from "xterm";
import { FitAddon } from "xterm-addon-fit";
import "xterm/css/xterm.css";

import { onBeforeUnmount, onMounted, ref, watch } from "vue";

const props = defineProps<{
  title: string;
  streamUrl: string | null;
  theme: "nightshade" | "sysadmin";
}>();

const container = ref<HTMLDivElement | null>(null);
let term: Terminal | null = null;
let fitAddon: FitAddon | null = null;
let ws: WebSocket | null = null;
let themeObserver: MutationObserver | null = null;

type Rgba = { r: number; g: number; b: number; a: number };

function parseCssColor(value: string): Rgba | null {
  if (!value) return null;
  if (value === "transparent") return { r: 0, g: 0, b: 0, a: 0 };

  const match = value
    .replace(/\s+/g, "")
    .match(/^rgba?\((\d+),(\d+),(\d+)(?:,(\d*\.?\d+))?\)$/);

  if (!match) return null;

  return {
    r: Number(match[1]),
    g: Number(match[2]),
    b: Number(match[3]),
    a: match[4] === undefined ? 1 : Number(match[4]),
  };
}

function rgba({ r, g, b, a }: Rgba): string {
  return `rgba(${r}, ${g}, ${b}, ${a})`;
}

function resolveEffectiveBackground(el: HTMLElement): string {
  let node: HTMLElement | null = el;
  while (node) {
    const bg = getComputedStyle(node).backgroundColor;
    const parsed = parseCssColor(bg);
    if (parsed && parsed.a > 0.01) return bg;
    node = node.parentElement;
  }
  return "transparent";
}

function buildXtermThemeFromContainer(el: HTMLElement): ITheme {
  const computed = getComputedStyle(el);
  const foreground = computed.color;
  const background = resolveEffectiveBackground(el);

  const fg = parseCssColor(foreground) || { r: 229, g: 231, b: 235, a: 1 };

  return {
    foreground,
    background,
    cursor: rgba({ ...fg, a: 0.9 }),
    cursorAccent: background,
    selectionBackground: rgba({ ...fg, a: 0.2 }),
  };
}

function applyTerminalTheme(): void {
  if (!term || !container.value) return;
  term.options.theme = buildXtermThemeFromContainer(container.value);
  if (term.rows > 0) {
    term.refresh(0, term.rows - 1);
  }
}

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
    cursorStyle: "bar",
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace",
    fontSize: 12,
  });

  fitAddon = new FitAddon();
  term.loadAddon(fitAddon);
  term.open(container.value);
  fitAddon.fit();
  applyTerminalTheme();

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
    window.requestAnimationFrame(() => {
      applyTerminalTheme();
    });
  }
);

function handleResize(): void {
  fitAddon?.fit();
  applyTerminalTheme();
}

function startThemeObserver(): void {
  themeObserver?.disconnect();

  if (!container.value) return;

  themeObserver = new MutationObserver(() => {
    window.requestAnimationFrame(() => {
      applyTerminalTheme();
    });
  });

  themeObserver.observe(document.body, {
    attributes: true,
    attributeFilter: ["class", "style"],
  });

  themeObserver.observe(container.value, {
    attributes: true,
    attributeFilter: ["class", "style"],
  });
}

onMounted(() => {
  initTerminal();
  startThemeObserver();

  window.addEventListener("resize", handleResize);
  if (props.streamUrl) {
    connect(props.streamUrl);
  }
});

onBeforeUnmount(() => {
  window.removeEventListener("resize", handleResize);
  themeObserver?.disconnect();
  themeObserver = null;

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
      <div
        ref="container"
        class="h-full w-full rounded-lg overflow-hidden border"
        :style="{ backgroundColor: 'var(--np-surface)', color: 'var(--np-text)', borderColor: 'var(--np-border)' }"
      ></div>
    </div>
  </div>
</template>
