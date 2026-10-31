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
let themeObserver: MutationObserver | null = null;
let resizeObserver: ResizeObserver | null = null;
let fitQueued = false;

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

/**
 * Re-fit once the container has its real size.
 *
 * The drawer this sits in is revealed with a transform, and it is mounted
 * before its final height settles — fitting only on mount left the terminal at
 * 384px inside a 170px panel, so the last rows were cut off and the interior
 * scrolled inside a box that already filled the screen. Fitting on every
 * container resize (and once more after the first paint) keeps the terminal
 * exactly the size of the space it is given.
 */
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
  });

  fitAddon = new FitAddon();
  term.loadAddon(fitAddon);
  term.open(container.value);
  applyTerminalTheme();

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

watch(
  () => props.theme,
  () => {
    window.requestAnimationFrame(() => {
      applyTerminalTheme();
    });
  }
);

function handleResize(): void {
  scheduleFit();
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
  themeObserver?.disconnect();
  themeObserver = null;
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
      <div
        ref="container"
        class="h-full w-full rounded-lg overflow-hidden"
        style="border: 1px solid var(--np-border); background: var(--np-bg); color: var(--np-text);"
      ></div>
    </div>
  </div>
</template>
