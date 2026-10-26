<script setup lang="ts">
/**
 * One animated glyph family for the whole shell.
 *
 * Lucide gave the app a consistent stroke weight but no character: every icon
 * was a still line drawing, and the shell's own navigation could only be
 * identified by reading the label. These are hand-drawn for the four things
 * NetPulse actually does -- look at a network, scan it, log it, configure it --
 * and each one moves in the way its subject moves: a scan line crosses the
 * monitor, topology pulses travel the links, log lines scroll, the gear turns.
 *
 * Motion is state-driven, never a permanent loop: a glyph animates while it is
 * hovered or while it represents the page you are on, and is still otherwise.
 * Everything is SVG + CSS, so there is no animation runtime and reduced-motion
 * users get the same drawings without the movement.
 */
type GlyphName =
  | "dashboard"
  | "topology"
  | "devices"
  | "toolbox"
  | "logs"
  | "settings"
  | "scan"
  | "sweep"
  | "terminal"
  | "packets";

withDefaults(
  defineProps<{
    name: GlyphName;
    /** Set while the action is busy or its page is open. */
    active?: boolean;
  }>(),
  { active: false }
);
</script>

<template>
  <span class="np-glyph" :class="[`np-glyph--${name}`, { 'is-active': active }]">
    <!-- Dashboard: four panels that settle into place. -->
    <svg
      v-if="name === 'dashboard'"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="1.6"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      <rect class="np-g-panel np-g-panel--1" x="3" y="3" width="7.4" height="7.4" rx="1.8" />
      <rect class="np-g-panel np-g-panel--2" x="13.6" y="3" width="7.4" height="4.6" rx="1.8" />
      <rect class="np-g-panel np-g-panel--3" x="13.6" y="10.4" width="7.4" height="10.6" rx="1.8" />
      <rect class="np-g-panel np-g-panel--4" x="3" y="13.2" width="7.4" height="7.8" rx="1.8" />
    </svg>

    <!-- Topology: two leaves and a trunk, with traffic on the links. -->
    <svg
      v-else-if="name === 'topology'"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="1.6"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      <path class="np-g-link" d="M12 9v4.4M12 13.4 6.4 17M12 13.4l5.6 3.6" />
      <circle class="np-g-node np-g-node--trunk" cx="12" cy="6.2" r="2.8" />
      <circle class="np-g-node np-g-node--a" cx="5.2" cy="18.6" r="2.4" />
      <circle class="np-g-node np-g-node--b" cx="18.8" cy="18.6" r="2.4" />
    </svg>

    <!-- Devices: a monitor whose scan line sweeps while it is watched. -->
    <svg
      v-else-if="name === 'devices'"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="1.6"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      <rect x="2.6" y="4.4" width="18.8" height="12.2" rx="2.2" />
      <path class="np-g-stand" d="M9.2 20.4h5.6M12 16.6v3.8" />
      <path class="np-g-scanline" d="M5 8.4h13.8" />
    </svg>

    <!-- Toolbox: the latch lifts, then the lid settles. -->
    <svg
      v-else-if="name === 'toolbox'"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="1.6"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      <path d="M3 9.6h18v9.2a1.6 1.6 0 0 1-1.6 1.6H4.6A1.6 1.6 0 0 1 3 18.8Z" />
      <path class="np-g-lid" d="M3 9.6V8a1.6 1.6 0 0 1 1.6-1.6h14.8A1.6 1.6 0 0 1 21 8v1.6" />
      <path class="np-g-handle" d="M8.6 6.4V4.9A1.4 1.4 0 0 1 10 3.5h4a1.4 1.4 0 0 1 1.4 1.4v1.5" />
      <path class="np-g-latch" d="M10 13.2h4" />
    </svg>

    <!-- Logs: a sheet whose lines scroll, newest at the bottom. -->
    <svg
      v-else-if="name === 'logs'"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="1.6"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      <path d="M5.4 3.4h9.2l4.4 4.4v12.8H5.4Z" />
      <path class="np-g-fold" d="M14.6 3.4v4.4h4.4" />
      <path class="np-g-lines" d="M8.4 12h7.2M8.4 15h7.2M8.4 18h4.4" />
    </svg>

    <!-- Settings: a gear that turns only while it has attention. -->
    <svg
      v-else-if="name === 'settings'"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="1.6"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      <g class="np-g-gear">
        <path
          d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2Z"
        />
      </g>
      <circle class="np-g-core" cx="12" cy="12" r="3" />
    </svg>

    <!-- Targeted port scan: a reticle that turns onto the target. -->
    <svg
      v-else-if="name === 'scan'"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="1.6"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="7.5" />
      <path d="M12 2.5v3M12 18.5v3M2.5 12h3M18.5 12h3" />
      <circle class="np-g-core" cx="12" cy="12" r="1.6" />
      <path class="np-g-sweep-hand" d="M12 12 17.3 6.7" />
    </svg>

    <!-- Discovery sweep: rings going out until something answers. -->
    <svg
      v-else-if="name === 'sweep'"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="1.6"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      <circle class="np-g-core" cx="12" cy="12" r="1.5" />
      <path class="np-g-ping np-g-ping--1" d="M8.4 15.6a5.1 5.1 0 0 1 0-7.2" />
      <path class="np-g-ping np-g-ping--2" d="M15.6 8.4a5.1 5.1 0 0 1 0 7.2" />
      <path class="np-g-ping np-g-ping--3" d="M5.6 18.4a9 9 0 0 1 0-12.8" />
      <path class="np-g-ping np-g-ping--4" d="M18.4 5.6a9 9 0 0 1 0 12.8" />
    </svg>

    <!-- Remote shell: a prompt whose caret blinks. -->
    <svg
      v-else-if="name === 'terminal'"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="1.6"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      <path d="M4 5.5h16a1.5 1.5 0 0 1 1.5 1.5v10a1.5 1.5 0 0 1-1.5 1.5H4A1.5 1.5 0 0 1 2.5 17V7A1.5 1.5 0 0 1 4 5.5Z" />
      <path class="np-g-chevron" d="m6.8 10 2.4 2-2.4 2" />
      <path class="np-g-caret" d="M11.6 14.2h3.2" />
    </svg>

    <!-- Packet capture: traffic moving across a wire. -->
    <svg
      v-else
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="1.6"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      <path class="np-g-wave np-g-wave--1" d="M2.5 9c2.3-3.2 4.6-3.2 6.9 0s4.6 3.2 6.9 0 4.6-3.2 5.2 0" />
      <path class="np-g-wave np-g-wave--2" d="M2.5 15c2.3 3.2 4.6 3.2 6.9 0s4.6-3.2 6.9 0 4.6 3.2 5.2 0" />
      <circle class="np-g-particle np-g-particle--1" cx="7" cy="12" r="0.9" />
      <circle class="np-g-particle np-g-particle--2" cx="12" cy="12" r="0.9" />
      <circle class="np-g-particle np-g-particle--3" cx="17" cy="12" r="0.9" />
    </svg>
  </span>
</template>

<style scoped>
.np-glyph {
  display: inline-flex;
  height: 18px;
  width: 18px;
}

.np-glyph svg {
  height: 100%;
  width: 100%;
  overflow: visible;
}

/* ── Dashboard: panels breathe outward from the centre ─────────────────── */
.np-g-panel {
  transition: transform 220ms cubic-bezier(0.2, 0.8, 0.2, 1);
}
.np-glyph:hover .np-g-panel--1,
.np-glyph.is-active .np-g-panel--1 { transform: translate(-0.6px, -0.6px); }
.np-glyph:hover .np-g-panel--2,
.np-glyph.is-active .np-g-panel--2 { transform: translate(0.6px, -0.6px); }
.np-glyph:hover .np-g-panel--3,
.np-glyph.is-active .np-g-panel--3 { transform: translate(0.6px, 0.6px); }
.np-glyph:hover .np-g-panel--4,
.np-glyph.is-active .np-g-panel--4 { transform: translate(-0.6px, 0.6px); }

/* ── Topology: pulses travel along the links ───────────────────────────── */
.np-g-link {
  stroke-dasharray: 2.6 2.6;
  opacity: 0.7;
}
.np-glyph:hover .np-g-link,
.np-glyph.is-active .np-g-link {
  animation: np-g-flow 1.4s linear infinite;
}
.np-glyph:hover .np-g-node--a,
.np-glyph.is-active .np-g-node--a { animation: np-g-fade 1.4s ease-in-out infinite; }
.np-glyph:hover .np-g-node--b,
.np-glyph.is-active .np-g-node--b { animation: np-g-fade 1.4s ease-in-out infinite 0.35s; }
.np-glyph:hover .np-g-node--trunk,
.np-glyph.is-active .np-g-node--trunk { animation: np-g-fade 1.4s ease-in-out infinite 0.7s; }

@keyframes np-g-flow {
  to { stroke-dashoffset: -10.4; }
}
@keyframes np-g-fade {
  0%, 100% { opacity: 0.45; }
  50% { opacity: 1; }
}

/* ── Devices: the scan line crosses the screen ─────────────────────────── */
.np-g-scanline {
  opacity: 0;
  stroke: var(--np-accent, currentColor);
}
.np-glyph:hover .np-g-scanline,
.np-glyph.is-active .np-g-scanline {
  animation: np-g-scan 1.8s cubic-bezier(0.4, 0, 0.2, 1) infinite;
}

@keyframes np-g-scan {
  0% { opacity: 0; transform: translateY(-4.6px); }
  15% { opacity: 0.9; }
  85% { opacity: 0.9; }
  100% { opacity: 0; transform: translateY(3.4px); }
}

/* ── Toolbox: the latch lifts ─────────────────────────────────────────── */
.np-g-latch,
.np-g-handle,
.np-g-lid {
  transition: transform 240ms cubic-bezier(0.2, 0.8, 0.2, 1);
}
.np-glyph:hover .np-g-latch,
.np-glyph.is-active .np-g-latch { transform: translateY(-1.1px); }
.np-glyph:hover .np-g-lid,
.np-glyph.is-active .np-g-lid { transform: translateY(-0.5px); }
.np-glyph:hover .np-g-handle,
.np-glyph.is-active .np-g-handle { transform: translateY(-0.7px); }

/* ── Logs: lines scroll, as the viewer does ───────────────────────────── */
.np-glyph:hover .np-g-lines,
.np-glyph.is-active .np-g-lines {
  animation: np-g-scroll 1.6s ease-in-out infinite;
}
.np-glyph:hover .np-g-fold,
.np-glyph.is-active .np-g-fold { opacity: 0.8; }

@keyframes np-g-scroll {
  0%, 100% { transform: translateY(0); opacity: 1; }
  50% { transform: translateY(-1.6px); opacity: 0.55; }
}

/* ── Settings: a quarter turn while hovered ───────────────────────────── */
.np-g-gear {
  transform-origin: 12px 12px;
  transition: transform 420ms cubic-bezier(0.2, 0.8, 0.2, 1);
}
.np-glyph:hover .np-g-gear,
.np-glyph.is-active .np-g-gear {
  animation: np-g-turn 5s linear infinite;
}

@keyframes np-g-turn {
  to { transform: rotate(360deg); }
}

/* ── Scan: the reticle turns onto the target ───────────────────────────── */
.np-g-sweep-hand {
  transform-origin: 12px 12px;
  opacity: 0.55;
}
.np-glyph:hover .np-g-sweep-hand,
.np-glyph.is-active .np-g-sweep-hand {
  animation: np-g-turn 2.4s linear infinite;
  opacity: 0.9;
}
.np-glyph:hover .np-g-core,
.np-glyph.is-active .np-g-core {
  animation: np-g-pulse 1.6s ease-in-out infinite;
}

@keyframes np-g-pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.35; }
}

/* ── Sweep: rings leave the centre one after another ───────────────────── */
.np-g-ping {
  opacity: 0.35;
}
.np-glyph:hover .np-g-ping,
.np-glyph.is-active .np-g-ping {
  animation: np-g-ping 1.8s ease-out infinite;
}
.np-glyph:hover .np-g-ping--2,
.np-glyph.is-active .np-g-ping--2 { animation-delay: 0.45s; }
.np-glyph:hover .np-g-ping--3,
.np-glyph.is-active .np-g-ping--3 { animation-delay: 0.9s; }
.np-glyph:hover .np-g-ping--4,
.np-glyph.is-active .np-g-ping--4 { animation-delay: 1.35s; }

@keyframes np-g-ping {
  0% { opacity: 0.25; transform: scale(0.86); }
  40% { opacity: 0.9; }
  100% { opacity: 0.25; transform: scale(1.06); }
}

/* ── Terminal: caret blinks; the prompt nudges ────────────────────────── */
.np-g-caret { opacity: 0.85; }
.np-glyph:hover .np-g-caret,
.np-glyph.is-active .np-g-caret {
  animation: np-g-blink 1.1s steps(1, end) infinite;
}
.np-glyph:hover .np-g-chevron,
.np-glyph.is-active .np-g-chevron {
  animation: np-g-nudge 1.6s ease-in-out infinite;
}

@keyframes np-g-blink {
  0%, 55% { opacity: 1; }
  56%, 100% { opacity: 0.15; }
}

@keyframes np-g-nudge {
  0%, 100% { transform: translateX(0); }
  50% { transform: translateX(1px); }
}

/* ── Packets: a wave travels the wire, a packet rides it ──────────────── */
.np-g-wave--2 { opacity: 0.45; }
.np-g-particle { opacity: 0.5; }
.np-glyph:hover .np-g-wave,
.np-glyph.is-active .np-g-wave {
  animation: np-g-wave 2s ease-in-out infinite;
  stroke-dasharray: 22 6;
}
.np-glyph:hover .np-g-particle,
.np-glyph.is-active .np-g-particle {
  animation: np-g-ride 2s ease-in-out infinite;
}
.np-glyph:hover .np-g-particle--2,
.np-glyph.is-active .np-g-particle--2 { animation-delay: 0.25s; }
.np-glyph:hover .np-g-particle--3,
.np-glyph.is-active .np-g-particle--3 { animation-delay: 0.5s; }

@keyframes np-g-wave {
  to { stroke-dashoffset: -28; }
}

@keyframes np-g-ride {
  0%, 100% { opacity: 0.35; }
  50% { opacity: 1; }
}

/* Motion is the point, but it is also optional. */
@media (prefers-reduced-motion: reduce) {
  .np-glyph svg * {
    animation: none !important;
    transition: none !important;
  }
}
</style>
