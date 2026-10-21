<script setup lang="ts">
/**
 * NetPulse brand mark.
 *
 * The product watches a network and reports whether anything answers, so the
 * mark is a node doing exactly that: a core that emits a heartbeat ring on a
 * slow beat, under a radar sweep. Everything is drawn in currentColor, so the
 * mark inherits whatever accent the surrounding text uses and needs no theme
 * variants of its own.
 *
 * It is SVG and CSS rather than a GIF or MP4: it stays sharp at 16px, follows
 * the theme automatically, and costs a few hundred bytes instead of megabytes.
 * Under prefers-reduced-motion it holds still as a plain node.
 */
defineProps<{ size?: number }>();
</script>

<template>
  <svg
    class="np-brand-mark"
    :width="size"
    :height="size"
    viewBox="0 0 32 32"
    fill="none"
    aria-hidden="true"
    focusable="false"
  >
    <rect x="2.5" y="2.5" width="27" height="27" rx="8.5" class="np-brand-mark__frame" />
    <circle cx="16" cy="16" r="6" class="np-brand-mark__ring np-brand-mark__ring--a" />
    <circle cx="16" cy="16" r="6" class="np-brand-mark__ring np-brand-mark__ring--b" />
    <g class="np-brand-mark__sweep">
      <path d="M16 16V5.5" class="np-brand-mark__beam" />
    </g>
    <circle cx="16" cy="16" r="3.4" class="np-brand-mark__core" />
  </svg>
</template>

<style scoped>
.np-brand-mark {
  display: block;
  overflow: visible;
}

.np-brand-mark__frame {
  stroke: currentColor;
  stroke-opacity: 0.35;
  stroke-width: 1.5;
}

.np-brand-mark__core {
  fill: currentColor;
}

.np-brand-mark__ring {
  fill: none;
  stroke: currentColor;
  stroke-width: 1.5;
  transform-box: fill-box;
  transform-origin: center;
  animation: np-mark-ping 3.2s cubic-bezier(0.22, 0.61, 0.36, 1) infinite;
}

.np-brand-mark__ring--b {
  animation-delay: 1.6s;
}

.np-brand-mark__sweep {
  transform-box: fill-box;
  transform-origin: center;
  animation: np-mark-sweep 4.2s linear infinite;
}

.np-brand-mark__beam {
  stroke: currentColor;
  stroke-opacity: 0.5;
  stroke-width: 1.5;
  stroke-linecap: round;
}

@keyframes np-mark-ping {
  0% {
    transform: scale(0.55);
    stroke-opacity: 0.55;
  }
  70% {
    stroke-opacity: 0.12;
  }
  100% {
    transform: scale(1.85);
    stroke-opacity: 0;
  }
}

@keyframes np-mark-sweep {
  to {
    transform: rotate(360deg);
  }
}

@media (prefers-reduced-motion: reduce) {
  .np-brand-mark__ring,
  .np-brand-mark__sweep {
    animation: none;
  }
  .np-brand-mark__ring {
    stroke-opacity: 0.22;
    transform: scale(1.25);
  }
  .np-brand-mark__ring--b {
    display: none;
  }
}
</style>
