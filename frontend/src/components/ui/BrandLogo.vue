<script setup lang="ts">
/**
 * The app logo: a drop-in custom asset when one exists, the built-in mark
 * otherwise.
 *
 * Drop a file named `logo.svg`, `logo.gif`, `logo.png` or `logo.webp` into
 * `frontend/public/branding/` and it replaces the drawn mark everywhere without
 * a rebuild of this component. The candidates are probed in that order and the
 * first one that loads wins.
 *
 * Failure is deliberately boring: a missing directory, a 404, a file the
 * browser cannot decode, or a corrupt GIF all fall back to the built-in
 * BrandMark. Nothing throws, nothing blocks render — the app draws the mark it
 * ships with and carries on. The same fallback runs from `@error`, so a file
 * that disappears after the probe still cannot leave an empty hole.
 */
import { onMounted, ref } from "vue";

import BrandMark from "./BrandMark.vue";

withDefaults(defineProps<{ size?: number }>(), { size: 20 });

// Order matters only for preference; probing stops at the first success.
const CANDIDATES = [
  "/branding/logo.svg",
  "/branding/logo.gif",
  "/branding/logo.png",
  "/branding/logo.webp",
];

const customSrc = ref<string | null>(null);

function probe(urls: string[]): void {
  const [next, ...rest] = urls;
  if (!next) {
    customSrc.value = null;
    return;
  }

  const probeImage = new Image();
  probeImage.onload = () => {
    // A zero-width decode (a stub file, a blocked response) is not a logo.
    customSrc.value = probeImage.naturalWidth > 0 ? next : null;
    if (!customSrc.value) probe(rest);
  };
  probeImage.onerror = () => probe(rest);
  probeImage.src = next;
}

onMounted(() => probe(CANDIDATES));
</script>

<template>
  <img
    v-if="customSrc"
    :src="customSrc"
    :width="size"
    :height="size"
    alt=""
    aria-hidden="true"
    draggable="false"
    class="object-contain"
    @error="customSrc = null"
  />
  <BrandMark v-else :size="size" />
</template>
