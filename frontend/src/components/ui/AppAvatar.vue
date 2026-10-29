<script setup lang="ts">
/**
 * A living portrait for an account, in the shell's own visual language.
 *
 * DiceBear draws a portrait seeded by the account. The default skin is a flat
 * colour face; the optional line-art skin's ink follows `currentColor` (see
 * utils/avatar.ts), so it rides the theme like every AppGlyph does. The circle
 * behind it uses the brand tint ring the old letter-initial chips had, keeping
 * the silhouette seated on the same surface other identity marks live on.
 */
import { computed } from "vue";

import { avatarSvg, normalizeAvatarStyle } from "../../utils/avatar";

const props = withDefaults(
  defineProps<{
    /** The stable seed (already percent-encoded) that the portrait grows from. */
    seed?: string | null;
    /** Accessible name — shown as tooltip and read by screen readers. */
    label?: string | null;
    /** Rendered diameter. */
    size?: number;
    /** DiceBear skin id; unknown/null falls back to the app default. */
    avatarStyle?: string | null;
  }>(),
  { seed: "", label: "", size: 32, avatarStyle: null },
);

const svg = computed(() =>
  avatarSvg(props.seed || "netpulse-account", props.size, normalizeAvatarStyle(props.avatarStyle)),
);
</script>

<template>
  <span
    class="np-brand-border np-brand-bg relative inline-flex shrink-0 items-center justify-center overflow-hidden rounded-full border"
    :style="{ width: `${size}px`, height: `${size}px` }"
    role="img"
    :aria-label="label || undefined"
    :title="label || undefined"
  >
    <span
      class="flex h-full w-full items-center justify-center text-[var(--np-accent)]"
      v-html="svg"
    />
  </span>
</template>
