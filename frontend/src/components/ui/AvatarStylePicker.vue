<script setup lang="ts">
/**
 * Portrait-skin picker for the profile menu.
 *
 * A row of the account's own face in each available DiceBear skin lets the
 * person see exactly what changes before they commit — a dropdown of skin
 * names they would have to recognise was the worst option here.
 *
 * Kept as a single compact row: at this size the faces read as a quick visual
 * pick, and the menu stays a menu rather than turning into a settings page.
 * The selected skin carries an accent tile; the rest fill in on hover. Nothing
 * scales or rotates on hover, so picking a skin cannot make the row shimmer.
 */
import { AVATAR_STYLES } from "../../utils/avatar";
import AppAvatar from "./AppAvatar.vue";

defineProps<{
  /** The signed-in account's portrait seed (already percent-encoded). */
  seed: string;
  /** Currently selected skin id. */
  modelValue: string;
}>();

const emit = defineEmits<{ (e: "update:modelValue", value: string): void }>();
</script>

<template>
  <div class="px-3 py-2.5">
    <p class="mb-2 px-0.5 text-[0.55rem] font-mono uppercase tracking-widest text-[var(--np-text-dim)]">
      Avatar style
    </p>
    <div class="flex items-center gap-1.5">
      <button
        v-for="style in AVATAR_STYLES"
        :key="style.id"
        type="button"
        :title="style.label"
        :aria-label="`Avatar style: ${style.label}`"
        :aria-pressed="style.id === modelValue"
        class="avatar-style-option flex h-9 w-9 items-center justify-center rounded-full border"
        :class="
          style.id === modelValue
            ? 'avatar-style-option--active border-[var(--np-accent-border)] bg-[var(--np-accent-soft)]'
            : 'border-transparent hover:border-[var(--np-border-subtle)] hover:bg-[var(--np-surface-hover)]'
        "
        @click="emit('update:modelValue', style.id)"
      >
        <AppAvatar :seed="seed" :avatar-style="style.id" :label="style.label" :size="28" />
      </button>
    </div>
  </div>
</template>
