<script setup lang="ts">
/**
 * On/off switch.
 *
 * The track uses the theme accent token rather than a colour of its own, so
 * switching themes moves the switch with the rest of the interface. The old
 * build painted amber in light mode and teal in dark, which left a second
 * accent colour alive on every settings screen.
 */
interface Props {
  modelValue: boolean;
  theme: "nightshade" | "sysadmin";
  disabled?: boolean;
  label?: string;
}

const props = withDefaults(defineProps<Props>(), {
  disabled: false,
  label: undefined,
});

const emit = defineEmits<{
  (e: "update:modelValue", value: boolean): void;
}>();

function toggle(): void {
  if (!props.disabled) {
    emit("update:modelValue", !props.modelValue);
  }
}
</script>

<template>
  <button
    type="button"
    role="switch"
    :aria-checked="modelValue"
    :aria-label="label"
    :title="label"
    @click="toggle"
    :disabled="disabled"
    class="np-switch relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors duration-200 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--np-accent)] disabled:opacity-50 disabled:cursor-not-allowed"
    :class="modelValue ? 'np-switch--on' : 'np-switch--off'"
  >
    <span
      class="np-switch__knob inline-block h-4 w-4 transform rounded-full transition-transform duration-200"
      :class="modelValue ? 'translate-x-6' : 'translate-x-1'"
    />
  </button>
</template>

<style scoped>
.np-switch--on {
  background: var(--np-accent);
}

.np-switch--off {
  background: color-mix(in srgb, var(--np-text-dim) 40%, transparent);
}

.np-switch__knob {
  background: #ffffff;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.25);
}

.np-switch--on .np-switch__knob {
  box-shadow: 0 0 8px var(--np-accent-glow);
}
</style>
