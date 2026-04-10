<script setup lang="ts">
interface Props {
  variant?: "primary" | "ghost" | "danger";
  size?: "sm" | "md";
  disabled?: boolean;
  loading?: boolean;
  type?: "button" | "submit" | "reset";
}

const props = withDefaults(defineProps<Props>(), {
  variant: "primary",
  size: "md",
  disabled: false,
  loading: false,
  type: "button",
});
</script>

<template>
  <button
    :type="props.type"
    :disabled="props.disabled || props.loading"
    class="inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-all duration-200 focus:outline-none disabled:opacity-50 disabled:cursor-not-allowed"
    :class="[
      props.size === 'sm' ? 'px-3 py-1.5 text-xs' : 'px-4 py-2 text-sm',
      props.variant === 'primary' && 'np-cyber-btn',
      props.variant === 'ghost' && 'border border-amber-500/15 dark:border-teal-500/20 bg-transparent text-slate-400 dark:text-teal-300 hover:text-slate-100 dark:hover:text-sky-100 hover:border-amber-500 dark:hover:border-teal-500',
      props.variant === 'danger' && 'text-red-400 hover:bg-red-400/10 border border-red-400/30',
    ]"
  >
    <svg
      v-if="props.loading"
      class="h-4 w-4 animate-spin"
      fill="none"
      viewBox="0 0 24 24"
    >
      <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
      <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
    </svg>
    <slot />
  </button>
</template>
