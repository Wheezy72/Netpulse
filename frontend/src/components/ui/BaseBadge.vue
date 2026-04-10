<script setup lang="ts">
interface Props {
  variant?: "success" | "warning" | "danger" | "info" | "muted";
}

const props = withDefaults(defineProps<Props>(), {
  variant: "muted",
});
</script>

<template>
  <span
    class="inline-flex items-center rounded px-1.5 py-0.5 text-[0.6rem] font-semibold uppercase tracking-wider"
    :class="[
      props.variant === 'success' && 'bg-emerald-500/20 text-emerald-400',
      props.variant === 'warning' && 'bg-amber-500/20 text-amber-400',
      props.variant === 'danger'  && 'bg-red-500/20 text-red-400',
      props.variant === 'info'    && 'bg-sky-500/20 text-sky-400',
      props.variant === 'muted'   && 'bg-gray-900 dark:bg-[#0a0f1e] text-slate-400 dark:text-teal-300',
    ]"
  >
    <slot />
  </span>
</template>
