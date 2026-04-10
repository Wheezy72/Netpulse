<script setup lang="ts">
interface Props {
  modelValue: boolean;
  theme: "nightshade" | "sysadmin";
  disabled?: boolean;
}

const props = withDefaults(defineProps<Props>(), {
  disabled: false,
});

const emit = defineEmits<{
  (e: "update:modelValue", value: boolean): void;
}>();

function toggle(): void {
  if (!props.disabled) {
    emit("update:modelValue", !props.modelValue);
  }
}

const isNightshade = () => props.theme === "nightshade";
</script>

<template>
  <button
    type="button"
    @click="toggle"
    :disabled="disabled"
    class="relative inline-flex h-6 w-11 items-center rounded-full transition-colors duration-200 focus:outline-none disabled:opacity-50 disabled:cursor-not-allowed"
    :class="[
      modelValue
        ? isNightshade()
          ? 'bg-teal-500/60'
          : 'bg-amber-500/60'
        : isNightshade()
          ? 'bg-gray-700'
          : 'bg-slate-700'
    ]"
    :style="modelValue ? (isNightshade() ? { boxShadow: '0 0 8px rgba(20, 184, 166, 0.4)' } : { boxShadow: '0 0 8px rgba(245, 158, 11, 0.4)' }) : {}"
  >
    <span
      class="inline-block h-4 w-4 transform rounded-full transition-transform duration-200"
      :class="[
        modelValue
          ? 'translate-x-6'
          : 'translate-x-1',
        modelValue
          ? isNightshade()
            ? 'bg-teal-400'
            : 'bg-amber-400'
          : 'bg-gray-400'
      ]"
    />
  </button>
</template>
