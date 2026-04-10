<script setup lang="ts">
import BrainPanel from "../components/features/BrainPanel.vue";

type Theme = "nightshade" | "sysadmin";

interface Props {
  theme: Theme;
}

defineProps<Props>();
defineEmits<{
  (e: "toast", type: "success" | "error" | "warning" | "info", message: string): void;
}>();
</script>

<template>
  <div class="space-y-4">
    <header class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-bold tracking-wide text-amber-500 dark:text-teal-500">
          Automation
        </h1>
        <p class="text-xs text-slate-400 dark:text-teal-300">
          Scripts, automation tools, and code generation
        </p>
      </div>
    </header>
    <BrainPanel @toast="(type: string, msg: string) => $emit('toast', type, msg)" />
  </div>
</template>
