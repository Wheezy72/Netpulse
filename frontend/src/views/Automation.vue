<script setup lang="ts">
import BrainPanel from "../components/BrainPanel.vue";

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
        <h1 class="text-xl font-bold tracking-wide" style="color: var(--np-accent-primary)">
          Automation
        </h1>
        <p class="text-xs text-[var(--np-muted-text)]">
          Scripts, automation tools, and code generation
        </p>
      </div>
    </header>
    <BrainPanel @toast="(type: string, msg: string) => $emit('toast', type, msg)" />
  </div>
</template>
