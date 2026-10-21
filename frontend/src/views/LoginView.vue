<script setup lang="ts">
/**
 * Login page with the theme toggle the form itself does not render.
 *
 * The toggle lives here rather than inside Login.vue so the form stays a pure
 * credential form; this wrapper is the only place that knows about chrome.
 * Theme state and the actual switch are still owned by the app shell: the
 * button re-emits `toggle-theme` upward so there is exactly one place that
 * flips the theme.
 */
import { Moon, Sun } from "lucide-vue-next";

import Login from "./Login.vue";

defineProps<{ theme: "nightshade" | "sysadmin" }>();

defineEmits<{
  (e: "login-success", payload: { token: string; rememberMe: boolean }): void;
  (e: "switch-to-register"): void;
  (e: "toggle-theme"): void;
}>();
</script>

<template>
  <div class="relative">
    <button
      type="button"
      class="np-brand-border np-brand-bg np-brand-text fixed right-4 top-4 z-50 rounded-lg border p-2.5 transition-colors hover:opacity-90"
      :title="theme === 'nightshade' ? 'Switch to light' : 'Switch to dark'"
      :aria-label="theme === 'nightshade' ? 'Switch to light' : 'Switch to dark'"
      @click="$emit('toggle-theme')"
    >
      <!-- The icon shows where the button takes you, not where you are. -->
      <Sun v-if="theme === 'nightshade'" class="h-5 w-5" :stroke-width="1.7" />
      <Moon v-else class="h-5 w-5" :stroke-width="1.7" />
    </button>

    <Login
      :theme="theme"
      @login-success="$emit('login-success', $event)"
      @switch-to-register="$emit('switch-to-register')"
      @toggle-theme="$emit('toggle-theme')"
    />
  </div>
</template>
