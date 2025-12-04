<script setup lang="ts">
/**
 * Login.vue
 *
 * Simple credentials form. The look and feel is theme-driven:
 *  - CyberDeck: dark, neon, "console" style.
 *  - SysAdmin: light, clean, card-style.
 */

import axios from "axios";
import { ref } from "vue";

const email = ref("");
const password = ref("");
const isSubmitting = ref(false);
const errorMessage = ref<string | null>(null);

const emit = defineEmits<{
  (e: "login-success", token: string): void;
}>();

async function handleSubmit(): Promise<void> {
  errorMessage.value = null;

  if (!email.value || !password.value) {
    errorMessage.value = "Please enter both email and password.";
    return;
  }

  isSubmitting.value = true;
  try {
    const { data } = await axios.post<{ access_token: string; token_type: string }>(
      "/api/auth/login",
      {
        email: email.value,
        password: password.value,
      }
    );
    emit("login-success", data.access_token);
  } catch {
    errorMessage.value = "Login failed. Check your credentials.";
  } finally {
    isSubmitting.value = false;
  }
}
</script>

<template>
  <div class="flex h-full items-center justify-center">
    <div class="np-login-panel w-full max-w-sm rounded-lg px-6 py-5 shadow-lg">
      <h2 class="text-sm font-semibold tracking-[0.18em] uppercase">
        Sign In
      </h2>
      <p class="mt-1 text-[0.75rem] text-[var(--np-muted-text)]">
        Enter your credentials to access NetPulse.
      </p>

      <form class="mt-4 space-y-3" @submit.prevent="handleSubmit">
        <label class="block text-[0.75rem] text-[var(--np-muted-text)]">
          Email
          <input
            v-model="email"
            type="email"
            autocomplete="username"
            class="mt-1 w-full rounded-md border px-2 py-1 text-[0.8rem]
                   focus:outline-none focus:ring-1"
            placeholder="you@example.com"
          />
        </label>

        <label class="block text-[0.75rem] text-[var(--np-muted-text)]">
          Password
          <input
            v-model="password"
            type="password"
            autocomplete="current-password"
            class="mt-1 w-full rounded-md border px-2 py-1 text-[0.8rem]
                   focus:outline-none focus:ring-1"
            placeholder="••••••••"
          />
        </label>

        <button
          type="submit"
          class="mt-2 inline-flex w-full items-center justify-center rounded-md border px-3 py-2 text-[0.8rem] font-medium disabled:opacity-50"
          :disabled="isSubmitting"
        >
          <span v-if="!isSubmitting">Login</span>
          <span v-else>Signing in…</span>
        </button>

        <p v-if="errorMessage" class="mt-2 text-[0.75rem] text-rose-300">
          {{ errorMessage }}
        </p>
      </form>
    </div>
  </div>
</template>