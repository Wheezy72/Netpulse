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
const fullName = ref("");
const mode = ref<"login" | "register">("login");
const isSubmitting = ref(false);
const errorMessage = ref<string | null>(null);

const emit = defineEmits<{
  (e: "login-success", token: string): void;
}>();

async function submitLogin(): Promise<void> {
  const { data } = await axios.post<{ access_token: string; token_type: string }>(
    "/api/auth/login",
    {
      email: email.value,
      password: password.value,
    }
  );
  emit("login-success", data.access_token);
}

async function submitRegister(): Promise<void> {
  await axios.post("/api/auth/users", {
    email: email.value,
    password: password.value,
    full_name: fullName.value || null,
  });
  // After successful registration, immediately log in.
  await submitLogin();
}

async function handleSubmit(): Promise<void> {
  errorMessage.value = null;

  if (!email.value || !password.value) {
    errorMessage.value = "Please enter both email and password.";
    return;
  }

  isSubmitting.value = true;
  try {
    if (mode.value === "login") {
      await submitLogin();
    } else {
      await submitRegister();
    }
  } catch {
    errorMessage.value =
      mode.value === "login"
        ? "Login failed. Check your credentials."
        : "Registration failed. Try a different email or check the server logs.";
  } finally {
    isSubmitting.value = false;
  }
}
</script>

<template>
  <div class="flex h-full items-center justify-center">
    <div class="np-login-panel w-full max-w-sm rounded-lg px-6 py-5 shadow-lg">
      <h2 class="np-login-title text-sm font-semibold tracking-[0.18em] uppercase">
        {{ mode === "login" ? "Sign In" : "Create Account" }}
      </h2>
      <p class="mt-1 text-[0.75rem] text-[var(--np-muted-text)]">
        {{ mode === "login"
          ? "Enter your credentials to access NetPulse."
          : "Create a local account for this NetPulse instance." }}
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

        <label
          v-if="mode === 'register'"
          class="block text-[0.75rem] text-[var(--np-muted-text)]"
        >
          Full name (optional)
          <input
            v-model="fullName"
            type="text"
            autocomplete="name"
            class="mt-1 w-full rounded-md border px-2 py-1 text-[0.8rem]
                   focus:outline-none focus:ring-1"
            placeholder="Your name"
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
          <span v-if="!isSubmitting">
            {{ mode === "login" ? "Login" : "Register & Sign In" }}
          </span>
          <span v-else>
            {{ mode === "login" ? "Signing in..." : "Creating account..." }}
          </span>
        </button>

        <button
          type="button"
          class="mt-2 w-full text-[0.7rem] text-[var(--np-muted-text)] hover:underline"
          @click="mode = mode === 'login' ? 'register' : 'login'"
        >
          {{ mode === "login"
            ? "Need an account? Create one."
            : "Already have an account? Sign in." }}
        </button>

        <p v-if="errorMessage" class="mt-2 text-[0.75rem] text-rose-300">
          {{ errorMessage }}
        </p>
      </form>
    </div>
  </div>
</template>