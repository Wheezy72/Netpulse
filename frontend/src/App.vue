<script setup lang="ts">
import axios from "axios";
import { computed, onMounted, ref, watch } from "vue";

import Dashboard from "./views/Dashboard.vue";
import Login from "./views/Login.vue";

type Theme = "cyberdeck" | "sysadmin";

type CurrentUser = {
  id: number;
  email: string;
  full_name: string | null;
  role: "viewer" | "operator" | "admin";
};

/**
 * Theme state.
 * This drives the <body> class and therefore which CSS variables are active.
 */
const theme = ref<Theme>("cyberdeck");

/**
 * Authentication state.
 * A non-empty token means the user is considered logged in.
 */
const accessToken = ref<string | null>(null);
const isAuthenticated = computed(() => !!accessToken.value);

/**
 * Current user profile for display in the header.
 */
const currentUser = ref<CurrentUser | null>(null);

function applyTheme(next: Theme): void {
  const body = document.body;
  body.classList.remove("theme-cyberdeck", "theme-sysadmin");
  body.classList.add(`theme-${next}`);
  localStorage.setItem("np-theme", next);
}

function setAuthToken(token: string | null): void {
  accessToken.value = token;
  if (token) {
    localStorage.setItem("np-token", token);
    axios.defaults.headers.common["Authorization"] = `Bearer ${token}`;
  } else {
    localStorage.removeItem("np-token");
    delete axios.defaults.headers.common["Authorization"];
    currentUser.value = null;
  }
}

async function loadCurrentUser(): Promise<void> {
  try {
    const { data } = await axios.get<CurrentUser>("/api/auth/me");
    currentUser.value = data;
  } catch {
    currentUser.value = null;
  }
}

onMounted(() => {
  // Restore theme
  const storedTheme = localStorage.getItem("np-theme") as Theme | null;
  if (storedTheme === "cyberdeck" || storedTheme === "sysadmin") {
    theme.value = storedTheme;
    applyTheme(storedTheme);
  } else {
    applyTheme(theme.value);
  }

  // Restore auth token if present
  const storedToken = localStorage.getItem("np-token");
  if (storedToken) {
    setAuthToken(storedToken);
    loadCurrentUser();
  }
});

watch(
  () => theme.value,
  (value) => {
    applyTheme(value);
  }
);

function toggleTheme(): void {
  theme.value = theme.value === "cyberdeck" ? "sysadmin" : "cyberdeck";
}

async function handleLoginSuccess(token: string): Promise<void> {
  setAuthToken(token);
  await loadCurrentUser();
}

function handleLogout(): void {
  setAuthToken(null);
}
</script>

<template>
  <div
    class="min-h-screen flex flex-col"
    :style="{
      backgroundColor: 'var(--np-bg)',
      color: 'var(--np-text)'
    }"
  >
    <header
      class="flex items-center justify-between px-6 py-3 border-b"
      :class="[
        theme === 'cyberdeck'
          ? 'border-cyan-400/40 bg-black/40'
          : 'border-slate-200 bg-white/80 backdrop-blur'
      ]"
    >
      <div class="flex items-center gap-3">
        <div
          class="h-8 w-8 rounded-full flex items-center justify-center"
          :class="[
            theme === 'cyberdeck'
              ? 'bg-emerald-400/20 border border-emerald-400/80'
              : 'bg-blue-600/10 border border-blue-600/60'
          ]"
        >
          <span
            class="text-xs font-semibold"
            :class="[theme === 'cyberdeck' ? 'text-emerald-300' : 'text-blue-700']"
          >
            NP
          </span>
        </div>
        <div class="flex flex-col">
          <h1
            class="text-sm font-semibold tracking-[0.18em] uppercase"
            :class="[
              theme === 'cyberdeck' ? 'text-cyan-300 np-text-glow' : 'text-slate-800'
            ]"
          >
            NetPulse Enterprise
          </h1>
          <p
            class="text-xs"
            :class="[theme === 'cyberdeck' ? 'text-cyan-200/70' : 'text-slate-500']"
          >
            Single Pane of Glass · Network Ops &amp; Security
          </p>
        </div>
      </div>

      <div class="flex items-center gap-6">
        <!-- Theme selector -->
        <div class="flex flex-col items-end">
          <span
            class="text-xs font-medium"
            :class="[theme === 'cyberdeck' ? 'text-cyan-200' : 'text-slate-700']"
          >
            Theme
          </span>
          <span
            class="text-[0.7rem] uppercase tracking-[0.16em]"
            :class="[theme === 'cyberdeck' ? 'text-cyan-300' : 'text-slate-500']"
          >
            {{ theme === "cyberdeck" ? "CyberDeck" : "SysAdmin Pro" }}
          </span>
        </div>

        <!-- Theme toggle switch is always available -->
        <button
          type="button"
          @click="toggleTheme"
          class="relative inline-flex h-8 w-16 items-center rounded-full border transition
                 focus:outline-none focus:ring-2 focus:ring-offset-2"
          :class="[
            theme === 'cyberdeck'
              ? 'border-cyan-400 bg-black/70 focus:ring-cyan-400'
              : 'border-slate-300 bg-slate-100 focus:ring-blue-500'
          ]"
        >
          <span
            class="inline-flex h-6 w-6 transform items-center justify-center rounded-full text-[0.6rem] font-semibold transition"
            :class="[
              theme === 'cyberdeck'
                ? 'translate-x-1 bg-cyan-400 text-black shadow-[0_0_12px_rgba(34,211,238,0.9)]'
                : 'translate-x-9 bg-blue-600 text-white shadow-sm'
            ]"
          >
            {{ theme === "cyberdeck" ? "CD" : "SA" }}
          </span>
        </button>

        <!-- User indicator and logout -->
        <div v-if="isAuthenticated" class="flex items-center gap-4">
          <div v-if="currentUser" class="flex flex-col items-end text-xs">
            <span
              class="font-mono"
              :class="[
                theme === 'cyberdeck' ? 'text-cyan-200' : 'text-slate-700'
              ]"
            >
              {{ currentUser.email }}
            </span>
            <span
              class="text-[0.65rem] uppercase tracking-[0.16em]"
              :class="[
                theme === 'cyberdeck' ? 'text-emerald-300' : 'text-slate-500'
              ]"
            >
              {{ currentUser.role }}
            </span>
          </div>
          <button
            type="button"
            @click="handleLogout"
            class="text-[0.7rem] rounded border px-2 py-0.5"
            :class="[
              theme === 'cyberdeck'
                ? 'border-cyan-400/60 text-cyan-200 hover:bg-cyan-500/10'
                : 'border-slate-300 text-slate-700 hover:bg-slate-100'
            ]"
          >
            Logout
          </button>
        </div>
      </div>
    </header>

    <main class="flex-1 px-4 py-4 md:px-6 md:py-6">
      <Login v-if="!isAuthenticated" @login-success="handleLoginSuccess" />
      <Dashboard v-else />
    </main>
  </div>
</template>