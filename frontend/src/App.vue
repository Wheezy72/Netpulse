<script setup lang="ts">
/**
 * Root application shell.
 *
 * - Auth state managed by the Pinia auth store.
 * - Theme managed by the Pinia ui store.
 * - Navigation via Vue Router (lazy-loaded routes).
 * - Global Cmd+K / Ctrl+K command palette via VueUse useMagicKeys.
 */
import { onMounted, computed, ref, watch } from "vue";
import { useRouter, useRoute } from "vue-router";
import { useMagicKeys } from "@vueuse/core";
import axios from "axios";

import CommandPalette from "./components/features/CommandPalette.vue";
import Toast from "./components/ui/Toast.vue";

import { useAuthStore } from "./stores/auth";
import { useUiStore } from "./stores/ui";

const router = useRouter();
const route = useRoute();
const auth = useAuthStore();
const ui = useUiStore();

const isNightshade = computed(() => ui.theme === "nightshade");

function toggleTheme() {
  ui.setTheme(isNightshade.value ? "sysadmin" : "nightshade");
}

const toastRef = ref<InstanceType<typeof Toast> | null>(null);
const mobileMenuOpen = ref(false);
const logoError = ref(false);
const infoMode = ref<"full" | "compact">((localStorage.getItem("np-info-mode") as any) || "full");

watch(infoMode, (val) => {
  localStorage.setItem("np-info-mode", val);
});

// Open the command palette with Cmd+K or Ctrl+K.
const { Meta_k, Ctrl_k } = useMagicKeys();
watch([Meta_k, Ctrl_k], ([mk, ck]) => {
  if ((mk || ck) && auth.isAuthenticated) {
    ui.openCommandPalette();
  }
});

const navItems = [
  { id: "dashboard", label: "Dashboard", icon: "dashboard" },
  { id: "devices", label: "Devices", icon: "devices" },
  { id: "toolbox", label: "Toolbox", icon: "toolbox" },
  { id: "packets", label: "Packets", icon: "packets" },
  { id: "logs", label: "Logs", icon: "logs" },
  { id: "settings", label: "Settings", icon: "settings" },
] as const;

function isActive(id: string) {
  return route.name === id;
}

function navigateTo(id: string) {
  router.push(`/${id}`);
  mobileMenuOpen.value = false;
}

function handleLogout() {
  auth.logout();
  router.push("/login");
}

async function handleAuthSuccess(arg: string | { token: string; rememberMe?: boolean }) {
  const t = typeof arg === "string" ? arg : arg.token;
  const persist = typeof arg === "string" ? true : (arg.rememberMe ?? true);
  auth.setToken(t, persist);
  await auth.loadUser();
  router.push("/dashboard");
}

onMounted(async () => {
  await auth.loadUser();

  // Redirect to login if not authenticated and not on a guest route.
  if (!auth.isAuthenticated && !route.meta?.guest) {
    router.push("/login");
  }

  // Handle Google OAuth callback.
  const isGoogleCallback = window.location.pathname === "/auth/google/callback";
  if (isGoogleCallback) {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get("code");
    const state = urlParams.get("state");
    const savedState = sessionStorage.getItem("np-oauth-state");
    sessionStorage.removeItem("np-oauth-state");
    window.history.replaceState({}, "", "/");

    if (code && state === savedState) {
      try {
        const { default: axios } = await import("axios");
        const redirectUri = `${window.location.origin}/auth/google/callback`;
        const { data } = await axios.post<{ access_token: string }>("/api/auth/google/callback", {
          code,
          redirect_uri: redirectUri,
        });
        auth.setToken(data.access_token);
        await auth.loadUser();
        router.push("/dashboard");
      } catch {
        router.push("/login");
      }
    } else {
      router.push("/login");
    }
  }

  if (window.innerWidth < 768) {
    ui.sidebarExpanded = false;
    localStorage.setItem("np-sidebar-expanded", "false");
  }
});

const forceNewPassword = ref("");
const forceConfirmPassword = ref("");
const forceSubmitting = ref(false);
const forceError = ref<string | null>(null);

async function handleForcePasswordChange() {
  forceError.value = null;
  if (!forceNewPassword.value || !forceConfirmPassword.value) {
    forceError.value = "All fields are required.";
    return;
  }
  if (forceNewPassword.value.length < 6) {
    forceError.value = "New password must be at least 6 characters.";
    return;
  }
  if (forceNewPassword.value !== forceConfirmPassword.value) {
    forceError.value = "Passwords do not match.";
    return;
  }
  
  forceSubmitting.value = true;
  try {
    await axios.post("/api/auth/update-password", {
      new_password: forceNewPassword.value,
    });
    // Load the updated user profile
    await auth.loadUser();
  } catch (err: any) {
    forceError.value = err?.response?.data?.detail ?? err?.response?.data?.error?.message ?? "Failed to update password.";
  } finally {
    forceSubmitting.value = false;
  }
}
</script>

<template>
  <div class="min-h-screen flex flex-col cyber-canvas relative overflow-hidden bg-[var(--np-bg)] text-[var(--np-text)] transition-all duration-300">
    <!-- Ambient drifting purple glow behind everything -->
    <div class="absolute inset-0 ambient-glow pointer-events-none z-0" />

    <!-- Command palette (global) -->
    <CommandPalette />

    <!-- Unauthenticated: just render the router-view (Login / Register) -->
    <template v-if="!auth.isAuthenticated">
      <div class="w-full relative z-10">
        <RouterView v-slot="{ Component }">
          <component
            :is="Component"
            :theme="ui.theme"
            :info-mode="infoMode"
            @update:infoMode="infoMode = $event"
            @login-success="handleAuthSuccess"
            @register-success="handleAuthSuccess"
            @switch-to-register="router.push('/register')"
            @switch-to-login="router.push('/login')"
            @toggle-theme="ui.setTheme(ui.theme === 'nightshade' ? 'sysadmin' : 'nightshade')"
          />
        </RouterView>
      </div>
    </template>

    <!-- Authenticated shell -->
    <template v-else>
      <!-- Force Password Change Mode -->
      <template v-if="auth.user?.force_password_change">
        <div class="min-h-screen w-full flex items-center justify-center p-4 relative z-50 bg-[var(--np-bg)] transition-colors duration-300">
          <div class="np-login-panel w-full max-w-md p-8 relative">
            <div class="text-center mb-6">
              <h1 class="text-xl font-bold tracking-wider mb-2 font-mono text-emerald-400 animate-pulse">
                SECURITY INITIALIZATION
              </h1>
              <p class="text-[0.65rem] font-mono text-slate-300/60 uppercase tracking-wider">
                First login password reset required
              </p>
            </div>
            
            <form @submit.prevent="handleForcePasswordChange" class="space-y-4">
              <div>
                <label class="block text-[0.65rem] uppercase tracking-wider mb-1.5 font-mono text-slate-300/60">
                  New Password (min 6 characters)
                </label>
                <input
                  v-model="forceNewPassword"
                  type="password"
                  class="np-neon-input w-full rounded-lg px-4 py-2.5 text-xs font-mono bg-[#0d0a1b]"
                  placeholder="••••••••••••"
                  required
                />
              </div>

              <div>
                <label class="block text-[0.65rem] uppercase tracking-wider mb-1.5 font-mono text-slate-300/60">
                  Confirm New Password
                </label>
                <input
                  v-model="forceConfirmPassword"
                  type="password"
                  class="np-neon-input w-full rounded-lg px-4 py-2.5 text-xs font-mono bg-[#0d0a1b]"
                  placeholder="••••••••••••"
                  required
                />
              </div>

              <div class="pt-2">
                <button
                  type="submit"
                  class="np-login-btn w-full rounded-lg px-4 py-2.5 text-xs font-semibold flex items-center justify-center gap-2"
                  :disabled="forceSubmitting"
                >
                  <svg
                    v-if="forceSubmitting"
                    class="w-4 h-4 animate-spin"
                    fill="none"
                    viewBox="0 0 24 24"
                  >
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
                  </svg>
                  <span>{{ forceSubmitting ? "UPDATING PASSWORD..." : "UPDATE & INITIALIZE" }}</span>
                </button>
              </div>

              <p v-if="forceError" class="text-center text-xs text-rose-400 font-mono">
                {{ forceError }}
              </p>
            </form>

            <div class="mt-6 pt-4 border-t border-slate-500/10 flex items-center justify-center gap-2">
              <span class="np-status-dot" />
              <span class="text-[0.65rem] font-mono text-slate-400/40 uppercase tracking-widest">
                Policy Active &bull; Netpulse Security
              </span>
            </div>
          </div>
        </div>
      </template>

      <!-- Standard Shell -->
      <template v-else>
        <!-- Premium Top Header Navigation (replacing sidebar) -->
      <header class="sticky top-0 z-40 w-full border-b border-slate-600/10 bg-[var(--np-glass-bg)] backdrop-blur-md transition-all duration-200">
        <div class="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between gap-4">
          
          <!-- Left: Logo & Netpulse title -->
          <div class="flex items-center gap-2.5 shrink-0">
            <div class="h-8 w-8 rounded-lg flex items-center justify-center bg-emerald-500/15 border border-emerald-500/35 shadow-lg shadow-emerald-500/5">
              <img v-if="!logoError" src="/logo.png" alt="NP" class="h-4.5 w-4.5 object-contain" @error="logoError = true" />
              <span v-else class="text-[0.65rem] font-bold font-mono text-emerald-400">NP</span>
            </div>
            <div class="flex flex-col">
              <div class="flex items-center gap-1.5 leading-none">
                <span class="text-xs font-bold tracking-widest uppercase text-emerald-400">NetPulse</span>
                <span class="text-[0.5rem] px-1 py-0.2 rounded font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">v0.1.0</span>
              </div>
              <span class="text-[0.55rem] text-slate-400/50 uppercase tracking-widest mt-0.5 font-semibold">Command Console</span>
            </div>
          </div>

          <!-- Center: Pill Navigation Capsule -->
          <nav class="hidden lg:flex items-center bg-[var(--np-surface)] border border-slate-600/10 rounded-full p-1 gap-0.5 shadow-inner">
            <button
              v-for="item in navItems"
              :key="item.id"
              type="button"
              @click="navigateTo(item.id)"
              class="px-4 py-2 rounded-full text-[0.65rem] uppercase tracking-wider font-semibold transition-all duration-150 flex items-center gap-1.5"
              :class="[
                isActive(item.id)
                  ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/20 shadow'
                  : 'text-slate-400/60 hover:text-slate-200 border border-transparent'
              ]"
            >
              <span>{{ item.label }}</span>
            </button>
          </nav>

          <!-- Right: Action utilities & Profile -->
          <div class="flex items-center gap-2">
            <!-- Cmd+K Hint Trigger -->
            <button
              type="button"
              @click="ui.openCommandPalette()"
              class="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#0d0a1b]/60 border border-slate-600/10 text-slate-400/50 hover:text-slate-300 hover:border-slate-600/20 transition-all text-xs"
              title="Open command palette"
            >
              <span class="text-[0.65rem]">Search…</span>
              <kbd class="text-[0.55rem] px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400/60 border border-emerald-500/10">⌘K</kbd>
            </button>

            <!-- Theme Switcher -->
            <button
              type="button"
              @click="toggleTheme"
              class="p-2 rounded-full border border-slate-600/10 bg-[#0d0a1b]/60 text-slate-400/70 hover:text-emerald-400 hover:border-emerald-500/20 transition-all"
              :title="isNightshade ? 'Switch to SysAdmin' : 'Switch to Nightshade'"
            >
              <svg v-if="isNightshade" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
              </svg>
              <svg v-else class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
              </svg>
            </button>

            <!-- Profile Dropdown (using CSS hover for dropdown display) -->
            <div class="relative group">
              <button
                type="button"
                class="flex items-center gap-2 pl-2 pr-3 py-1 rounded-full bg-[var(--np-surface-elevated)] border border-slate-600/10 hover:border-slate-600/20 transition-all text-left"
              >
                <div class="w-6 h-6 rounded-full flex items-center justify-center text-[0.65rem] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                  {{ (auth.user?.email?.[0] || "U").toUpperCase() }}
                </div>
                <div class="hidden md:flex flex-col text-xs leading-tight">
                  <span class="text-slate-200 font-medium truncate max-w-[80px]">{{ auth.user?.email?.split('@')[0] || "Operator" }}</span>
                  <span class="text-[0.55rem] text-emerald-400/60 font-mono uppercase tracking-wider">{{ auth.user?.role || "operator" }}</span>
                </div>
                <svg class="w-3 h-3 text-slate-400/50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                </svg>
              </button>
              
              <!-- Dropdown Menu -->
              <div class="absolute right-0 mt-2 w-48 rounded-xl border border-slate-600/15 bg-[var(--np-glass-bg)] backdrop-blur-md shadow-xl py-1 opacity-0 pointer-events-none group-hover:opacity-100 group-hover:pointer-events-auto transition-all duration-200 z-[100]">
                <div class="px-4 py-2 border-b border-slate-600/10">
                  <p class="text-[0.6rem] text-slate-400/50 uppercase tracking-widest font-mono">Operator</p>
                  <p class="text-xs font-semibold text-slate-200 truncate mt-0.5">{{ auth.user?.email || "operator@netpulse.local" }}</p>
                </div>
                <button
                  type="button"
                  @click="handleLogout"
                  class="w-full flex items-center gap-2.5 px-4 py-2.5 text-xs text-rose-400 hover:bg-rose-500/10 transition-colors text-left"
                >
                  <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                  </svg>
                  <span>Logout</span>
                </button>
              </div>
            </div>

            <!-- Hamburger Button for Mobile -->
            <button
              type="button"
              @click="mobileMenuOpen = !mobileMenuOpen"
              class="lg:hidden p-2 rounded-full border border-slate-600/10 bg-[var(--np-surface-elevated)] text-slate-400/70 hover:text-emerald-400 hover:border-emerald-500/20 transition-all"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            </button>
          </div>
        </div>
      </header>

      <!-- Mobile navigation overlay backdrop -->
      <div
        v-if="mobileMenuOpen"
        class="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm lg:hidden transition-opacity"
        @click="mobileMenuOpen = false"
      />

      <!-- Mobile navigation menu -->
      <transition name="drawer">
        <aside
          v-if="mobileMenuOpen"
          class="fixed top-0 right-0 z-50 w-64 h-full bg-[var(--np-glass-bg)] backdrop-blur-lg border-l border-slate-600/15 p-6 flex flex-col gap-6 lg:hidden shadow-2xl"
        >
          <div class="flex items-center justify-between border-b border-slate-600/10 pb-4">
            <span class="text-xs font-bold uppercase tracking-wider text-slate-400">Navigation</span>
            <button @click="mobileMenuOpen = false" class="p-1 text-slate-400 hover:text-slate-200">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" /></svg>
            </button>
          </div>

          <nav class="flex flex-col gap-2">
            <button
              v-for="item in navItems"
              :key="item.id"
              type="button"
              @click="navigateTo(item.id)"
              class="w-full text-left px-4 py-3 rounded-xl text-xs font-semibold uppercase tracking-wider transition-all"
              :class="[
                isActive(item.id)
                  ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/20'
                  : 'text-slate-400/70 hover:text-slate-200 border border-transparent'
              ]"
            >
              {{ item.label }}
            </button>
          </nav>

          <div class="mt-auto border-t border-slate-600/10 pt-4 flex flex-col gap-3">
            <div class="flex items-center gap-2 px-1">
              <div class="w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                {{ (auth.user?.email?.[0] || "U").toUpperCase() }}
              </div>
              <div class="flex flex-col text-xs leading-none">
                <span class="text-slate-200 font-medium truncate max-w-[120px]">{{ auth.user?.email || "Operator" }}</span>
                <span class="text-[0.55rem] text-emerald-400/60 font-mono uppercase tracking-wider mt-0.5">{{ auth.user?.role || "operator" }}</span>
              </div>
            </div>
            <button
              type="button"
              @click="handleLogout"
              class="w-full flex items-center justify-center gap-2.5 py-2.5 rounded-xl text-xs font-semibold uppercase tracking-wider bg-rose-500/10 text-rose-400 border border-rose-500/20 hover:bg-rose-500/20 transition-all"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
              </svg>
              <span>Logout</span>
            </button>
          </div>
        </aside>
      </transition>

      <!-- Main content view (contained within standard maximum width layout) -->
      <main class="flex-1 max-w-7xl w-full mx-auto px-4 md:px-6 py-6 overflow-y-auto relative z-10">
        <RouterView v-slot="{ Component }">
          <component
            :is="Component"
            :theme="ui.theme"
            :is-admin="auth.isAdmin"
            :info-mode="infoMode"
            @update:infoMode="infoMode = $event"
            @login-success="handleAuthSuccess"
            @register-success="handleAuthSuccess"
            @switch-to-register="router.push('/register')"
            @switch-to-login="router.push('/login')"
            @toggle-theme="ui.setTheme(ui.theme === 'nightshade' ? 'sysadmin' : 'nightshade')"
            @toast="(type: any, msg: string) => toastRef?.show(type, msg)"
          />
        </RouterView>
      </main>
    </template>
  </template>

    <Toast ref="toastRef" :theme="ui.theme" />
  </div>
</template>
