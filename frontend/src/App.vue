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

import CommandPalette from "./components/features/CommandPalette.vue";
import Toast from "./components/ui/Toast.vue";

import { useAuthStore } from "./stores/auth";
import { useUiStore } from "./stores/ui";

const router = useRouter();
const route = useRoute();
const auth = useAuthStore();
const ui = useUiStore();

const toastRef = ref<InstanceType<typeof Toast> | null>(null);
const mobileMenuOpen = ref(false);
const logoError = ref(false);

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
  { id: "diagnostics", label: "Diagnostics", icon: "diagnostics" },
  { id: "scanning", label: "Scanning", icon: "scanning" },
  { id: "packets", label: "Packets", icon: "packets" },
  { id: "logs", label: "Logs", icon: "logs" },
  { id: "automation", label: "Automation", icon: "automation" },
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
</script>

<template>
  <div class="min-h-screen flex cyber-canvas">
    <!-- Command palette (global) -->
    <CommandPalette />

    <!-- Unauthenticated: just render the router-view (Login / Register) -->
    <template v-if="!auth.isAuthenticated">
      <div class="w-full">
        <RouterView v-slot="{ Component }">
          <component
            :is="Component"
            :theme="ui.theme"
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
      <!-- Mobile menu overlay -->
      <button
        type="button"
        @click="mobileMenuOpen = !mobileMenuOpen"
        class="fixed top-3 left-3 z-50 md:hidden rounded-lg p-2 border text-sm transition-colors"
        style="background: var(--np-surface); border-color: var(--np-border); color: var(--np-accent-primary);"
      >
        <svg v-if="!mobileMenuOpen" class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
        </svg>
        <svg v-else class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
        </svg>
      </button>

      <div
        v-if="mobileMenuOpen"
        class="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm md:hidden"
        @click="mobileMenuOpen = false"
      />

      <!-- Sidebar -->
      <aside
        class="fixed md:sticky top-0 left-0 z-40 h-screen flex flex-col border-r transition-all duration-200 shrink-0 np-glass"
        :class="[
          mobileMenuOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0',
          ui.sidebarExpanded ? 'w-48' : 'w-14',
        ]"
        style="border-color: var(--np-glass-border);"
      >
        <!-- Logo -->
        <div class="flex items-center gap-2.5 px-3 py-3 border-b" style="border-color: var(--np-border-subtle);">
          <div class="h-7 w-7 rounded-lg flex items-center justify-center shrink-0" style="background: color-mix(in srgb, var(--np-accent-primary) 15%, transparent); border: 1px solid color-mix(in srgb, var(--np-accent-primary) 30%, transparent);">
            <img v-if="!logoError" src="/logo.png" alt="NP" class="h-4 w-4 object-contain" @error="logoError = true" />
            <span v-else class="text-[0.6rem] font-bold font-mono" style="color: var(--np-accent-primary);">NP</span>
          </div>
          <div v-if="ui.sidebarExpanded" class="flex flex-col overflow-hidden">
            <h1 class="text-xs font-semibold tracking-widest uppercase truncate" style="color: var(--np-accent-primary);">NetPulse</h1>
            <p class="text-[0.55rem] tracking-wide truncate" style="color: var(--np-text-dim);">Network Ops</p>
          </div>
        </div>

        <!-- Collapse toggle -->
        <button
          type="button"
          @click="ui.toggleSidebar()"
          class="hidden md:flex items-center justify-center w-full py-1.5 transition-colors border-b"
          style="color: var(--np-text-dim); border-color: var(--np-border-subtle);"
        >
          <svg
            class="w-3.5 h-3.5 transition-transform duration-300"
            :class="{ 'rotate-180': !ui.sidebarExpanded }"
            fill="none" stroke="currentColor" viewBox="0 0 24 24"
          >
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 19l-7-7 7-7m8 14l-7-7 7-7" />
          </svg>
        </button>

        <!-- Cmd+K hint -->
        <button
          v-if="ui.sidebarExpanded"
          type="button"
          @click="ui.openCommandPalette()"
          class="mx-2 mt-2 flex items-center gap-2 px-2.5 py-1.5 rounded-lg border text-xs transition-colors"
          style="border-color: var(--np-border-subtle); color: var(--np-text-dim);"
          title="Open command palette"
        >
          <span class="flex-1 text-left text-[0.65rem]">Search…</span>
          <kbd class="text-[0.55rem] px-1 rounded" style="background: color-mix(in srgb, var(--np-accent-primary) 10%, transparent); color: var(--np-text-dim);">⌘K</kbd>
        </button>

        <!-- Nav -->
        <nav class="flex-1 py-2 px-1 space-y-0.5 overflow-y-auto">
          <button
            v-for="item in navItems"
            :key="item.id"
            type="button"
            @click="navigateTo(item.id)"
            class="w-full flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-[0.65rem] uppercase tracking-wider font-medium transition-all duration-150"
            :class="[
              isActive(item.id)
                ? 'np-accent-bg np-accent-text border-l-2 np-accent-border'
                : 'border-l-2 border-transparent',
            ]"
            :style="!isActive(item.id) ? { color: 'var(--np-text-dim)' } : {}"
            :title="item.label"
          >
            <!-- Inline SVG icons per nav item -->
            <svg v-if="item.id === 'dashboard'" class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M3.75 6A2.25 2.25 0 016 3.75h2.25A2.25 2.25 0 0110.5 6v2.25a2.25 2.25 0 01-2.25 2.25H6a2.25 2.25 0 01-2.25-2.25V6zM3.75 15.75A2.25 2.25 0 016 13.5h2.25a2.25 2.25 0 012.25 2.25V18a2.25 2.25 0 01-2.25 2.25H6A2.25 2.25 0 013.75 18v-2.25zM13.5 6a2.25 2.25 0 012.25-2.25H18A2.25 2.25 0 0120.25 6v2.25A2.25 2.25 0 0118 10.5h-2.25a2.25 2.25 0 01-2.25-2.25V6zM13.5 15.75a2.25 2.25 0 012.25-2.25H18a2.25 2.25 0 012.25 2.25V18A2.25 2.25 0 0118 20.25h-2.25A2.25 2.25 0 0113.5 18v-2.25z" />
            </svg>
            <svg v-else-if="item.id === 'devices'" class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 15V5.25A2.25 2.25 0 015.25 3h13.5A2.25 2.25 0 0121 5.25z" />
            </svg>
            <svg v-else-if="item.id === 'diagnostics'" class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.141 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0" />
            </svg>
            <svg v-else-if="item.id === 'scanning'" class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
            </svg>
            <svg v-else-if="item.id === 'packets'" class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M6.75 7.5h10.5m-10.5 4.5h10.5m-10.5 4.5h10.5M5.25 4.5h13.5A2.25 2.25 0 0121 6.75v10.5A2.25 2.25 0 0118.75 19.5H5.25A2.25 2.25 0 013 17.25V6.75A2.25 2.25 0 015.25 4.5z" />
            </svg>
            <svg v-else-if="item.id === 'logs'" class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M6.75 7.5l3 2.25-3 2.25m4.5 0h3m-9 8.25h13.5A2.25 2.25 0 0021 18V6a2.25 2.25 0 00-2.25-2.25H5.25A2.25 2.25 0 003 6v12a2.25 2.25 0 002.25 2.25z" />
            </svg>
            <svg v-else-if="item.id === 'automation'" class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" />
            </svg>
            <svg v-else-if="item.id === 'settings'" class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.324.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 011.37.49l1.296 2.247a1.125 1.125 0 01-.26 1.431l-1.003.827c-.293.24-.438.613-.431.992a6.759 6.759 0 010 .255c-.007.378.138.75.43.99l1.005.828c.424.35.534.954.26 1.43l-1.298 2.247a1.125 1.125 0 01-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.57 6.57 0 01-.22.128c-.331.183-.581.495-.644.869l-.213 1.28c-.09.543-.56.941-1.11.941h-2.594c-.55 0-1.02-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 01-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 01-1.369-.49l-1.297-2.247a1.125 1.125 0 01.26-1.431l1.004-.827c.292-.24.437-.613.43-.992a6.932 6.932 0 010-.255c.007-.378-.138-.75-.43-.99l-1.004-.828a1.125 1.125 0 01-.26-1.43l1.297-2.247a1.125 1.125 0 011.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.087.22-.128.332-.183.582-.495.644-.869l.214-1.281z" />
              <path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>
            <span v-if="ui.sidebarExpanded" class="truncate">{{ item.label }}</span>
          </button>
        </nav>

        <!-- Footer: user info + logout -->
        <div class="border-t px-1 py-2 space-y-0.5" style="border-color: var(--np-border-subtle);">
          <div class="flex items-center gap-2.5 px-2.5 py-1.5">
            <div class="w-6 h-6 rounded-lg flex items-center justify-center text-[0.6rem] font-bold shrink-0" style="background: color-mix(in srgb, var(--np-accent-primary) 15%, transparent); color: var(--np-accent-primary); border: 1px solid color-mix(in srgb, var(--np-accent-primary) 20%, transparent);">
              {{ (auth.user?.email?.[0] || "U").toUpperCase() }}
            </div>
            <div v-if="ui.sidebarExpanded" class="flex-1 min-w-0">
              <p class="text-[0.65rem] truncate" style="color: var(--np-text-muted);">{{ auth.user?.email || "Operator" }}</p>
              <p class="text-[0.55rem] uppercase tracking-widest" style="color: var(--np-accent-primary); opacity: 0.6;">
                {{ auth.user?.role === "admin" ? "Admin" : auth.user?.role === "auditor" ? "Auditor" : "Operator" }}
              </p>
            </div>
          </div>

          <button
            type="button"
            @click="handleLogout"
            class="w-full flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg text-[0.65rem] transition-colors hover:text-rose-400 hover:bg-rose-400/5"
            style="color: var(--np-text-dim);"
          >
            <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15m3 0l3-3m0 0l-3-3m3 3H9" />
            </svg>
            <span v-if="ui.sidebarExpanded" class="truncate">Logout</span>
          </button>
        </div>
      </aside>

      <!-- Main content via Vue Router -->
      <main class="flex-1 relative overflow-auto min-h-screen cyber-canvas">
        <RouterView v-slot="{ Component }">
          <component
            :is="Component"
            :theme="ui.theme"
            :is-admin="auth.isAdmin"
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

    <Toast ref="toastRef" :theme="ui.theme" />
  </div>
</template>
