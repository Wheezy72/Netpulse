<script setup lang="ts">
import axios from "axios";
import { computed, onMounted, ref, watch } from "vue";

import Dashboard from "./views/Dashboard.vue";
import Login from "./views/Login.vue";
import Register from "./views/Register.vue";
import Settings from "./views/Settings.vue";
import Scanning from "./views/Scanning.vue";
import PacketBrowser from "./views/PacketBrowser.vue";
import Devices from "./views/Devices.vue";
import Logs from "./views/Logs.vue";
import ChatBot from "./components/ChatBot.vue";
import Toast from "./components/Toast.vue";

const toastRef = ref<InstanceType<typeof Toast> | null>(null);

function showToast(type: "success" | "error" | "warning" | "info", message: string): void {
  toastRef.value?.show(type, message);
}

type Theme = "nightshade" | "sysadmin";
type View = "dashboard" | "devices" | "scanning" | "packets" | "logs" | "settings";
type AuthView = "login" | "register";

type CurrentUser = {
  id: number;
  email: string;
  full_name: string | null;
  role: "admin" | "operator";
};

const theme = ref<Theme>("nightshade");
const currentView = ref<View>("dashboard");
const authView = ref<AuthView>("login");
const accessToken = ref<string | null>(null);
const isAuthenticated = computed(() => !!accessToken.value);
const currentUser = ref<CurrentUser | null>(null);
const isAdmin = computed(() => currentUser.value?.role === "admin");

const sidebarExpanded = ref(true);
const mobileMenuOpen = ref(false);
const logoError = ref(false);

const aiDrawerOpen = ref(false);

const infoMode = ref<'full' | 'compact'>((localStorage.getItem('np-info-mode') as 'full' | 'compact') || 'full');

function handleInfoModeUpdate(mode: 'full' | 'compact'): void {
  infoMode.value = mode;
  localStorage.setItem('np-info-mode', mode);
}

const isNightshade = computed(() => theme.value === "nightshade");

const navItems: { id: View; label: string }[] = [
  { id: "dashboard", label: "Dashboard" },
  { id: "devices", label: "Devices" },
  { id: "scanning", label: "Scanning" },
  { id: "packets", label: "Packets" },
  { id: "logs", label: "Logs" },
  { id: "settings", label: "Settings" },
];

function applyTheme(next: Theme): void {
  const body = document.body;
  body.classList.remove("theme-nightshade", "theme-sysadmin");
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

async function handleGoogleCallback(code: string): Promise<void> {
  try {
    const redirectUri = `${window.location.origin}/auth/google/callback`;
    const { data } = await axios.post<{ access_token: string }>("/api/auth/google/callback", {
      code,
      redirect_uri: redirectUri,
    });
    setAuthToken(data.access_token);
    await loadCurrentUser();
  } catch {
    authView.value = "login";
  }
}

onMounted(() => {
  const storedTheme = localStorage.getItem("np-theme") as Theme | null;
  if (storedTheme === "nightshade" || storedTheme === "sysadmin") {
    theme.value = storedTheme;
    applyTheme(storedTheme);
  } else {
    applyTheme(theme.value);
  }

  const urlParams = new URLSearchParams(window.location.search);
  const googleCode = urlParams.get("code");
  const googleState = urlParams.get("state");
  const isGoogleCallback = window.location.pathname === "/auth/google/callback";

  if (isGoogleCallback && googleCode) {
    const savedState = sessionStorage.getItem("np-oauth-state");
    sessionStorage.removeItem("np-oauth-state");
    window.history.replaceState({}, "", "/");
    if (savedState && googleState === savedState) {
      handleGoogleCallback(googleCode);
    } else {
      authView.value = "login";
    }
  } else {
    const storedToken = localStorage.getItem("np-token");
    if (storedToken) {
      setAuthToken(storedToken);
      loadCurrentUser();
    }
  }

  axios.interceptors.response.use(
    (response) => response,
    (error) => {
      if (error.response?.status === 401 && accessToken.value) {
        setAuthToken(null);
        authView.value = "login";
      }
      return Promise.reject(error);
    }
  );

  if (window.innerWidth < 768) {
    sidebarExpanded.value = false;
  }
});

watch(
  () => theme.value,
  (value) => {
    applyTheme(value);
  }
);

function toggleTheme(): void {
  theme.value = theme.value === "nightshade" ? "sysadmin" : "nightshade";
}

function toggleSidebar(): void {
  sidebarExpanded.value = !sidebarExpanded.value;
}

function navigateTo(view: View): void {
  currentView.value = view;
  mobileMenuOpen.value = false;
}

async function handleLoginSuccess(token: string): Promise<void> {
  setAuthToken(token);
  await loadCurrentUser();
}

function handleLogout(): void {
  setAuthToken(null);
  authView.value = "login";
}
</script>

<template>
  <div
    class="min-h-screen flex"
    :style="{
      backgroundColor: 'var(--np-bg)',
      color: 'var(--np-text)'
    }"
  >
    <template v-if="!isAuthenticated">
      <div class="w-full">
        <Login
          v-if="authView === 'login'"
          :theme="theme"
          @login-success="handleLoginSuccess"
          @switch-to-register="authView = 'register'"
          @toggle-theme="toggleTheme"
        />
        <Register
          v-else
          :theme="theme"
          @register-success="handleLoginSuccess"
          @switch-to-login="authView = 'login'"
          @toggle-theme="toggleTheme"
        />
      </div>
    </template>

    <template v-else>
      <button
        type="button"
        @click="mobileMenuOpen = !mobileMenuOpen"
        class="fixed top-3 left-3 z-50 md:hidden rounded-lg p-2 transition-colors"
        :class="isNightshade ? 'bg-gray-900/90 text-teal-400' : 'bg-slate-800/90 text-amber-400'"
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
        class="fixed inset-0 z-40 bg-black/60 md:hidden"
        @click="mobileMenuOpen = false"
      ></div>

      <aside
        class="fixed md:sticky top-0 left-0 z-40 h-screen flex flex-col border-r transition-all duration-300 shrink-0"
        :class="[
          mobileMenuOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0',
          sidebarExpanded ? 'w-56' : 'w-16',
          isNightshade
            ? 'bg-[#030712] border-teal-500/20'
            : 'bg-slate-900 border-amber-500/20'
        ]"
      >
        <div class="flex items-center gap-3 px-3 py-4 border-b" :style="{ borderColor: 'var(--np-border)' }">
          <div
            class="h-9 w-9 rounded-lg flex items-center justify-center border shrink-0"
            :class="isNightshade ? 'border-teal-400/60 bg-slate-900/80' : 'border-amber-500/50 bg-slate-800/50'"
            :style="isNightshade ? { boxShadow: '0 0 8px rgba(20, 184, 166, 0.3)' } : { boxShadow: '0 0 8px rgba(245, 158, 11, 0.3)' }"
          >
            <img v-if="!logoError" :src="'/logo.png'" alt="NP" class="h-6 w-6 object-contain" @error="logoError = true" />
            <span v-else class="text-sm font-bold font-mono" :class="isNightshade ? 'text-teal-400' : 'text-amber-400'">NP</span>
          </div>
          <div v-if="sidebarExpanded" class="flex flex-col overflow-hidden">
            <h1
              class="text-sm font-semibold tracking-wider uppercase truncate"
              :class="isNightshade ? 'text-teal-400' : 'text-amber-400'"
              :style="{ fontFamily: isNightshade ? '\'Orbitron\', sans-serif' : '\'Inter\', system-ui, sans-serif' }"
            >
              NetPulse
            </h1>
            <p class="text-[0.6rem] tracking-wide text-[var(--np-muted-text)] truncate">
              Network Operations Console
            </p>
          </div>
        </div>

        <button
          type="button"
          @click="toggleSidebar"
          class="hidden md:flex items-center justify-center w-full py-2 text-[var(--np-muted-text)] hover:text-[var(--np-text)] transition-colors border-b"
          :style="{ borderColor: 'var(--np-border)' }"
        >
          <svg
            class="w-4 h-4 transition-transform duration-300"
            :class="{ 'rotate-180': !sidebarExpanded }"
            fill="none" stroke="currentColor" viewBox="0 0 24 24"
          >
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 19l-7-7 7-7m8 14l-7-7 7-7" />
          </svg>
        </button>

        <nav class="flex-1 py-3 px-2 space-y-1 overflow-y-auto">
          <button
            v-for="item in navItems"
            :key="item.id"
            type="button"
            @click="navigateTo(item.id)"
            class="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs uppercase tracking-wider font-medium transition-all duration-200"
            :class="[
              currentView === item.id
                ? isNightshade
                  ? 'bg-teal-500/15 text-teal-400'
                  : 'bg-amber-500/15 text-amber-400'
                : 'text-[var(--np-muted-text)] hover:text-[var(--np-text)] hover:bg-white/5'
            ]"
            :title="item.label"
          >
            <svg v-if="item.id === 'dashboard'" class="w-5 h-5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M3.75 6A2.25 2.25 0 016 3.75h2.25A2.25 2.25 0 0110.5 6v2.25a2.25 2.25 0 01-2.25 2.25H6a2.25 2.25 0 01-2.25-2.25V6zM3.75 15.75A2.25 2.25 0 016 13.5h2.25a2.25 2.25 0 012.25 2.25V18a2.25 2.25 0 01-2.25 2.25H6A2.25 2.25 0 013.75 18v-2.25zM13.5 6a2.25 2.25 0 012.25-2.25H18A2.25 2.25 0 0120.25 6v2.25A2.25 2.25 0 0118 10.5h-2.25a2.25 2.25 0 01-2.25-2.25V6zM13.5 15.75a2.25 2.25 0 012.25-2.25H18a2.25 2.25 0 012.25 2.25V18A2.25 2.25 0 0118 20.25h-2.25A2.25 2.25 0 0113.5 18v-2.25z" />
            </svg>
            <svg v-else-if="item.id === 'devices'" class="w-5 h-5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 15V5.25A2.25 2.25 0 015.25 3h13.5A2.25 2.25 0 0121 5.25z" />
            </svg>
            <svg v-else-if="item.id === 'scanning'" class="w-5 h-5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
            </svg>
            <svg v-else-if="item.id === 'packets'" class="w-5 h-5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M6.75 7.5h10.5m-10.5 4.5h10.5m-10.5 4.5h10.5M5.25 4.5h13.5A2.25 2.25 0 0121 6.75v10.5A2.25 2.25 0 0118.75 19.5H5.25A2.25 2.25 0 013 17.25V6.75A2.25 2.25 0 015.25 4.5z" />
            </svg>
            <svg v-else-if="item.id === 'logs'" class="w-5 h-5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M6.75 7.5l3 2.25-3 2.25m4.5 0h3m-9 8.25h13.5A2.25 2.25 0 0021 18V6a2.25 2.25 0 00-2.25-2.25H5.25A2.25 2.25 0 003 6v12a2.25 2.25 0 002.25 2.25z" />
            </svg>
            <svg v-else-if="item.id === 'settings'" class="w-5 h-5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.324.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 011.37.49l1.296 2.247a1.125 1.125 0 01-.26 1.431l-1.003.827c-.293.24-.438.613-.431.992a6.759 6.759 0 010 .255c-.007.378.138.75.43.99l1.005.828c.424.35.534.954.26 1.43l-1.298 2.247a1.125 1.125 0 01-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.57 6.57 0 01-.22.128c-.331.183-.581.495-.644.869l-.213 1.28c-.09.543-.56.941-1.11.941h-2.594c-.55 0-1.02-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 01-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 01-1.369-.49l-1.297-2.247a1.125 1.125 0 01.26-1.431l1.004-.827c.292-.24.437-.613.43-.992a6.932 6.932 0 010-.255c.007-.378-.138-.75-.43-.99l-1.004-.828a1.125 1.125 0 01-.26-1.43l1.297-2.247a1.125 1.125 0 011.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.087.22-.128.332-.183.582-.495.644-.869l.214-1.281z" />
              <path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>
            <span v-if="sidebarExpanded" class="truncate" :style="{ fontFamily: isNightshade ? '\'Orbitron\', sans-serif' : '\'Inter\', system-ui, sans-serif' }">
              {{ item.label }}
            </span>
          </button>
        </nav>

        <div class="border-t px-2 py-3 space-y-2" :style="{ borderColor: 'var(--np-border)' }">
          <button
            type="button"
            @click="toggleTheme"
            class="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs transition-colors hover:bg-white/5"
            :title="isNightshade ? 'Switch to SysAdmin' : 'Switch to Nightshade'"
          >
            <svg v-if="isNightshade" class="w-5 h-5 shrink-0 text-teal-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
            </svg>
            <svg v-else class="w-5 h-5 shrink-0 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
            </svg>
            <span v-if="sidebarExpanded" class="truncate text-[var(--np-muted-text)]">
              {{ isNightshade ? 'Nightshade' : 'SysAdmin' }}
            </span>
          </button>

          <div class="flex items-center gap-3 px-3 py-2">
            <div
              class="w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold shrink-0"
              :class="isNightshade ? 'bg-teal-500/20 text-teal-400' : 'bg-amber-500/20 text-amber-400'"
            >
              {{ (currentUser?.email?.[0] || 'U').toUpperCase() }}
            </div>
            <div v-if="sidebarExpanded" class="flex-1 min-w-0">
              <p class="text-xs truncate text-[var(--np-text)]">
                {{ currentUser?.email || 'Operator' }}
              </p>
              <p :class="['text-[0.6rem] uppercase tracking-widest', isNightshade ? 'text-emerald-400' : 'text-amber-400']">
                {{ currentUser?.role === 'admin' ? 'Admin' : 'Operator' }}
              </p>
            </div>
          </div>

          <button
            type="button"
            @click="handleLogout"
            class="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs transition-colors text-red-400 hover:bg-red-400/10"
            title="Logout"
          >
            <svg class="w-5 h-5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15m3 0l3-3m0 0l-3-3m3 3H9" />
            </svg>
            <span v-if="sidebarExpanded" class="truncate" :style="{ fontFamily: isNightshade ? '\'Orbitron\', sans-serif' : '\'Inter\', system-ui, sans-serif' }">
              Logout
            </span>
          </button>
        </div>
      </aside>

      <main class="flex-1 p-6 relative overflow-auto min-h-screen">
        <div class="np-pulse-bg opacity-30"></div>
        <div class="np-fade-in" :key="currentView">
          <Dashboard
            v-if="currentView === 'dashboard'"
            :info-mode="infoMode"
            :is-admin="isAdmin"
          />
          <Devices
            v-else-if="currentView === 'devices'"
            :theme="theme"
            :is-admin="isAdmin"
          />
          <Scanning
            v-else-if="currentView === 'scanning'"
            :theme="theme"
            :is-admin="isAdmin"
            @toast="(type, msg) => toastRef?.show(type, msg)"
          />
          <PacketBrowser
            v-else-if="currentView === 'packets'"
            :theme="theme"
          />
          <Logs
            v-else-if="currentView === 'logs'"
            :theme="theme"
          />
          <Settings
            v-else
            :theme="theme"
            :info-mode="infoMode"
            :is-admin="isAdmin"
            @update:info-mode="handleInfoModeUpdate"
          />
        </div>
      </main>

      <button
        type="button"
        @click="aiDrawerOpen = !aiDrawerOpen"
        class="fixed bottom-6 right-6 z-[70] w-14 h-14 rounded-full flex items-center justify-center shadow-lg transition-all duration-300 hover:scale-110"
        :class="[
          isNightshade
            ? 'bg-teal-500/20 border-2 border-teal-400 text-teal-400 hover:bg-teal-500/30'
            : 'bg-amber-500/20 border-2 border-amber-400 text-amber-400 hover:bg-amber-500/30'
        ]"
        :style="isNightshade ? { boxShadow: '0 0 20px rgba(20, 184, 166, 0.4)' } : { boxShadow: '0 0 20px rgba(245, 158, 11, 0.4)' }"
        :title="aiDrawerOpen ? 'Close AI Analyst' : 'Open AI Analyst'"
      >
        <svg v-if="!aiDrawerOpen" class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
        </svg>
        <svg v-else class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
        </svg>
      </button>

      <div
        class="fixed inset-0 z-[55] bg-black/60 transition-opacity duration-300"
        :class="aiDrawerOpen ? 'opacity-100' : 'opacity-0 pointer-events-none'"
        @click="aiDrawerOpen = false"
      ></div>

      <div
        class="fixed inset-y-0 right-0 z-[60] w-full max-w-md transform transition-transform duration-300"
        :class="aiDrawerOpen ? 'translate-x-0' : 'translate-x-full'"
      >
        <div class="h-full p-4">
          <ChatBot class="h-full" :theme="theme" @close="aiDrawerOpen = false" />
        </div>
      </div>
    </template>

    <Toast ref="toastRef" :theme="theme" />
  </div>
</template>
