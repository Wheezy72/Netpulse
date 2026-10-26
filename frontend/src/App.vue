<script setup lang="ts">
/**
 * Root application shell.
 *
 * Layout: fixed 64px icon rail (desktop) + sticky header with text tabs +
 * scrollable canvas. On mobile the rail collapses into a slide-in drawer.
 */
import { ref, computed, nextTick, onMounted, onUnmounted, watch } from "vue";
import { useRouter, useRoute } from "vue-router";
import axios from "axios";
import { useMagicKeys } from "@vueuse/core";
import {
  Bell,
  ChevronDown,
  LoaderCircle,
  Menu,
  Moon,
  Sun,
  X,
} from "lucide-vue-next";

import AppGlyph from "./components/ui/AppGlyph.vue";
import BrandLogo from "./components/ui/BrandLogo.vue";
import CommandPalette from "./components/features/CommandPalette.vue";
import Toast from "./components/ui/Toast.vue";

import { useAuthStore } from "./stores/auth";
import { describeRequestError } from "./utils/requestError";
import { useUiStore } from "./stores/ui";
import { useDeviceDiscovery } from "./composables/useDeviceDiscovery";

const router = useRouter();
const route = useRoute();
const auth = useAuthStore();
const ui = useUiStore();

const isNightshade = computed(() => ui.theme === "nightshade");

function toggleTheme(event?: MouseEvent) {
  // The reveal grows from the button itself, so it reads as a consequence of
  // the click rather than an unrelated full-page effect.
  ui.setTheme(
    isNightshade.value ? "sysadmin" : "nightshade",
    event ? { x: event.clientX, y: event.clientY } : undefined
  );
}

const toastRef = ref<InstanceType<typeof Toast> | null>(null);
const mobileMenuOpen = ref(false);
const profileOpen = ref(false);

// The profile menu is click-driven. A hover-only menu broke as soon as the
// pointer crossed the gap to the panel, so it could never be clicked.
function toggleProfile(): void {
  profileOpen.value = !profileOpen.value;
}

function closeProfile(): void {
  profileOpen.value = false;
}

// Accounts can be created without an email, so the address is the last thing
// to fall back on rather than the first thing shown.
const profileLabel = computed(() => {
  const u = auth.user;
  return u?.full_name?.trim() || u?.username?.trim() || u?.email || "Signed in";
});

const profileDetail = computed(() => {
  const u = auth.user;
  if (!u?.email || u.email === profileLabel.value) return "";
  return u.email;
});

const profileInitial = computed(() => {
  const source = profileLabel.value.trim();
  return (source[0] || "U").toUpperCase();
});

function onDocumentPointerDown(event: PointerEvent): void {
  const target = event.target as HTMLElement | null;
  if (!target?.closest("[data-profile-menu]")) closeProfile();
}

// Esc closes the quick-action flyout — a popover you can only dismiss by
// clicking its little X is a trap on a keyboard-driven console.
function onDocumentKeydown(event: KeyboardEvent): void {
  if (event.key === "Escape" && activePanel.value) {
    event.stopPropagation();
    closePanel();
  }
}

onMounted(() => {
  document.addEventListener("pointerdown", onDocumentPointerDown);
  document.addEventListener("keydown", onDocumentKeydown);
  window.addEventListener("resize", closeProfile);
});

onUnmounted(() => {
  document.removeEventListener("pointerdown", onDocumentPointerDown);
  document.removeEventListener("keydown", onDocumentKeydown);
  window.removeEventListener("resize", closeProfile);
});

watch(
  () => route.fullPath,
  () => closeProfile()
);

// Open the command palette with Cmd+K or Ctrl+K.
const { Meta_k, Ctrl_k } = useMagicKeys();
watch([Meta_k, Ctrl_k], ([mk, ck]) => {
  if ((mk || ck) && auth.isAuthenticated) {
    ui.openCommandPalette();
  }
});

function notify(type: "success" | "error" | "warning" | "info", message: string) {
  toastRef.value?.show(type, message);
}

/** Adapter for pages that emit `toast` themselves (Toolbox). */
function showToast(type: "success" | "error" | "warning" | "info", message: string): void {
  notify(type, message);
}

// One drawn glyph family for the whole shell (AppGlyph): navigation and the
// rail actions share stroke weight, corner radius and motion language, so the
// app reads as one piece of equipment rather than a Lucide sampler.
type NavPage = { id: string; label: string; glyph: string };

const navItems: NavPage[] = [
  { id: "dashboard", label: "Dashboard", glyph: "dashboard" },
  { id: "topology", label: "Topology", glyph: "topology" },
  { id: "devices", label: "Devices", glyph: "devices" },
  { id: "toolbox", label: "Toolbox", glyph: "toolbox" },
  { id: "logs", label: "Logs", glyph: "logs" },
  { id: "settings", label: "Settings", glyph: "settings" },
];

// Header tabs: the navigation. The left rail never duplicates these.
const headerTabs = navItems.filter((item) =>
  ["dashboard", "topology", "devices", "toolbox"].includes(item.id)
);

function isActive(id: string) {
  return route.name === id;
}

function navigateTo(id: string) {
  router.push(`/${id}`);
  mobileMenuOpen.value = false;
}

// The drawer closes first so the dialog a rail action may open is not stacked
// behind the menu overlay.
function runRailActionFromDrawer(id: string) {
  mobileMenuOpen.value = false;
  runRailAction(id);
}

// ---------------------------------------------------------------------------
// Rail quick actions — things you *fire*, not places you go.
// ---------------------------------------------------------------------------
// Rail actions carry their own drawn glyphs rather than Lucide stand-ins: a
// magnifier did not say "discover devices", and a fish did not say "capture
// packets". Each glyph animates while it is hovered or running.
type RailGlyphName = "scan" | "sweep" | "terminal" | "packets";

const railActions: {
  id: string;
  label: string;
  glyph: RailGlyphName;
}[] = [
  { id: "scan", label: "Run a quick scan", glyph: "scan" },
  { id: "sweep", label: "Sweep the network for devices", glyph: "sweep" },
  { id: "terminal", label: "Open MobaXterm", glyph: "terminal" },
  { id: "wireshark", label: "Open Wireshark", glyph: "packets" },
];

const activePanel = ref<"scan" | "sweep" | "terminal" | null>(null);
const dialogInput = ref<HTMLInputElement | null>(null);

// MobaXterm and Wireshark are launched on the machine running the backend, not
// in the browser, so a phone can only ask for them — it can never show them.
// The UI says where they open instead of appearing to do nothing.
const isMobile = ref(false);
let mobileQuery: MediaQueryList | null = null;

function syncIsMobile(event?: MediaQueryListEvent): void {
  isMobile.value = event ? event.matches : (mobileQuery?.matches ?? false);
}

const hostLabel = computed(() => window.location.hostname || "the NetPulse host");

// Land the caret in the only text field a dialog owns. `autofocus` does not
// fire for content inserted after the initial page load.
watch(activePanel, async (panel) => {
  if (!panel) return;
  await nextTick();
  dialogInput.value?.focus();
});

function runRailAction(id: string) {
  if (id === "scan" || id === "terminal" || id === "sweep") {
    // Everything that needs input opens the same dialog. A sweep used to fire
    // immediately from the rail with no target and no confirmation.
    activePanel.value = activePanel.value === id ? null : id;
    if (activePanel.value === "terminal") void loadTerminalInfo();
    if (activePanel.value === "sweep") sweepMessage.value = null;
    if (activePanel.value === "scan") void suggestScanTarget();
    return;
  }
  activePanel.value = null;
  if (id === "wireshark") void launchWireshark();
}

function closePanel() {
  activePanel.value = null;
}

// Quick scan -----------------------------------------------------------------
// Profile ids, not raw commands: the planner decides the scan type from what
// this machine can actually do (SYN vs connect scan), so a box without Npcap
// or root still gets a working scan instead of "Failed to open device".
const scanProfiles = [
  { label: "Ping sweep — who is alive", profile: "sweep" },
  { label: "Top ports — fast service check", profile: "quick" },
  { label: "Version probe — services + versions", profile: "services" },
  { label: "Full TCP — every port", profile: "full" },
];
const scanProfile = ref(scanProfiles[0].label);
const scanTarget = ref("");
const scanBusy = ref(false);
const scanBusyTargets = ref(false);
const lastScanId = ref<string | null>(null);

// The target is almost always "the network I am on", so ask the backend and
// fill the field in. Anything the operator has already typed wins; this only
// removes the step of looking up your own subnet.
async function suggestScanTarget() {
  if (scanTarget.value.trim()) return;
  scanBusyTargets.value = true;
  try {
    const { data } = await axios.get<{ cidr?: string | null }>("/api/networks/current");
    if (data?.cidr && !scanTarget.value.trim()) scanTarget.value = data.cidr;
  } catch {
    // No detection (no route, no permissions): leave the field editable.
  } finally {
    scanBusyTargets.value = false;
  }
}

// Conservative character allowlist — the backend validates again regardless.
const TARGET_RE = /^[A-Za-z0-9.:/_-]{1,128}$/;

async function runQuickScan() {
  const target = scanTarget.value.trim();
  if (!TARGET_RE.test(target)) {
    notify(
      "error",
      "Enter a host, IP, range or CIDR — letters, digits, . : / _ - only."
    );
    return;
  }
  scanBusy.value = true;
  lastScanId.value = null;
  try {
    const profile =
      scanProfiles.find((p) => p.label === scanProfile.value) ?? scanProfiles[0];
    const { data } = await axios.post<{ id: string }>("/api/nmap/execute", {
      profile: profile.profile,
      target,
      save_results: true,
    });
    lastScanId.value = data.id;
    notify("success", `Scan queued for ${target}. Live output is in the Toolbox.`);
  } catch (e: any) {
    notify("error", describeRequestError(e, "Scan could not be started."));
  } finally {
    scanBusy.value = false;
  }
}

// Discovery sweep ------------------------------------------------------------
const { discovering, discover, notice } = useDeviceDiscovery();
const sweepTarget = ref("");
const sweepMessage = ref<string | null>(null);
const sweepKind = ref<"ok" | "warn" | "error" | null>(null);

async function runSweep() {
  if (discovering.value) return;
  sweepMessage.value = null;
  sweepKind.value = null;
  const result = await discover(sweepTarget.value.trim() || null);
  if (notice.value) {
    sweepMessage.value = notice.value.text;
    sweepKind.value = notice.value.kind;
    notify(
      notice.value.kind === "ok"
        ? "success"
        : notice.value.kind === "warn"
          ? "warning"
          : "error",
      notice.value.text
    );
  } else if (result) {
    sweepMessage.value = "Sweep finished.";
    sweepKind.value = "ok";
  }
}

function goToDevices(): void {
  closePanel();
  router.push("/devices");
}

// Terminal / MobaXterm -------------------------------------------------------
const termInfo = ref<{
  platform: string;
  kind: string;
  available: boolean;
  options: { index: number; name: string }[];
  download_url: string | null;
  note: string | null;
} | null>(null);
const termBusy = ref(false);

async function loadTerminalInfo() {
  try {
    const { data } = await axios.get("/api/tools/terminal");
    termInfo.value = data;
  } catch {
    termInfo.value = null;
  }
}

// Wireshark launcher ---------------------------------------------------------
// Same allowlist model as the terminal: the browser asks, the backend resolves
// a fixed executable path. Nothing from the client is ever passed to a shell.
const wiresharkBusy = ref(false);

async function launchWireshark() {
  if (wiresharkBusy.value) return;
  wiresharkBusy.value = true;
  try {
    const { data } = await axios.get("/api/tools/wireshark");
    if (!data.available) {
      notify(
        "warning",
        data.note || `Wireshark is not installed on ${hostLabel.value}.`
      );
      // Installing Wireshark on a phone is not a thing: offer the download only
      // where it can actually be used, which is the machine running NetPulse.
      if (data.download_url && !isMobile.value) {
        window.open(data.download_url, "_blank", "noopener");
      }
      return;
    }
    await axios.post("/api/tools/wireshark/open", { index: 0 });
    notify("success", `Wireshark opened on ${hostLabel.value}.`);
  } catch (e: any) {
    notify(
      "error",
      e?.response?.data?.detail || "Could not open Wireshark."
    );
  } finally {
    wiresharkBusy.value = false;
  }
}

async function openTerminal(index: number) {
  termBusy.value = true;
  try {
    const { data } = await axios.post<{ name: string }>("/api/tools/terminal/open", {
      index,
    });
    notify("success", `${data.name} opened on ${hostLabel.value}.`);
    activePanel.value = null;
  } catch (e: any) {
    notify("error", e?.response?.data?.detail || "Could not open the terminal.");
  } finally {
    termBusy.value = false;
  }
}


async function handleLogout() {
  await auth.logout();
  router.push("/login");
}

async function handleAuthSuccess(arg: string | { token: string; rememberMe?: boolean }) {
  const t = typeof arg === "string" ? arg : arg.token;
  const persist = typeof arg === "string" ? true : (arg.rememberMe ?? true);
  auth.setToken(t, persist);
  await auth.loadUser();
  // Resume the page that triggered login when it is a safe local path.
  const redirect = route.query.redirect;
  const target =
    typeof redirect === "string" && redirect.startsWith("/") && !redirect.startsWith("//")
      ? redirect
      : "/dashboard";
  router.push(target);
}

onMounted(async () => {
  mobileQuery = window.matchMedia("(max-width: 767px)");
  syncIsMobile();
  mobileQuery.addEventListener("change", syncIsMobile);

  if (window.innerWidth < 768) {
    ui.sidebarExpanded = false;
    localStorage.setItem("np-sidebar-expanded", "false");
  }
});

onUnmounted(() => {
  mobileQuery?.removeEventListener("change", syncIsMobile);
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
  if (forceNewPassword.value.length < 12) {
    forceError.value = "New password must be at least 12 characters.";
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
    await auth.loadUser();
  } catch (err: any) {
    forceError.value =
      err?.response?.data?.detail ??
      err?.response?.data?.error?.message ??
      "Failed to update password.";
  } finally {
    forceSubmitting.value = false;
  }
}
</script>

<template>
  <div class="min-h-screen cyber-canvas canvas-glow relative text-[var(--np-text)]">
    <!-- Command palette (global) -->
    <CommandPalette />

    <!-- Unauthenticated: just render the router-view (Login / Register) -->
    <template v-if="!auth.isAuthenticated || route.meta?.guest">
      <RouterView v-slot="{ Component }">
        <component
          :is="Component"
          :theme="ui.theme"
          @login-success="handleAuthSuccess"
          @register-success="handleAuthSuccess"
          @switch-to-register="router.push('/setup')"
          @switch-to-login="router.push('/login')"
          @toggle-theme="ui.setTheme(ui.theme === 'nightshade' ? 'sysadmin' : 'nightshade')"
        />
      </RouterView>
    </template>

    <!-- Authenticated shell -->
    <template v-else>
      <!-- Force Password Change Mode -->
      <div
        v-if="auth.user?.force_password_change"
        class="min-h-screen w-full flex items-center justify-center p-4 relative z-50 bg-[var(--np-bg)]"
      >
        <div class="np-login-panel w-full max-w-md p-8 relative">
          <div class="text-center mb-6">
            <h1 class="np-brand-text animate-pulse text-xl font-bold tracking-wider mb-2 font-mono">
              Set a new password
            </h1>
            <p class="text-[0.65rem] font-mono text-[var(--np-text-muted)] uppercase tracking-wider">
              First login password reset required
            </p>
          </div>

          <form @submit.prevent="handleForcePasswordChange" class="space-y-4">
            <div>
              <label class="block text-[0.65rem] uppercase tracking-wider mb-1.5 font-mono text-[var(--np-text-muted)]">
                New Password (min 6 characters)
              </label>
              <input
                v-model="forceNewPassword"
                type="password"
                class="np-neon-input w-full rounded-lg px-4 py-2.5 text-xs font-mono"
                placeholder="••••••••••••"
                required
              />
            </div>

            <div>
              <label class="block text-[0.65rem] uppercase tracking-wider mb-1.5 font-mono text-[var(--np-text-muted)]">
                Confirm New Password
              </label>
              <input
                v-model="forceConfirmPassword"
                type="password"
                class="np-neon-input w-full rounded-lg px-4 py-2.5 text-xs font-mono"
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
                <LoaderCircle v-if="forceSubmitting" class="h-4 w-4 animate-spin" :stroke-width="1.7" />
                <span>{{ forceSubmitting ? "Updating…" : "Update password" }}</span>
              </button>
            </div>

            <p v-if="forceError" class="text-center text-xs text-rose-400 font-mono">
              {{ forceError }}
            </p>
          </form>

          <div class="mt-6 pt-4 border-t border-[var(--np-border-subtle)] flex items-center justify-center gap-2">
            <span class="np-status-dot" />
            <span class="text-[0.65rem] font-mono text-[var(--np-text-dim)] uppercase tracking-widest">
              Signed in &bull; Netpulse
            </span>
          </div>
        </div>
      </div>

      <!-- Standard Shell -->
      <template v-else>
        <!-- Left: 64px icon rail (desktop) -->
        <aside
          class="hidden md:flex fixed left-0 top-0 z-40 h-screen w-16 flex-col items-center border-r border-[var(--np-border-subtle)] bg-[var(--np-surface)]/85 backdrop-blur-xl"
        >
          <!-- Brand. A link, not decoration: the mark is the fastest way back
               to the dashboard from anywhere in the app. -->
          <div class="flex h-16 w-full items-center justify-center border-b border-[var(--np-border-subtle)]">
            <RouterLink
              to="/dashboard"
              class="np-brand-bg np-brand-border np-brand-text flex h-9 w-9 items-center justify-center rounded-xl border shadow-lg shadow-[0_0_14px_var(--np-accent-glow)] transition-transform hover:scale-105 active:scale-95"
              aria-label="NetPulse — go to the dashboard"
              title="NetPulse — dashboard"
            >
              <BrandLogo :size="20" />
            </RouterLink>
          </div>

          <!-- Quick actions, low on the rail: things you fire, not page links.
               Sitting them just above the floor keeps the top of the rail for
               the brand and leaves the middle empty rather than crowded. -->
          <nav class="flex flex-1 flex-col items-center justify-end gap-1.5 w-full px-2 pb-6">
            <button
              v-for="item in railActions"
              :key="item.id"
              type="button"
              :title="item.label"
              :aria-label="item.label"
              @click.stop.prevent="runRailAction(item.id)"
              class="group relative flex h-10 w-10 items-center justify-center rounded-xl border transition-all duration-200"
              :class="
                activePanel === item.id
                  ? 'np-brand-border np-brand-bg np-brand-text shadow-[0_0_18px_var(--np-accent-glow)]'
                  : 'border-transparent text-[var(--np-text-dim)] hover:border-[var(--np-border-subtle)] hover:bg-[var(--np-surface-hover)] hover:text-[var(--np-text)]'
              "
            >
              <AppGlyph
                :name="item.glyph"
                :active="(item.id === 'sweep' && discovering) || (item.id === 'scan' && scanBusy)"
              />
              <span
                v-if="item.id === 'sweep' && discovering"
                class="absolute -right-0.5 -top-0.5 h-2 w-2 animate-ping rounded-full bg-[var(--np-accent)]"
              />
              <!-- Tooltip -->
              <span
                class="pointer-events-none absolute left-full ml-2 whitespace-nowrap rounded-md border border-[var(--np-border-subtle)] bg-[var(--np-surface-elevated)] px-2 py-1 text-[0.6rem] font-mono uppercase tracking-wider text-[var(--np-text)] opacity-0 shadow-lg transition-opacity group-hover:opacity-100"
              >
                {{ item.label }}
              </span>
            </button>
          </nav>

        </aside>

        <!-- Dimmed backdrop. Quick actions are dialogs now: a floating card
             pinned to the rail read as part of the page it was covering. -->
        <div
          v-if="activePanel"
          class="np-dialog-scrim fixed inset-0 z-[70]"
          @click="closePanel"
        />

        <!-- Quick nmap scan -->
        <section
          v-if="activePanel === 'scan'"
          class="np-dialog glass-card glass-card--static fixed z-[80] w-[min(26rem,calc(100vw-2rem))] p-5"
          role="dialog"
          aria-modal="true"
          aria-labelledby="quick-scan-title"
        >
          <header class="flex items-start justify-between gap-2">
            <div>
              <p class="text-[0.55rem] font-mono uppercase tracking-widest text-[var(--np-text-dim)]">Quick scan</p>
              <h2 id="quick-scan-title" class="mt-0.5 text-sm font-bold text-[var(--np-text)]">nmap without leaving the page</h2>
            </div>
            <button
              type="button"
              class="rounded-md p-1 text-[var(--np-text-dim)] transition-colors hover:text-[var(--np-text)]"
              aria-label="Close"
              @click="closePanel"
            >
              <X class="h-4 w-4" :stroke-width="1.7" />
            </button>
          </header>

          <label class="mt-3 block text-[0.6rem] font-mono uppercase tracking-wider text-[var(--np-text-dim)]">
            Target
          </label>
          <input
            ref="dialogInput"
            v-model="scanTarget"
            type="text"
            :placeholder="scanBusyTargets ? 'Detecting this network…' : '192.168.1.0/24 or one-host'"
            class="np-neon-input mt-1 w-full px-3 py-2 font-mono text-xs"
            @keyup.enter="runQuickScan"
          />

          <label class="mt-2.5 block text-[0.6rem] font-mono uppercase tracking-wider text-[var(--np-text-dim)]">
            Profile
          </label>
          <select v-model="scanProfile" class="np-neon-input mt-1 w-full cursor-pointer px-2 py-2 text-xs">
            <option v-for="p in scanProfiles" :key="p.profile" :value="p.label">{{ p.label }}</option>
          </select>

          <div class="mt-3 flex gap-2">
            <button
              type="button"
              class="np-cyber-btn flex-1 py-2 text-[0.65rem] uppercase tracking-wider"
              :disabled="scanBusy || discovering"
              @click="runQuickScan"
            >
              {{ scanBusy ? "Queuing…" : "Run scan" }}
            </button>
            <button
              type="button"
              class="rounded-xl border border-[var(--np-border-subtle)] px-3 py-2 text-[0.65rem] font-semibold uppercase tracking-wider text-[var(--np-text-muted)] transition-colors hover:text-[var(--np-text)]"
              @click="navigateTo('toolbox'); closePanel()"
            >
              Toolbox
            </button>
          </div>

          <p v-if="lastScanId" class="np-accent-text mt-2 font-mono text-[0.6rem]">
            Scan {{ lastScanId }} queued.
          </p>
        </section>

        <!-- Discovery sweep -->
        <section
          v-if="activePanel === 'sweep'"
          class="np-dialog glass-card glass-card--static fixed z-[80] w-[min(28rem,calc(100vw-2rem))] p-5"
          role="dialog"
          aria-modal="true"
          aria-labelledby="quick-sweep-title"
        >
          <header class="flex items-start justify-between gap-2">
            <div>
              <p class="text-[0.55rem] font-mono uppercase tracking-widest text-[var(--np-text-dim)]">Discovery</p>
              <h2 id="quick-sweep-title" class="mt-0.5 text-sm font-bold text-[var(--np-text)]">Sweep the network</h2>
            </div>
            <button
              type="button"
              class="rounded-md p-1 text-[var(--np-text-dim)] transition-colors hover:text-[var(--np-text)]"
              aria-label="Close"
              @click="closePanel"
            >
              <X class="h-4 w-4" :stroke-width="1.7" />
            </button>
          </header>

          <p class="mt-3 text-xs leading-relaxed text-[var(--np-text-muted)]">
            Adds every host that answers to the inventory. No port scan.
          </p>

          <label class="mt-4 block text-[0.6rem] font-mono uppercase tracking-wider text-[var(--np-text-dim)]">
            Target <span class="normal-case tracking-normal opacity-70">(optional)</span>
          </label>
          <input
            ref="dialogInput"
            v-model="sweepTarget"
            type="text"
            placeholder="192.168.1.0/24"
            class="np-neon-input mt-1 w-full px-3 py-2 font-mono text-xs"
            @keyup.enter="runSweep"
          />
          <p class="mt-1.5 text-[0.65rem] text-[var(--np-text-dim)]">
            Leave blank to sweep the networks this host is attached to.
          </p>

          <p
            v-if="sweepMessage"
            class="mt-3 rounded border px-3 py-2 text-[0.7rem]"
            :class="{
              'text-[var(--np-success)]': sweepKind === 'ok',
              'text-[var(--np-warning)]': sweepKind === 'warn',
              'text-[var(--np-danger)]': sweepKind === 'error',
            }"
            :style="{
              borderColor:
                sweepKind === 'ok'
                  ? 'var(--np-success)'
                  : sweepKind === 'warn'
                    ? 'var(--np-warning)'
                    : 'var(--np-danger)',
            }"
          >
            {{ sweepMessage }}
          </p>

          <div class="mt-4 flex gap-2">
            <button
              type="button"
              class="np-cyber-btn np-cyber-btn--solid flex-1 py-2 text-[0.65rem] uppercase tracking-wider"
              :disabled="discovering || !auth.isAdmin"
              @click="runSweep"
            >
              {{ discovering ? "Sweeping…" : "Start sweep" }}
            </button>
            <button
              type="button"
              class="rounded-xl border border-[var(--np-border-subtle)] px-3 py-2 text-[0.65rem] font-semibold uppercase tracking-wider text-[var(--np-text-muted)] transition-colors hover:text-[var(--np-text)]"
              @click="goToDevices"
            >
              Devices
            </button>
          </div>

          <p v-if="!auth.isAdmin" class="mt-2 text-[0.65rem] text-[var(--np-warning)]">
            Admin access is required to sweep the network.
          </p>
        </section>

        <!-- Terminal / MobaXterm -->
        <section
          v-if="activePanel === 'terminal'"
          class="np-dialog glass-card glass-card--static fixed z-[80] w-[min(26rem,calc(100vw-2rem))] p-5"
          role="dialog"
          aria-modal="true"
          aria-labelledby="terminal-title"
        >
          <header class="flex items-start justify-between gap-2">
            <div>
              <p class="text-[0.55rem] font-mono uppercase tracking-widest text-[var(--np-text-dim)]">Desktop</p>
              <h2 id="terminal-title" class="mt-0.5 text-sm font-bold text-[var(--np-text)]">Open MobaXterm</h2>
            </div>
            <button
              type="button"
              class="rounded-md p-1 text-[var(--np-text-dim)] transition-colors hover:text-[var(--np-text)]"
              aria-label="Close"
              @click="closePanel"
            >
              <X class="h-4 w-4" :stroke-width="1.7" />
            </button>
          </header>

          <p v-if="!termInfo" class="mt-3 text-xs text-[var(--np-text-dim)]">Checking what's installed…</p>

          <template v-else>
            <div v-if="termInfo.available" class="mt-3 flex flex-col gap-1.5">
              <button
                v-for="opt in termInfo.options"
                :key="opt.index"
                type="button"
                class="flex items-center justify-between rounded-xl border border-[var(--np-border-subtle)] bg-[var(--np-surface-elevated)]/60 px-3 py-2 text-left text-xs font-semibold text-[var(--np-text)] transition-colors hover:border-[var(--np-border)] disabled:opacity-50"
                :disabled="termBusy"
                @click="openTerminal(opt.index)"
              >
                <span>{{ opt.name }}</span>
                <span class="np-accent-text font-mono text-[0.6rem]">Open</span>
              </button>
              <p class="mt-1 text-[0.6rem] text-[var(--np-text-dim)]">
                Opens on {{ hostLabel }}.
              </p>
            </div>

            <div v-else class="mt-3">
              <p class="text-xs text-[var(--np-text-muted)]">{{ termInfo.note }}</p>
              <a
                v-if="termInfo.download_url && !isMobile"
                :href="termInfo.download_url"
                target="_blank"
                rel="noopener noreferrer"
                class="np-cyber-btn mt-3 inline-block w-full py-2 text-center text-[0.65rem] uppercase tracking-wider"
              >
                Download MobaXterm
              </a>
              <p v-if="isMobile" class="mt-2 text-[0.65rem] leading-relaxed text-[var(--np-text-dim)]">
                Install MobaXterm on {{ hostLabel }}.
              </p>
            </div>
          </template>
        </section>

        <!-- Content column, offset by the rail -->
        <div class="flex min-h-screen flex-col md:pl-16">
          <!-- Sticky header: text tabs left, utilities right -->
          <header
            class="sticky top-0 z-30 w-full border-b border-[var(--np-border-subtle)] bg-[var(--np-glass-bg)] backdrop-blur-xl"
          >
            <div class="flex h-16 items-center justify-between gap-3 px-4 md:px-8">
              <!-- Mobile brand -->
              <RouterLink
                to="/dashboard"
                class="flex items-center gap-2 md:hidden"
                aria-label="NetPulse — go to the dashboard"
              >
                <span class="np-brand-bg np-brand-border np-brand-text flex h-8 w-8 items-center justify-center rounded-lg border">
                  <BrandLogo :size="17" />
                </span>
                <span class="text-xs uppercase tracking-widest font-semibold">NetPulse</span>
              </RouterLink>

              <!-- Desktop text tabs with active underline -->
              <nav class="hidden md:flex h-16 items-stretch gap-1 overflow-x-auto">
                <button
                  v-for="item in headerTabs"
                  :key="item.id"
                  type="button"
                  @click="navigateTo(item.id)"
                  class="group relative flex items-center gap-2 px-4 text-[0.72rem] font-semibold uppercase tracking-wider transition-colors"
                  :class="
                    isActive(item.id)
                      ? 'text-[var(--np-text)]'
                      : 'text-[var(--np-text-dim)] hover:text-[var(--np-text)]'
                  "
                >
                  <AppGlyph :name="item.glyph as any" :active="isActive(item.id)" class="h-4 w-4" />
                  {{ item.label }}
              <span
                v-if="isActive(item.id)"
                class="absolute inset-x-3 bottom-0 h-[2px] rounded-full bg-[var(--np-accent)] shadow-[0_0_12px_var(--np-accent-glow)]"
              />
                </button>
              </nav>

              <!-- Utilities -->
              <div class="flex items-center gap-1.5 sm:gap-2">
                <button
                  type="button"
                  @click="router.push('/settings')"
                  class="flex items-center gap-2 rounded-full border px-3 py-1.5 text-[0.65rem] font-semibold transition-all"
                  :class="
                    isActive('settings')
                      ? 'border-[var(--np-accent-border)] bg-[var(--np-accent-soft)] text-[var(--np-accent)]'
                      : 'border-[var(--np-border-subtle)] bg-[var(--np-surface-elevated)]/60 text-[var(--np-text-dim)] hover:border-[var(--np-border)] hover:text-[var(--np-text)]'
                  "
                  title="Settings"
                  aria-label="Settings"
                >
                  <AppGlyph name="settings" :active="isActive('settings')" class="h-4 w-4" />
                  <span class="hidden lg:inline">Settings</span>
                </button>

                <button
                  type="button"
                  @click="router.push('/logs')"
                  class="relative flex h-9 w-9 items-center justify-center rounded-full border border-[var(--np-border-subtle)] bg-[var(--np-surface-elevated)]/60 text-[var(--np-text-dim)] transition-all hover:text-[var(--np-text)]"
                  title="Notifications"
                >
                  <Bell class="h-4 w-4" :stroke-width="1.7" />
                  <span class="absolute right-2 top-2 h-1.5 w-1.5 rounded-full bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.8)]" />
                </button>

                <button
                  type="button"
                  @click="toggleTheme($event)"
                  class="flex h-9 w-9 items-center justify-center rounded-full border border-[var(--np-border-subtle)] bg-[var(--np-surface-elevated)]/60 text-[var(--np-text-dim)] transition-all hover:text-[var(--np-text)]"
                  :title="isNightshade ? 'Switch to light' : 'Switch to dark'"
                >
                  <Moon v-if="isNightshade" class="h-4 w-4" :stroke-width="1.7" />
                  <Sun v-else class="h-4 w-4" :stroke-width="1.7" />
                </button>

                <!-- Profile menu (click to open, Escape/outside click to close) -->
                <div class="relative" data-profile-menu>
                  <button
                    type="button"
                    :aria-expanded="profileOpen"
                    aria-haspopup="menu"
                    @click="toggleProfile"
                    class="flex items-center gap-2 rounded-full border py-1 pl-1 pr-2 transition-all hover:border-[var(--np-border)]"
                    :class="profileOpen ? 'border-[var(--np-border)] bg-[var(--np-surface-hover)]' : 'border-[var(--np-border-subtle)] bg-[var(--np-surface-elevated)]/60'"
                  >
                    <div class="np-brand-bg np-brand-border np-brand-text flex h-7 w-7 items-center justify-center rounded-full border text-[0.65rem] font-bold">
                      {{ profileInitial }}
                    </div>
                    <ChevronDown class="h-3 w-3 text-[var(--np-text-dim)]" :stroke-width="1.7" />
                  </button>

                  <div
                    v-if="profileOpen"
                    role="menu"
                    class="absolute right-0 top-full z-[100] mt-2 w-52 rounded-xl border border-[var(--np-border-subtle)] bg-[var(--np-surface-elevated)] py-1 shadow-2xl"
                  >
                    <div class="border-b border-[var(--np-border-subtle)] px-4 py-2">
                      <p class="text-[0.55rem] font-mono uppercase tracking-widest text-[var(--np-text-dim)]">Signed in as</p>
                      <p class="mt-0.5 truncate text-xs font-bold text-[var(--np-text)]">{{ profileLabel }}</p>
                      <p v-if="profileDetail" class="truncate text-[0.6rem] text-[var(--np-text-dim)]">{{ profileDetail }}</p>
                      <p class="np-brand-text text-[0.55rem] font-mono uppercase tracking-wider">{{ auth.user?.role }}</p>
                    </div>
                    <button
                      type="button"
                      role="menuitem"
                      @click="closeProfile(); handleLogout()"
                      class="flex w-full items-center gap-2.5 px-4 py-2 text-xs font-bold text-[var(--np-danger)] transition-colors hover:bg-[var(--np-surface-hover)]"
                    >
                      Logout
                    </button>
                  </div>
                </div>

                <!-- Hamburger (mobile) -->
                <button
                  type="button"
                  @click="mobileMenuOpen = !mobileMenuOpen"
                  class="flex h-9 w-9 items-center justify-center rounded-full border border-[var(--np-border-subtle)] bg-[var(--np-surface-elevated)]/60 text-[var(--np-text-dim)] transition-all hover:text-[var(--np-text)] md:hidden"
                  title="Menu"
                  aria-label="Menu"
                >
                  <Menu class="h-4 w-4" :stroke-width="1.7" />
                </button>
              </div>
            </div>
          </header>

          <!-- Mobile navigation overlay -->
          <div
            v-if="mobileMenuOpen"
            class="fixed inset-0 z-40 bg-[var(--np-surface-elevated)] backdrop-blur-sm md:hidden"
            @click="mobileMenuOpen = false"
          />

          <transition name="drawer">
            <aside
              v-if="mobileMenuOpen"
              class="fixed right-0 top-0 z-50 flex h-full w-[min(18rem,86vw)] flex-col gap-6 overflow-y-auto border-l border-[var(--np-border-subtle)] bg-[var(--np-surface)] p-5 shadow-2xl md:hidden"
            >
              <div class="flex items-center justify-between border-b border-[var(--np-border-subtle)] pb-4">
                <span class="text-xs font-bold uppercase tracking-wider text-[var(--np-text-dim)]">Navigation</span>
                <button @click="mobileMenuOpen = false" class="p-1 text-[var(--np-text-muted)]" aria-label="Close menu">
                  <X class="h-5 w-5" :stroke-width="1.7" />
                </button>
              </div>

              <nav class="flex flex-col gap-1">
                <button
                  v-for="item in navItems"
                  :key="item.id"
                  type="button"
                  @click="navigateTo(item.id)"
                  class="flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-left text-xs font-semibold uppercase tracking-wider transition-all"
                  :class="
                    isActive(item.id)
                      ? 'np-brand-bg np-brand-text np-brand-border border'
                      : 'text-[var(--np-text-dim)] hover:bg-[var(--np-surface-hover)] hover:text-[var(--np-text)] border border-transparent'
                  "
                >
                  <AppGlyph :name="item.glyph as any" :active="isActive(item.id)" class="shrink-0" />
                  {{ item.label }}
                </button>
              </nav>

              <!-- Run-it actions, the same four the desktop rail offers. A scan
                   or a sweep works from a phone because the backend does the
                   work; MobaXterm and Wireshark only ever open on the host, so
                   the caption says that instead of failing silently. -->
              <div class="flex flex-col gap-1">
                <span class="px-3 pb-1 text-[0.55rem] font-mono uppercase tracking-widest text-[var(--np-text-dim)]">
                  Actions
                </span>
                <button
                  v-for="item in railActions"
                  :key="item.id"
                  type="button"
                  @click="runRailActionFromDrawer(item.id)"
                  class="flex w-full items-center gap-3 rounded-xl border border-transparent px-3 py-2.5 text-left text-xs font-semibold text-[var(--np-text-muted)] transition-colors hover:bg-[var(--np-surface-hover)] hover:text-[var(--np-text)]"
                >
                  <AppGlyph :name="item.glyph" class="shrink-0" />
                  {{ item.label }}
                </button>
                <p class="px-3 pt-1 text-[0.6rem] leading-relaxed text-[var(--np-text-dim)]">
                  Runs on {{ hostLabel }}.
                </p>
              </div>

              <div class="mt-auto flex flex-col gap-3 border-t border-[var(--np-border-subtle)] pt-4">
                <div class="px-1">
                  <span class="block truncate text-xs font-bold text-[var(--np-text)]">{{ profileLabel }}</span>
                  <span class="np-brand-text text-[0.55rem] font-mono uppercase tracking-wider">{{ auth.user?.role }}</span>
                </div>
                <button
                  type="button"
                  @click="handleLogout"
                  class="flex w-full items-center justify-center gap-2 rounded-xl border border-rose-500/25 bg-rose-500/10 py-2.5 text-xs font-bold uppercase tracking-wider text-rose-400"
                >
                  Logout
                </button>
              </div>
            </aside>
          </transition>

          <!-- Canvas -->
          <main class="flex-1 px-4 py-6 md:px-8 md:py-8">
            <div class="mx-auto w-full max-w-[1600px]">
              <!-- Toolbox is the only page that declares a `toast` event. Binding
                   it on every routed component made Vue warn about extraneous
                   listeners for five pages that can never emit one, so the
                   binding is scoped to that route. -->
              <RouterView v-slot="{ Component }">
                <component
                  :is="Component"
                  :theme="ui.theme"
                  :is-admin="auth.isAdmin"
                  v-on="route.name === 'toolbox' ? { toast: showToast } : {}"
                />
              </RouterView>
            </div>
          </main>
        </div>
      </template>
    </template>

    <Toast ref="toastRef" :theme="ui.theme" />
  </div>
</template>
