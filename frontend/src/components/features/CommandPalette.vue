<script setup lang="ts">
/**
 * Global command palette – opens on Cmd+K / Ctrl+K.
 *
 * Provides instant keyboard navigation and scan dispatch without a mouse.
 * Uses VueUse's useMagicKeys for the hotkey and onClickOutside for dismissal.
 */
import { ref, computed, watch } from "vue";
import { useRouter } from "vue-router";
import { useMagicKeys, onClickOutside } from "@vueuse/core";
import { useUiStore } from "../stores/ui";

const ui = useUiStore();
const router = useRouter();

const query = ref("");
const selectedIdx = ref(0);

// Close palette on Escape.
const { escape } = useMagicKeys();
watch(escape, (v) => { if (v) ui.closeCommandPalette(); });

const paletteRef = ref<HTMLElement | null>(null);
onClickOutside(paletteRef, () => ui.closeCommandPalette());

// All navigable commands / actions.
const allCommands = [
  { label: "Dashboard", icon: "◈", action: () => router.push("/dashboard") },
  { label: "Devices", icon: "⬡", action: () => router.push("/devices") },
  { label: "Scanning", icon: "⊕", action: () => router.push("/scanning") },
  { label: "Packet Browser", icon: "◎", action: () => router.push("/packets") },
  { label: "Diagnostics / MTR", icon: "⊘", action: () => router.push("/diagnostics") },
  { label: "Logs", icon: "≡", action: () => router.push("/logs") },
  { label: "Automation", icon: "⚙", action: () => router.push("/automation") },
  { label: "Settings", icon: "⚙", action: () => router.push("/settings") },
  { label: "Theme: Nightshade", icon: "◑", action: () => ui.setTheme("nightshade") },
  { label: "Theme: Sysadmin", icon: "◐", action: () => ui.setTheme("sysadmin") },
];

const filtered = computed(() => {
  const q = query.value.trim().toLowerCase();
  if (!q) return allCommands;
  return allCommands.filter((c) => c.label.toLowerCase().includes(q));
});

watch(filtered, () => { selectedIdx.value = 0; });

function selectUp() {
  selectedIdx.value = Math.max(0, selectedIdx.value - 1);
}

function selectDown() {
  selectedIdx.value = Math.min(filtered.value.length - 1, selectedIdx.value + 1);
}

function execute(idx = selectedIdx.value) {
  const cmd = filtered.value[idx];
  if (cmd) {
    cmd.action();
    ui.closeCommandPalette();
    query.value = "";
  }
}
</script>

<template>
  <Teleport to="body">
    <Transition name="np-fade">
      <div
        v-if="ui.commandPaletteOpen"
        class="fixed inset-0 z-50 flex items-start justify-center pt-24 bg-black/60 backdrop-blur-sm"
      >
        <div
          ref="paletteRef"
          class="w-full max-w-lg rounded-xl border shadow-2xl overflow-hidden bg-gray-900 dark:bg-[#0a0f1e] border-amber-500/15 dark:border-teal-500/20"
        >
          <!-- Search input -->
          <div class="flex items-center gap-3 px-4 py-3 border-b border-amber-500/15 dark:border-teal-500/20">
            <span class="text-slate-400 dark:text-teal-300">⌘</span>
            <input
              autofocus
              v-model="query"
              type="text"
              placeholder="Search commands, navigate views…"
              class="flex-1 bg-transparent outline-none text-sm text-slate-100 dark:text-sky-100"
              @keydown.up.prevent="selectUp"
              @keydown.down.prevent="selectDown"
              @keydown.enter.prevent="execute()"
              @keydown.escape="ui.closeCommandPalette()"
            />
            <kbd
              class="text-xs px-1.5 py-0.5 rounded border border-amber-500/15 dark:border-teal-500/20 text-slate-400 dark:text-teal-300"
            >Esc</kbd>
          </div>

          <!-- Command list -->
          <ul class="max-h-80 overflow-y-auto py-1" role="listbox">
            <li
              v-if="filtered.length === 0"
              class="px-4 py-3 text-sm text-slate-400 dark:text-teal-300"
            >
              No commands found
            </li>
            <li
              v-for="(cmd, idx) in filtered"
              :key="cmd.label"
              role="option"
              :aria-selected="idx === selectedIdx"
              class="flex items-center gap-3 px-4 py-2.5 cursor-pointer text-sm transition-colors text-slate-100 dark:text-sky-100"
              :class="idx === selectedIdx ? 'bg-amber-500/10 dark:bg-teal-500/10' : ''"
              @mouseenter="selectedIdx = idx"
              @click="execute(idx)"
            >
              <span class="text-amber-500 dark:text-teal-500">{{ cmd.icon }}</span>
              {{ cmd.label }}
            </li>
          </ul>

          <!-- Footer hint -->
          <div
            class="px-4 py-2 text-xs flex gap-4 border-t text-slate-400 dark:text-teal-300 border-amber-500/15 dark:border-teal-500/20"
          >
            <span><kbd>↑↓</kbd> navigate</span>
            <span><kbd>↵</kbd> select</span>
            <span><kbd>Esc</kbd> close</span>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>
