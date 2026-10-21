<script setup lang="ts">
/**
 * Global command palette – opens on Cmd+K / Ctrl+K.
 *
 * Spotlight-style frosted-glass interface.
 * Supports navigation, theme switching, and scan dispatch.
 */
import { ref, computed, watch, onBeforeUnmount } from "vue";
import { useRouter } from "vue-router";
import { useMagicKeys, onClickOutside } from "@vueuse/core";
import type { Component } from "vue";
import {
  LayoutDashboard,
  Monitor,
  Moon,
  PanelLeft,
  ScrollText,
  Search,
  Settings,
  Sun,
  Wrench,
} from "lucide-vue-next";

import { useUiStore } from "../../stores/ui";

const ui = useUiStore();
const router = useRouter();

const query = ref("");
const selectedIdx = ref(0);

// Close palette on Escape.
const { escape } = useMagicKeys();
const stopEscapeWatch = watch(escape, (v) => { if (v) close(); });

const paletteRef = ref<HTMLElement | null>(null);
onClickOutside(paletteRef, () => close());

function close() {
  ui.closeCommandPalette();
  query.value = "";
  selectedIdx.value = 0;
}

onBeforeUnmount(() => {
  stopEscapeWatch();
});

type CommandGroup = "Navigation" | "Theme" | "Actions";

interface Command {
  label: string;
  hint?: string;
  group: CommandGroup;
  icon: Component;
  action: () => void;
}

// All navigable commands / actions.
const allCommands: Command[] = [
  { label: "Dashboard", hint: "Network overview at a glance", group: "Navigation", icon: LayoutDashboard, action: () => router.push("/dashboard") },
  { label: "Devices", hint: "Host inventory and status", group: "Navigation", icon: Monitor, action: () => router.push("/devices") },
  { label: "Toolbox", hint: "Scans and diagnostics", group: "Navigation", icon: Wrench, action: () => router.push("/toolbox") },
  { label: "Logs", hint: "Application and syslog", group: "Navigation", icon: ScrollText, action: () => router.push("/logs") },
  { label: "Settings", hint: "Account, alerts and system", group: "Navigation", icon: Settings, action: () => router.push("/settings") },
  { label: "Theme: Nightshade", hint: "Dark", group: "Theme", icon: Moon, action: () => ui.setTheme("nightshade") },
  { label: "Theme: SysAdmin", hint: "Light", group: "Theme", icon: Sun, action: () => ui.setTheme("sysadmin") },
  { label: "Toggle Sidebar", hint: "Collapse or expand nav", group: "Actions", icon: PanelLeft, action: () => ui.toggleSidebar() },
];

const filtered = computed(() => {
  const q = query.value.trim().toLowerCase();
  if (!q) return allCommands;
  return allCommands.filter(
    (c) => c.label.toLowerCase().includes(q) || (c.hint ?? "").toLowerCase().includes(q)
  );
});

// Group filtered results.
const groupedFiltered = computed(() => {
  const groups: Record<CommandGroup, Command[]> = { Navigation: [], Theme: [], Actions: [] };
  for (const cmd of filtered.value) {
    groups[cmd.group].push(cmd);
  }
  return Object.entries(groups).filter(([, cmds]) => cmds.length > 0) as [CommandGroup, Command[]][];
});

// Flat index for keyboard navigation across groups.
const flatFiltered = computed(() => filtered.value);

watch(filtered, () => { selectedIdx.value = 0; });

function selectUp() {
  selectedIdx.value = Math.max(0, selectedIdx.value - 1);
}

function selectDown() {
  selectedIdx.value = Math.min(flatFiltered.value.length - 1, selectedIdx.value + 1);
}

function execute(cmd: Command) {
  cmd.action();
  close();
}

function executeSelected() {
  const cmd = flatFiltered.value[selectedIdx.value];
  if (cmd) execute(cmd);
}

// Map flat index → whether it is the selected item.
function isSelected(cmd: Command): boolean {
  return flatFiltered.value[selectedIdx.value] === cmd;
}

function hoverCmd(cmd: Command) {
  const idx = flatFiltered.value.indexOf(cmd);
  if (idx !== -1) selectedIdx.value = idx;
}

</script>

<template>
  <Teleport to="body">
    <Transition name="np-fade">
      <div
        v-if="ui.commandPaletteOpen"
        class="fixed inset-0 z-[100] flex items-start justify-center pt-20 sm:pt-28 bg-[var(--np-surface-elevated)] backdrop-blur-sm"
        @click.self="close"
      >
        <div
          ref="paletteRef"
          class="w-full max-w-xl mx-4 rounded-xl overflow-hidden shadow-2xl np-glass border"
          style="border-color: var(--np-glass-border); box-shadow: 0 25px 60px rgba(0,0,0,0.7);"
        >
          <!-- Search input -->
          <div
            class="flex items-center gap-3 px-4 py-3.5 border-b"
            style="border-color: var(--np-glass-border);"
          >
            <Search class="w-4 h-4 shrink-0" style="color: var(--np-text-dim);" :stroke-width="1.7" />
            <input
              autofocus
              v-model="query"
              type="text"
              placeholder="Search commands, views, actions…"
              class="flex-1 bg-transparent outline-none text-sm placeholder:text-[var(--np-text-dim)]/30 font-sans"
              style="color: var(--np-text);"
              @keydown.up.prevent="selectUp"
              @keydown.down.prevent="selectDown"
              @keydown.enter.prevent="executeSelected"
              @keydown.escape="close"
            />
            <kbd class="text-[0.6rem] px-1.5 py-0.5 rounded border font-mono" style="border-color: var(--np-border); color: var(--np-text-dim);">Esc</kbd>
          </div>

          <!-- Grouped command list -->
          <ul class="max-h-80 overflow-y-auto py-2 font-sans" role="listbox">
            <template v-if="flatFiltered.length === 0">
              <li class="px-4 py-3 text-sm" style="color: var(--np-text-dim);">No commands found.</li>
            </template>
            <template v-else>
              <template v-for="[group, cmds] in groupedFiltered" :key="group">
                <!-- Group header -->
                <li class="px-4 pt-2 pb-1 text-[0.6rem] uppercase tracking-widest" style="color: var(--np-text-dim);">{{ group }}</li>
                <!-- Commands in group -->
                <li
                  v-for="cmd in cmds"
                  :key="cmd.label"
                  role="option"
                  :aria-selected="isSelected(cmd)"
                  class="flex items-center gap-3 px-4 py-2.5 cursor-pointer text-sm transition-colors duration-100"
                  :class="isSelected(cmd) ? 'bg-[var(--np-accent-soft)] text-[var(--np-accent)]' : ''"
                  :style="!isSelected(cmd) ? { color: 'var(--np-text-muted)' } : {}"
                  @mouseenter="hoverCmd(cmd)"
                  @click="execute(cmd)"
                >
                  <!-- Left indicator bar for selected -->
                  <span
                    class="w-0.5 h-4 rounded-full shrink-0 transition-colors"
                    :class="isSelected(cmd) ? 'bg-[var(--np-accent)]' : 'bg-transparent'"
                  ></span>
                  <component
                    :is="cmd.icon"
                    class="w-4 h-4 shrink-0"
                    :class="isSelected(cmd) ? 'text-[var(--np-accent)]' : ''"
                    :style="!isSelected(cmd) ? { color: 'var(--np-text-dim)' } : {}"
                    :stroke-width="1.7"
                  />
                  <span class="flex-1 font-medium">{{ cmd.label }}</span>
                  <span v-if="cmd.hint" class="text-[0.7rem] truncate max-w-[140px]" style="color: var(--np-text-dim);">{{ cmd.hint }}</span>
                </li>
              </template>
            </template>
          </ul>

          <!-- Footer hint -->
          <div
            class="px-4 py-2 text-[0.65rem] flex gap-4 border-t"
            style="border-color: var(--np-glass-border); color: var(--np-text-dim);"
          >
            <span><kbd class="font-mono">↑↓</kbd> navigate</span>
            <span><kbd class="font-mono">↵</kbd> select</span>
            <span><kbd class="font-mono">Esc</kbd> close</span>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>
