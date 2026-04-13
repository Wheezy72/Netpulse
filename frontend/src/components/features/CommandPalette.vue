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
  icon: string;
  action: () => void;
}

// All navigable commands / actions.
const allCommands: Command[] = [
  { label: "Dashboard", hint: "Command center overview", group: "Navigation", icon: "▦", action: () => router.push("/dashboard") },
  { label: "Devices", hint: "Host inventory & SNMP", group: "Navigation", icon: "⬡", action: () => router.push("/devices") },
  { label: "Diagnostics", hint: "MTR / traceroute", group: "Navigation", icon: "⊘", action: () => router.push("/diagnostics") },
  { label: "Scanning", hint: "Nmap scan console", group: "Navigation", icon: "⊕", action: () => router.push("/scanning") },
  { label: "Packet Browser", hint: "Live packet capture", group: "Navigation", icon: "◎", action: () => router.push("/packets") },
  { label: "Logs", hint: "Application & syslog", group: "Navigation", icon: "≡", action: () => router.push("/logs") },
  { label: "Automation", hint: "Playbooks & scripts", group: "Navigation", icon: "⚡", action: () => router.push("/automation") },
  { label: "Settings", hint: "Provider & system config", group: "Navigation", icon: "⚙", action: () => router.push("/settings") },
  { label: "Theme: Nightshade", hint: "Blue-500 accent", group: "Theme", icon: "◑", action: () => ui.setTheme("nightshade") },
  { label: "Theme: SysAdmin", hint: "Amber-500 accent", group: "Theme", icon: "◐", action: () => ui.setTheme("sysadmin") },
  { label: "Toggle Sidebar", hint: "Collapse / expand nav", group: "Actions", icon: "◫", action: () => ui.toggleSidebar() },
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

const isNightshade = computed(() => ui.theme === "nightshade");
</script>

<template>
  <Teleport to="body">
    <Transition name="np-fade">
      <div
        v-if="ui.commandPaletteOpen"
        class="fixed inset-0 z-[100] flex items-start justify-center pt-20 sm:pt-28 bg-black/70 backdrop-blur-sm"
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
            <svg class="w-4 h-4 shrink-0 text-zinc-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input
              autofocus
              v-model="query"
              type="text"
              placeholder="Search commands, views, actions…"
              class="flex-1 bg-transparent outline-none text-sm text-zinc-100 placeholder:text-zinc-600 font-sans"
              @keydown.up.prevent="selectUp"
              @keydown.down.prevent="selectDown"
              @keydown.enter.prevent="executeSelected"
              @keydown.escape="close"
            />
            <kbd class="text-[0.6rem] px-1.5 py-0.5 rounded border border-zinc-700 text-zinc-500 font-mono">Esc</kbd>
          </div>

          <!-- Grouped command list -->
          <ul class="max-h-80 overflow-y-auto py-2 font-sans" role="listbox">
            <template v-if="flatFiltered.length === 0">
              <li class="px-4 py-3 text-sm text-zinc-500">No commands found.</li>
            </template>
            <template v-else>
              <template v-for="[group, cmds] in groupedFiltered" :key="group">
                <!-- Group header -->
                <li class="px-4 pt-2 pb-1 text-[0.6rem] uppercase tracking-widest text-zinc-600">{{ group }}</li>
                <!-- Commands in group -->
                <li
                  v-for="cmd in cmds"
                  :key="cmd.label"
                  role="option"
                  :aria-selected="isSelected(cmd)"
                  class="flex items-center gap-3 px-4 py-2.5 cursor-pointer text-sm transition-colors duration-100"
                  :class="isSelected(cmd)
                    ? isNightshade ? 'bg-blue-500/10 text-zinc-100' : 'bg-amber-500/10 text-zinc-100'
                    : 'text-zinc-300 hover:text-zinc-100'"
                  @mouseenter="hoverCmd(cmd)"
                  @click="execute(cmd)"
                >
                  <!-- Left indicator bar for selected -->
                  <span
                    class="w-0.5 h-4 rounded-full shrink-0 transition-colors"
                    :class="isSelected(cmd)
                      ? isNightshade ? 'bg-blue-500' : 'bg-amber-500'
                      : 'bg-transparent'"
                  ></span>
                  <span class="w-4 text-center shrink-0 font-mono text-xs"
                    :class="isSelected(cmd)
                      ? isNightshade ? 'text-blue-400' : 'text-amber-400'
                      : 'text-zinc-600'"
                  >{{ cmd.icon }}</span>
                  <span class="flex-1 font-medium">{{ cmd.label }}</span>
                  <span v-if="cmd.hint" class="text-[0.7rem] text-zinc-600 truncate max-w-[140px]">{{ cmd.hint }}</span>
                </li>
              </template>
            </template>
          </ul>

          <!-- Footer hint -->
          <div
            class="px-4 py-2 text-[0.65rem] flex gap-4 border-t text-zinc-600"
            style="border-color: var(--np-glass-border);"
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
