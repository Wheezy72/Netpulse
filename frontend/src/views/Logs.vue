<script setup lang="ts">
import axios from "axios";
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { RecycleScroller } from "vue-virtual-scroller";
import "vue-virtual-scroller/dist/vue-virtual-scroller.css";

type Theme = "nightshade" | "sysadmin";

interface Props {
  theme: Theme;
}

const props = defineProps<Props>();

interface LogEntry {
  timestamp: string;
  level: string;
  logger: string;
  message: string;
  module: string | null;
  function: string | null;
  line: number | null;
  extra: Record<string, unknown>;
}

interface LogStats {
  total: number;
  debug: number;
  info: number;
  warning: number;
  error: number;
  critical: number;
}

interface SyslogMessage {
  timestamp: string;
  source_ip: string;
  facility: string;
  severity: string;
  hostname: string;
  message: string;
}

interface SyslogStatus {
  running: boolean;
  message_count: number;
  port: number;
}

const activeTab = ref<"application" | "syslog">("application");

const logs = ref<LogEntry[]>([]);
const stats = ref<LogStats>({
  total: 0,
  debug: 0,
  info: 0,
  warning: 0,
  error: 0,
  critical: 0,
});
const loading = ref(false);
const error = ref<string | null>(null);

const showSystemErrors = ref(false);
const expandedErrorIds = ref<Set<number>>(new Set());

const filteredLogs = computed(() => {
  let list = logs.value;
  if (!showSystemErrors.value) {
    list = list.filter((log) => log.level !== "error" && log.level !== "critical");
  }
  const raw = searchQuery.value.trim();
  if (!raw) return list;
  // Try regex, fall back to substring
  let pattern: RegExp | null = null;
  try {
    pattern = new RegExp(raw, "i");
  } catch {
    // invalid regex — use plain text
  }
  return list.filter((log) => {
    const haystack = `${log.message} ${log.logger} ${log.module ?? ""} ${log.function ?? ""}`;
    return pattern ? pattern.test(haystack) : haystack.toLowerCase().includes(raw.toLowerCase());
  });
});

function toggleErrorExpand(index: number): void {
  if (expandedErrorIds.value.has(index)) {
    expandedErrorIds.value.delete(index);
  } else {
    expandedErrorIds.value.add(index);
  }
}

function isErrorLevel(level: string): boolean {
  return level === "error" || level === "critical";
}

function truncateMessage(msg: string, len = 60): string {
  return msg.length > len ? msg.slice(0, len) + "..." : msg;
}

const levelFilter = ref<string>("");
const searchQuery = ref<string>("");
const autoRefresh = ref(true);
const refreshInterval = ref<number | null>(null);

const isNightshade = computed(() => props.theme === "nightshade");

const levelColors = {
  debug: { bg: "bg-slate-500/20", text: "text-slate-400", border: "border-slate-500/40" },
  info: { bg: "bg-blue-500/20", text: "text-blue-400", border: "border-blue-500/40" },
  warning: { bg: "bg-amber-500/20", text: "text-amber-400", border: "border-amber-500/40" },
  error: { bg: "bg-rose-500/20", text: "text-rose-400", border: "border-rose-500/40" },
  critical: { bg: "bg-red-600/30", text: "text-red-400", border: "border-red-500/50" },
};

async function loadLogs(): Promise<void> {
  loading.value = true;
  error.value = null;
  try {
    const params: Record<string, string | number> = { limit: 200 };
    if (levelFilter.value && levelFilter.value !== "all") params.level = levelFilter.value;
    if (searchQuery.value) params.search = searchQuery.value;
    
    const [logsResponse, statsResponse] = await Promise.all([
      axios.get<{ logs: LogEntry[] }>("/api/logs", { params }),
      axios.get<LogStats>("/api/logs/stats"),
    ]);
    
    logs.value = logsResponse.data.logs;
    stats.value = statsResponse.data;
  } catch {
    error.value = "Failed to load logs";
  } finally {
    loading.value = false;
  }
}

async function clearLogs(): Promise<void> {
  if (!confirm("Clear all in-memory logs? File logs will be preserved.")) return;
  try {
    await axios.delete("/api/logs");
    await loadLogs();
  } catch {
    error.value = "Failed to clear logs";
  }
}

function formatTimestamp(ts: string): string {
  const date = new Date(ts);
  if (isNaN(date.getTime())) return ts;
  return date.toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

function formatDate(ts: string): string {
  const date = new Date(ts);
  if (isNaN(date.getTime())) return "";
  return date.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
  });
}

function toggleAutoRefresh(): void {
  autoRefresh.value = !autoRefresh.value;
  if (autoRefresh.value) {
    startAutoRefresh();
  } else {
    stopAutoRefresh();
  }
}

function startAutoRefresh(): void {
  if (refreshInterval.value) return;
  refreshInterval.value = window.setInterval(loadLogs, 5000);
}

function stopAutoRefresh(): void {
  if (refreshInterval.value) {
    clearInterval(refreshInterval.value);
    refreshInterval.value = null;
  }
}

async function downloadLogsPDF(): Promise<void> {
  try {
    const response = await axios.post("/api/reports/logs/pdf", {
      level: levelFilter.value || null,
      limit: 500,
    }, { responseType: "blob" });
    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement("a");
    link.href = url;
    link.download = `Logs_${new Date().toISOString().slice(0, 10)}.pdf`;
    link.click();
    window.URL.revokeObjectURL(url);
  } catch {
    error.value = "Failed to download PDF report";
  }
}

const syslogMessages = ref<SyslogMessage[]>([]);
const syslogStatus = ref<SyslogStatus>({ running: false, message_count: 0, port: 1514 });
const syslogLoading = ref(false);
const syslogError = ref<string | null>(null);
const syslogTotal = ref(0);
const syslogPage = ref(0);
const syslogLimit = 50;
const syslogSeverityFilter = ref("");
const syslogSourceFilter = ref("");
const syslogSearchFilter = ref("");
const syslogToggling = ref(false);

const syslogSeverityColors: Record<string, { bg: string; text: string }> = {
  Emergency: { bg: "bg-rose-600/30", text: "text-rose-300" },
  Alert: { bg: "bg-rose-500/25", text: "text-rose-400" },
  Critical: { bg: "bg-red-500/25", text: "text-red-400" },
  Error: { bg: "bg-orange-500/25", text: "text-orange-400" },
  Warning: { bg: "bg-amber-500/20", text: "text-amber-400" },
  Notice: { bg: "bg-blue-500/20", text: "text-blue-400" },
  Info: { bg: "bg-sky-500/20", text: "text-sky-400" },
  Debug: { bg: "bg-slate-500/20", text: "text-slate-400" },
};

function getSeverityStyle(severity: string): { bg: string; text: string } {
  return syslogSeverityColors[severity] || { bg: "bg-slate-500/20", text: "text-slate-400" };
}

async function loadSyslogStatus(): Promise<void> {
  try {
    const res = await axios.get<SyslogStatus>("/api/syslog/status");
    syslogStatus.value = res.data;
  } catch {
    // silent
  }
}

async function loadSyslogMessages(): Promise<void> {
  syslogLoading.value = true;
  syslogError.value = null;
  try {
    const params: Record<string, string | number> = {
      offset: syslogPage.value * syslogLimit,
      limit: syslogLimit,
    };
    if (syslogSeverityFilter.value) params.severity = syslogSeverityFilter.value;
    if (syslogSourceFilter.value) params.source_ip = syslogSourceFilter.value;
    if (syslogSearchFilter.value) params.search = syslogSearchFilter.value;

    const [msgRes, statusRes] = await Promise.all([
      axios.get<{ messages: SyslogMessage[]; total: number }>("/api/syslog/messages", { params }),
      axios.get<SyslogStatus>("/api/syslog/status"),
    ]);
    syslogMessages.value = msgRes.data.messages;
    syslogTotal.value = msgRes.data.total;
    syslogStatus.value = statusRes.data;
  } catch {
    syslogError.value = "Failed to load syslog messages";
  } finally {
    syslogLoading.value = false;
  }
}

async function toggleSyslogListener(): Promise<void> {
  syslogToggling.value = true;
  syslogError.value = null;
  try {
    if (syslogStatus.value.running) {
      await axios.post("/api/syslog/stop");
    } else {
      await axios.post("/api/syslog/start");
    }
    await loadSyslogStatus();
  } catch {
    syslogError.value = "Failed to toggle syslog listener";
  } finally {
    syslogToggling.value = false;
  }
}

async function clearSyslogMessages(): Promise<void> {
  if (!confirm("Clear all syslog messages?")) return;
  try {
    await axios.delete("/api/syslog/messages");
    syslogPage.value = 0;
    await loadSyslogMessages();
  } catch {
    syslogError.value = "Failed to clear syslog messages";
  }
}

const syslogTotalPages = computed(() => Math.max(1, Math.ceil(syslogTotal.value / syslogLimit)));

function syslogPrevPage(): void {
  if (syslogPage.value > 0) {
    syslogPage.value--;
    loadSyslogMessages();
  }
}

function syslogNextPage(): void {
  if (syslogPage.value < syslogTotalPages.value - 1) {
    syslogPage.value++;
    loadSyslogMessages();
  }
}

function syslogApplyFilters(): void {
  syslogPage.value = 0;
  loadSyslogMessages();
}

watch(activeTab, (tab) => {
  if (tab === "syslog") {
    loadSyslogMessages();
  }
});

onMounted(() => {
  loadLogs();
  if (autoRefresh.value) {
    startAutoRefresh();
  }
});

onUnmounted(() => {
  stopAutoRefresh();
});
</script>

<template>
  <div class="space-y-4">
    <!-- Tab bar -->
    <div class="flex items-center gap-1 border-b" style="border-color: var(--np-border);">
      <button
        v-for="tab in ['application', 'syslog']"
        :key="tab"
        @click="activeTab = (tab as 'application' | 'syslog')"
        class="px-4 py-2.5 text-xs font-semibold tracking-wider uppercase border-b-2 -mb-px transition-colors"
        :class="activeTab === tab
          ? isNightshade ? 'border-blue-500 text-blue-400' : 'border-amber-500 text-amber-400'
          : 'border-transparent text-zinc-500 hover:text-zinc-200 hover:border-zinc-600'"
      >
        {{ tab === 'application' ? 'Application Logs' : 'Syslog Receiver' }}
      </button>
    </div>

    <!-- Application Logs tab -->
    <template v-if="activeTab === 'application'">
      <header class="flex flex-wrap items-center gap-3 justify-between">
        <div>
          <h1 class="text-sm font-semibold text-zinc-200">Log Viewer</h1>
          <p class="text-xs text-zinc-500">Real-time application logs and diagnostics</p>
        </div>
        <div class="flex flex-wrap items-center gap-2">
          <button
            @click="showSystemErrors = !showSystemErrors"
            class="np-cyber-btn"
            :class="showSystemErrors ? 'border-red-500/50 text-red-400' : ''"
          >
            {{ showSystemErrors ? 'Hide Errors' : 'Show Errors' }}
          </button>
          <button @click="downloadLogsPDF" class="np-cyber-btn">PDF</button>
          <button
            @click="toggleAutoRefresh"
            class="np-cyber-btn flex items-center gap-1.5"
            :class="autoRefresh ? 'border-emerald-500/50 text-emerald-400' : ''"
          >
            <span class="w-1.5 h-1.5 rounded-full" :class="autoRefresh ? 'bg-emerald-400 animate-pulse' : 'bg-zinc-600'"></span>
            {{ autoRefresh ? 'Live' : 'Paused' }}
          </button>
          <button @click="loadLogs" :disabled="loading" class="np-cyber-btn disabled:opacity-40">
            {{ loading ? '…' : 'Refresh' }}
          </button>
          <button @click="clearLogs" class="np-cyber-btn border-red-500/30 text-red-400 hover:border-red-400">Clear</button>
        </div>
      </header>

      <!-- Stat chips -->
      <div class="grid gap-2 sm:grid-cols-5">
        <div
          v-for="(count, level) in { debug: stats.debug, info: stats.info, warning: stats.warning, error: stats.error, critical: stats.critical }"
          :key="level"
          class="flex items-center justify-between rounded border px-3 py-2"
          :class="[(levelColors as any)[level].bg, (levelColors as any)[level].border]"
        >
          <span class="text-[0.65rem] font-semibold uppercase tracking-widest" :class="(levelColors as any)[level].text">{{ level }}</span>
          <span class="font-mono text-sm font-bold" :class="(levelColors as any)[level].text">{{ count }}</span>
        </div>
      </div>

      <!-- Filters -->
      <div class="flex flex-wrap items-center gap-2">
        <select
          v-model="levelFilter"
          @change="loadLogs"
          class="np-neon-input px-3 py-1.5 text-xs"
        >
          <option value="">Network Activity</option>
          <option value="all">All Levels</option>
          <option value="debug">Debug</option>
          <option value="info">Info</option>
          <option value="warning">Warning</option>
          <option value="error">Error</option>
          <option value="critical">Critical</option>
        </select>
        <div class="relative flex-1 min-w-[200px]">
          <svg class="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-zinc-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            v-model="searchQuery"
            type="text"
            placeholder="Search or regex (e.g. ERROR|WARN, ^user.*failed)…"
            class="np-neon-input w-full pl-8 pr-8 py-1.5 text-xs"
          />
          <button
            v-if="searchQuery"
            @click="searchQuery = ''"
            class="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300"
          >×</button>
        </div>
      </div>

      <div v-if="error" class="rounded border border-red-500/40 bg-red-500/5 px-4 py-3 text-xs text-red-400">
        {{ error }}
      </div>

      <!-- Virtualized log list -->
      <div class="rounded border overflow-hidden" style="border-color: var(--np-border); background: var(--np-surface);">
        <div v-if="filteredLogs.length === 0 && !loading" class="p-8 text-center text-sm text-zinc-600">
          No logs found
        </div>
        <div v-else-if="loading" class="space-y-1.5 p-2">
          <div v-for="i in 8" :key="i" class="np-skeleton h-9 rounded"></div>
        </div>
        <RecycleScroller
          v-else
          class="h-[calc(100vh-28rem)] min-h-[300px]"
          :items="filteredLogs"
          :item-size="56"
          key-field="timestamp"
          v-slot="{ item: log, index }"
        >
          <div
            class="flex items-start gap-3 px-4 py-2.5 border-b transition-colors hover:bg-white/[0.025]"
            style="border-color: var(--np-border-subtle);"
            :class="{ 'cursor-pointer': isErrorLevel(log.level) }"
            @click="isErrorLevel(log.level) ? toggleErrorExpand(index) : undefined"
          >
            <!-- Level badge -->
            <span
              class="mt-0.5 shrink-0 rounded px-1.5 py-0.5 text-[0.6rem] font-bold uppercase"
              :class="[(levelColors as any)[log.level]?.bg || levelColors.info.bg, (levelColors as any)[log.level]?.text || levelColors.info.text]"
            >{{ log.level }}</span>

            <div class="min-w-0 flex-1">
              <div class="flex items-baseline gap-2 text-[0.7rem]">
                <span class="font-mono text-zinc-400 shrink-0">{{ formatTimestamp(log.timestamp) }}</span>
                <span class="font-mono text-zinc-600 text-[0.6rem] shrink-0">{{ formatDate(log.timestamp) }}</span>
                <span class="font-mono text-zinc-600 truncate">{{ log.logger }}</span>
                <span v-if="isErrorLevel(log.level)" class="shrink-0 text-zinc-600">
                  {{ expandedErrorIds.has(index) ? '▼' : '▶' }}
                </span>
              </div>
              <p
                class="mt-0.5 font-mono text-xs text-zinc-300 leading-relaxed"
                :class="isErrorLevel(log.level) && !expandedErrorIds.has(index) ? 'truncate' : 'break-words'"
              >{{ log.message }}</p>
              <div
                v-if="expandedErrorIds.has(index) && (log.module || log.function)"
                class="mt-0.5 flex items-center gap-1.5 text-[0.6rem] text-zinc-600 font-mono"
              >
                <span v-if="log.module">{{ log.module }}</span>
                <span v-if="log.function">→ {{ log.function }}()</span>
                <span v-if="log.line">:{{ log.line }}</span>
              </div>
            </div>
          </div>
        </RecycleScroller>
      </div>

      <p class="text-center text-[0.65rem] text-zinc-600">
        Showing {{ filteredLogs.length }} of {{ stats.total }} log entries
      </p>
    </template>

    <!-- Syslog tab -->
    <template v-if="activeTab === 'syslog'">
      <header class="flex flex-wrap items-center gap-3 justify-between">
        <div>
          <h1 class="text-sm font-semibold text-zinc-200">Syslog Receiver</h1>
          <p class="text-xs text-zinc-500">UDP syslog listener — port {{ syslogStatus.port }}</p>
        </div>
        <div class="flex flex-wrap items-center gap-2">
          <!-- Status pip -->
          <div class="flex items-center gap-2 rounded border px-3 py-1.5 text-xs" style="border-color: var(--np-border);">
            <span class="w-1.5 h-1.5 rounded-full" :class="syslogStatus.running ? 'bg-emerald-400 animate-pulse' : 'bg-zinc-600'"></span>
            <span class="text-zinc-400">{{ syslogStatus.running ? 'Running' : 'Stopped' }}</span>
            <span class="font-mono text-zinc-300">{{ syslogStatus.message_count }} msgs</span>
          </div>
          <button
            @click="toggleSyslogListener"
            :disabled="syslogToggling"
            class="np-cyber-btn"
            :class="syslogStatus.running ? 'border-red-500/40 text-red-400' : 'border-emerald-500/40 text-emerald-400'"
          >
            {{ syslogToggling ? '…' : syslogStatus.running ? 'Stop' : 'Start' }}
          </button>
          <button @click="loadSyslogMessages" :disabled="syslogLoading" class="np-cyber-btn disabled:opacity-40">
            {{ syslogLoading ? '…' : 'Refresh' }}
          </button>
          <button @click="clearSyslogMessages" class="np-cyber-btn border-red-500/30 text-red-400 hover:border-red-400">Clear All</button>
        </div>
      </header>

      <!-- Syslog filters -->
      <div class="flex flex-wrap items-center gap-2">
        <select v-model="syslogSeverityFilter" @change="syslogApplyFilters" class="np-neon-input px-3 py-1.5 text-xs">
          <option value="">All Severities</option>
          <option v-for="s in ['Emergency','Alert','Critical','Error','Warning','Notice','Info','Debug']" :key="s" :value="s">{{ s }}</option>
        </select>
        <input
          v-model="syslogSourceFilter"
          @keyup.enter="syslogApplyFilters"
          type="text"
          placeholder="Source IP…"
          class="np-neon-input px-3 py-1.5 text-xs w-36"
        />
        <div class="relative flex-1 min-w-[160px]">
          <input
            v-model="syslogSearchFilter"
            @keyup.enter="syslogApplyFilters"
            type="text"
            placeholder="Search messages…"
            class="np-neon-input w-full px-3 pr-8 py-1.5 text-xs"
          />
          <button
            v-if="syslogSearchFilter"
            @click="syslogSearchFilter = ''; syslogApplyFilters()"
            class="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300"
          >×</button>
        </div>
      </div>

      <div v-if="syslogError" class="rounded border border-red-500/40 bg-red-500/5 px-4 py-3 text-xs text-red-400">
        {{ syslogError }}
      </div>

      <!-- Syslog table -->
      <div class="overflow-x-auto rounded border" style="border-color: var(--np-border); background: var(--np-surface);">
        <div v-if="syslogMessages.length === 0 && !syslogLoading" class="p-8 text-center text-sm text-zinc-600">
          No syslog messages found
        </div>
        <table v-else class="w-full text-left text-xs">
          <thead>
            <tr>
              <th class="px-4 py-2.5">Timestamp</th>
              <th class="px-4 py-2.5">Source IP</th>
              <th class="px-4 py-2.5">Severity</th>
              <th class="px-4 py-2.5">Hostname</th>
              <th class="px-4 py-2.5">Message</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(msg, idx) in syslogMessages" :key="idx" class="transition-colors hover:bg-white/[0.025]">
              <td class="whitespace-nowrap px-4 py-2 font-mono text-zinc-400">{{ msg.timestamp }}</td>
              <td class="whitespace-nowrap px-4 py-2 font-mono" style="color: var(--np-accent-secondary);">{{ msg.source_ip }}</td>
              <td class="whitespace-nowrap px-4 py-2">
                <span class="rounded px-1.5 py-0.5 text-[0.6rem] font-bold uppercase"
                  :class="[getSeverityStyle(msg.severity).bg, getSeverityStyle(msg.severity).text]">
                  {{ msg.severity }}
                </span>
              </td>
              <td class="whitespace-nowrap px-4 py-2 font-mono text-zinc-500">{{ msg.hostname }}</td>
              <td class="max-w-md truncate px-4 py-2 font-mono text-zinc-200" :title="msg.message">{{ msg.message }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="flex items-center justify-between">
        <p class="text-[0.65rem] text-zinc-600">Showing {{ syslogMessages.length }} of {{ syslogTotal }} messages</p>
        <div class="flex items-center gap-2">
          <button @click="syslogPrevPage" :disabled="syslogPage === 0" class="np-cyber-btn disabled:opacity-30 text-xs px-2 py-1">Prev</button>
          <span class="font-mono text-xs text-zinc-500">{{ syslogPage + 1 }} / {{ syslogTotalPages }}</span>
          <button @click="syslogNextPage" :disabled="syslogPage >= syslogTotalPages - 1" class="np-cyber-btn disabled:opacity-30 text-xs px-2 py-1">Next</button>
        </div>
      </div>
    </template>
  </div>
</template>

