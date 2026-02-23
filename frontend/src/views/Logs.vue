<script setup lang="ts">
import axios from "axios";
import { computed, onMounted, onUnmounted, ref, watch } from "vue";

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
  if (showSystemErrors.value) return logs.value;
  return logs.value.filter(
    (log) => log.level !== "error" && log.level !== "critical"
  );
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
  <div class="space-y-4 p-4">
    <div class="flex items-center gap-1 rounded-lg border p-1"
      :class="isNightshade ? 'border-teal-400/20 bg-black/30' : 'border-slate-700 bg-slate-900/50'"
    >
      <button
        @click="activeTab = 'application'"
        class="flex-1 rounded-md px-4 py-2 text-sm font-medium transition-colors"
        :class="activeTab === 'application'
          ? isNightshade
            ? 'bg-teal-500/20 text-teal-300 border border-teal-400/30'
            : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
          : isNightshade
            ? 'text-teal-100/50 hover:text-teal-100/80 hover:bg-white/5 border border-transparent'
            : 'text-slate-400 hover:text-slate-300 hover:bg-white/5 border border-transparent'
        "
      >
        Application Logs
      </button>
      <button
        @click="activeTab = 'syslog'"
        class="flex-1 rounded-md px-4 py-2 text-sm font-medium transition-colors"
        :class="activeTab === 'syslog'
          ? isNightshade
            ? 'bg-teal-500/20 text-teal-300 border border-teal-400/30'
            : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
          : isNightshade
            ? 'text-teal-100/50 hover:text-teal-100/80 hover:bg-white/5 border border-transparent'
            : 'text-slate-400 hover:text-slate-300 hover:bg-white/5 border border-transparent'
        "
      >
        Syslog Receiver
      </button>
    </div>

    <template v-if="activeTab === 'application'">
      <header class="flex items-center justify-between">
        <div>
          <h1
            class="text-xl font-semibold"
            :class="isNightshade ? 'text-teal-400' : 'text-amber-400'"
          >
            Log Viewer
          </h1>
          <p class="text-xs" :class="isNightshade ? 'text-teal-100/60' : 'text-slate-400'">
            Real-time application logs and diagnostics
          </p>
        </div>
        <div class="flex items-center gap-3">
          <button
            @click="showSystemErrors = !showSystemErrors"
            class="flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs transition-colors"
            :class="
              showSystemErrors
                ? isNightshade
                  ? 'border-rose-500/50 bg-rose-500/10 text-rose-400'
                  : 'border-rose-500/50 bg-rose-500/10 text-rose-500'
                : isNightshade
                ? 'border-teal-400/30 bg-black/30 text-teal-200/70'
                : 'border-slate-500/30 bg-slate-800/50 text-slate-400'
            "
          >
            {{ showSystemErrors ? 'Hide System Errors' : 'Show System Errors' }}
          </button>
          <button
            @click="downloadLogsPDF"
            class="rounded-md border px-3 py-1.5 text-xs transition-colors"
            :class="
              isNightshade
                ? 'border-teal-400/30 bg-black/30 text-teal-200 hover:bg-teal-500/10'
                : 'border-amber-500/30 bg-slate-800/50 text-slate-300 hover:bg-amber-500/10'
            "
            title="Download Logs PDF"
          >
            Download PDF
          </button>
          <button
            @click="toggleAutoRefresh"
            class="flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs transition-colors"
            :class="
              autoRefresh
                ? isNightshade
                  ? 'border-emerald-500/50 bg-emerald-500/10 text-emerald-400'
                  : 'border-green-500/50 bg-green-500/10 text-green-500'
                : isNightshade
                ? 'border-teal-400/30 bg-black/30 text-teal-200/70'
                : 'border-slate-500/30 bg-slate-800/50 text-slate-400'
            "
          >
            <span
              class="h-2 w-2 rounded-full"
              :class="autoRefresh ? (isNightshade ? 'bg-emerald-400 animate-pulse' : 'bg-green-500 animate-pulse') : 'bg-slate-500'"
            ></span>
            {{ autoRefresh ? "Live" : "Paused" }}
          </button>
          <button
            @click="loadLogs"
            :disabled="loading"
            class="rounded-md border px-3 py-1.5 text-xs transition-colors"
            :class="
              isNightshade
                ? 'border-teal-400/30 bg-black/30 text-teal-200 hover:bg-teal-500/10'
                : 'border-amber-500/30 bg-slate-800/50 text-slate-300 hover:bg-amber-500/10'
            "
          >
            {{ loading ? "Loading..." : "Refresh" }}
          </button>
          <button
            @click="clearLogs"
            class="rounded-md border px-3 py-1.5 text-xs transition-colors"
            :class="
              isNightshade
                ? 'border-rose-400/30 bg-black/30 text-rose-300 hover:bg-rose-500/10'
                : 'border-rose-500/30 bg-slate-800/50 text-rose-400 hover:bg-rose-500/10'
            "
          >
            Clear
          </button>
        </div>
      </header>

      <div class="grid gap-2 sm:grid-cols-5">
        <div
          v-for="(count, level) in { debug: stats.debug, info: stats.info, warning: stats.warning, error: stats.error, critical: stats.critical }"
          :key="level"
          class="flex items-center justify-between rounded-md border px-3 py-2"
          :class="[
            (levelColors as any)[level].bg,
            (levelColors as any)[level].border,
          ]"
        >
          <span
            class="text-xs font-medium uppercase"
            :class="(levelColors as any)[level].text"
          >
            {{ level }}
          </span>
          <span
            class="font-mono text-sm font-bold"
            :class="(levelColors as any)[level].text"
          >
            {{ count }}
          </span>
        </div>
      </div>

      <div class="flex items-center gap-3">
        <select
          v-model="levelFilter"
          @change="loadLogs"
          class="rounded-md border px-3 py-2 text-xs"
          :class="
            isNightshade
              ? 'border-teal-400/30 bg-black/50 text-teal-100'
              : 'border-slate-600 bg-slate-800 text-slate-200'
          "
        >
          <option value="">Network Activity</option>
          <option value="all">All Levels</option>
          <option value="debug">Debug</option>
          <option value="info">Info</option>
          <option value="warning">Warning</option>
          <option value="error">Error</option>
          <option value="critical">Critical</option>
        </select>
        <div class="relative flex-1">
          <input
            v-model="searchQuery"
            @keyup.enter="loadLogs"
            type="text"
            placeholder="Search logs..."
            class="w-full rounded-md border px-3 py-2 text-xs"
            :class="
              isNightshade
                ? 'border-teal-400/30 bg-black/50 text-teal-100 placeholder-teal-100/40'
                : 'border-slate-600 bg-slate-800 text-slate-200 placeholder-slate-500'
            "
          />
          <button
            v-if="searchQuery"
            @click="searchQuery = ''; loadLogs()"
            class="absolute right-2 top-1/2 -translate-y-1/2 text-xs"
            :class="isNightshade ? 'text-teal-400' : 'text-slate-400'"
          >
            ×
          </button>
        </div>
      </div>

      <div
        v-if="error"
        class="rounded-md border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-400"
      >
        {{ error }}
      </div>

      <div
        class="overflow-hidden rounded-lg border"
        :class="
          isNightshade
            ? 'border-teal-400/30 bg-black/40'
            : 'border-slate-700 bg-slate-900/50'
        "
      >
        <div
          v-if="filteredLogs.length === 0 && !loading"
          class="p-8 text-center text-sm"
          :class="isNightshade ? 'text-teal-100/50' : 'text-slate-500'"
        >
          No logs found
        </div>

        <div v-else class="divide-y" :class="isNightshade ? 'divide-teal-400/10' : 'divide-slate-700/50'">
          <div
            v-for="(log, index) in filteredLogs"
            :key="index"
            class="px-4 py-2 transition-colors hover:bg-white/5"
            :class="{ 'cursor-pointer': isErrorLevel(log.level) }"
            @click="isErrorLevel(log.level) ? toggleErrorExpand(index) : undefined"
          >
            <template v-if="isErrorLevel(log.level) && !expandedErrorIds.has(index)">
              <div class="flex items-center gap-3">
                <span
                  class="shrink-0 rounded px-1.5 py-0.5 text-[0.65rem] font-bold uppercase"
                  :class="[
                    (levelColors as any)[log.level]?.bg || levelColors.info.bg,
                    (levelColors as any)[log.level]?.text || levelColors.info.text,
                  ]"
                >
                  {{ log.level }}
                </span>
                <span class="font-mono text-xs" :class="isNightshade ? 'text-teal-300' : 'text-slate-300'">
                  {{ formatTimestamp(log.timestamp) }}
                </span>
                <span
                  class="min-w-0 flex-1 truncate font-mono text-xs"
                  :class="isNightshade ? 'text-teal-100/60' : 'text-slate-400'"
                >
                  {{ truncateMessage(log.message) }}
                </span>
                <span class="shrink-0 text-[0.6rem]" :class="isNightshade ? 'text-teal-100/30' : 'text-slate-500'">▶</span>
              </div>
            </template>

            <template v-else>
              <div class="flex items-start gap-3">
                <span
                  class="mt-0.5 shrink-0 rounded px-1.5 py-0.5 text-[0.65rem] font-bold uppercase"
                  :class="[
                    (levelColors as any)[log.level]?.bg || levelColors.info.bg,
                    (levelColors as any)[log.level]?.text || levelColors.info.text,
                  ]"
                >
                  {{ log.level }}
                </span>
                <div class="min-w-0 flex-1">
                  <div class="flex items-baseline gap-2 text-xs">
                    <span class="font-mono" :class="isNightshade ? 'text-teal-300' : 'text-slate-300'">
                      {{ formatTimestamp(log.timestamp) }}
                    </span>
                    <span class="text-[0.65rem]" :class="isNightshade ? 'text-teal-100/40' : 'text-slate-500'">
                      {{ formatDate(log.timestamp) }}
                    </span>
                    <span
                      class="truncate text-[0.65rem] font-mono"
                      :class="isNightshade ? 'text-purple-400/70' : 'text-amber-400/70'"
                    >
                      {{ log.logger }}
                    </span>
                    <span
                      v-if="isErrorLevel(log.level)"
                      class="shrink-0 text-[0.6rem]"
                      :class="isNightshade ? 'text-teal-100/30' : 'text-slate-500'"
                    >▼</span>
                  </div>
                  <p
                    class="mt-1 break-words font-mono text-xs leading-relaxed"
                    :class="isNightshade ? 'text-teal-100/90' : 'text-slate-200'"
                  >
                    {{ log.message }}
                  </p>
                  <div
                    v-if="log.module || log.function"
                    class="mt-1 flex items-center gap-2 text-[0.65rem]"
                    :class="isNightshade ? 'text-teal-100/40' : 'text-slate-500'"
                  >
                    <span v-if="log.module">{{ log.module }}</span>
                    <span v-if="log.function">→ {{ log.function }}()</span>
                    <span v-if="log.line">:{{ log.line }}</span>
                  </div>
                </div>
              </div>
            </template>
          </div>
        </div>
      </div>

      <p
        class="text-center text-xs"
        :class="isNightshade ? 'text-teal-100/40' : 'text-slate-500'"
      >
        Showing {{ filteredLogs.length }} of {{ stats.total }} logs
      </p>
    </template>

    <template v-if="activeTab === 'syslog'">
      <header class="flex items-center justify-between">
        <div>
          <h1
            class="text-xl font-semibold"
            :class="isNightshade ? 'text-teal-400' : 'text-amber-400'"
          >
            Syslog Receiver
          </h1>
          <p class="text-xs" :class="isNightshade ? 'text-teal-100/60' : 'text-slate-400'">
            UDP syslog listener on port {{ syslogStatus.port }}
          </p>
        </div>
        <div class="flex items-center gap-3">
          <div class="flex items-center gap-2 rounded-md border px-3 py-1.5 text-xs"
            :class="isNightshade ? 'border-teal-400/20 bg-black/30' : 'border-slate-700 bg-slate-900/50'"
          >
            <span class="h-2 w-2 rounded-full"
              :class="syslogStatus.running ? (isNightshade ? 'bg-emerald-400 animate-pulse' : 'bg-green-500 animate-pulse') : 'bg-slate-500'"
            ></span>
            <span :class="isNightshade ? 'text-teal-100/70' : 'text-slate-400'">
              {{ syslogStatus.running ? 'Running' : 'Stopped' }}
            </span>
            <span class="font-mono" :class="isNightshade ? 'text-teal-300' : 'text-slate-300'">
              {{ syslogStatus.message_count }} msgs
            </span>
          </div>
          <button
            @click="toggleSyslogListener"
            :disabled="syslogToggling"
            class="rounded-md border px-3 py-1.5 text-xs font-medium transition-colors"
            :class="syslogStatus.running
              ? isNightshade
                ? 'border-rose-400/30 bg-rose-500/10 text-rose-300 hover:bg-rose-500/20'
                : 'border-rose-500/30 bg-rose-500/10 text-rose-400 hover:bg-rose-500/20'
              : isNightshade
                ? 'border-emerald-400/30 bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20'
                : 'border-green-500/30 bg-green-500/10 text-green-400 hover:bg-green-500/20'
            "
          >
            {{ syslogToggling ? '...' : syslogStatus.running ? 'Stop Listener' : 'Start Listener' }}
          </button>
          <button
            @click="loadSyslogMessages"
            :disabled="syslogLoading"
            class="rounded-md border px-3 py-1.5 text-xs transition-colors"
            :class="
              isNightshade
                ? 'border-teal-400/30 bg-black/30 text-teal-200 hover:bg-teal-500/10'
                : 'border-amber-500/30 bg-slate-800/50 text-slate-300 hover:bg-amber-500/10'
            "
          >
            {{ syslogLoading ? "Loading..." : "Refresh" }}
          </button>
          <button
            @click="clearSyslogMessages"
            class="rounded-md border px-3 py-1.5 text-xs transition-colors"
            :class="
              isNightshade
                ? 'border-rose-400/30 bg-black/30 text-rose-300 hover:bg-rose-500/10'
                : 'border-rose-500/30 bg-slate-800/50 text-rose-400 hover:bg-rose-500/10'
            "
          >
            Clear All
          </button>
        </div>
      </header>

      <div class="flex items-center gap-3">
        <select
          v-model="syslogSeverityFilter"
          @change="syslogApplyFilters"
          class="rounded-md border px-3 py-2 text-xs"
          :class="
            isNightshade
              ? 'border-teal-400/30 bg-black/50 text-teal-100'
              : 'border-slate-600 bg-slate-800 text-slate-200'
          "
        >
          <option value="">All Severities</option>
          <option value="Emergency">Emergency</option>
          <option value="Alert">Alert</option>
          <option value="Critical">Critical</option>
          <option value="Error">Error</option>
          <option value="Warning">Warning</option>
          <option value="Notice">Notice</option>
          <option value="Info">Info</option>
          <option value="Debug">Debug</option>
        </select>
        <input
          v-model="syslogSourceFilter"
          @keyup.enter="syslogApplyFilters"
          type="text"
          placeholder="Source IP..."
          class="rounded-md border px-3 py-2 text-xs w-40"
          :class="
            isNightshade
              ? 'border-teal-400/30 bg-black/50 text-teal-100 placeholder-teal-100/40'
              : 'border-slate-600 bg-slate-800 text-slate-200 placeholder-slate-500'
          "
        />
        <div class="relative flex-1">
          <input
            v-model="syslogSearchFilter"
            @keyup.enter="syslogApplyFilters"
            type="text"
            placeholder="Search messages..."
            class="w-full rounded-md border px-3 py-2 text-xs"
            :class="
              isNightshade
                ? 'border-teal-400/30 bg-black/50 text-teal-100 placeholder-teal-100/40'
                : 'border-slate-600 bg-slate-800 text-slate-200 placeholder-slate-500'
            "
          />
          <button
            v-if="syslogSearchFilter"
            @click="syslogSearchFilter = ''; syslogApplyFilters()"
            class="absolute right-2 top-1/2 -translate-y-1/2 text-xs"
            :class="isNightshade ? 'text-teal-400' : 'text-slate-400'"
          >
            ×
          </button>
        </div>
      </div>

      <div
        v-if="syslogError"
        class="rounded-md border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-400"
      >
        {{ syslogError }}
      </div>

      <div
        class="overflow-hidden rounded-lg border"
        :class="
          isNightshade
            ? 'border-teal-400/30 bg-black/40'
            : 'border-slate-700 bg-slate-900/50'
        "
      >
        <div
          v-if="syslogMessages.length === 0 && !syslogLoading"
          class="p-8 text-center text-sm"
          :class="isNightshade ? 'text-teal-100/50' : 'text-slate-500'"
        >
          No syslog messages found
        </div>

        <table v-else class="w-full text-left text-xs">
          <thead>
            <tr class="border-b" :class="isNightshade ? 'border-teal-400/20' : 'border-slate-700'">
              <th class="px-4 py-2.5 font-medium" :class="isNightshade ? 'text-teal-300/80' : 'text-slate-400'">Timestamp</th>
              <th class="px-4 py-2.5 font-medium" :class="isNightshade ? 'text-teal-300/80' : 'text-slate-400'">Source IP</th>
              <th class="px-4 py-2.5 font-medium" :class="isNightshade ? 'text-teal-300/80' : 'text-slate-400'">Severity</th>
              <th class="px-4 py-2.5 font-medium" :class="isNightshade ? 'text-teal-300/80' : 'text-slate-400'">Hostname</th>
              <th class="px-4 py-2.5 font-medium" :class="isNightshade ? 'text-teal-300/80' : 'text-slate-400'">Message</th>
            </tr>
          </thead>
          <tbody class="divide-y" :class="isNightshade ? 'divide-teal-400/10' : 'divide-slate-700/50'">
            <tr
              v-for="(msg, idx) in syslogMessages"
              :key="idx"
              class="transition-colors hover:bg-white/5"
            >
              <td class="whitespace-nowrap px-4 py-2 font-mono" :class="isNightshade ? 'text-teal-300' : 'text-slate-300'">
                {{ msg.timestamp }}
              </td>
              <td class="whitespace-nowrap px-4 py-2 font-mono" :class="isNightshade ? 'text-purple-400/80' : 'text-amber-400/80'">
                {{ msg.source_ip }}
              </td>
              <td class="whitespace-nowrap px-4 py-2">
                <span
                  class="rounded px-1.5 py-0.5 text-[0.65rem] font-bold uppercase"
                  :class="[getSeverityStyle(msg.severity).bg, getSeverityStyle(msg.severity).text]"
                >
                  {{ msg.severity }}
                </span>
              </td>
              <td class="whitespace-nowrap px-4 py-2 font-mono" :class="isNightshade ? 'text-teal-100/70' : 'text-slate-400'">
                {{ msg.hostname }}
              </td>
              <td class="max-w-md truncate px-4 py-2 font-mono" :class="isNightshade ? 'text-teal-100/90' : 'text-slate-200'" :title="msg.message">
                {{ msg.message }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="flex items-center justify-between">
        <p class="text-xs" :class="isNightshade ? 'text-teal-100/40' : 'text-slate-500'">
          Showing {{ syslogMessages.length }} of {{ syslogTotal }} messages
        </p>
        <div class="flex items-center gap-2">
          <button
            @click="syslogPrevPage"
            :disabled="syslogPage === 0"
            class="rounded-md border px-3 py-1 text-xs transition-colors disabled:opacity-30"
            :class="
              isNightshade
                ? 'border-teal-400/30 bg-black/30 text-teal-200 hover:bg-teal-500/10'
                : 'border-slate-600 bg-slate-800 text-slate-300 hover:bg-slate-700'
            "
          >
            Prev
          </button>
          <span class="text-xs font-mono" :class="isNightshade ? 'text-teal-100/60' : 'text-slate-400'">
            {{ syslogPage + 1 }} / {{ syslogTotalPages }}
          </span>
          <button
            @click="syslogNextPage"
            :disabled="syslogPage >= syslogTotalPages - 1"
            class="rounded-md border px-3 py-1 text-xs transition-colors disabled:opacity-30"
            :class="
              isNightshade
                ? 'border-teal-400/30 bg-black/30 text-teal-200 hover:bg-teal-500/10'
                : 'border-slate-600 bg-slate-800 text-slate-300 hover:bg-slate-700'
            "
          >
            Next
          </button>
        </div>
      </div>
    </template>
  </div>
</template>
