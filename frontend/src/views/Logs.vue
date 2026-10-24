<script setup lang="ts">
import axios from "axios";
import { computed, onMounted, onUnmounted, ref, shallowRef, watch } from "vue";
import { Download, Pause, Play, RefreshCw, Search, Trash2 } from "lucide-vue-next";

type Theme = "nightshade" | "sysadmin";

interface Props {
  theme: Theme;
}

defineProps<Props>();

interface LogEntry {
  /** Server-side monotonic id: row key and incremental cursor. */
  seq: number;
  timestamp: string;
  level: string;
  logger: string;
  message: string;
  module: string | null;
  function: string | null;
  line: number | null;
  extra: Record<string, unknown>;
  /** Client-only: marks a row that arrived on the last refresh. */
  isNew?: boolean;
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

/** Rows kept in the viewer; the API's in-memory buffer holds a thousand. */
const PAGE_LIMIT = 200;
/** How long a freshly-arrived row stays highlighted. */
const NEW_ROW_MS = 2400;
/** Poll cadence for the append refresh. */
const REFRESH_MS = 4000;

const logs = ref<LogEntry[]>([]);
const stats = ref<LogStats>({
  total: 0,
  debug: 0,
  info: 0,
  warning: 0,
  error: 0,
  critical: 0,
});
const initialLoading = ref(true);
const error = ref<string | null>(null);

const showSystemErrors = ref(false);
const expandedRows = ref<Set<number>>(new Set());

/** Highest seq already displayed — everything above it is new. */
const cursor = ref(0);
let newRowTimer: number | null = null;

const levelFilter = ref<string>("all");
const searchQuery = ref<string>("");
const autoRefresh = ref(true);
const refreshInterval = ref<number | null>(null);

function levelClass(level: string): string {
  const known = ["debug", "info", "warning", "error", "critical"];
  return `np-level-${known.includes(level) ? level : "info"}`;
}

function isErrorLevel(level: string): boolean {
  return level === "error" || level === "critical";
}

/**
 * Put fetched entries into the list.
 *
 * `replace` is for a filter change or a manual reload. `append` is the polling
 * path: entries the viewer already shows keep their object identity, so Vue
 * patches nothing and only the new rows mount — that is what removes the
 * full-list flash every four seconds.
 */
function ingest(incoming: LogEntry[], mode: "replace" | "append"): void {
  if (mode === "replace") {
    logs.value = incoming.map((entry) => ({ ...entry, isNew: false }));
    cursor.value = incoming.reduce((max, entry) => Math.max(max, entry.seq), 0);
    return;
  }

  const known = new Set(logs.value.map((entry) => entry.seq));
  const fresh = incoming
    .filter((entry) => !known.has(entry.seq))
    .map((entry) => ({ ...entry, isNew: true }));
  if (fresh.length === 0) return;

  logs.value = [...fresh, ...logs.value].slice(0, PAGE_LIMIT);
  cursor.value = Math.max(cursor.value, ...fresh.map((entry) => entry.seq));

  // Highlight is a one-shot: clear it after the row has had its moment.
  if (newRowTimer !== null) window.clearTimeout(newRowTimer);
  newRowTimer = window.setTimeout(() => {
    for (const entry of logs.value) {
      if (entry.isNew) entry.isNew = false;
    }
    newRowTimer = null;
  }, NEW_ROW_MS);
}

async function loadLogs(options: { incremental?: boolean } = {}): Promise<void> {
  // A first load has nothing to append to, so it always fetches the page.
  const incremental =
    options.incremental === true && logs.value.length > 0 && cursor.value > 0;

  if (!incremental) initialLoading.value = logs.value.length === 0;
  error.value = null;

  try {
    const params: Record<string, string | number> = { limit: PAGE_LIMIT };
    if (levelFilter.value !== "all") params.level = levelFilter.value;
    if (incremental) params.since_seq = cursor.value;

    const [logsResponse, statsResponse] = await Promise.all([
      axios.get<{ logs: LogEntry[] }>("/api/logs", { params }),
      axios.get<LogStats>("/api/logs/stats"),
    ]);

    ingest(logsResponse.data.logs, incremental ? "append" : "replace");
    stats.value = statsResponse.data;
  } catch {
    error.value = "Failed to load logs";
  } finally {
    initialLoading.value = false;
  }
}

async function clearLogs(): Promise<void> {
  if (!confirm("Clear the in-memory log buffer? Log files on disk are kept.")) return;
  try {
    await axios.delete("/api/logs");
    cursor.value = 0;
    logs.value = [];
    await loadLogs();
  } catch {
    error.value = "Failed to clear logs";
  }
}

function toggleRow(seq: number): void {
  const next = new Set(expandedRows.value);
  if (next.has(seq)) next.delete(seq);
  else next.add(seq);
  expandedRows.value = next;
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

const filteredLogs = computed(() => {
  let list = logs.value;
  if (!showSystemErrors.value) {
    list = list.filter((log) => !isErrorLevel(log.level));
  }
  const raw = searchQuery.value.trim();
  if (!raw) return list;

  // Try regex, fall back to plain substring.
  let pattern: RegExp | null = null;
  try {
    pattern = new RegExp(raw, "i");
  } catch {
    // invalid regex — substring match instead
  }
  return list.filter((log) => {
    const haystack = `${log.message} ${log.logger} ${log.module ?? ""} ${log.function ?? ""}`;
    return pattern ? pattern.test(haystack) : haystack.toLowerCase().includes(raw.toLowerCase());
  });
});

const levelSummary = computed(() => [
  { key: "debug", label: "debug", count: stats.value.debug },
  { key: "info", label: "info", count: stats.value.info },
  { key: "warning", label: "warn", count: stats.value.warning },
  { key: "error", label: "error", count: stats.value.error },
  { key: "critical", label: "crit", count: stats.value.critical },
]);

function toggleAutoRefresh(): void {
  autoRefresh.value = !autoRefresh.value;
  if (autoRefresh.value) startAutoRefresh();
  else stopAutoRefresh();
}

function startAutoRefresh(): void {
  if (refreshInterval.value) return;
  refreshInterval.value = window.setInterval(
    () => void loadLogs({ incremental: true }),
    REFRESH_MS
  );
}

function stopAutoRefresh(): void {
  if (refreshInterval.value) {
    clearInterval(refreshInterval.value);
    refreshInterval.value = null;
  }
}

async function downloadLogsPDF(): Promise<void> {
  try {
    const response = await axios.post(
      "/api/reports/logs/pdf",
      { level: levelFilter.value || null, limit: 500 },
      { responseType: "blob" }
    );
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

// A filter change is a different query, so the cursor starts over.
watch(levelFilter, () => {
  cursor.value = 0;
  void loadLogs();
});

// ---------------------------------------------------------------------------
// Syslog tab
// ---------------------------------------------------------------------------
const syslogMessages = shallowRef<SyslogMessage[]>([]);
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

function getSeverityClass(severity: string): string {
  const s = severity.toLowerCase();
  if (s === "emergency" || s === "alert" || s === "critical") return "np-level-critical";
  if (s === "error") return "np-level-error";
  if (s === "warning") return "np-level-warning";
  if (s === "debug") return "np-level-debug";
  return "np-level-info";
}

async function loadSyslogStatus(): Promise<void> {
  try {
    const res = await axios.get<SyslogStatus>("/api/syslog/status");
    syslogStatus.value = res.data;
  } catch {
    // silent: the status pip just stays as it was
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
    void loadSyslogMessages();
  }
}

function syslogNextPage(): void {
  if (syslogPage.value < syslogTotalPages.value - 1) {
    syslogPage.value++;
    void loadSyslogMessages();
  }
}

function syslogApplyFilters(): void {
  syslogPage.value = 0;
  void loadSyslogMessages();
}

watch(activeTab, (tab) => {
  if (tab === "syslog") void loadSyslogMessages();
});

onMounted(() => {
  void loadLogs();
  if (autoRefresh.value) startAutoRefresh();
});

onUnmounted(() => {
  stopAutoRefresh();
  if (newRowTimer !== null) window.clearTimeout(newRowTimer);
});
</script>

<template>
  <div class="np-fade-in space-y-4">
    <!-- Same tab chrome as Settings: one tabs idiom across the app. -->
    <div class="flex flex-wrap gap-1 border-b border-[var(--np-border-subtle)] pb-0">
      <button
        v-for="tab in [
          { key: 'application', label: 'Application' },
          { key: 'syslog', label: 'Syslog' },
        ]"
        :key="tab.key"
        type="button"
        class="np-subtab-btn -mb-px flex items-center gap-1.5 border-b-2 px-3 py-2.5 text-xs transition-all duration-300"
        :class="{ active: activeTab === tab.key }"
        @click="activeTab = tab.key as 'application' | 'syslog'"
      >
        {{ tab.label }}
      </button>
    </div>

    <!-- Application logs -->
    <section v-if="activeTab === 'application'" class="np-panel p-4">
      <header class="np-panel-header -mx-4 -mt-4 mb-3 px-4">
        <div class="flex flex-col">
          <span class="np-panel-title">Logs</span>
          <span class="text-[0.7rem] text-[var(--np-text-dim)]/50">
            Live application output — new lines are appended, not redrawn.
          </span>
        </div>
        <div class="flex items-center gap-2">
          <button
            type="button"
            class="np-cyber-btn flex items-center gap-1.5"
            :class="autoRefresh ? 'np-brand-border np-brand-text' : ''"
            :title="autoRefresh ? 'Pause the live refresh' : 'Resume the live refresh'"
            @click="toggleAutoRefresh"
          >
            <Pause v-if="autoRefresh" class="h-3.5 w-3.5" :stroke-width="1.7" />
            <Play v-else class="h-3.5 w-3.5" :stroke-width="1.7" />
            {{ autoRefresh ? 'Live' : 'Paused' }}
          </button>
          <button
            type="button"
            class="np-cyber-btn flex items-center gap-1"
            title="Download the log report as PDF"
            @click="downloadLogsPDF"
          >
            <Download class="h-3.5 w-3.5" :stroke-width="1.7" />
            PDF
          </button>
          <button
            type="button"
            class="np-cyber-btn flex items-center gap-1 disabled:opacity-40"
            title="Reload from the server"
            @click="loadLogs()"
          >
            <RefreshCw class="h-3.5 w-3.5" :stroke-width="1.7" />
            Refresh
          </button>
          <button
            type="button"
            class="np-cyber-btn np-level-error flex items-center gap-1"
            title="Clear the in-memory buffer"
            @click="clearLogs"
          >
            <Trash2 class="h-3.5 w-3.5" :stroke-width="1.7" />
            Clear
          </button>
        </div>
      </header>

      <!-- Level summary: a single quiet line instead of five coloured cards. -->
      <div class="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[0.65rem]">
        <span
          v-for="item in levelSummary"
          :key="item.key"
          class="flex items-center gap-1.5"
          :class="levelClass(item.key)"
        >
          <span class="h-1.5 w-1.5 rounded-full bg-current"></span>
          <span class="uppercase tracking-wider opacity-70">{{ item.label }}</span>
          <span class="font-bold tabular-nums">{{ item.count }}</span>
        </span>
        <button
          type="button"
          class="ml-auto text-[0.65rem] font-semibold uppercase tracking-wider transition-colors"
          :class="
            showSystemErrors
              ? 'text-[var(--np-danger)]'
              : 'text-[var(--np-text-dim)] hover:text-[var(--np-text)]'
          "
          @click="showSystemErrors = !showSystemErrors"
        >
          {{ showSystemErrors ? "Hiding nothing" : "Errors hidden" }}
        </button>
      </div>

      <!-- Filters -->
      <div class="mt-3 flex flex-wrap items-center gap-2">
        <select v-model="levelFilter" class="np-neon-input px-3 py-1.5 text-xs">
          <option value="all">All levels</option>
          <option value="debug">Debug</option>
          <option value="info">Info</option>
          <option value="warning">Warning</option>
          <option value="error">Error</option>
          <option value="critical">Critical</option>
        </select>
        <div class="relative min-w-[200px] flex-1">
          <Search
            class="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2"
            style="color: var(--np-text-dim)"
            :stroke-width="1.7"
          />
          <input
            v-model="searchQuery"
            type="text"
            placeholder="Filter loaded lines, or a regex (ERROR|WARN)…"
            class="np-neon-input w-full py-1.5 pl-8 pr-8 text-xs"
          />
          <button
            v-if="searchQuery"
            type="button"
            class="absolute right-2 top-1/2 -translate-y-1/2 text-[var(--np-text-dim)]"
            aria-label="Clear search"
            @click="searchQuery = ''"
          >
            ×
          </button>
        </div>
      </div>

      <div v-if="error" class="np-level-error mt-3 rounded px-4 py-3 text-xs">
        {{ error }}
      </div>

      <!-- Rows: keyed by server seq, so an appended line mounts one node. -->
      <div
        class="mt-3 max-h-[calc(100vh-26rem)] min-h-[16rem] overflow-y-auto rounded border"
        style="border-color: var(--np-border-subtle); background: var(--np-surface)"
      >
        <div v-if="initialLoading" class="space-y-1.5 p-2">
          <div v-for="i in 8" :key="i" class="np-skeleton h-9 rounded"></div>
        </div>
        <p
          v-else-if="filteredLogs.length === 0"
          class="p-10 text-center text-xs"
          style="color: var(--np-text-dim)"
        >
          No log lines match this filter.
        </p>
        <div
          v-for="log in filteredLogs"
          v-else
          :key="log.seq"
          class="np-log-row flex items-start gap-3 border-b px-3 py-2 transition-colors hover:bg-[var(--np-surface-hover)]"
          :class="{ 'np-log-row--new': log.isNew, 'cursor-pointer': isErrorLevel(log.level) }"
          style="border-color: var(--np-border-subtle)"
          @click="isErrorLevel(log.level) ? toggleRow(log.seq) : undefined"
        >
          <span
            class="mt-0.5 shrink-0 font-mono text-[0.7rem] tabular-nums"
            style="color: var(--np-text-muted)"
            >{{ formatTimestamp(log.timestamp) }}</span
          >
          <span
            class="mt-0.5 w-14 shrink-0 rounded px-1.5 py-0.5 text-center text-[0.6rem] font-bold uppercase"
            :class="levelClass(log.level)"
            >{{ log.level }}</span
          >
          <div class="min-w-0 flex-1">
            <div class="flex items-baseline gap-2">
              <span
                class="truncate font-mono text-[0.65rem]"
                style="color: var(--np-text-dim)"
                >{{ log.logger }}</span
              >
              <span
                v-if="isErrorLevel(log.level)"
                class="shrink-0 font-mono text-[0.6rem]"
                style="color: var(--np-text-dim)"
              >
                {{ expandedRows.has(log.seq) ? "collapse" : "details" }}
              </span>
            </div>
            <p
              class="font-mono text-xs leading-relaxed"
              style="color: var(--np-text)"
              :class="
                isErrorLevel(log.level) && !expandedRows.has(log.seq)
                  ? 'line-clamp-2'
                  : 'break-words'
              "
            >
              {{ log.message }}
            </p>
            <p
              v-if="expandedRows.has(log.seq) && (log.module || log.function)"
              class="mt-0.5 font-mono text-[0.6rem]"
              style="color: var(--np-text-dim)"
            >
              <span v-if="log.module">{{ log.module }}</span>
              <span v-if="log.function"> :: {{ log.function }}()</span>
              <span v-if="log.line">:{{ log.line }}</span>
            </p>
          </div>
        </div>
      </div>

      <p class="mt-2 text-[0.65rem]" style="color: var(--np-text-dim)">
        Showing {{ filteredLogs.length }} of {{ stats.total }} buffered entries ·
        {{ autoRefresh ? `live every ${REFRESH_MS / 1000}s` : "refresh paused" }}
      </p>
    </section>

    <!-- Syslog -->
    <section v-else class="np-panel p-4">
      <header class="np-panel-header -mx-4 -mt-4 mb-3 px-4">
        <div class="flex flex-col">
          <span class="np-panel-title">Syslog</span>
          <span class="text-[0.7rem] text-[var(--np-text-dim)]/50">
            UDP listener on port {{ syslogStatus.port }} — what the network appliances send.
          </span>
        </div>
        <div class="flex items-center gap-2">
          <span
            class="flex items-center gap-2 rounded border px-2.5 py-1.5 text-[0.65rem]"
            style="border-color: var(--np-border-subtle)"
          >
            <span
              class="h-1.5 w-1.5 rounded-full"
              :class="syslogStatus.running ? 'animate-pulse' : ''"
              :style="{
                background: syslogStatus.running
                  ? 'var(--np-accent)'
                  : 'var(--np-text-dim)',
              }"
            ></span>
            <span style="color: var(--np-text-muted)">{{
              syslogStatus.running ? "Listening" : "Stopped"
            }}</span>
            <span class="font-mono" style="color: var(--np-text)">{{
              syslogStatus.message_count
            }}</span>
          </span>
          <button
            type="button"
            class="np-cyber-btn disabled:opacity-40"
            :class="syslogStatus.running ? 'np-level-error' : 'np-brand-border np-brand-text'"
            :disabled="syslogToggling"
            @click="toggleSyslogListener"
          >
            {{ syslogToggling ? "…" : syslogStatus.running ? "Stop" : "Start" }}
          </button>
          <button
            type="button"
            class="np-cyber-btn disabled:opacity-40"
            @click="loadSyslogMessages"
          >
            Refresh
          </button>
          <button type="button" class="np-cyber-btn np-level-error" @click="clearSyslogMessages">
            Clear
          </button>
        </div>
      </header>

      <div class="flex flex-wrap items-center gap-2">
        <select
          v-model="syslogSeverityFilter"
          class="np-neon-input px-3 py-1.5 text-xs"
          @change="syslogApplyFilters"
        >
          <option value="">All severities</option>
          <option
            v-for="s in ['Emergency', 'Alert', 'Critical', 'Error', 'Warning', 'Notice', 'Info', 'Debug']"
            :key="s"
            :value="s"
          >
            {{ s }}
          </option>
        </select>
        <input
          v-model="syslogSourceFilter"
          type="text"
          placeholder="Source IP…"
          class="np-neon-input w-36 px-3 py-1.5 font-mono text-xs"
          @keyup.enter="syslogApplyFilters"
        />
        <div class="relative min-w-[160px] flex-1">
          <input
            v-model="syslogSearchFilter"
            type="text"
            placeholder="Search messages…"
            class="np-neon-input w-full px-3 py-1.5 pr-8 text-xs"
            @keyup.enter="syslogApplyFilters"
          />
          <button
            v-if="syslogSearchFilter"
            type="button"
            class="absolute right-2 top-1/2 -translate-y-1/2 text-[var(--np-text-dim)]"
            aria-label="Clear search"
            @click="
              syslogSearchFilter = '';
              syslogApplyFilters();
            "
          >
            ×
          </button>
        </div>
      </div>

      <div v-if="syslogError" class="np-level-error mt-3 rounded px-4 py-3 text-xs">
        {{ syslogError }}
      </div>

      <div
        class="mt-3 overflow-x-auto rounded border"
        style="border-color: var(--np-border-subtle); background: var(--np-surface)"
      >
        <p
          v-if="syslogMessages.length === 0 && !syslogLoading"
          class="p-10 text-center text-xs"
          style="color: var(--np-text-dim)"
        >
          Nothing received yet. Point an appliance's syslog output at this host.
        </p>
        <table v-else class="w-full text-left text-xs tabular-nums">
          <thead>
            <tr class="border-b" style="border-color: var(--np-border-subtle)">
              <th
                v-for="head in ['Received', 'Source', 'Severity', 'Host', 'Message']"
                :key="head"
                class="px-3 py-2 text-[0.6rem] font-semibold uppercase tracking-wider"
                style="color: var(--np-text-dim)"
              >
                {{ head }}
              </th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="(msg, idx) in syslogMessages"
              :key="idx"
              class="border-b transition-colors last:border-0 hover:bg-[var(--np-surface-hover)]"
              style="border-color: var(--np-border-subtle)"
            >
              <td class="whitespace-nowrap px-3 py-1.5 font-mono" style="color: var(--np-text-muted)">
                {{ msg.timestamp }}
              </td>
              <td
                class="whitespace-nowrap px-3 py-1.5 font-mono"
                style="color: var(--np-accent-secondary)"
              >
                {{ msg.source_ip }}
              </td>
              <td class="whitespace-nowrap px-3 py-1.5">
                <span
                  class="rounded px-1.5 py-0.5 text-[0.6rem] font-bold uppercase"
                  :class="getSeverityClass(msg.severity)"
                >
                  {{ msg.severity }}
                </span>
              </td>
              <td class="whitespace-nowrap px-3 py-1.5 font-mono" style="color: var(--np-text-dim)">
                {{ msg.hostname }}
              </td>
              <td
                class="max-w-md truncate px-3 py-1.5 font-mono"
                style="color: var(--np-text)"
                :title="msg.message"
              >
                {{ msg.message }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="mt-2 flex items-center justify-between">
        <p class="text-[0.65rem]" style="color: var(--np-text-dim)">
          Showing {{ syslogMessages.length }} of {{ syslogTotal }} messages
        </p>
        <div class="flex items-center gap-2">
          <button
            type="button"
            class="np-cyber-btn px-2 py-1 text-xs disabled:opacity-30"
            :disabled="syslogPage === 0"
            @click="syslogPrevPage"
          >
            Prev
          </button>
          <span class="font-mono text-xs" style="color: var(--np-text-dim)">
            {{ syslogPage + 1 }} / {{ syslogTotalPages }}
          </span>
          <button
            type="button"
            class="np-cyber-btn px-2 py-1 text-xs disabled:opacity-30"
            :disabled="syslogPage >= syslogTotalPages - 1"
            @click="syslogNextPage"
          >
            Next
          </button>
        </div>
      </div>
    </section>
  </div>
</template>
