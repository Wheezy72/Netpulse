<script setup lang="ts">
/**
 * Logs — a stream viewer, not a table dump.
 *
 * The page follows one reading order: what is happening (counts), then the
 * filter that narrows it, then the stream itself, with a status bar that says
 * how current the view is. Levels are shown as a coloured dot and their name,
 * never as a bright slab, so a page of warnings stays readable.
 */
import axios from "axios";
import { computed, nextTick, onMounted, onUnmounted, ref, shallowRef, watch } from "vue";
import {
  ArrowDownToLine,
  ChevronDown,
  CircleAlert,
  Copy,
  Check,
  Pause,
  Play,
  RefreshCw,
  Search,
  Trash2,
  X,
} from "lucide-vue-next";

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
const lastLoadedAt = ref<Date | null>(null);

const expandedRows = ref<Set<number>>(new Set());
const copiedSeq = ref<number | null>(null);

/** Highest seq already displayed — everything above it is new. */
const cursor = ref(0);
let newRowTimer: number | null = null;

const levelFilter = ref<string>("all");
/** "Errors" is a view over two levels, so it cannot be a server-side filter. */
const errorFocus = ref(false);
const searchQuery = ref<string>("");
const searchInput = ref<HTMLInputElement | null>(null);
const autoRefresh = ref(true);
const refreshInterval = ref<number | null>(null);

const LEVELS = ["debug", "info", "warning", "error", "critical"] as const;
type Level = (typeof LEVELS)[number];

const LEVEL_COLOR: Record<Level, string> = {
  debug: "var(--np-text-dim)",
  info: "var(--np-info)",
  warning: "var(--np-warning)",
  error: "var(--np-danger)",
  critical: "var(--np-danger)",
};

function levelOf(level: string): Level {
  return (LEVELS as readonly string[]).includes(level) ? (level as Level) : "info";
}

function levelColor(level: string): string {
  return LEVEL_COLOR[levelOf(level)];
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
    lastLoadedAt.value = new Date();
  } catch {
    error.value = "Could not reach the log buffer. The API may be restarting.";
  } finally {
    initialLoading.value = false;
  }
}

async function clearLogs(): Promise<void> {
  if (!confirm("Clear the live log view? Files on disk are kept.")) return;
  try {
    await axios.delete("/api/logs");
    cursor.value = 0;
    logs.value = [];
    await loadLogs();
  } catch {
    error.value = "Could not clear the buffer";
  }
}

function toggleRow(seq: number): void {
  const next = new Set(expandedRows.value);
  if (next.has(seq)) next.delete(seq);
  else next.add(seq);
  expandedRows.value = next;
}

async function copyRow(entry: LogEntry): Promise<void> {
  const line = `${entry.timestamp} ${entry.level.toUpperCase()} ${entry.logger} — ${entry.message}`;
  try {
    await navigator.clipboard.writeText(line);
    copiedSeq.value = entry.seq;
    window.setTimeout(() => {
      if (copiedSeq.value === entry.seq) copiedSeq.value = null;
    }, 1600);
  } catch {
    // Clipboard is permission-gated; the row stays selectable instead.
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

function formatDetail(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "object") return JSON.stringify(value, null, 2);
  return String(value);
}

const filteredLogs = computed(() => {
  const raw = searchQuery.value.trim();
  if (!raw) return logs.value;

  // Try regex, fall back to plain substring.
  let pattern: RegExp | null = null;
  try {
    pattern = new RegExp(raw, "i");
  } catch {
    // invalid regex — substring match instead
  }
  return logs.value.filter((log) => {
    const haystack = `${log.message} ${log.logger} ${log.module ?? ""} ${log.function ?? ""}`;
    return pattern ? pattern.test(haystack) : haystack.toLowerCase().includes(raw.toLowerCase());
  });
});

const levelChips = computed(() => [
  { key: "all", label: "All", count: stats.value.total },
  { key: "error", label: "Errors", count: stats.value.error + stats.value.critical },
  { key: "warning", label: "Warnings", count: stats.value.warning },
  { key: "info", label: "Info", count: stats.value.info },
  { key: "debug", label: "Debug", count: stats.value.debug },
]);

function selectLevel(key: string): void {
  // "Errors" covers error and critical, which the API cannot express in one
  // query, so that chip filters what is already loaded. The rest map to one
  // server-side level each.
  if (key === "error") {
    errorFocus.value = true;
    if (levelFilter.value !== "all") {
      levelFilter.value = "all";
      return; // the levelFilter watcher reloads with the full buffer
    }
    if (logs.value.length === 0) void loadLogs();
    return;
  }
  errorFocus.value = false;
  levelFilter.value = key;
}

function chipActive(key: string): boolean {
  if (key === "error") return errorFocus.value;
  return !errorFocus.value && levelFilter.value === key;
}

const visibleLogs = computed(() =>
  errorFocus.value ? filteredLogs.value.filter((log) => isErrorLevel(log.level)) : filteredLogs.value
);

const filteredCount = computed(() => visibleLogs.value.length);

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
    error.value = "Could not build the PDF report";
  }
}

/** "/" jumps to search without stealing characters from an input. */
function onKeydown(event: KeyboardEvent): void {
  const target = event.target as HTMLElement | null;
  const typing = target?.tagName === "INPUT" || target?.tagName === "TEXTAREA";
  if (event.key === "/" && !typing) {
    event.preventDefault();
    void nextTick(() => searchInput.value?.focus());
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

function getSeverityColor(severity: string): string {
  const s = severity.toLowerCase();
  if (s === "emergency" || s === "alert" || s === "critical" || s === "error") {
    return "var(--np-danger)";
  }
  if (s === "warning") return "var(--np-warning)";
  if (s === "debug") return "var(--np-text-dim)";
  return "var(--np-info)";
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
    syslogError.value = "Could not load syslog messages";
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
    syslogError.value = "Could not change the listener state";
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
    syslogError.value = "Could not clear syslog messages";
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
  document.addEventListener("keydown", onKeydown);
});

onUnmounted(() => {
  stopAutoRefresh();
  document.removeEventListener("keydown", onKeydown);
  if (newRowTimer !== null) window.clearTimeout(newRowTimer);
});
</script>

<template>
  <div class="np-fade-in space-y-4">
    <!-- Page header: what this page is, and the two streams it carries. -->
    <header class="flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 class="text-lg font-bold tracking-tight text-[var(--np-text)]">Logs</h1>
        <p class="mt-1 text-xs text-[var(--np-text-dim)]">
          Everything the API and the worker have said, streamed live.
        </p>
      </div>
      <div class="flex gap-1 rounded-lg border border-[var(--np-border-subtle)] p-1">
        <button
          v-for="tab in [
            { key: 'application', label: 'Application' },
            { key: 'syslog', label: 'Syslog' },
          ]"
          :key="tab.key"
          type="button"
          class="rounded-md px-3 py-1.5 text-xs font-semibold transition-colors"
          :class="
            activeTab === tab.key
              ? 'bg-[var(--np-surface-hover)] text-[var(--np-text)]'
              : 'text-[var(--np-text-dim)] hover:text-[var(--np-text)]'
          "
          @click="activeTab = tab.key as 'application' | 'syslog'"
        >
          {{ tab.label }}
        </button>
      </div>
    </header>

    <!-- ── Application stream ─────────────────────────────────────────── -->
    <section
      v-if="activeTab === 'application'"
      class="overflow-hidden rounded-xl border border-[var(--np-border-subtle)] bg-[var(--np-surface)]"
    >
      <!-- Toolbar. One row: state, level filters, search, actions. -->
      <div class="flex flex-wrap items-center gap-2 border-b border-[var(--np-border-subtle)] px-3 py-2">
        <button
          type="button"
          class="flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[0.65rem] font-semibold transition-colors"
          :class="
            autoRefresh
              ? 'border-[var(--np-accent-border)] bg-[var(--np-accent-soft)] text-[var(--np-accent)]'
              : 'border-[var(--np-border-subtle)] text-[var(--np-text-dim)] hover:text-[var(--np-text)]'
          "
          :title="autoRefresh ? 'Pause the live refresh' : 'Resume the live refresh'"
          @click="toggleAutoRefresh"
        >
          <span
            class="h-1.5 w-1.5 rounded-full bg-current"
            :class="autoRefresh ? 'animate-pulse' : 'opacity-50'"
          />
          {{ autoRefresh ? "Live" : "Paused" }}
          <component
            :is="autoRefresh ? Pause : Play"
            class="h-3 w-3 opacity-60"
            :stroke-width="1.7"
          />
        </button>

        <div class="flex items-center gap-1">
          <button
            v-for="chip in levelChips"
            :key="chip.key"
            type="button"
            class="flex items-center gap-1.5 rounded-md px-2 py-1 text-[0.65rem] font-medium transition-colors"
            :class="
              chipActive(chip.key)
                ? 'bg-[var(--np-surface-hover)] text-[var(--np-text)]'
                : 'text-[var(--np-text-dim)] hover:bg-[var(--np-surface-hover)]/60 hover:text-[var(--np-text)]'
            "
            :aria-pressed="chipActive(chip.key)"
            @click="selectLevel(chip.key)"
          >
            <span
              v-if="chip.key !== 'all'"
              class="h-1.5 w-1.5 rounded-full"
              :style="{ background: levelColor(chip.key) }"
            />
            {{ chip.label }}
            <span class="font-mono tabular-nums opacity-60">{{ chip.count }}</span>
          </button>
        </div>

        <div class="ml-auto flex flex-wrap items-center gap-2">
          <div class="relative">
            <Search
              class="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--np-text-dim)]"
              :stroke-width="1.7"
            />
            <input
              ref="searchInput"
              v-model="searchQuery"
              type="text"
              placeholder="Search or regex…"
              class="np-neon-input h-8 w-56 py-1 pl-8 pr-16 font-mono text-[0.7rem]"
              aria-label="Filter loaded log lines"
            />
            <span
              v-if="!searchQuery"
              class="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 rounded border border-[var(--np-border-subtle)] px-1 font-mono text-[0.55rem] text-[var(--np-text-dim)]"
              >/</span
            >
            <button
              v-else
              type="button"
              class="absolute right-2 top-1/2 -translate-y-1/2 text-[var(--np-text-dim)] hover:text-[var(--np-text)]"
              aria-label="Clear search"
              @click="searchQuery = ''"
            >
              <X class="h-3.5 w-3.5" :stroke-width="1.7" />
            </button>
          </div>

          <div class="flex items-center gap-1">
            <button
              type="button"
              class="flex h-8 items-center gap-1.5 rounded-md px-2 text-[0.65rem] font-medium text-[var(--np-text-dim)] transition-colors hover:bg-[var(--np-surface-hover)] hover:text-[var(--np-text)]"
              title="Reload from the server"
              @click="loadLogs()"
            >
              <RefreshCw class="h-3.5 w-3.5" :stroke-width="1.7" />
              Refresh
            </button>
            <button
              type="button"
              class="flex h-8 items-center gap-1.5 rounded-md px-2 text-[0.65rem] font-medium text-[var(--np-text-dim)] transition-colors hover:bg-[var(--np-surface-hover)] hover:text-[var(--np-text)]"
              title="Download these logs as a PDF"
              @click="downloadLogsPDF"
            >
              <ArrowDownToLine class="h-3.5 w-3.5" :stroke-width="1.7" />
              PDF
            </button>
            <button
              type="button"
              class="flex h-8 items-center gap-1.5 rounded-md px-2 text-[0.65rem] font-medium text-[var(--np-text-dim)] transition-colors hover:bg-[var(--np-surface-hover)] hover:text-[var(--np-danger)]"
              title="Clear the in-memory buffer; files on disk are kept"
              @click="clearLogs"
            >
              <Trash2 class="h-3.5 w-3.5" :stroke-width="1.7" />
              Clear
            </button>
          </div>
        </div>
      </div>

      <div
        v-if="error"
        class="flex items-center gap-2 border-b border-[var(--np-danger)]/30 bg-[var(--np-danger)]/10 px-3 py-2 text-xs text-[var(--np-danger)]"
      >
        <CircleAlert class="h-3.5 w-3.5 shrink-0" :stroke-width="1.7" />
        {{ error }}
      </div>

      <!-- Stream -->
      <div class="custom-scrollbar max-h-[calc(100vh-17rem)] min-h-[18rem] overflow-y-auto">
        <div v-if="initialLoading" class="space-y-1.5 p-3">
          <div v-for="i in 8" :key="i" class="np-skeleton h-7 rounded"></div>
        </div>

        <div v-else-if="logs.length === 0" class="flex flex-col items-center gap-2 px-6 py-16 text-center">
          <CircleAlert class="h-5 w-5 text-[var(--np-text-dim)]" :stroke-width="1.5" />
          <p class="text-sm font-semibold text-[var(--np-text)]">Nothing logged in this session yet</p>
          <p class="max-w-sm text-xs text-[var(--np-text-dim)]">
            Lines appear here as the API and the worker write them. The buffer is
            held in memory, so a restart starts a fresh one — the files on disk keep
            the history.
          </p>
        </div>

        <div
          v-else-if="visibleLogs.length === 0"
          class="flex flex-col items-center gap-2 px-6 py-16 text-center"
        >
          <Search class="h-5 w-5 text-[var(--np-text-dim)]" :stroke-width="1.5" />
          <p class="text-sm font-semibold text-[var(--np-text)]">No lines match this filter</p>
          <p class="text-xs text-[var(--np-text-dim)]">
            {{ filteredCount }} of {{ logs.length }} loaded lines shown.
          </p>
          <button
            type="button"
            class="mt-1 rounded-md border border-[var(--np-border-subtle)] px-2.5 py-1 text-[0.65rem] font-semibold text-[var(--np-text-muted)] hover:text-[var(--np-text)]"
            @click="
              searchQuery = '';
              errorFocus = false;
              levelFilter = 'all';
            "
          >
            Clear filters
          </button>
        </div>

        <div v-else class="divide-y divide-[var(--np-border-subtle)]">
          <template v-for="log in visibleLogs" :key="log.seq">
            <div
              class="np-log-row group grid cursor-pointer grid-cols-[4.5rem_1.35rem_auto_1fr_auto] items-baseline gap-x-2 px-3 py-1.5 text-[0.7rem] hover:bg-[var(--np-surface-hover)]/60"
              :class="{ 'np-log-row--new': log.isNew }"
              role="button"
              tabindex="0"
              :aria-expanded="expandedRows.has(log.seq)"
              @click="toggleRow(log.seq)"
              @keydown.enter.prevent="toggleRow(log.seq)"
              @keydown.space.prevent="toggleRow(log.seq)"
            >
              <span class="font-mono tabular-nums text-[var(--np-text-dim)]">
                {{ formatTimestamp(log.timestamp) }}
              </span>
              <span
                class="mt-[0.35rem] h-1.5 w-1.5 justify-self-center rounded-full"
                :style="{ background: levelColor(log.level) }"
                :title="log.level"
              />
              <span class="truncate font-mono text-[0.62rem] text-[var(--np-text-dim)]" :title="log.logger">
                {{ log.logger }}
              </span>
              <p
                class="min-w-0 break-words font-mono leading-relaxed"
                :class="
                  isErrorLevel(log.level)
                    ? 'text-[var(--np-text)]'
                    : 'text-[var(--np-text-muted)]'
                "
              >
                {{ log.message }}
              </p>
              <div class="flex items-center gap-1 opacity-0 transition-opacity group-hover:opacity-100">
                <button
                  type="button"
                  class="rounded p-0.5 text-[var(--np-text-dim)] hover:text-[var(--np-text)]"
                  :title="copiedSeq === log.seq ? 'Copied' : 'Copy this line'"
                  aria-label="Copy this log line"
                  @click.stop="copyRow(log)"
                >
                  <component
                    :is="copiedSeq === log.seq ? Check : Copy"
                    class="h-3 w-3"
                    :stroke-width="1.7"
                  />
                </button>
                <ChevronDown
                  class="h-3 w-3 text-[var(--np-text-dim)] transition-transform"
                  :class="expandedRows.has(log.seq) ? 'rotate-180' : ''"
                  :stroke-width="1.7"
                />
              </div>
            </div>

            <!-- Detail: where the line came from, and whatever it carried. -->
            <div
              v-if="expandedRows.has(log.seq)"
              class="border-l-2 bg-[var(--np-surface-elevated)]/40 px-3 py-2"
              :style="{ borderColor: levelColor(log.level) }"
            >
              <dl class="grid grid-cols-[5.5rem_1fr] gap-x-3 gap-y-1 font-mono text-[0.62rem]">
                <dt class="text-[var(--np-text-dim)]">Level</dt>
                <dd class="font-semibold" :style="{ color: levelColor(log.level) }">
                  {{ log.level }}
                </dd>
                <dt class="text-[var(--np-text-dim)]">Logger</dt>
                <dd class="break-all text-[var(--np-text-muted)]">{{ log.logger }}</dd>
                <template v-if="log.module || log.function">
                  <dt class="text-[var(--np-text-dim)]">Source</dt>
                  <dd class="break-all text-[var(--np-text-muted)]">
                    <span v-if="log.module">{{ log.module }}</span>
                    <span v-if="log.function">:: {{ log.function }}()</span>
                    <span v-if="log.line">:{{ log.line }}</span>
                  </dd>
                </template>
                <template v-if="Object.keys(log.extra || {}).length">
                  <dt class="text-[var(--np-text-dim)]">Extra</dt>
                  <dd class="whitespace-pre-wrap break-all text-[var(--np-text-muted)]">
                    {{ formatDetail(log.extra) }}
                  </dd>
                </template>
                <template v-if="log.level === 'error' || log.level === 'critical'">
                  <dt class="text-[var(--np-text-dim)]">Seen</dt>
                  <dd class="text-[var(--np-text-muted)]">
                    {{ new Date(log.timestamp).toLocaleString() }}
                  </dd>
                </template>
              </dl>
            </div>
          </template>
        </div>
      </div>

      <!-- Status bar: how much of what, and how fresh. -->
      <div
        class="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-[var(--np-border-subtle)] px-3 py-1.5 font-mono text-[0.6rem] text-[var(--np-text-dim)]"
      >
        <span>
          {{ filteredCount }} of {{ logs.length }} loaded
          <span class="opacity-70">·</span>
          {{ stats.total }} in the buffer
        </span>
        <span class="opacity-70">·</span>
        <span>{{ autoRefresh ? `refreshing every ${REFRESH_MS / 1000}s` : "refresh paused" }}</span>
        <span v-if="lastLoadedAt" class="ml-auto">
          updated {{ lastLoadedAt.toLocaleTimeString("en-US", { hour12: false }) }}
        </span>
      </div>
    </section>

    <!-- ── Syslog ─────────────────────────────────────────────────────── -->
    <section
      v-else
      class="overflow-hidden rounded-xl border border-[var(--np-border-subtle)] bg-[var(--np-surface)]"
    >
      <div class="flex flex-wrap items-center gap-2 border-b border-[var(--np-border-subtle)] px-3 py-2">
        <span
          class="flex items-center gap-2 rounded-full border px-2.5 py-1 text-[0.65rem] font-semibold"
          :class="
            syslogStatus.running
              ? 'border-[var(--np-accent-border)] bg-[var(--np-accent-soft)] text-[var(--np-accent)]'
              : 'border-[var(--np-border-subtle)] text-[var(--np-text-dim)]'
          "
        >
          <span
            class="h-1.5 w-1.5 rounded-full bg-current"
            :class="syslogStatus.running ? 'animate-pulse' : 'opacity-50'"
          />
          {{ syslogStatus.running ? `Listening on ${syslogStatus.port}` : "Listener stopped" }}
          <span class="font-mono opacity-70">{{ syslogStatus.message_count }}</span>
        </span>

        <div class="ml-auto flex items-center gap-1">
          <button
            type="button"
            class="flex h-8 items-center rounded-md px-2.5 text-[0.65rem] font-semibold transition-colors disabled:opacity-40"
            :class="
              syslogStatus.running
                ? 'text-[var(--np-text-dim)] hover:bg-[var(--np-surface-hover)] hover:text-[var(--np-danger)]'
                : 'text-[var(--np-accent)] hover:bg-[var(--np-accent-soft)]'
            "
            :disabled="syslogToggling"
            @click="toggleSyslogListener"
          >
            {{ syslogStatus.running ? "Stop listener" : "Start listener" }}
          </button>
          <button
            type="button"
            class="flex h-8 items-center gap-1.5 rounded-md px-2 text-[0.65rem] font-medium text-[var(--np-text-dim)] hover:bg-[var(--np-surface-hover)] hover:text-[var(--np-text)]"
            @click="loadSyslogMessages"
          >
            <RefreshCw class="h-3.5 w-3.5" :stroke-width="1.7" />
            Refresh
          </button>
          <button
            type="button"
            class="flex h-8 items-center gap-1.5 rounded-md px-2 text-[0.65rem] font-medium text-[var(--np-text-dim)] hover:bg-[var(--np-surface-hover)] hover:text-[var(--np-danger)]"
            @click="clearSyslogMessages"
          >
            <Trash2 class="h-3.5 w-3.5" :stroke-width="1.7" />
            Clear
          </button>
        </div>
      </div>

      <div class="flex flex-wrap items-center gap-2 border-b border-[var(--np-border-subtle)] px-3 py-2">
        <select
          v-model="syslogSeverityFilter"
          class="np-neon-input h-8 cursor-pointer px-2 text-[0.7rem]"
          aria-label="Severity"
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
          placeholder="Source IP"
          class="np-neon-input h-8 w-36 px-2 font-mono text-[0.7rem]"
          aria-label="Source IP"
          @keyup.enter="syslogApplyFilters"
        />
        <input
          v-model="syslogSearchFilter"
          type="text"
          placeholder="Search messages"
          class="np-neon-input h-8 min-w-[12rem] flex-1 px-2 text-[0.7rem]"
          aria-label="Search syslog messages"
          @keyup.enter="syslogApplyFilters"
        />
        <button
          type="button"
          class="rounded-md border border-[var(--np-border-subtle)] px-2.5 py-1 text-[0.65rem] font-semibold text-[var(--np-text-muted)] hover:text-[var(--np-text)]"
          @click="syslogApplyFilters"
        >
          Apply
        </button>
      </div>

      <div
        v-if="syslogError"
        class="border-b border-[var(--np-danger)]/30 bg-[var(--np-danger)]/10 px-3 py-2 text-xs text-[var(--np-danger)]"
      >
        {{ syslogError }}
      </div>

      <div class="custom-scrollbar max-h-[calc(100vh-19rem)] overflow-auto">
        <p
          v-if="syslogMessages.length === 0 && !syslogLoading"
          class="px-6 py-16 text-center text-xs text-[var(--np-text-dim)]"
        >
          Nothing received yet. Point a device's syslog at UDP
          {{ syslogStatus.port }} and its messages land here.
        </p>
        <table v-else class="w-full text-left text-[0.7rem]">
          <thead class="sticky top-0 bg-[var(--np-surface-elevated)]">
            <tr class="border-b border-[var(--np-border-subtle)]">
              <th
                v-for="head in ['Received', 'Source', 'Severity', 'Host', 'Message']"
                :key="head"
                class="px-3 py-2 text-[0.6rem] font-semibold text-[var(--np-text-dim)]"
              >
                {{ head }}
              </th>
            </tr>
          </thead>
          <tbody class="divide-y divide-[var(--np-border-subtle)]">
            <tr
              v-for="(msg, idx) in syslogMessages"
              :key="idx"
              class="hover:bg-[var(--np-surface-hover)]/60"
            >
              <td class="whitespace-nowrap px-3 py-1.5 font-mono tabular-nums text-[var(--np-text-dim)]">
                {{ msg.timestamp }}
              </td>
              <td class="whitespace-nowrap px-3 py-1.5 font-mono text-[var(--np-text-muted)]">
                {{ msg.source_ip }}
              </td>
              <td class="whitespace-nowrap px-3 py-1.5">
                <span class="flex items-center gap-1.5 text-[0.65rem]">
                  <span
                    class="h-1.5 w-1.5 rounded-full"
                    :style="{ background: getSeverityColor(msg.severity) }"
                  />
                  {{ msg.severity }}
                </span>
              </td>
              <td class="whitespace-nowrap px-3 py-1.5 font-mono text-[var(--np-text-dim)]">
                {{ msg.hostname }}
              </td>
              <td
                class="max-w-md truncate px-3 py-1.5 font-mono text-[var(--np-text)]"
                :title="msg.message"
              >
                {{ msg.message }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div
        class="flex items-center justify-between border-t border-[var(--np-border-subtle)] px-3 py-1.5 font-mono text-[0.6rem] text-[var(--np-text-dim)]"
      >
        <span>{{ syslogMessages.length }} of {{ syslogTotal }} messages</span>
        <div class="flex items-center gap-2">
          <button
            type="button"
            class="rounded px-2 py-0.5 hover:text-[var(--np-text)] disabled:opacity-30"
            :disabled="syslogPage === 0"
            @click="syslogPrevPage"
          >
            Prev
          </button>
          <span>{{ syslogPage + 1 }} / {{ syslogTotalPages }}</span>
          <button
            type="button"
            class="rounded px-2 py-0.5 hover:text-[var(--np-text)] disabled:opacity-30"
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
