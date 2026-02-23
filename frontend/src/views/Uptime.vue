<script setup lang="ts">
import axios from "axios";
import { computed, onMounted, onUnmounted, ref } from "vue";

interface Props {
  theme: "nightshade" | "sysadmin";
}

const props = defineProps<Props>();
const isNightshade = computed(() => props.theme === "nightshade");

type UptimeTargetRow = {
  id: number;
  name: string;
  target: string;
  check_type: string;
  interval_seconds: number;
  is_active: boolean;
  last_status: string | null;
  last_checked_at: string | null;
  last_latency_ms: number | null;
  consecutive_failures: number;
};

type UptimeSummaryData = {
  total_targets: number;
  targets_up: number;
  targets_down: number;
  targets_degraded: number;
  targets: UptimeTargetRow[];
};

type UptimeCheckRow = {
  id: number;
  target_id: number;
  timestamp: string;
  status: string;
  latency_ms: number | null;
  status_code: number | null;
  error_message: string | null;
};

const summary = ref<UptimeSummaryData | null>(null);
const loading = ref(false);
const error = ref<string | null>(null);

const formName = ref("");
const formTarget = ref("");
const formCheckType = ref("ping");
const formInterval = ref(60);
const formLoading = ref(false);
const showForm = ref(false);

const selectedTargetId = ref<number | null>(null);
const history = ref<UptimeCheckRow[]>([]);
const historyLoading = ref(false);

const checkingIds = ref<Set<number>>(new Set());

let refreshInterval: ReturnType<typeof setInterval> | null = null;

async function fetchSummary() {
  loading.value = true;
  error.value = null;
  try {
    const { data } = await axios.get<UptimeSummaryData>("/api/uptime");
    summary.value = data;
  } catch (e: any) {
    error.value = e.response?.data?.error?.message || "Failed to load uptime data";
  } finally {
    loading.value = false;
  }
}

async function createTarget() {
  if (!formName.value.trim() || !formTarget.value.trim()) return;
  formLoading.value = true;
  try {
    await axios.post("/api/uptime", {
      name: formName.value.trim(),
      target: formTarget.value.trim(),
      check_type: formCheckType.value,
      interval_seconds: formInterval.value,
    });
    formName.value = "";
    formTarget.value = "";
    formCheckType.value = "ping";
    formInterval.value = 60;
    showForm.value = false;
    await fetchSummary();
  } catch (e: any) {
    error.value = e.response?.data?.error?.message || e.response?.data?.detail || "Failed to create target";
  } finally {
    formLoading.value = false;
  }
}

async function deleteTarget(id: number) {
  if (!confirm("Delete this uptime target and all its history?")) return;
  try {
    await axios.delete(`/api/uptime/${id}`);
    if (selectedTargetId.value === id) {
      selectedTargetId.value = null;
      history.value = [];
    }
    await fetchSummary();
  } catch (e: any) {
    error.value = e.response?.data?.error?.message || "Failed to delete target";
  }
}

async function runCheck(id: number) {
  checkingIds.value.add(id);
  try {
    await axios.post(`/api/uptime/${id}/check`);
    await fetchSummary();
    if (selectedTargetId.value === id) {
      await fetchHistory(id);
    }
  } catch (e: any) {
    error.value = e.response?.data?.error?.message || "Check failed";
  } finally {
    checkingIds.value.delete(id);
  }
}

async function fetchHistory(targetId: number) {
  historyLoading.value = true;
  try {
    const { data } = await axios.get<UptimeCheckRow[]>(`/api/uptime/${targetId}/history?limit=50`);
    history.value = data;
  } catch {
    history.value = [];
  } finally {
    historyLoading.value = false;
  }
}

function selectTarget(id: number) {
  if (selectedTargetId.value === id) {
    selectedTargetId.value = null;
    history.value = [];
  } else {
    selectedTargetId.value = id;
    fetchHistory(id);
  }
}

function downloadUptimeReport(): void {
  if (!summary.value || !summary.value.targets.length) {
    error.value = "No uptime targets to export.";
    return;
  }
  const targets = summary.value.targets;
  const headers = ["Name", "Target", "Type", "Status", "Uptime %", "Avg Latency", "Last Check"];
  const rows = targets.map((t) => [
    t.name,
    t.target,
    t.check_type,
    t.last_status || "unknown",
    "",
    t.last_latency_ms !== null ? `${t.last_latency_ms.toFixed(1)} ms` : "",
    t.last_checked_at || "Never",
  ]);
  const csv = [headers.join(","), ...rows.map((r) => r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(","))].join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `netpulse_uptime_${new Date().toISOString().slice(0, 10)}.csv`;
  link.click();
  URL.revokeObjectURL(url);
}

function statusColor(status: string | null): string {
  if (status === "up") return "#22c55e";
  if (status === "down") return "#ef4444";
  if (status === "degraded") return "#eab308";
  return "var(--np-muted-text)";
}

function statusLabel(status: string | null): string {
  if (status === "up") return "UP";
  if (status === "down") return "DOWN";
  if (status === "degraded") return "DEGRADED";
  return "UNKNOWN";
}

function formatTime(iso: string | null): string {
  if (!iso) return "Never";
  try {
    const d = new Date(iso);
    return d.toLocaleString();
  } catch {
    return iso;
  }
}

function formatLatency(ms: number | null): string {
  if (ms === null || ms === undefined) return "--";
  return `${ms.toFixed(1)} ms`;
}

onMounted(() => {
  fetchSummary();
  refreshInterval = setInterval(fetchSummary, 30000);
});

onUnmounted(() => {
  if (refreshInterval) clearInterval(refreshInterval);
});
</script>

<template>
  <div class="space-y-6">
    <div class="flex items-center justify-between">
      <h2
        class="text-sm font-bold tracking-wider uppercase"
        :class="isNightshade ? 'text-teal-400' : 'text-amber-400'"
        :style="{ fontFamily: isNightshade ? '\'Orbitron\', sans-serif' : '\'Inter\', sans-serif' }"
      >
        Uptime Monitor
      </h2>
      <div class="flex items-center gap-2">
        <button
          type="button"
          @click="downloadUptimeReport"
          class="px-3 py-2 rounded-lg text-[0.7rem] font-semibold uppercase tracking-wider transition-all flex items-center gap-1.5"
          :class="isNightshade
            ? 'bg-teal-500/10 text-teal-400 border border-teal-500/30 hover:bg-teal-500/20'
            : 'bg-amber-500/10 text-amber-400 border border-amber-500/30 hover:bg-amber-500/20'"
          title="Download Uptime Report CSV"
        >
          <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
          </svg>
          CSV
        </button>
        <button
          type="button"
          @click="showForm = !showForm"
          class="px-4 py-2 rounded-lg text-[0.7rem] font-semibold uppercase tracking-wider transition-all"
          :class="isNightshade
            ? 'bg-teal-500/20 text-teal-400 border border-teal-500/30 hover:bg-teal-500/30'
            : 'bg-amber-500/20 text-amber-400 border border-amber-500/30 hover:bg-amber-500/30'"
        >
          {{ showForm ? 'Cancel' : '+ Add Target' }}
        </button>
      </div>
    </div>

    <div v-if="showForm" class="np-panel p-4 rounded-lg border" :style="{ borderColor: 'var(--np-border)', backgroundColor: 'var(--np-surface)' }">
      <form @submit.prevent="createTarget" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 items-end">
        <div>
          <label class="block text-xs uppercase tracking-wider mb-1" :style="{ color: 'var(--np-muted-text)' }">Name</label>
          <input
            v-model="formName"
            type="text"
            placeholder="Google DNS"
            class="w-full px-3 py-2 rounded-lg text-sm border outline-none"
            :style="{ backgroundColor: 'var(--np-bg)', borderColor: 'var(--np-border)', color: 'var(--np-text)' }"
          />
        </div>
        <div>
          <label class="block text-xs uppercase tracking-wider mb-1" :style="{ color: 'var(--np-muted-text)' }">Target (IP/URL)</label>
          <input
            v-model="formTarget"
            type="text"
            placeholder="8.8.8.8 or https://example.com"
            class="w-full px-3 py-2 rounded-lg text-sm border outline-none"
            :style="{ backgroundColor: 'var(--np-bg)', borderColor: 'var(--np-border)', color: 'var(--np-text)' }"
          />
        </div>
        <div>
          <label class="block text-xs uppercase tracking-wider mb-1" :style="{ color: 'var(--np-muted-text)' }">Check Type</label>
          <select
            v-model="formCheckType"
            class="w-full px-3 py-2 rounded-lg text-sm border outline-none"
            :style="{ backgroundColor: 'var(--np-bg)', borderColor: 'var(--np-border)', color: 'var(--np-text)' }"
          >
            <option value="ping">Ping</option>
            <option value="http">HTTP</option>
          </select>
        </div>
        <div>
          <label class="block text-xs uppercase tracking-wider mb-1" :style="{ color: 'var(--np-muted-text)' }">Interval (sec)</label>
          <input
            v-model.number="formInterval"
            type="number"
            min="10"
            class="w-full px-3 py-2 rounded-lg text-sm border outline-none"
            :style="{ backgroundColor: 'var(--np-bg)', borderColor: 'var(--np-border)', color: 'var(--np-text)' }"
          />
        </div>
        <div>
          <button
            type="submit"
            :disabled="formLoading || !formName.trim() || !formTarget.trim()"
            class="w-full px-4 py-2 rounded-lg text-xs font-semibold uppercase tracking-wider transition-all disabled:opacity-40"
            :class="isNightshade
              ? 'bg-teal-500 text-black hover:bg-teal-400'
              : 'bg-amber-500 text-black hover:bg-amber-400'"
          >
            {{ formLoading ? 'Adding...' : 'Add Target' }}
          </button>
        </div>
      </form>
    </div>

    <div v-if="error" class="p-3 rounded-lg border border-red-500/30 bg-red-500/10 text-red-400 text-sm">
      {{ error }}
      <button @click="error = null" class="ml-2 underline text-xs">dismiss</button>
    </div>

    <div class="grid grid-cols-2 sm:grid-cols-4 gap-4">
      <div
        v-for="card in [
          { label: 'Total Targets', value: summary?.total_targets ?? 0, color: 'var(--np-accent-primary)' },
          { label: 'Up', value: summary?.targets_up ?? 0, color: '#22c55e' },
          { label: 'Down', value: summary?.targets_down ?? 0, color: '#ef4444' },
          { label: 'Degraded', value: summary?.targets_degraded ?? 0, color: '#eab308' },
        ]"
        :key="card.label"
        class="np-panel p-4 rounded-lg border text-center"
        :style="{ borderColor: 'var(--np-border)', backgroundColor: 'var(--np-surface)' }"
      >
        <div class="text-lg font-bold font-mono" :style="{ color: card.color }">
          {{ card.value }}
        </div>
        <div class="text-[0.65rem] uppercase tracking-wider mt-1" :style="{ color: 'var(--np-muted-text)' }">
          {{ card.label }}
        </div>
      </div>
    </div>

    <div v-if="loading && !summary" class="text-center py-12" :style="{ color: 'var(--np-muted-text)' }">
      Loading uptime data...
    </div>

    <div v-else-if="summary && summary.targets.length === 0" class="text-center py-12" :style="{ color: 'var(--np-muted-text)' }">
      <p class="text-sm">No uptime targets configured yet.</p>
      <p class="text-xs mt-1">Click "Add Target" to start monitoring.</p>
    </div>

    <div v-else-if="summary" class="space-y-3">
      <div
        v-for="t in summary.targets"
        :key="t.id"
        class="np-panel rounded-lg border overflow-hidden transition-all"
        :style="{ borderColor: selectedTargetId === t.id ? 'var(--np-accent-primary)' : 'var(--np-border)', backgroundColor: 'var(--np-surface)' }"
      >
        <div
          class="flex items-center gap-4 p-4 cursor-pointer hover:bg-white/5 transition-colors"
          @click="selectTarget(t.id)"
        >
          <div
            class="w-3 h-3 rounded-full shrink-0"
            :style="{ backgroundColor: statusColor(t.last_status), boxShadow: `0 0 8px ${statusColor(t.last_status)}` }"
          ></div>

          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2">
              <span class="text-sm font-semibold truncate" :style="{ color: 'var(--np-text)' }">{{ t.name }}</span>
              <span
                class="px-2 py-0.5 rounded text-[0.6rem] font-bold uppercase tracking-wider"
                :style="{ backgroundColor: statusColor(t.last_status) + '20', color: statusColor(t.last_status) }"
              >
                {{ statusLabel(t.last_status) }}
              </span>
              <span
                class="px-1.5 py-0.5 rounded text-[0.55rem] uppercase tracking-wider"
                :style="{ backgroundColor: 'var(--np-bg)', color: 'var(--np-muted-text)', border: '1px solid var(--np-border)' }"
              >
                {{ t.check_type }}
              </span>
            </div>
            <div class="text-xs mt-0.5 truncate" :style="{ color: 'var(--np-muted-text)' }">
              {{ t.target }}
            </div>
          </div>

          <div class="hidden sm:flex items-center gap-6 text-xs shrink-0" :style="{ color: 'var(--np-muted-text)' }">
            <div class="text-right">
              <div class="font-mono" :style="{ color: 'var(--np-text)' }">{{ formatLatency(t.last_latency_ms) }}</div>
              <div class="text-[0.6rem] uppercase tracking-wider">Latency</div>
            </div>
            <div class="text-right">
              <div class="font-mono" :style="{ color: t.consecutive_failures > 0 ? '#ef4444' : 'var(--np-text)' }">{{ t.consecutive_failures }}</div>
              <div class="text-[0.6rem] uppercase tracking-wider">Failures</div>
            </div>
            <div class="text-right max-w-[140px]">
              <div class="font-mono truncate" :style="{ color: 'var(--np-text)' }">{{ formatTime(t.last_checked_at) }}</div>
              <div class="text-[0.6rem] uppercase tracking-wider">Last Check</div>
            </div>
          </div>

          <div class="flex items-center gap-2 shrink-0">
            <button
              type="button"
              @click.stop="runCheck(t.id)"
              :disabled="checkingIds.has(t.id)"
              class="px-3 py-1.5 rounded text-[0.65rem] font-semibold uppercase tracking-wider transition-all border disabled:opacity-40"
              :class="isNightshade
                ? 'border-teal-500/30 text-teal-400 hover:bg-teal-500/20'
                : 'border-amber-500/30 text-amber-400 hover:bg-amber-500/20'"
            >
              {{ checkingIds.has(t.id) ? 'Checking...' : 'Check Now' }}
            </button>
            <button
              type="button"
              @click.stop="deleteTarget(t.id)"
              class="px-2 py-1.5 rounded text-[0.65rem] font-semibold transition-all border border-red-500/30 text-red-400 hover:bg-red-500/20"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
                <path stroke-linecap="round" stroke-linejoin="round" d="m14.74 9-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0" />
              </svg>
            </button>
          </div>
        </div>

        <div v-if="selectedTargetId === t.id" class="border-t px-4 py-3" :style="{ borderColor: 'var(--np-border)', backgroundColor: 'var(--np-bg)' }">
          <div class="text-xs uppercase tracking-wider mb-2 font-semibold" :style="{ color: 'var(--np-muted-text)' }">
            Check History (Last 50)
          </div>
          <div v-if="historyLoading" class="text-xs py-4 text-center" :style="{ color: 'var(--np-muted-text)' }">
            Loading history...
          </div>
          <div v-else-if="history.length === 0" class="text-xs py-4 text-center" :style="{ color: 'var(--np-muted-text)' }">
            No checks recorded yet.
          </div>
          <div v-else class="overflow-x-auto max-h-64 overflow-y-auto">
            <table class="w-full text-xs">
              <thead>
                <tr :style="{ color: 'var(--np-muted-text)' }">
                  <th class="text-left py-1 px-2 uppercase tracking-wider font-medium">Time</th>
                  <th class="text-left py-1 px-2 uppercase tracking-wider font-medium">Status</th>
                  <th class="text-right py-1 px-2 uppercase tracking-wider font-medium">Latency</th>
                  <th class="text-right py-1 px-2 uppercase tracking-wider font-medium">Code</th>
                  <th class="text-left py-1 px-2 uppercase tracking-wider font-medium">Error</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="c in history"
                  :key="c.id"
                  class="border-t"
                  :style="{ borderColor: 'var(--np-border)' }"
                >
                  <td class="py-1 px-2 font-mono whitespace-nowrap" :style="{ color: 'var(--np-text)' }">{{ formatTime(c.timestamp) }}</td>
                  <td class="py-1 px-2">
                    <span
                      class="px-1.5 py-0.5 rounded text-[0.6rem] font-bold uppercase"
                      :style="{ backgroundColor: statusColor(c.status) + '20', color: statusColor(c.status) }"
                    >
                      {{ statusLabel(c.status) }}
                    </span>
                  </td>
                  <td class="py-1 px-2 text-right font-mono" :style="{ color: 'var(--np-text)' }">{{ formatLatency(c.latency_ms) }}</td>
                  <td class="py-1 px-2 text-right font-mono" :style="{ color: 'var(--np-text)' }">{{ c.status_code ?? '--' }}</td>
                  <td class="py-1 px-2 truncate max-w-[200px]" :style="{ color: '#ef4444' }">{{ c.error_message || '--' }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
