<script setup lang="ts">
import axios from "axios";
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { RecycleScroller } from "vue-virtual-scroller";

type Theme = "nightshade" | "sysadmin";

interface Props {
  theme: Theme;
}

const props = defineProps<Props>();

const isNightshade = computed(() => props.theme === "nightshade");

type PcapFile = {
  id: number;
  filename: string;
  interface: string | null;
  bpf_filter: string | null;
  file_size_bytes: number;
  packet_count: number;
  captured_started_at: string | null;
  captured_finished_at: string | null;
  indexed_at: string | null;
  index_error: string | null;
};

type PcapPacket = {
  id: number;
  packet_index: number;
  timestamp: string;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  protocol: string | null;
  length: number;
};

type PacketQueryResponse = {
  items: PcapPacket[];
  next_cursor: string | null;
};

type ZeekConversationRow = {
  orig_h: string;
  resp_h: string;
  service: string | null;
  proto: string | null;
  count: number;
  bytes_out?: number;
  bytes_in?: number;
};

type ZeekDnsQueryRow = {
  query: string;
  qtype_name: string | null;
  count: number;
};

type ZeekSummary = {
  ran?: boolean;
  error?: string | null;
  timeout_seconds?: number | null;
  returncode?: number | null;
  conn?: {
    top_conversations?: ZeekConversationRow[];
  };
  dns?: {
    top_queries?: ZeekDnsQueryRow[];
  };
  [key: string]: unknown;
};

const pcaps = ref<PcapFile[]>([]);
const pcapsLoading = ref(false);
const pcapsError = ref<string | null>(null);



const selectedPcapId = ref<number | null>(null);

const packets = ref<PcapPacket[]>([]);
const nextCursor = ref<string | null>(null);
const hasMore = ref(true);
const packetsLoading = ref(false);
const packetsError = ref<string | null>(null);

const zeekSummary = ref<ZeekSummary | null>(null);
const zeekSummaryLoading = ref(false);
const zeekSummaryError = ref<string | null>(null);
const zeekIndexingStatus = ref<string | null>(null);

const pageSize = 250;

// Packet filters (server-side; applied to /api/pcaps/{id}/packets)
const filterSrcIp = ref("");
const filterDstIp = ref("");
const filterProtocol = ref("");
const filterSrcPort = ref("");
const filterDstPort = ref("");

const selectedPcap = computed(() => pcaps.value.find((c) => c.id === selectedPcapId.value) || null);

function formatEndpoint(ip: string | null, port: number | null): string {
  if (!ip) return "—";
  if (port == null) return ip;
  return `${ip}:${port}`;
}

function formatTimestamp(ts: string): string {
  const date = new Date(ts);
  if (isNaN(date.getTime())) return ts;
  return date.toLocaleString(undefined, {
    year: "2-digit",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

function formatNumber(value: number): string {
  return new Intl.NumberFormat().format(value);
}

function formatBytes(value: number): string {
  if (!Number.isFinite(value)) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let idx = 0;
  let n = Math.max(0, value);
  while (n >= 1024 && idx < units.length - 1) {
    n /= 1024;
    idx += 1;
  }
  const rounded = idx === 0 ? n.toFixed(0) : n.toFixed(n >= 10 ? 1 : 2);
  return `${rounded} ${units[idx]}`;
}

function pickZeekSummary(payload: unknown): ZeekSummary | null {
  if (!payload || typeof payload !== "object") return null;
  const obj = payload as Record<string, unknown>;
  if ("zeek_summary" in obj) {
    const maybeSummary = obj.zeek_summary;
    if (!maybeSummary || typeof maybeSummary !== "object") return null;
    return maybeSummary as ZeekSummary;
  }
  return obj as ZeekSummary;
}

function getApiErrorMessage(e: any, fallback: string): string {
  return (
    e?.response?.data?.error?.message ||
    e?.response?.data?.detail ||
    fallback
  );
}

const hasZeekSummary = computed(() => {
  if (!zeekSummary.value) return false;
  return Object.keys(zeekSummary.value).length > 0;
});

const zeekTopConversations = computed(() => zeekSummary.value?.conn?.top_conversations || []);
const zeekTopDnsQueries = computed(() => zeekSummary.value?.dns?.top_queries || []);

const zeekTopTalkers = computed(() => {
  const counts = new Map<string, number>();
  for (const row of zeekTopConversations.value) {
    if (row.orig_h) counts.set(row.orig_h, (counts.get(row.orig_h) || 0) + (row.count || 0));
    if (row.resp_h) counts.set(row.resp_h, (counts.get(row.resp_h) || 0) + (row.count || 0));
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([ip, count]) => ({ ip, count }));
});

const zeekTopServices = computed(() => {
  const counts = new Map<string, number>();
  for (const row of zeekTopConversations.value) {
    if (!row.service) continue;
    counts.set(row.service, (counts.get(row.service) || 0) + (row.count || 0));
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([service, count]) => ({ service, count }));
});

const zeekTrafficBytes = computed(() => {
  let bytesOut = 0;
  let bytesIn = 0;
  for (const row of zeekTopConversations.value) {
    bytesOut += row.bytes_out || 0;
    bytesIn += row.bytes_in || 0;
  }
  return { bytesOut, bytesIn, total: bytesOut + bytesIn };
});

const zeekHasConversationBytes = computed(() =>
  zeekTopConversations.value.some((row) => row.bytes_in != null || row.bytes_out != null)
);

const zeekStats = computed(() => {
  const uniqueServices = new Set<string>();
  for (const row of zeekTopConversations.value) {
    if (row.service) uniqueServices.add(row.service);
  }

  return {
    conversations: zeekTopConversations.value.length,
    dns_queries: zeekTopDnsQueries.value.length,
    talkers: zeekTopTalkers.value.length,
    services: uniqueServices.size,
    bytes_total: zeekTrafficBytes.value.total,
  };
});

async function loadPcaps(): Promise<void> {
  pcapsLoading.value = true;
  pcapsError.value = null;
  try {
    const { data } = await axios.get<PcapFile[]>("/api/pcaps/", {
      params: { limit: 50, offset: 0 },
    });
    pcaps.value = data;

    if (!selectedPcapId.value && data.length > 0) {
      selectedPcapId.value = data[0].id;
    }
  } catch {
    pcapsError.value = "Failed to load pcap files";
  } finally {
    pcapsLoading.value = false;
  }
}

let packetsRequestId = 0;
async function loadPackets(reset = false): Promise<void> {
  if (!selectedPcapId.value) return;
  if (!reset && packetsLoading.value) return;
  if (!reset && !hasMore.value) return;

  const pcapId = selectedPcapId.value;
  const requestId = (packetsRequestId += 1);

  packetsLoading.value = true;
  packetsError.value = null;

  try {
    const params: Record<string, string | number> = {
      limit: pageSize,
    };

    if (!reset && nextCursor.value) {
      params.cursor = nextCursor.value;
    }

    const srcIp = filterSrcIp.value.trim();
    if (srcIp) params.src_ip = srcIp;

    const dstIp = filterDstIp.value.trim();
    if (dstIp) params.dst_ip = dstIp;

    const proto = filterProtocol.value.trim();
    if (proto) params.protocol = proto;

    const srcPortRaw = filterSrcPort.value.trim();
    if (srcPortRaw) {
      const srcPort = Number.parseInt(srcPortRaw, 10);
      if (!Number.isNaN(srcPort)) params.src_port = srcPort;
    }

    const dstPortRaw = filterDstPort.value.trim();
    if (dstPortRaw) {
      const dstPort = Number.parseInt(dstPortRaw, 10);
      if (!Number.isNaN(dstPort)) params.dst_port = dstPort;
    }

    const { data } = await axios.get<PacketQueryResponse>(`/api/pcaps/${pcapId}/packets`, {
      params,
    });

    if (requestId !== packetsRequestId) return;

    if (reset) {
      packets.value = data.items;
    } else {
      packets.value = [...packets.value, ...data.items];
    }

    nextCursor.value = data.next_cursor;

    // Infer pagination end:
    if (data.items.length === 0) {
      hasMore.value = false;
    } else if (data.items.length < pageSize) {
      hasMore.value = false;
    } else {
      hasMore.value = true;
    }
  } catch (e: any) {
    if (requestId !== packetsRequestId) return;
    packetsError.value = getApiErrorMessage(e, "Failed to load packets");
  } finally {
    if (requestId === packetsRequestId) {
      packetsLoading.value = false;
    }
  }
}

let zeekSummaryRequestId = 0;
async function loadZeekSummary(reset = false): Promise<void> {
  if (!selectedPcapId.value) {
    zeekSummary.value = null;
    zeekSummaryError.value = null;
    zeekIndexingStatus.value = null;
    zeekSummaryLoading.value = false;
    return;
  }

  if (zeekSummaryLoading.value && !reset) return;

  if (reset) {
    zeekSummary.value = null;
    zeekSummaryError.value = null;
    zeekIndexingStatus.value = null;
  }

  zeekSummaryLoading.value = true;
  zeekSummaryError.value = null;

  const requestId = (zeekSummaryRequestId += 1);

  try {
    const { data } = await axios.get(`/api/pcaps/${selectedPcapId.value}/zeek-summary`);
    if (requestId !== zeekSummaryRequestId) return;

    zeekIndexingStatus.value = (data as any)?.indexing_status ?? null;
    zeekSummary.value = pickZeekSummary(data);
  } catch (e: any) {
    if (requestId !== zeekSummaryRequestId) return;

    zeekSummary.value = null;
    zeekIndexingStatus.value = null;
    zeekSummaryError.value = getApiErrorMessage(e, "Failed to load Zeek summary");
  } finally {
    if (requestId === zeekSummaryRequestId) {
      zeekSummaryLoading.value = false;
    }
  }
}

let zeekPollTimer: number | null = null;
function stopZeekPoll(): void {
  if (zeekPollTimer != null) {
    window.clearInterval(zeekPollTimer);
    zeekPollTimer = null;
  }
}

function startZeekPoll(): void {
  stopZeekPoll();
  zeekPollTimer = window.setInterval(() => {
    if (!selectedPcapId.value) {
      stopZeekPoll();
      return;
    }

    if (zeekIndexingStatus.value !== "pending") {
      stopZeekPoll();
      return;
    }

    void loadZeekSummary(false);

    // If packets are still empty while indexing is pending, keep trying.
    if (packets.value.length === 0 && !packetsLoading.value) {
      void loadPackets(true);
    }
  }, 5000);
}

function refreshPackets(): void {
  packets.value = [];
  nextCursor.value = null;
  hasMore.value = true;
  void loadPackets(true);
}

function applyFilters(): void {
  refreshPackets();
}

function clearFilters(): void {
  filterSrcIp.value = "";
  filterDstIp.value = "";
  filterProtocol.value = "";
  filterSrcPort.value = "";
  filterDstPort.value = "";
  refreshPackets();
}

async function refreshCurrentPcap(): Promise<void> {
  stopZeekPoll();
  await loadZeekSummary(true);
  refreshPackets();

  if (zeekIndexingStatus.value === "pending") {
    startZeekPoll();
  }
}

watch(
  () => selectedPcapId.value,
  (value, oldValue) => {
    if (!value || value === oldValue) return;

    // Filters are per-PCAP to avoid confusing carry-over.
    filterSrcIp.value = "";
    filterDstIp.value = "";
    filterProtocol.value = "";
    filterSrcPort.value = "";
    filterDstPort.value = "";

    void refreshCurrentPcap();
  }
);

onMounted(() => {
  loadPcaps().then(() => {
    if (selectedPcapId.value) {
      void refreshCurrentPcap();
    }
  });
});

onBeforeUnmount(() => {
  stopZeekPoll();
});
</script>

<template>
  <div class="space-y-4">
    <header class="flex flex-wrap items-start justify-between gap-4">
      <div>
        <h1 class="text-xl font-semibold" :class="isNightshade ? 'text-teal-400' : 'text-amber-400'">
          Packet Browser
        </h1>
        <p class="text-xs" :class="isNightshade ? 'text-teal-100/60' : 'text-slate-400'">
          Browse parsed packet headers with virtualized rendering.
        </p>
      </div>

      <div class="flex items-center gap-2">
        <button
          type="button"
          class="rounded-md border px-3 py-1.5 text-xs transition-colors"
          :class="isNightshade
            ? 'border-teal-400/30 bg-black/30 text-teal-200 hover:bg-teal-500/10'
            : 'border-amber-500/30 bg-slate-800/50 text-slate-300 hover:bg-amber-500/10'"
          :disabled="pcapsLoading || !selectedPcapId"
          @click="refreshCurrentPcap"
        >
          Refresh
        </button>
      </div>
    </header>

    <div
      class="np-panel p-4 space-y-3"
      :class="isNightshade ? 'border-teal-400/10' : ''"
    >
      <div class="flex flex-wrap items-end gap-3">
        <div class="min-w-[260px]">
          <label class="block text-[0.7rem] uppercase tracking-widest text-[var(--np-muted-text)]">PCAP File</label>
          <select
            v-model="selectedPcapId"
            class="mt-1 w-full rounded-md border px-3 py-2 text-sm bg-transparent outline-none"
            :disabled="pcapsLoading || pcaps.length === 0"
            :class="isNightshade
              ? 'border-teal-400/30 text-teal-100 focus:border-teal-400/60'
              : 'border-amber-400/30 text-amber-100 focus:border-amber-400/60'"
          >
            <option v-if="pcaps.length === 0" :value="null">No pcaps found</option>
            <option v-for="c in pcaps" :key="c.id" :value="c.id">
              #{{ c.id }} — {{ c.filename }}
            </option>
          </select>
        </div>

        <div class="flex-1 min-w-[240px]">
          <div class="rounded-md border px-3 py-2 text-xs"
            :class="isNightshade ? 'border-teal-400/20 bg-black/20 text-teal-100/70' : 'border-slate-700 bg-slate-900/40 text-slate-400'"
          >
            <div v-if="pcapsLoading">Loading pcaps…</div>
            <div v-else-if="pcapsError" class="text-rose-400">{{ pcapsError }}</div>
            <div v-else-if="!selectedPcap">
              Select a pcap file to browse indexed packets.
            </div>
            <div v-else class="flex flex-wrap items-center gap-x-4 gap-y-1">
              <span class="font-mono">packets: {{ selectedPcap.packet_count }}</span>
              <span v-if="selectedPcap.interface" class="font-mono">iface: {{ selectedPcap.interface }}</span>
              <span v-if="selectedPcap.bpf_filter" class="font-mono">filter: {{ selectedPcap.bpf_filter }}</span>
              <span v-if="selectedPcap.indexed_at" class="font-mono">indexed: {{ formatTimestamp(selectedPcap.indexed_at) }}</span>
              <span v-if="selectedPcap.index_error" class="font-mono text-rose-400">index_error: {{ selectedPcap.index_error }}</span>
            </div>
          </div>
        </div>
      </div>

     

      <div class="grid gap-3 rounded-md border p-3"
        :class="isNightshade ? 'border-teal-400/20 bg-black/20' : 'border-slate-700 bg-slate-900/30'"
      >
        <div class="text-[0.7rem] font-semibold uppercase tracking-widest"
          :class="isNightshade ? 'text-teal-200/80' : 'text-slate-400'"
        >
          Packet filters
        </div>

        <div class="grid grid-cols-1 gap-3 md:grid-cols-5">
          <label class="text-[0.65rem] uppercase tracking-widest" :class="isNightshade ? 'text-teal-100/60' : 'text-slate-400'">
            Src IP
            <input
              v-model="filterSrcIp"
              type="text"
              placeholder="10.0.0.10"
              class="mt-1 w-full rounded-md border bg-transparent px-2 py-1 text-xs outline-none"
              :class="isNightshade ? 'border-teal-400/20 text-teal-100 focus:border-teal-400/50' : 'border-slate-700 text-slate-200 focus:border-amber-400/50'"
            />
          </label>

          <label class="text-[0.65rem] uppercase tracking-widest" :class="isNightshade ? 'text-teal-100/60' : 'text-slate-400'">
            Dst IP
            <input
              v-model="filterDstIp"
              type="text"
              placeholder="10.0.0.20"
              class="mt-1 w-full rounded-md border bg-transparent px-2 py-1 text-xs outline-none"
              :class="isNightshade ? 'border-teal-400/20 text-teal-100 focus:border-teal-400/50' : 'border-slate-700 text-slate-200 focus:border-amber-400/50'"
            />
          </label>

          <label class="text-[0.65rem] uppercase tracking-widest" :class="isNightshade ? 'text-teal-100/60' : 'text-slate-400'">
            Protocol
            <input
              v-model="filterProtocol"
              type="text"
              placeholder="TCP"
              class="mt-1 w-full rounded-md border bg-transparent px-2 py-1 text-xs outline-none"
              :class="isNightshade ? 'border-teal-400/20 text-teal-100 focus:border-teal-400/50' : 'border-slate-700 text-slate-200 focus:border-amber-400/50'"
            />
          </label>

          <label class="text-[0.65rem] uppercase tracking-widest" :class="isNightshade ? 'text-teal-100/60' : 'text-slate-400'">
            Src port
            <input
              v-model="filterSrcPort"
              type="text"
              inputmode="numeric"
              placeholder="443"
              class="mt-1 w-full rounded-md border bg-transparent px-2 py-1 text-xs outline-none"
              :class="isNightshade ? 'border-teal-400/20 text-teal-100 focus:border-teal-400/50' : 'border-slate-700 text-slate-200 focus:border-amber-400/50'"
            />
          </label>

          <label class="text-[0.65rem] uppercase tracking-widest" :class="isNightshade ? 'text-teal-100/60' : 'text-slate-400'">
            Dst port
            <input
              v-model="filterDstPort"
              type="text"
              inputmode="numeric"
              placeholder="53"
              class="mt-1 w-full rounded-md border bg-transparent px-2 py-1 text-xs outline-none"
              :class="isNightshade ? 'border-teal-400/20 text-teal-100 focus:border-teal-400/50' : 'border-slate-700 text-slate-200 focus:border-amber-400/50'"
            />
          </label>
        </div>

        <div class="flex flex-wrap items-center gap-2">
          <button
            type="button"
            class="rounded-md border px-3 py-1.5 text-xs transition-colors"
            :class="isNightshade
              ? 'border-teal-400/30 bg-black/30 text-teal-200 hover:bg-teal-500/10'
              : 'border-amber-500/30 bg-slate-800/50 text-slate-300 hover:bg-amber-500/10'"
            :disabled="!selectedPcapId"
            @click="applyFilters"
          >
            Apply
          </button>
          <button
            type="button"
            class="rounded-md border px-3 py-1.5 text-xs transition-colors"
            :class="isNightshade
              ? 'border-teal-400/20 bg-black/10 text-teal-100/70 hover:bg-teal-500/10'
              : 'border-slate-700 bg-slate-900/30 text-slate-400 hover:bg-slate-800/40'"
            :disabled="!selectedPcapId"
            @click="clearFilters"
          >
            Clear
          </button>
          <span v-if="zeekIndexingStatus === 'pending'" class="text-xs"
            :class="isNightshade ? 'text-teal-100/50' : 'text-slate-500'"
          >
            Indexing in progress — auto-refreshing every 5s.
          </span>
        </div>
      </div>

      <div
        v-if="zeekSummaryLoading"
        class="rounded-lg border border-zinc-200 bg-white px-4 py-3 text-sm text-zinc-600 dark:border-zinc-800 dark:bg-zinc-950 dark:text-zinc-300"
      >
        <div class="flex items-center gap-3">
          <div class="np-spinner"></div>
          <div>
            <div class="font-semibold text-zinc-900 dark:text-zinc-100">Loading Zeek summary…</div>
            <div class="text-xs text-zinc-500 dark:text-zinc-400">/api/pcaps/{{ selectedPcapId }}/zeek-summary</div>
          </div>
        </div>
      </div>

      <div
        v-else-if="zeekSummaryError"
        class="rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-600 dark:text-rose-400"
      >
        {{ zeekSummaryError }}
      </div>

      <section
        v-else-if="hasZeekSummary"
        class="rounded-lg border border-zinc-200 bg-white dark:border-zinc-800 dark:bg-zinc-950"
      >
        <div class="flex flex-wrap items-start justify-between gap-4 border-b border-zinc-200 px-4 py-3 dark:border-zinc-800">
          <div>
            <h2 class="text-sm font-semibold text-zinc-900 dark:text-zinc-100">Zeek Summary</h2>
            <p class="text-xs text-zinc-500 dark:text-zinc-400">conn.log + dns.log (top 20 rows)</p>
          </div>

          <div class="flex flex-wrap items-center gap-2 text-xs">
            <span
              class="inline-flex items-center rounded-md border px-2 py-1 font-mono"
              :class="zeekSummary?.error
                ? 'border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300'
                : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'"
            >
              {{ zeekSummary?.error ? 'error' : 'ok' }}
            </span>
            <span v-if="zeekSummary?.ran !== undefined" class="font-mono text-zinc-500 dark:text-zinc-400">ran: {{ zeekSummary?.ran ? 'true' : 'false' }}</span>
            <span v-if="zeekSummary?.returncode !== undefined && zeekSummary?.returncode !== null" class="font-mono text-zinc-500 dark:text-zinc-400">rc: {{ zeekSummary?.returncode }}</span>
            <span v-if="zeekSummary?.timeout_seconds" class="font-mono text-zinc-500 dark:text-zinc-400">timeout: {{ zeekSummary?.timeout_seconds }}s</span>
          </div>
        </div>

        <div class="p-4 space-y-4">
          <div
            v-if="zeekSummary?.error"
            class="rounded-md border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-700 dark:text-rose-300"
          >
            <span class="font-semibold">Zeek:</span> {{ zeekSummary?.error }}
          </div>

          <div class="grid grid-cols-2 gap-3 md:grid-cols-5">
            <div class="rounded-md border border-zinc-200 px-3 py-2 dark:border-zinc-800">
              <div class="text-[0.65rem] uppercase tracking-widest text-zinc-500 dark:text-zinc-400">Conversations</div>
              <div class="mt-1 font-mono text-sm text-zinc-900 dark:text-zinc-100">{{ formatNumber(zeekStats.conversations) }}</div>
            </div>
            <div class="rounded-md border border-zinc-200 px-3 py-2 dark:border-zinc-800">
              <div class="text-[0.65rem] uppercase tracking-widest text-zinc-500 dark:text-zinc-400">Talkers</div>
              <div class="mt-1 font-mono text-sm text-zinc-900 dark:text-zinc-100">{{ formatNumber(zeekStats.talkers) }}</div>
            </div>
            <div class="rounded-md border border-zinc-200 px-3 py-2 dark:border-zinc-800">
              <div class="text-[0.65rem] uppercase tracking-widest text-zinc-500 dark:text-zinc-400">Services</div>
              <div class="mt-1 font-mono text-sm text-zinc-900 dark:text-zinc-100">{{ formatNumber(zeekStats.services) }}</div>
            </div>
            <div class="rounded-md border border-zinc-200 px-3 py-2 dark:border-zinc-800">
              <div class="text-[0.65rem] uppercase tracking-widest text-zinc-500 dark:text-zinc-400">DNS Queries</div>
              <div class="mt-1 font-mono text-sm text-zinc-900 dark:text-zinc-100">{{ formatNumber(zeekStats.dns_queries) }}</div>
            </div>
            <div class="rounded-md border border-zinc-200 px-3 py-2 dark:border-zinc-800">
              <div class="text-[0.65rem] uppercase tracking-widest text-zinc-500 dark:text-zinc-400">Bytes (sample)</div>
              <div class="mt-1 font-mono text-sm text-zinc-900 dark:text-zinc-100">{{ formatBytes(zeekStats.bytes_total) }}</div>
            </div>
          </div>

          <div class="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <div
              v-if="zeekTopConversations.length > 0"
              class="overflow-hidden rounded-lg border border-zinc-200 dark:border-zinc-800"
            >
              <div class="flex items-center justify-between border-b border-zinc-200 bg-zinc-50 px-3 py-2 text-xs font-semibold uppercase tracking-wider text-zinc-600 dark:border-zinc-800 dark:bg-zinc-900/40 dark:text-zinc-300">
                <span>Top conversations</span>
                <span class="font-mono normal-case">count</span>
              </div>
              <div class="divide-y divide-zinc-100 text-xs dark:divide-zinc-900">
                <div
                  v-for="row in zeekTopConversations.slice(0, 10)"
                  :key="`${row.orig_h}-${row.resp_h}-${row.service || 'na'}-${row.proto || 'na'}`"
                  class="flex items-center gap-3 px-3 py-2"
                >
                  <div class="min-w-0 flex-1">
                    <div class="truncate font-mono text-zinc-900 dark:text-zinc-100">
                      {{ row.orig_h }} <span class="text-zinc-400">→</span> {{ row.resp_h }}
                    </div>
                    <div class="mt-0.5 flex flex-wrap items-center gap-1">
                      <span
                        v-if="row.proto"
                        class="inline-flex items-center rounded border border-zinc-200 bg-white px-1.5 py-0.5 text-[0.65rem] font-semibold uppercase text-zinc-600 dark:border-zinc-800 dark:bg-zinc-950 dark:text-zinc-300"
                      >{{ row.proto }}</span>
                      <span
                        v-if="row.service"
                        class="inline-flex items-center rounded border border-zinc-200 bg-white px-1.5 py-0.5 text-[0.65rem] font-semibold text-zinc-600 dark:border-zinc-800 dark:bg-zinc-950 dark:text-zinc-300"
                      >{{ row.service }}</span>
                      <span v-if="zeekHasConversationBytes" class="font-mono text-[0.65rem] text-zinc-400">
                        {{ formatBytes((row.bytes_out || 0) + (row.bytes_in || 0)) }}
                      </span>
                    </div>
                  </div>
                  <div class="shrink-0 font-mono text-zinc-700 dark:text-zinc-300">{{ formatNumber(row.count || 0) }}</div>
                </div>
              </div>
            </div>

            <div
              v-if="zeekTopDnsQueries.length > 0"
              class="overflow-hidden rounded-lg border border-zinc-200 dark:border-zinc-800"
            >
              <div class="flex items-center justify-between border-b border-zinc-200 bg-zinc-50 px-3 py-2 text-xs font-semibold uppercase tracking-wider text-zinc-600 dark:border-zinc-800 dark:bg-zinc-900/40 dark:text-zinc-300">
                <span>Top DNS queries</span>
                <span class="font-mono normal-case">count</span>
              </div>
              <div class="divide-y divide-zinc-100 text-xs dark:divide-zinc-900">
                <div
                  v-for="row in zeekTopDnsQueries.slice(0, 10)"
                  :key="`${row.query}-${row.qtype_name || 'na'}`"
                  class="flex items-center gap-3 px-3 py-2"
                >
                  <div class="min-w-0 flex-1">
                    <div class="truncate font-mono text-zinc-900 dark:text-zinc-100">{{ row.query }}</div>
                    <div class="mt-0.5 text-[0.65rem] text-zinc-500 dark:text-zinc-400">{{ row.qtype_name || '—' }}</div>
                  </div>
                  <div class="shrink-0 font-mono text-zinc-700 dark:text-zinc-300">{{ formatNumber(row.count || 0) }}</div>
                </div>
              </div>
            </div>

            <div
              v-if="zeekTopTalkers.length > 0"
              class="overflow-hidden rounded-lg border border-zinc-200 dark:border-zinc-800"
            >
              <div class="border-b border-zinc-200 bg-zinc-50 px-3 py-2 text-xs font-semibold uppercase tracking-wider text-zinc-600 dark:border-zinc-800 dark:bg-zinc-900/40 dark:text-zinc-300">Top talkers</div>
              <div class="divide-y divide-zinc-100 text-xs dark:divide-zinc-900">
                <div
                  v-for="(row, idx) in zeekTopTalkers.slice(0, 10)"
                  :key="row.ip"
                  class="flex items-center justify-between gap-3 px-3 py-2"
                >
                  <div class="min-w-0 flex items-center gap-2">
                    <span class="w-5 text-right font-mono text-zinc-400">{{ idx + 1 }}</span>
                    <span class="truncate font-mono text-zinc-900 dark:text-zinc-100">{{ row.ip }}</span>
                  </div>
                  <span class="shrink-0 font-mono text-zinc-700 dark:text-zinc-300">{{ formatNumber(row.count) }}</span>
                </div>
              </div>
            </div>

            <div
              v-if="zeekTopServices.length > 0"
              class="overflow-hidden rounded-lg border border-zinc-200 dark:border-zinc-800"
            >
              <div class="border-b border-zinc-200 bg-zinc-50 px-3 py-2 text-xs font-semibold uppercase tracking-wider text-zinc-600 dark:border-zinc-800 dark:bg-zinc-900/40 dark:text-zinc-300">Top services</div>
              <div class="divide-y divide-zinc-100 text-xs dark:divide-zinc-900">
                <div
                  v-for="(row, idx) in zeekTopServices.slice(0, 10)"
                  :key="row.service"
                  class="flex items-center justify-between gap-3 px-3 py-2"
                >
                  <div class="min-w-0 flex items-center gap-2">
                    <span class="w-5 text-right font-mono text-zinc-400">{{ idx + 1 }}</span>
                    <span class="truncate font-mono text-zinc-900 dark:text-zinc-100">{{ row.service }}</span>
                  </div>
                  <span class="shrink-0 font-mono text-zinc-700 dark:text-zinc-300">{{ formatNumber(row.count) }}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <div
        v-if="packetsError"
        class="rounded-md border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-400"
      >
        {{ packetsError }}
      </div>

      <div
        class="overflow-hidden rounded-lg border"
        :class="isNightshade ? 'border-teal-400/30 bg-black/40' : 'border-slate-700 bg-slate-900/50'"
      >
        <div class="grid grid-cols-[10.25rem_3.5rem_11rem_11rem_6rem_5rem] gap-0 border-b px-3 py-2 text-[0.65rem] font-semibold uppercase tracking-wider"
          :class="isNightshade ? 'border-teal-400/20 text-teal-300/80' : 'border-slate-700 text-slate-400'"
        >
          <div>Timestamp</div>
          <div>#</div>
          <div>Source</div>
          <div>Destination</div>
          <div>Protocol</div>
          <div>Len</div>
        </div>

        <div v-if="!selectedPcapId" class="p-8 text-center text-sm" :class="isNightshade ? 'text-teal-100/50' : 'text-slate-500'">
          Select a pcap file.
        </div>

        <div v-else-if="packets.length === 0 && packetsLoading" class="p-10 flex flex-col items-center justify-center gap-3">
          <div class="np-spinner"></div>
          <div class="text-sm" :class="isNightshade ? 'text-teal-100/60' : 'text-slate-400'">Loading packets…</div>
        </div>

        <div v-else-if="packets.length === 0" class="p-8 text-center text-sm" :class="isNightshade ? 'text-teal-100/50' : 'text-slate-500'">
          No packets found for this pcap. If you just captured it, wait for indexing to finish.
        </div>

        <RecycleScroller
          v-else
          class="np-packet-scroller"
          :items="packets"
          :item-size="40"
          key-field="id"
          :buffer="600"
          :emit-update="true"
          @update="handleUpdate"
        >
          <template #default="{ item }">
            <div
              class="grid grid-cols-[10.25rem_3.5rem_11rem_11rem_6rem_5rem] px-3 h-10 items-center border-b font-mono text-xs transition-colors"
              :class="isNightshade
                ? 'border-teal-400/10 hover:bg-teal-500/5'
                : 'border-slate-700/50 hover:bg-slate-700/30'"
              :style="{ borderColor: 'var(--np-border)' }"
            >
              <div class="truncate text-[var(--np-text)]" :title="item.timestamp">{{ formatTimestamp(item.timestamp) }}</div>
              <div class="text-[var(--np-muted-text)]">{{ item.packet_index }}</div>
              <div class="truncate text-[var(--np-text)]" :title="formatEndpoint(item.src_ip, item.src_port)">{{ formatEndpoint(item.src_ip, item.src_port) }}</div>
              <div class="truncate text-[var(--np-text)]" :title="formatEndpoint(item.dst_ip, item.dst_port)">{{ formatEndpoint(item.dst_ip, item.dst_port) }}</div>
              <div>
                <span
                  class="px-1.5 py-0.5 rounded text-[0.6rem] font-semibold uppercase"
                  :class="isNightshade
                    ? 'bg-teal-500/20 text-teal-300'
                    : 'bg-amber-500/20 text-amber-300'"
                >{{ item.protocol || '—' }}</span>
              </div>
              <div class="text-[var(--np-muted-text)]">{{ item.length }}</div>
            </div>
          </template>
        </RecycleScroller>
      </div>

      <div class="flex items-center justify-between text-xs" :class="isNightshade ? 'text-teal-100/40' : 'text-slate-500'">
        <span class="font-mono">loaded: {{ packets.length }}</span>
        <span v-if="packetsLoading" class="font-mono">loading…</span>
        <span v-else-if="hasMore" class="font-mono">scroll to load more</span>
        <span v-else class="font-mono">end of capture</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.np-packet-scroller {
  height: calc(100vh - 21rem);
}
</style>
