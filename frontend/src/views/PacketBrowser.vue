<script setup lang="ts">
import axios from "axios";
import { computed, onMounted, ref, watch } from "vue";
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

const pcaps = ref<PcapFile[]>([]);
const pcapsLoading = ref(false);
const pcapsError = ref<string | null>(null);

const selectedPcapId = ref<number | null>(null);

const packets = ref<PcapPacket[]>([]);
const nextCursor = ref<string | null>(null);
const hasMore = ref(true);
const packetsLoading = ref(false);
const packetsError = ref<string | null>(null);

const pageSize = 250;

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

async function loadPackets(reset = false): Promise<void> {
  if (!selectedPcapId.value) return;
  if (packetsLoading.value) return;
  if (!reset && !hasMore.value) return;

  packetsLoading.value = true;
  packetsError.value = null;

  try {
    const params: Record<string, string | number> = {
      limit: pageSize,
    };

    if (!reset && nextCursor.value) {
      params.cursor = nextCursor.value;
    }

    const { data } = await axios.get<PacketQueryResponse>(`/api/pcaps/${selectedPcapId.value}/packets`, {
      params,
    });

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
    packetsError.value = e?.response?.data?.detail || "Failed to load packets";
  } finally {
    packetsLoading.value = false;
  }
}

function refreshPackets(): void {
  packets.value = [];
  nextCursor.value = null;
  hasMore.value = true;
  loadPackets(true);
}

function handleUpdate(_startIndex: number, endIndex: number): void {
  if (!hasMore.value || packetsLoading.value) return;
  if (endIndex >= packets.value.length - 40) {
    loadPackets(false);
  }
}

watch(
  () => selectedPcapId.value,
  (value, oldValue) => {
    if (!value || value === oldValue) return;
    refreshPackets();
  }
);

onMounted(() => {
  loadPcaps().then(() => {
    if (selectedPcapId.value) {
      refreshPackets();
    }
  });
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
          @click="refreshPackets"
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
