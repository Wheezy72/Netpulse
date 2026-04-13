<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount } from "vue";
import axios from "axios";
import PulsePanel from "../components/features/PulsePanel.vue";
import TopologyPanel from "../components/features/TopologyPanel.vue";

interface Props {
  infoMode?: "full" | "compact";
  isAdmin: boolean;
  theme: "nightshade" | "sysadmin";
}

const props = defineProps<Props>();

// Quick-access header stats pulled from /api/metrics/pulse-latest
type StatSummary = {
  latency_ms: number | null;
  jitter_ms: number | null;
  packet_loss_pct: number | null;
  health: number | null;
};

const stats = ref<StatSummary>({ latency_ms: null, jitter_ms: null, packet_loss_pct: null, health: null });

async function fetchStats() {
  try {
    const [pulseRes, healthRes] = await Promise.all([
      axios.get<{ targets: { latency_ms: number | null; jitter_ms: number | null; packet_loss_pct: number | null }[] }>(
        "/api/metrics/pulse-latest"
      ),
      axios.get<{ points: { value: number }[] }>("/api/metrics/internet-health-recent"),
    ]);
    const targets = pulseRes.data.targets ?? [];
    const gw = targets[0];
    const pts = healthRes.data.points ?? [];
    stats.value = {
      latency_ms: gw?.latency_ms ?? null,
      jitter_ms: gw?.jitter_ms ?? null,
      packet_loss_pct: gw?.packet_loss_pct ?? null,
      health: pts.length ? pts[pts.length - 1].value : null,
    };
  } catch {
    // Stats remain null — PulsePanel handles the detail
  }
}

let statsTimer: number | undefined;
onMounted(() => {
  fetchStats();
  statsTimer = window.setInterval(fetchStats, 30_000);
});
onBeforeUnmount(() => clearInterval(statsTimer));

function fmt(v: number | null, decimals = 1) {
  return v !== null ? v.toFixed(decimals) : "—";
}

const headerStats = [
  { key: "latency_ms" as const, label: "Latency", unit: "ms", warn: (v: number) => v > 100, crit: (v: number) => v > 200 },
  { key: "jitter_ms" as const, label: "Jitter", unit: "ms", warn: (v: number) => v > 20, crit: (v: number) => v > 50 },
  { key: "packet_loss_pct" as const, label: "Pkt Loss", unit: "%", warn: (v: number) => v > 1, crit: (v: number) => v > 5 },
  { key: "health" as const, label: "Health", unit: "%", warn: (v: number) => v < 80, crit: (v: number) => v < 60 },
];

function statColor(item: (typeof headerStats)[number]) {
  const v = stats.value[item.key];
  if (v === null) return "text-zinc-500";
  if (item.crit(v)) return "text-red-400";
  if (item.warn(v)) return "text-amber-400";
  return "text-emerald-400";
}
</script>

<template>
  <div class="flex flex-col gap-3 h-full">
    <!-- Command-center header bar -->
    <header class="flex items-center justify-between border border-zinc-800 bg-[#111113] rounded px-4 py-2">
      <div class="flex items-center gap-6">
        <span class="text-[0.65rem] font-semibold uppercase tracking-widest text-zinc-500">Command Center</span>
        <!-- Inline stat chips -->
        <div class="flex items-center gap-4">
          <div v-for="item in headerStats" :key="item.key" class="flex items-center gap-1.5">
            <span class="text-[0.6rem] uppercase tracking-wide text-zinc-600">{{ item.label }}</span>
            <span class="text-xs font-semibold font-mono" :class="statColor(item)">
              {{ fmt(stats[item.key]) }}<span class="text-[0.6rem] font-normal text-zinc-600 ml-0.5">{{ item.unit }}</span>
            </span>
          </div>
        </div>
      </div>
      <div class="flex items-center gap-1.5">
        <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
        <span class="text-[0.6rem] text-zinc-500 uppercase tracking-widest">Live</span>
      </div>
    </header>

    <!-- Bento grid: PulsePanel (2/3) + Topology (1/3) -->
    <div class="grid gap-3 flex-1 min-h-0" style="grid-template-columns: 1fr 340px;">
      <PulsePanel class="min-h-0" />
      <TopologyPanel class="min-h-0" :is-admin="props.isAdmin" />
    </div>
  </div>
</template>
