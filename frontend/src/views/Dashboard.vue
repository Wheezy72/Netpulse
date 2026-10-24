<script setup lang="ts">
/**
 * Dashboard — a deliberately small overview.
 *
 * Device detail, inventory search and node drawers live on the Devices and
 * Topology pages. This page answers three questions only: how big is the
 * fleet, is it responding, and what is on it. Everything shown here is
 * derived from real data — no placeholder risks, platforms or health scores.
 */
import { computed, nextTick, onMounted, ref, watch } from "vue";
import { useRouter } from "vue-router";
import axios from "axios";
import { useDeviceDiscovery } from "../composables/useDeviceDiscovery";

type Theme = "nightshade" | "sysadmin";

const props = defineProps<{ theme: Theme; isAdmin: boolean }>();
const router = useRouter();

const loading = ref(false);
const error = ref<string | null>(null);

interface DeviceRow {
  id: number;
  hostname: string | null;
  ip_address: string;
  device_type: string | null;
  os: string | null;
  vendor: string | null;
  zone: string | null;
  is_gateway: boolean;
  last_seen: string | null;
}

const devices = ref<DeviceRow[]>([]);

// Resolve chart colours from the live theme tokens instead of hardcoding the
// dark theme's emerald. Switching themes now re-reads the same variables the
// rest of the UI uses.
const accent = ref("#10b981");
const accentStrong = ref("#34d399");
const mutedText = ref("#94a3b8");
const faintText = ref("#64748b");
const chartBorder = ref("rgba(255,255,255,0.12)");

function readThemeColors() {
  const styles = getComputedStyle(document.body);
  accent.value = styles.getPropertyValue("--np-accent").trim() || accent.value;
  accentStrong.value = styles.getPropertyValue("--np-accent-strong").trim() || accentStrong.value;
  mutedText.value = styles.getPropertyValue("--np-text-muted").trim() || mutedText.value;
  faintText.value = styles.getPropertyValue("--np-text-dim").trim() || faintText.value;
  chartBorder.value = styles.getPropertyValue("--np-border").trim() || chartBorder.value;
  warningColor.value = styles.getPropertyValue("--np-warning").trim() || warningColor.value;
}

function alpha(hex: string, percent: number): string {
  const value = hex.replace("#", "");
  if (value.length !== 6) return `rgba(16, 185, 129, ${percent / 100})`;
  const r = parseInt(value.slice(0, 2), 16);
  const g = parseInt(value.slice(2, 4), 16);
  const b = parseInt(value.slice(4, 6), 16);
  return `rgba(${r}, ${g}, ${b}, ${percent / 100})`;
}

const ONLINE_WINDOW_MS = 10 * 60 * 1000;

function isOnline(device: DeviceRow): boolean {
  if (!device.last_seen) return false;
  const seen = new Date(device.last_seen).getTime();
  if (Number.isNaN(seen)) return false;
  return Date.now() - seen <= ONLINE_WINDOW_MS;
}

// Ping status -----------------------------------------------------------------
// Replaces the old "Devices by role" chart: role counts were static trivia,
// while per-device ping answers tell the operator what to fix right now.

interface PingResultRow {
  id: number;
  hostname: string | null;
  ip_address: string;
  status: "up" | "slow" | "down";
  latency_ms: number | null;
  last_seen: string | null;
}

interface PingStatusResponse {
  checked_at: string;
  summary: { up: number; slow: number; down: number; total: number };
  results: PingResultRow[];
}

const pingChecking = ref(false);
const pingError = ref<string | null>(null);
const pingResults = ref<PingResultRow[]>([]);
const pingSummary = ref<PingStatusResponse["summary"] | null>(null);

const answering = computed(() =>
  pingResults.value
    .filter((r) => r.status !== "down" && r.latency_ms !== null)
    .sort((a, b) => (b.latency_ms ?? 0) - (a.latency_ms ?? 0))
);
const notResponding = computed(() => pingResults.value.filter((r) => r.status === "down"));
const warningColor = ref("#f59e0b");

async function checkPingStatus() {
  pingChecking.value = true;
  pingError.value = null;
  try {
    const { data } = await axios.get<PingStatusResponse>("/api/devices/ping-status", {
      params: { limit: 12 },
    });
    pingResults.value = data.results;
    pingSummary.value = data.summary;
  } catch {
    pingError.value = "The ping check could not run. Is the backend reachable?";
  } finally {
    pingChecking.value = false;
  }
}

function labelFor(row: PingResultRow): string {
  return row.hostname || row.ip_address;
}

// The overview speaks about one network: the one this machine is attached to.
// Counting every remembered network would mix five homes' inventories into one
// number, which is exactly what the network records exist to prevent.
interface NetworkRow {
  id: number;
  name: string;
  cidr: string;
  is_current: boolean;
}
const currentNetwork = ref<NetworkRow | null>(null);

async function loadCurrentNetwork(): Promise<void> {
  try {
    const { data } = await axios.get<NetworkRow[]>("/api/networks");
    currentNetwork.value = data.find((n) => n.is_current) ?? null;
  } catch {
    currentNetwork.value = null;
  }
}

async function loadDevices() {
  loading.value = true;
  error.value = null;
  try {
    const params: Record<string, string> = {};
    if (currentNetwork.value) {
      params.network_id = String(currentNetwork.value.id);
    }
    const { data } = await axios.get<DeviceRow[]>("/api/devices", { params });
    devices.value = data;
  } catch {
    error.value = "Could not load the device inventory.";
  } finally {
    loading.value = false;
  }
}

const totalDevices = computed(() => devices.value.length);
const onlineDevices = computed(() => devices.value.filter(isOnline).length);
const gatewayCount = computed(() => devices.value.filter((d) => d.is_gateway).length);

// Zones used to count `devices.zone`, which discovery never writes, so the
// card was mathematically always 0. A zone is a configured network segment;
// legacy manually assigned device labels are only a fallback.
interface SegmentRow {
  id: number;
  name: string;
  cidr: string;
  is_active: boolean;
}
const segments = ref<SegmentRow[]>([]);

async function loadSegments(): Promise<void> {
  try {
    const { data } = await axios.get<SegmentRow[]>("/api/network-segments");
    segments.value = data;
  } catch {
    segments.value = [];
  }
}

const zoneCount = computed(() => {
  if (segments.value.length) return segments.value.length;
  return new Set(devices.value.map((d) => d.zone).filter(Boolean)).size;
});
const availability = computed(() =>
  totalDevices.value ? Math.round((onlineDevices.value / totalDevices.value) * 100) : 0
);

const stats = computed(() => [
  {
    id: "total",
    label: "Devices",
    value: totalDevices.value,
    hint: "In the inventory",
  },
  {
    id: "online",
    label: "Responding",
    value: onlineDevices.value,
    hint: `Seen in the last 10 minutes`,
  },
  {
    id: "gateways",
    label: "Gateways",
    value: gatewayCount.value,
    hint: "Default-route nodes",
  },
  {
    id: "zones",
    label: "Zones",
    value: zoneCount.value,
    hint: "Configured segments",
  },
]);

const gaugeOption = computed(() => ({
  series: [
    {
      type: "gauge",
      startAngle: 220,
      endAngle: -40,
      min: 0,
      max: 100,
      radius: "94%",
      center: ["50%", "58%"],
      progress: {
        show: true,
        width: 12,
        roundCap: true,
        itemStyle: { color: accent.value },
      },
      axisLine: { lineStyle: { width: 12, color: [[1, chartBorder.value]] } },
      pointer: { show: false },
      axisTick: { show: false },
      splitLine: { show: false },
      axisLabel: { show: false },
      anchor: { show: false },
      title: {
        show: true,
        offsetCenter: [0, "36%"],
        color: faintText.value,
        fontSize: 10,
        fontFamily: "JetBrains Mono, monospace",
      },
      detail: {
        valueAnimation: true,
        fontSize: 28,
        fontWeight: 700,
        offsetCenter: [0, "2%"],
        color: accent.value,
        formatter: "{value}%",
      },
      data: [{ value: availability.value, name: "RESPONDING" }],
    },
  ],
}));

const pingChartOption = computed(() => {
  const rows = answering.value;
  return {
    tooltip: {
      trigger: "item",
      backgroundColor: "transparent",
      borderWidth: 0,
      textStyle: { color: mutedText.value, fontSize: 11 },
      formatter: (params: any) => {
        const row = rows[params.dataIndex];
        if (!row) return "";
        return `${labelFor(row)}: ${row.latency_ms?.toFixed(1) ?? "?"} ms`;
      },
    },
    grid: { left: 4, right: 16, top: 8, bottom: 4, containLabel: true },
    xAxis: {
      type: "value",
      axisLabel: {
        color: faintText.value,
        fontSize: 10,
        fontFamily: "JetBrains Mono, monospace",
        formatter: "{value} ms",
      },
      splitLine: { lineStyle: { color: chartBorder.value, type: "dashed" } },
    },
    yAxis: {
      type: "category",
      inverse: true,
      data: rows.map(labelFor),
      axisLabel: {
        color: faintText.value,
        fontSize: 10,
        fontFamily: "JetBrains Mono, monospace",
        width: 110,
        overflow: "truncate",
      },
      axisTick: { show: false },
      axisLine: { lineStyle: { color: chartBorder.value } },
    },
    series: [
      {
        type: "bar",
        data: rows.map((row) => ({
          value: Number((row.latency_ms ?? 0).toFixed(1)),
          itemStyle: {
            color: row.status === "slow" ? warningColor.value : accent.value,
            borderRadius: [0, 6, 6, 0],
          },
        })),
        barMaxWidth: 16,
        emphasis: { itemStyle: { color: accentStrong.value } },
      },
    ],
  };
});

const { discovering, discover } = useDeviceDiscovery();
const sweepNote = ref<string | null>(null);

async function runDiscovery() {
  sweepNote.value = null;
  await discover(null);
  await loadDevices();
  sweepNote.value = "Sweep finished — the inventory has been refreshed.";
}

watch(
  () => props.theme,
  async () => {
    await nextTick();
    readThemeColors();
  }
);

onMounted(async () => {
  await nextTick();
  readThemeColors();
  await loadCurrentNetwork();
  await Promise.all([loadDevices(), loadSegments()]);
  void checkPingStatus();
});
</script>

<template>
  <div class="space-y-6">
    <!-- Page heading -->
    <header class="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <p class="text-[0.6rem] font-mono uppercase tracking-[0.35em] text-[var(--np-text-dim)]">
          Overview
        </p>
        <h1 class="mt-1 text-2xl font-bold tracking-tight text-[var(--np-text)]">Network overview</h1>
        <p class="mt-1 text-xs text-[var(--np-text-muted)]">
          How many devices are out there, which ones answer, and what needs attention.
        </p>
      </div>
      <button
        class="np-cyber-btn self-start px-4 py-2 text-[0.65rem] uppercase tracking-wider sm:self-auto"
        :disabled="loading"
        @click="loadDevices"
      >
        {{ loading ? "Refreshing…" : "Refresh" }}
      </button>
    </header>

    <div v-if="error" class="np-level-error rounded-xl px-4 py-3 text-xs">
      {{ error }}
    </div>

    <!-- Stat strip: one row, equal weight, no decorative sparklines -->
    <section class="grid grid-cols-2 gap-4 xl:grid-cols-4">
      <article
        v-for="stat in stats"
        :key="stat.id"
        class="glass-card np-metric-tile p-5"
      >
        <p class="text-[0.6rem] font-mono uppercase tracking-widest text-[var(--np-text-dim)]">
          {{ stat.label }}
        </p>
        <p class="mt-2 text-3xl font-bold leading-none tracking-tight text-[var(--np-text)]">
          {{ stat.value }}
        </p>
        <p class="mt-2 text-[0.65rem] text-[var(--np-text-muted)]">{{ stat.hint }}</p>
      </article>
    </section>

    <!-- Ping status + reachability, side by side -->
    <section class="grid grid-cols-1 gap-5 lg:grid-cols-3">
      <article class="glass-card glass-card--static flex flex-col p-5 lg:col-span-2">
        <div class="flex items-start justify-between gap-3">
          <div>
            <p class="text-[0.6rem] font-mono uppercase tracking-widest text-[var(--np-text-dim)]">
              Ping status
            </p>
            <h2 class="mt-1 text-sm font-bold text-[var(--np-text)]">Who is answering right now</h2>
          </div>
          <button
            type="button"
            class="np-cyber-btn px-3 py-1.5 text-[0.6rem]"
            :disabled="pingChecking"
            @click="checkPingStatus"
          >
            {{ pingChecking ? "Checking…" : "Check now" }}
          </button>
        </div>

        <p v-if="pingSummary" class="mt-2 text-[0.7rem] text-[var(--np-text-muted)] tabular-nums">
          {{ pingSummary.up }} answering
          <template v-if="pingSummary.slow"> · {{ pingSummary.slow }} slow</template>
          <template v-if="pingSummary.down"> · {{ pingSummary.down }} silent</template>
          · checked {{ pingSummary.total }}
        </p>

        <div v-if="pingError" class="mt-3 rounded-xl border border-[var(--np-danger)]/30 bg-[var(--np-danger)]/10 px-3 py-2 text-xs text-[var(--np-danger)]">
          {{ pingError }}
        </div>

        <div v-else-if="pingChecking && answering.length === 0" class="flex flex-1 flex-col justify-center gap-2 py-10">
          <div class="np-skeleton h-3 w-2/3 rounded" />
          <div class="np-skeleton h-3 w-1/2 rounded" />
          <div class="np-skeleton h-3 w-3/5 rounded" />
        </div>

        <div v-else-if="answering.length === 0" class="flex flex-1 flex-col items-center justify-center gap-1 py-12 text-center">
          <p class="text-sm font-semibold text-[var(--np-text)]">No device answered</p>
          <p class="max-w-xs text-xs text-[var(--np-text-muted)]">
            The inventory is empty, or none of the checked hosts replied. Run a discovery sweep first.
          </p>
        </div>

        <v-chart v-else class="mt-2 h-[220px] w-full" :option="pingChartOption" autoresize />
      </article>

      <article class="glass-card glass-card--static flex flex-col p-5">
        <div>
          <p class="text-[0.6rem] font-mono uppercase tracking-widest text-[var(--np-text-dim)]">
            Reachability
          </p>
          <h2 class="mt-1 text-sm font-bold text-[var(--np-text)]">Seen in the last 10 minutes</h2>
        </div>
        <v-chart class="mt-1 h-[190px] w-full" :option="gaugeOption" autoresize />
        <div class="mt-auto flex items-center justify-between border-t border-[var(--np-border-subtle)] pt-3 text-[0.65rem]">
          <span class="font-mono uppercase tracking-wider text-[var(--np-text-dim)]">Online / total</span>
          <span class="font-mono font-bold text-[var(--np-text)] tabular-nums">{{ onlineDevices }} / {{ totalDevices }}</span>
        </div>
      </article>
    </section>

    <!-- Actions + status: the only place the page repeats what other pages do,
         and it does so as a link, not a copy of their UI. -->
    <section class="grid grid-cols-1 gap-5 lg:grid-cols-3">
      <article
        class="relative overflow-hidden rounded-2xl border p-5 lg:col-span-2"
        :style="{
          borderColor: `color-mix(in srgb, var(--np-accent) 28%, transparent)`,
          background: `color-mix(in srgb, var(--np-accent) 7%, transparent)`,
        }"
      >
        <p class="text-[0.6rem] font-mono uppercase tracking-[0.3em] text-[var(--np-accent)]">Status</p>
        <h2 class="mt-1 text-base font-bold text-[var(--np-text)]">
          {{ totalDevices === 0
            ? "Inventory is empty"
            : `${onlineDevices} of ${totalDevices} devices responding · ${zoneCount} zone${zoneCount === 1 ? "" : "s"}` }}
        </h2>
        <p class="mt-1 max-w-xl text-xs text-[var(--np-text-muted)]">
          {{ totalDevices === 0
            ? "Run a sweep to see what is on this network."
            : "Availability is based on device sightings collected in the last ten minutes." }}
          <span v-if="currentNetwork">
            Watching <strong class="text-[var(--np-text)]">{{ currentNetwork.name }}</strong>
            ({{ currentNetwork.cidr }}) — other networks keep their own inventory.
          </span>
        </p>
        <div class="mt-4 flex flex-wrap gap-2">
          <button
            class="np-cyber-btn px-4 py-2 text-[0.65rem] uppercase tracking-wider"
            :disabled="discovering"
            @click="runDiscovery"
          >
            {{ discovering ? "Sweeping…" : "Run discovery sweep" }}
          </button>
          <button
            class="np-cyber-btn px-4 py-2 text-[0.65rem] uppercase tracking-wider"
            @click="router.push('/topology')"
          >
            Topology
          </button>
          <button
            class="np-cyber-btn px-4 py-2 text-[0.65rem] uppercase tracking-wider"
            @click="router.push('/devices')"
          >
            Inventory
          </button>
        </div>
        <p v-if="sweepNote" class="mt-3 text-[0.65rem] text-[var(--np-text-muted)]">{{ sweepNote }}</p>
      </article>

      <article class="glass-card glass-card--static p-5">
        <p class="text-[0.6rem] font-mono uppercase tracking-widest text-[var(--np-text-dim)]">Attention</p>
        <h2 class="mt-1 text-sm font-bold text-[var(--np-text)]">Not responding</h2>
        <ul class="mt-3 space-y-2">
          <li
            v-for="row in notResponding"
            :key="row.id"
            class="flex items-center justify-between gap-3 text-xs"
          >
            <span class="flex min-w-0 items-center gap-2 text-[var(--np-text-muted)]">
              <span class="h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--np-danger)]" />
              <span class="truncate">{{ labelFor(row) }}</span>
            </span>
            <span class="shrink-0 font-mono text-[0.65rem] text-[var(--np-text-dim)] tabular-nums">{{ row.ip_address }}</span>
          </li>
          <li v-if="notResponding.length === 0 && pingSummary" class="text-xs text-[var(--np-text-dim)]">
            Every checked device answered.
          </li>
          <li v-else-if="!pingSummary && !pingChecking" class="text-xs text-[var(--np-text-dim)]">
            Run a ping check to see which devices are silent.
          </li>
        </ul>
      </article>
    </section>
  </div>
</template>

<style scoped>
.np-metric-tile {
  transition: border-color 0.15s ease, transform 0.15s ease;
}
.np-metric-tile:hover {
  transform: translateY(-1px);
}
</style>
