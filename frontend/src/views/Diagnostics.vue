<script setup lang="ts">
import axios from "axios";
import { computed, onBeforeUnmount, onMounted, ref } from "vue";

interface Props {
  theme: "nightshade" | "sysadmin";
  isAdmin: boolean;
}

const props = defineProps<Props>();
const isNightshade = computed(() => props.theme === "nightshade");

// ── Health summary ──────────────────────────────────────────────────────────
type NetworkHealth = {
  status: string;
  health_score: number;
  total_devices: number;
  online_devices: number;
  offline_devices: number;
  critical_issues: number;
  warning_issues: number;
  bottlenecks: Bottleneck[];
  last_updated: string;
};

type Bottleneck = {
  device_id: number;
  hostname: string;
  ip_address: string;
  device_type: string;
  issues: string[];
  severity: string;
  recommendation: string;
};

// ── Pulse path data ─────────────────────────────────────────────────────────
type PulseTarget = {
  target: string;
  label: string;
  latency_ms: number | null;
  jitter_ms: number | null;
  packet_loss_pct: number | null;
};

const health = ref<NetworkHealth | null>(null);
const healthLoading = ref(false);
const healthError = ref<string | null>(null);

const pulseTargets = ref<PulseTarget[]>([]);
const pulseLoading = ref(false);

const tcpHost = ref("");
const tcpPort = ref(80);
const tcpTesting = ref(false);
const tcpResult = ref<{ latency_ms: number | null; error: string | null } | null>(null);

// ── Path diagnosis ──────────────────────────────────────────────────────────
type HopStatus = {
  label: string;
  latency_ms: number | null;
  packet_loss_pct: number | null;
  jitter_ms: number | null;
  status: "ok" | "warning" | "critical" | "unknown";
  note: string;
};

const hops = computed((): HopStatus[] => {
  return pulseTargets.value.map((t) => {
    const lat = t.latency_ms;
    const loss = t.packet_loss_pct ?? 0;
    let status: "ok" | "warning" | "critical" | "unknown" = "unknown";
    let note = "No data yet.";

    if (lat !== null) {
      const isGateway = t.label === "Gateway";
      const highLat = isGateway ? lat > 30 : lat > 120;
      const critLat = isGateway ? lat > 60 : lat > 200;

      if (critLat || loss > 10) {
        status = "critical";
        note = loss > 10 ? `Packet loss ${loss.toFixed(1)}%` : `High latency ${lat.toFixed(0)} ms`;
      } else if (highLat || loss > 2) {
        status = "warning";
        note = loss > 2 ? `Elevated loss ${loss.toFixed(1)}%` : `Elevated latency ${lat.toFixed(0)} ms`;
      } else {
        status = "ok";
        note = `${lat.toFixed(0)} ms, ${loss.toFixed(1)}% loss`;
      }
    }

    return {
      label: t.label,
      latency_ms: t.latency_ms,
      packet_loss_pct: t.packet_loss_pct,
      jitter_ms: t.jitter_ms,
      status,
      note,
    };
  });
});

const pathConclusion = computed((): { level: "ok" | "warning" | "critical"; text: string } => {
  if (!hops.value.length) return { level: "ok", text: "No path data available yet — wait for the latency monitor to collect samples." };

  const gateway = hops.value.find((h) => h.label === "Gateway");
  const isp = hops.value.find((h) => h.label === "ISP Edge");
  const cloudflare = hops.value.find((h) => h.label === "Cloudflare");

  if (gateway?.status === "critical") {
    return {
      level: "critical",
      text: "⚠ Local network issue detected. High latency or packet loss reaching the gateway suggests a problem with your router, LAN switch, or physical cabling. Check switch port errors and router CPU load.",
    };
  }
  if (isp?.status === "critical") {
    return {
      level: "critical",
      text: "⚠ WAN/ISP issue detected. Your gateway is reachable but the ISP edge is degraded. Check the WAN interface on your router and consider contacting your ISP.",
    };
  }
  if (cloudflare?.status === "critical") {
    return {
      level: "warning",
      text: "⚠ Internet routing issue detected beyond the ISP. Gateway and ISP are healthy but internet destinations show high latency or loss. This is usually a peering or BGP routing issue.",
    };
  }
  if (gateway?.status === "warning" || isp?.status === "warning") {
    return {
      level: "warning",
      text: "Network is operating but with elevated latency or minor packet loss. Monitor for deterioration. Check router QoS, interface errors, and bandwidth utilization.",
    };
  }
  return {
    level: "ok",
    text: "All monitored hops are healthy. Gateway, ISP, and internet routing are operating within normal thresholds.",
  };
});

// ── TCP connection test ─────────────────────────────────────────────────────
async function runTcpTest(): Promise<void> {
  const host = tcpHost.value.trim();
  if (!host) return;

  tcpTesting.value = true;
  tcpResult.value = null;

  try {
    const { data } = await axios.post<{ latency_ms: number | null; error: string | null }>(
      "/api/insights/tcp-probe",
      { host, port: tcpPort.value }
    );
    tcpResult.value = data;
  } catch (err: any) {
    tcpResult.value = {
      latency_ms: null,
      error: err?.response?.data?.detail ?? "TCP probe failed — check backend logs.",
    };
  } finally {
    tcpTesting.value = false;
  }
}

// ── Data loaders ────────────────────────────────────────────────────────────
async function loadHealth(): Promise<void> {
  healthLoading.value = true;
  healthError.value = null;
  try {
    const { data } = await axios.get<NetworkHealth>("/api/insights/health");
    health.value = data;
  } catch {
    healthError.value = "Failed to load network health summary.";
  } finally {
    healthLoading.value = false;
  }
}

async function loadPulse(): Promise<void> {
  pulseLoading.value = true;
  try {
    const { data } = await axios.get<{ targets: PulseTarget[] }>("/api/metrics/pulse-latest");
    pulseTargets.value = data.targets ?? [];
  } catch {
    // silent
  } finally {
    pulseLoading.value = false;
  }
}

function refresh(): void {
  loadHealth();
  loadPulse();
}

let timer: number | undefined;
onMounted(() => {
  refresh();
  timer = window.setInterval(refresh, 30_000);
});
onBeforeUnmount(() => {
  if (timer !== undefined) clearInterval(timer);
});

function statusColor(status: string): string {
  if (status === "critical" || status === "critical") return "text-rose-400";
  if (status === "warning" || status === "degraded") return "text-amber-400";
  return "text-emerald-400";
}

function statusDot(status: string): string {
  if (status === "critical") return "bg-rose-500";
  if (status === "warning" || status === "degraded") return "bg-amber-500";
  if (status === "ok" || status === "healthy") return "bg-emerald-500";
  return "bg-slate-500";
}

function severityBadge(severity: string): string {
  if (severity === "critical") return "bg-rose-500/15 text-rose-400 border border-rose-500/30";
  if (severity === "warning") return "bg-amber-500/15 text-amber-400 border border-amber-500/30";
  return "bg-slate-500/15 text-slate-300 border border-slate-500/30";
}
</script>

<template>
  <div class="space-y-5">
    <!-- Page header -->
    <header class="flex items-center justify-between">
      <div>
        <h1
          class="text-xl font-bold tracking-wide"
          :style="{ color: 'var(--np-accent-primary)', fontFamily: isNightshade ? '\'Orbitron\', sans-serif' : '\'Inter\', system-ui, sans-serif' }"
        >
          Diagnostics
        </h1>
        <p class="text-xs text-[var(--np-muted-text)]">
          Network health · Path analysis · Issue localisation
        </p>
      </div>
      <button
        type="button"
        @click="refresh"
        class="flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs transition-colors"
        style="border-color: var(--np-border); color: var(--np-muted-text)"
        :class="healthLoading ? 'opacity-50 cursor-not-allowed' : 'hover:text-[var(--np-text)] hover:bg-white/5'"
        :disabled="healthLoading"
      >
        <svg class="w-3.5 h-3.5" :class="{ 'animate-spin': healthLoading }" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
        </svg>
        Refresh
      </button>
    </header>

    <!-- Health Overview Row -->
    <div class="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <template v-if="health">
        <!-- Score -->
        <div class="np-panel p-4 flex flex-col gap-1">
          <span class="text-[0.6rem] uppercase tracking-widest text-[var(--np-muted-text)]">Health Score</span>
          <div class="flex items-baseline gap-2">
            <span
              class="text-3xl font-bold"
              :class="statusColor(health.status)"
            >{{ health.health_score }}</span>
            <span class="text-sm text-[var(--np-muted-text)]">/ 100</span>
          </div>
          <div class="flex items-center gap-1.5 mt-1">
            <span class="w-2 h-2 rounded-full" :class="statusDot(health.status)"></span>
            <span class="text-[0.7rem] uppercase tracking-wider" :class="statusColor(health.status)">{{ health.status }}</span>
          </div>
        </div>
        <!-- Devices -->
        <div class="np-panel p-4 flex flex-col gap-1">
          <span class="text-[0.6rem] uppercase tracking-widest text-[var(--np-muted-text)]">Devices</span>
          <div class="flex items-baseline gap-2">
            <span class="text-3xl font-bold text-[var(--np-text)]">{{ health.total_devices }}</span>
            <span class="text-sm text-[var(--np-muted-text)]">total</span>
          </div>
          <div class="flex gap-3 text-[0.7rem] mt-1">
            <span class="text-emerald-400">{{ health.online_devices }} online</span>
            <span v-if="health.offline_devices" class="text-rose-400">{{ health.offline_devices }} offline</span>
          </div>
        </div>
        <!-- Issues -->
        <div class="np-panel p-4 flex flex-col gap-1">
          <span class="text-[0.6rem] uppercase tracking-widest text-[var(--np-muted-text)]">Active Issues</span>
          <div class="flex items-baseline gap-2">
            <span
              class="text-3xl font-bold"
              :class="health.critical_issues ? 'text-rose-400' : health.warning_issues ? 'text-amber-400' : 'text-emerald-400'"
            >{{ health.critical_issues + health.warning_issues }}</span>
          </div>
          <div class="flex gap-3 text-[0.7rem] mt-1">
            <span v-if="health.critical_issues" class="text-rose-400">{{ health.critical_issues }} critical</span>
            <span v-if="health.warning_issues" class="text-amber-400">{{ health.warning_issues }} warning</span>
            <span v-if="!health.critical_issues && !health.warning_issues" class="text-emerald-400">None detected</span>
          </div>
        </div>
        <!-- Last Updated -->
        <div class="np-panel p-4 flex flex-col gap-1">
          <span class="text-[0.6rem] uppercase tracking-widest text-[var(--np-muted-text)]">Last Updated</span>
          <span class="text-[0.75rem] text-[var(--np-text)] mt-1">
            {{ new Date(health.last_updated).toLocaleTimeString() }}
          </span>
          <span class="text-[0.65rem] text-[var(--np-muted-text)] mt-0.5">Auto-refreshes every 30s</span>
        </div>
      </template>
      <template v-else-if="healthLoading">
        <div class="np-panel p-4 col-span-4 text-center text-xs text-[var(--np-muted-text)]">
          Loading network health…
        </div>
      </template>
      <template v-else-if="healthError">
        <div class="np-panel p-4 col-span-4 text-center text-xs text-rose-300">{{ healthError }}</div>
      </template>
    </div>

    <!-- Path Analysis + Bottlenecks row -->
    <div class="grid gap-4 xl:grid-cols-2">

      <!-- Path Diagnosis -->
      <div class="np-panel p-4 space-y-3">
        <header class="flex items-center gap-2">
          <svg class="w-4 h-4" style="color: var(--np-accent-primary)" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.141 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0" />
          </svg>
          <span class="text-sm font-semibold" style="color: var(--np-accent-primary)">Path Analysis — Where Is the Problem?</span>
        </header>

        <!-- Hop chain -->
        <div class="space-y-2">
          <div
            v-for="(hop, idx) in hops"
            :key="hop.label"
            class="flex items-start gap-3 rounded-md border p-3"
            :class="{
              'border-emerald-500/30 bg-emerald-500/5': hop.status === 'ok',
              'border-amber-500/30 bg-amber-500/5': hop.status === 'warning',
              'border-rose-500/30 bg-rose-500/10': hop.status === 'critical',
              'border-[var(--np-border)] bg-black/20': hop.status === 'unknown',
            }"
          >
            <!-- Icon / connector -->
            <div class="flex flex-col items-center gap-1">
              <span
                class="w-3 h-3 rounded-full shrink-0 mt-0.5"
                :class="{
                  'bg-emerald-500': hop.status === 'ok',
                  'bg-amber-500': hop.status === 'warning',
                  'bg-rose-500 animate-pulse': hop.status === 'critical',
                  'bg-slate-500': hop.status === 'unknown',
                }"
              ></span>
              <div v-if="idx < hops.length - 1" class="w-0.5 h-3 bg-[var(--np-border)]"></div>
            </div>
            <div class="flex-1 min-w-0">
              <div class="flex items-center justify-between gap-2">
                <span class="text-[0.75rem] font-semibold text-[var(--np-text)]">{{ hop.label }}</span>
                <span
                  class="text-[0.65rem] uppercase tracking-wide"
                  :class="{
                    'text-emerald-400': hop.status === 'ok',
                    'text-amber-400': hop.status === 'warning',
                    'text-rose-400': hop.status === 'critical',
                    'text-[var(--np-muted-text)]': hop.status === 'unknown',
                  }"
                >
                  {{ hop.status === 'unknown' ? 'No data' : hop.status.toUpperCase() }}
                </span>
              </div>
              <p class="text-[0.7rem] text-[var(--np-muted-text)] mt-0.5">{{ hop.note }}</p>
              <div v-if="hop.latency_ms !== null" class="flex gap-3 mt-1 text-[0.65rem] text-[var(--np-muted-text)]">
                <span>Latency: <strong class="text-[var(--np-text)]">{{ hop.latency_ms.toFixed(1) }} ms</strong></span>
                <span v-if="hop.jitter_ms !== null">Jitter: <strong class="text-[var(--np-text)]">{{ hop.jitter_ms.toFixed(1) }} ms</strong></span>
                <span v-if="hop.packet_loss_pct !== null">Loss: <strong class="text-[var(--np-text)]">{{ hop.packet_loss_pct.toFixed(1) }}%</strong></span>
              </div>
            </div>
          </div>

          <p v-if="!hops.length && !pulseLoading" class="text-[0.7rem] text-[var(--np-muted-text)] text-center py-4">
            Path data will appear after the latency monitor collects its first samples (every 15 s).
          </p>
        </div>

        <!-- Conclusion banner -->
        <div
          v-if="hops.length"
          class="rounded-md border px-3 py-2 text-[0.72rem]"
          :class="{
            'border-emerald-500/40 bg-emerald-500/5 text-emerald-300': pathConclusion.level === 'ok',
            'border-amber-500/40 bg-amber-500/5 text-amber-300': pathConclusion.level === 'warning',
            'border-rose-500/40 bg-rose-500/10 text-rose-300': pathConclusion.level === 'critical',
          }"
        >
          {{ pathConclusion.text }}
        </div>

        <!-- TCP Probe -->
        <div class="border-t pt-3 space-y-2" style="border-color: var(--np-border)">
          <h3 class="text-[0.7rem] uppercase tracking-widest" style="color: var(--np-accent-primary)">
            TCP Connection Probe
          </h3>
          <p class="text-[0.65rem] text-[var(--np-muted-text)]">
            Test TCP handshake time to any host:port — detects server-level vs. network-level delays.
          </p>
          <div class="flex gap-2">
            <input
              v-model="tcpHost"
              type="text"
              placeholder="host or IP"
              class="flex-1 rounded-md border bg-black/60 px-2 py-1 text-[0.75rem] focus:outline-none focus:ring-1"
              style="border-color: var(--np-border); color: var(--np-text)"
              @keyup.enter="runTcpTest"
            />
            <input
              v-model.number="tcpPort"
              type="number"
              min="1"
              max="65535"
              placeholder="port"
              class="w-20 rounded-md border bg-black/60 px-2 py-1 text-[0.75rem] focus:outline-none focus:ring-1"
              style="border-color: var(--np-border); color: var(--np-text)"
            />
            <button
              type="button"
              @click="runTcpTest"
              :disabled="tcpTesting || !tcpHost.trim()"
              class="np-cyber-btn rounded-md px-3 py-1 text-[0.7rem] font-medium disabled:opacity-50 whitespace-nowrap"
            >
              {{ tcpTesting ? 'Testing…' : 'Probe TCP' }}
            </button>
          </div>
          <div
            v-if="tcpResult"
            class="rounded-md border px-3 py-2 text-[0.72rem]"
            :class="tcpResult.error
              ? 'border-rose-500/40 bg-rose-500/10 text-rose-300'
              : 'border-emerald-500/40 bg-emerald-500/5 text-emerald-300'"
          >
            <template v-if="tcpResult.error">
              ✗ {{ tcpResult.error }}
            </template>
            <template v-else>
              ✓ TCP handshake to <strong>{{ tcpHost }}:{{ tcpPort }}</strong> completed in
              <strong>{{ tcpResult.latency_ms?.toFixed(1) }} ms</strong>
              <span class="block mt-0.5 text-[0.65rem]" :class="(tcpResult.latency_ms ?? 0) > 200 ? 'text-amber-400' : 'text-[var(--np-muted-text)]'">
                {{ (tcpResult.latency_ms ?? 0) > 200 ? 'High TCP latency — possible server-side congestion or high server load.' : 'Connection time is within normal range.' }}
              </span>
            </template>
          </div>
        </div>
      </div>

      <!-- Bottlenecks -->
      <div class="np-panel p-4 space-y-3">
        <header class="flex items-center gap-2">
          <svg class="w-4 h-4" style="color: var(--np-accent-primary)" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <span class="text-sm font-semibold" style="color: var(--np-accent-primary)">Interface Bottlenecks</span>
          <span class="text-[0.6rem] text-[var(--np-muted-text)] ml-1">(SNMP-based, last 5 min)</span>
        </header>

        <div v-if="health?.bottlenecks?.length" class="space-y-3">
          <div
            v-for="b in health.bottlenecks"
            :key="b.device_id"
            class="rounded-md border p-3 space-y-1.5"
            :class="{
              'border-rose-500/30 bg-rose-500/5': b.severity === 'critical',
              'border-amber-500/30 bg-amber-500/5': b.severity === 'warning',
            }"
          >
            <div class="flex items-center justify-between gap-2">
              <div>
                <span class="text-[0.75rem] font-semibold text-[var(--np-text)]">{{ b.hostname }}</span>
                <span class="text-[0.65rem] text-[var(--np-muted-text)] ml-2 font-mono">{{ b.ip_address }}</span>
              </div>
              <span class="rounded px-2 py-0.5 text-[0.6rem] uppercase tracking-wider" :class="severityBadge(b.severity)">
                {{ b.severity }}
              </span>
            </div>
            <ul class="space-y-0.5">
              <li v-for="(issue, i) in b.issues" :key="i" class="text-[0.7rem] text-[var(--np-muted-text)] flex items-start gap-1">
                <span class="mt-0.5 w-1.5 h-1.5 rounded-full shrink-0" :class="b.severity === 'critical' ? 'bg-rose-500' : 'bg-amber-500'"></span>
                {{ issue }}
              </li>
            </ul>
            <p class="text-[0.68rem] text-[var(--np-muted-text)] italic">↳ {{ b.recommendation }}</p>
          </div>
        </div>

        <div v-else-if="healthLoading" class="text-[0.7rem] text-[var(--np-muted-text)] py-4 text-center">
          Loading bottleneck data…
        </div>

        <div v-else class="rounded-md border border-emerald-500/20 bg-emerald-500/5 px-3 py-4 text-center">
          <p class="text-[0.75rem] text-emerald-400 font-semibold">No interface bottlenecks detected</p>
          <p class="text-[0.65rem] text-[var(--np-muted-text)] mt-1">
            Enable SNMP polling on devices to get real-time bandwidth utilisation data.
          </p>
        </div>

        <!-- Interpretation guide -->
        <div class="border-t pt-3 space-y-2" style="border-color: var(--np-border)">
          <h3 class="text-[0.7rem] uppercase tracking-widest" style="color: var(--np-accent-primary)">
            How to Read This
          </h3>
          <dl class="space-y-2 text-[0.7rem] text-[var(--np-muted-text)]">
            <div>
              <dt class="font-semibold text-rose-400 inline">High gateway latency (>50 ms):</dt>
              <dd class="inline ml-1">Router overloaded or LAN issue. Check CPU, ARP table size, or switch errors.</dd>
            </div>
            <div>
              <dt class="font-semibold text-amber-400 inline">ISP latency spike, gateway fine:</dt>
              <dd class="inline ml-1">WAN/ISP congestion. Check your router WAN interface and call ISP.</dd>
            </div>
            <div>
              <dt class="font-semibold text-amber-400 inline">High jitter:</dt>
              <dd class="inline ml-1">Queue congestion — implement QoS prioritisation (VoIP/critical traffic).</dd>
            </div>
            <div>
              <dt class="font-semibold text-sky-400 inline">High TCP probe latency vs low ICMP:</dt>
              <dd class="inline ml-1">Server-side delay (app layer, DB slow queries, overloaded service).</dd>
            </div>
            <div>
              <dt class="font-semibold text-emerald-400 inline">Packet loss at gateway only:</dt>
              <dd class="inline ml-1">LAN issue — duplex mismatch, bad cable, or overloaded switch port.</dd>
            </div>
          </dl>
        </div>
      </div>

    </div>
  </div>
</template>
