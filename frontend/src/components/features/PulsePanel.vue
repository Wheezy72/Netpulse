<script setup lang="ts">
import axios from "axios";
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import { useWebSocket } from "../../composables/useWebSocket";

type InternetHealthPoint = {
  timestamp: string;
  value: number;
};

type PulseTargetSummary = {
  target: string;
  label: string;
  latency_ms: number | null;
  jitter_ms: number | null;
  packet_loss_pct: number | null;
};

const pulseLoading = ref(false);
const pulseError = ref<string | null>(null);
const internetHealthPoints = ref<InternetHealthPoint[]>([]);
const pulseChartOption = ref<any>({});
const pulseTargets = ref<PulseTargetSummary[]>([]);

const isDownloadingReport = ref(false);

const liveMetricsEnabled = ref(true);
const liveLatency = ref<number | null>(null);
const liveJitter = ref<number | null>(null);
const livePacketLoss = ref<number | null>(null);

const { connect: connectMetricsWs, disconnect: disconnectMetricsWs, connected: wsConnected } = useWebSocket({
  onMessage(payload) {
    const data = (payload as any);
    if (data.event === "metrics" && data.data) {
      const d = data.data;
      liveLatency.value = d.latency_ms;
      liveJitter.value = d.jitter_ms;
      livePacketLoss.value = d.packet_loss_pct;

      if (liveMetricsEnabled.value) {
        const point: InternetHealthPoint = {
          timestamp: d.timestamp,
          value: d.internet_health,
        };
        internetHealthPoints.value = [
          ...internetHealthPoints.value.slice(-29),
          point,
        ];
        pulseChartOption.value = buildPulseChartOption(internetHealthPoints.value);
      }
    }
  },
});

const isSysAdmin = ref(false);

function updateThemeDetection() {
  isSysAdmin.value = document.body.classList.contains("theme-sysadmin");
}

const latestInternetHealth = computed(() => {
  if (!internetHealthPoints.value.length) return 0;
  return internetHealthPoints.value[internetHealthPoints.value.length - 1].value;
});

type DiagnosisResult = {
  level: "ok" | "warning" | "critical";
  where: string;
  detail: string;
  icon: string;
};

const pathDiagnosis = computed((): DiagnosisResult | null => {
  if (!pulseTargets.value.length) return null;

  const gateway = pulseTargets.value.find((t) => t.label === "Gateway");
  const isp = pulseTargets.value.find((t) => t.label === "ISP Edge");
  const cloudflare = pulseTargets.value.find((t) => t.label === "Cloudflare");

  const gwLat = gateway?.latency_ms ?? null;
  const gwLoss = gateway?.packet_loss_pct ?? 0;
  const ispLat = isp?.latency_ms ?? null;
  const ispLoss = isp?.packet_loss_pct ?? 0;
  const cfLat = cloudflare?.latency_ms ?? null;
  const cfLoss = cloudflare?.packet_loss_pct ?? 0;

  // Local network / router problem
  if (gwLat !== null && gwLat > 50) {
    return {
      level: "critical",
      where: "Local Network / Router",
      detail: `High gateway latency (${gwLat.toFixed(0)} ms). Check your router, LAN switches, or cabling.`,
      icon: "🔴",
    };
  }
  if (gwLoss > 5) {
    return {
      level: "critical",
      where: "Local Network / Router",
      detail: `Packet loss to gateway (${gwLoss.toFixed(1)}%). Possible faulty cable, switch port error, or duplex mismatch.`,
      icon: "🔴",
    };
  }

  // ISP / WAN problem
  if (ispLat !== null && gwLat !== null && ispLat - gwLat > 80) {
    return {
      level: "critical",
      where: "ISP / WAN Link",
      detail: `ISP latency ${ispLat.toFixed(0)} ms vs gateway ${gwLat.toFixed(0)} ms. Likely ISP congestion or WAN link degradation.`,
      icon: "🟠",
    };
  }
  if (ispLoss > 5) {
    return {
      level: "critical",
      where: "ISP / WAN Link",
      detail: `Packet loss on WAN path (${ispLoss.toFixed(1)}%). Contact your ISP or check the WAN interface on the router.`,
      icon: "🟠",
    };
  }

  // Internet / DNS / remote routing
  if (cfLat !== null && ispLat !== null && cfLat - ispLat > 80) {
    return {
      level: "warning",
      where: "Internet Routing / Remote Server",
      detail: `Extra latency beyond ISP (${(cfLat - ispLat).toFixed(0)} ms to Cloudflare). Could be internet congestion or CDN routing.`,
      icon: "🟡",
    };
  }
  if (cfLoss > 5) {
    return {
      level: "warning",
      where: "Internet / Remote Server",
      detail: `Packet loss to Cloudflare DNS (${cfLoss.toFixed(1)}%). Check upstream routing or try alternate DNS.`,
      icon: "🟡",
    };
  }

  // Mild warning from health score
  if (latestInternetHealth.value < 80 && latestInternetHealth.value > 0) {
    return {
      level: "warning",
      where: "Network",
      detail: `Health score at ${latestInternetHealth.value.toFixed(0)}% — elevated latency or jitter detected. Monitor closely.`,
      icon: "🟡",
    };
  }

  if (latestInternetHealth.value >= 80) {
    return {
      level: "ok",
      where: "All Hops",
      detail: "All monitored hops look healthy. Gateway, ISP, and internet routing are within normal thresholds.",
      icon: "🟢",
    };
  }

  return null;
});

function buildPulseChartOption(points: InternetHealthPoint[]): any {
  const categories = points.map((p) =>
    p.timestamp.split("T")[1]?.slice(0, 8) ?? p.timestamp
  );
  const values = points.map((p) => p.value);

  const isSysAdminTheme = document.body.classList.contains("theme-sysadmin");

  const axisLineColor = isSysAdminTheme ? "#9ca3af" : "#14b8a655";
  const axisLabelColor = isSysAdminTheme ? "#4b5563" : "#99f6e4";
  const splitLineColor = isSysAdminTheme ? "#e5e7eb" : "#134e4a5";
  const lineColor = isSysAdminTheme ? "#f59e0b" : "#22c55e";
  const areaTop = isSysAdminTheme
    ? "rgba(245,158,11,0.35)"
    : "rgba(34,197,94,0.6)";
  const areaBottom = isSysAdminTheme
    ? "rgba(255,255,255,0.0)"
    : "rgba(15,23,42,0.1)";

  return {
    animation: true,
    animationDuration: 1000,
    animationEasing: "cubicOut",
    animationDurationUpdate: 700,
    animationEasingUpdate: "cubicOut",
    grid: {
      left: 40,
      right: 10,
      top: 20,
      bottom: 25,
    },
    tooltip: {
      trigger: "axis",
      axisPointer: {
        type: "line",
      },
    },
    xAxis: {
      type: "category",
      data: categories,
      boundaryGap: false,
      axisLine: { lineStyle: { color: axisLineColor } },
      axisLabel: {
        color: axisLabelColor,
        fontSize: 10,
      },
    },
    yAxis: {
      type: "value",
      min: 0,
      max: 100,
      axisLine: { lineStyle: { color: axisLineColor } },
      splitLine: { lineStyle: { color: splitLineColor } },
      axisLabel: {
        color: axisLabelColor,
        fontSize: 10,
        formatter: "{value}%",
      },
    },
    series: [
      {
        name: "Internet Health",
        type: "line",
        smooth: true,
        symbol: "none",
        data: values,
        lineStyle: {
          color: lineColor,
          width: 2,
        },
        areaStyle: {
          color: {
            type: "linear",
            x: 0,
            y: 0,
            x2: 0,
            y2: 1,
            colorStops: [
              { offset: 0, color: areaTop },
              { offset: 1, color: areaBottom },
            ],
          },
        },
      },
    ],
  };
}

async function loadPulse(): Promise<void> {
  pulseError.value = null;
  pulseLoading.value = true;

  try {
    const [healthRes, pulseRes] = await Promise.all([
      axios.get<{ points: InternetHealthPoint[] }>(
        "/api/metrics/internet-health-recent"
      ),
      axios.get<{ targets: PulseTargetSummary[] }>("/api/metrics/pulse-latest"),
    ]);

    internetHealthPoints.value = healthRes.data.points ?? [];
    pulseChartOption.value = buildPulseChartOption(internetHealthPoints.value);
    pulseTargets.value = pulseRes.data.targets ?? [];
  } catch {
    pulseError.value = "Failed to load Pulse metrics.";
    internetHealthPoints.value = [];
    pulseTargets.value = [];
  } finally {
    pulseLoading.value = false;
  }
}

function connectMetricsSocket(): void {
  const token = localStorage.getItem("np-token");
  if (!token) return;

  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/api/ws/metrics?token=${encodeURIComponent(token)}`;
  connectMetricsWs(wsUrl);
}

async function downloadReport(): Promise<void> {
  isDownloadingReport.value = true;
  try {
    const response = await axios.post(
      "/api/reports/generate",
      {
        report_type: "network_summary",
        title: "NetPulse Network Summary Report",
        include_devices: true,
        include_metrics: true,
        include_alerts: true,
        date_range_days: 7,
      },
      {
        responseType: "blob",
      }
    );

    const contentDisposition = response.headers["content-disposition"];
    let filename = "NetPulse_Report.pdf";
    if (contentDisposition) {
      const match = contentDisposition.match(/filename="?([^";\n]+)"?/);
      if (match && match[1]) {
        filename = match[1];
      }
    }

    const blob = new Blob([response.data], { type: "application/pdf" });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
  } catch (err) {
    console.error("Failed to download report:", err);
  } finally {
    isDownloadingReport.value = false;
  }
}

let pulseInterval: number | undefined;
let themeObserver: MutationObserver | undefined;

onMounted(() => {
  updateThemeDetection();
  themeObserver = new MutationObserver(() => updateThemeDetection());
  themeObserver.observe(document.body, { attributes: true, attributeFilter: ['class'] });
  loadPulse();
  connectMetricsSocket();

  pulseInterval = window.setInterval(() => {
    if (!wsConnected.value) {
      loadPulse();
    }
  }, 30000);
});

onBeforeUnmount(() => {
  if (pulseInterval !== undefined) {
    clearInterval(pulseInterval);
  }
  themeObserver?.disconnect();
  liveMetricsEnabled.value = false;
  disconnectMetricsWs();
});
</script>

<template>
  <section
    class="np-panel relative grid gap-4 p-4 overflow-hidden"
  >
    <header class="np-panel-header">
      <div class="flex items-center gap-2">
        <span class="np-panel-title">Pulse: Internet Health</span>
        <span class="text-[0.6rem] uppercase tracking-[0.18em] text-slate-400 dark:text-teal-300">
          Latency · Jitter · Packet Loss
        </span>
      </div>
      <div class="flex items-center gap-3 text-xs text-slate-400 dark:text-teal-300">
        <span>Gateway / ISP / Cloudflare</span>
        <span class="h-1 w-10 rounded-full" :class="isSysAdmin ? 'bg-amber-400/60' : 'bg-emerald-400/60'"></span>
        <button
          @click="downloadReport"
          :disabled="isDownloadingReport"
          class="ml-2 flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-[0.7rem] font-medium transition-colors
                 border-amber-500/15 dark:border-teal-500/20 bg-gray-900/50 dark:bg-slate-900/50 text-slate-400 dark:text-teal-300 hover:text-slate-100 dark:hover:text-sky-100
                 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <svg v-if="!isDownloadingReport" xmlns="http://www.w3.org/2000/svg" class="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
          <svg v-else xmlns="http://www.w3.org/2000/svg" class="h-3.5 w-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
          {{ isDownloadingReport ? 'Generating...' : 'Download Report' }}
        </button>
      </div>
    </header>

    <div class="grid gap-4 md:grid-cols-4">
      <div class="md:col-span-3">
        <div
          class="relative h-48 w-full rounded-md border bg-black/40 border-amber-500/15 dark:border-teal-500/20"
        >
          <v-chart
            v-if="!pulseLoading && internetHealthPoints.length"
            :option="pulseChartOption"
            autoresize
            class="h-48 w-full"
          />
          <div
            v-else-if="pulseLoading"
            class="absolute inset-0 flex items-center justify-center text-xs text-slate-400 dark:text-teal-300"
          >
            Loading Internet Health...
          </div>
          <div
            v-else
            class="absolute inset-0 flex flex-col items-center justify-center gap-2 text-center px-4"
          >
            <svg xmlns="http://www.w3.org/2000/svg" class="w-8 h-8 text-amber-500 dark:text-teal-500 opacity-40" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" />
            </svg>
            <span class="text-xs text-slate-400 dark:text-teal-300">Collecting network data...</span>
            <span class="text-[0.65rem] text-slate-400 dark:text-teal-300 opacity-60">The latency monitor runs every 15 seconds. Charts will appear once enough data points are collected.</span>
          </div>
        </div>
        <p v-if="pulseError" class="mt-2 text-[0.7rem] text-rose-300">
          {{ pulseError }}
        </p>
      </div>

      <div class="flex flex-col gap-3 text-xs">
        <div class="rounded-md border bg-black/50 p-3" :class="isSysAdmin ? 'border-amber-400/40' : 'border-emerald-400/40'">
          <div class="flex items-baseline justify-between">
            <span class="text-[0.6rem] uppercase tracking-[0.18em]" :class="isSysAdmin ? 'text-amber-300' : 'text-emerald-300'">
              Internet Health
            </span>
            <span class="text-lg font-semibold" :class="isSysAdmin ? 'text-amber-300' : 'text-emerald-300'">
              {{ latestInternetHealth.toFixed(0) }}%
            </span>
          </div>
        </div>

        <div v-if="liveLatency !== null" class="rounded-md border bg-black/40 p-2 border-amber-500/15 dark:border-teal-500/20">
          <div class="flex items-center gap-1 mb-2">
            <span class="w-2 h-2 rounded-full animate-pulse" :class="isSysAdmin ? 'bg-green-500' : 'bg-emerald-400'"></span>
            <span class="text-[0.6rem] uppercase tracking-widest text-slate-400 dark:text-teal-300">Live</span>
          </div>
          <div class="grid grid-cols-3 gap-2 text-center">
            <div>
              <div class="text-sm font-semibold text-slate-100 dark:text-sky-100">{{ liveLatency?.toFixed(1) ?? '--' }}</div>
              <div class="text-[0.55rem] text-slate-400 dark:text-teal-300">Latency ms</div>
            </div>
            <div>
              <div class="text-sm font-semibold text-slate-100 dark:text-sky-100">{{ liveJitter?.toFixed(1) ?? '--' }}</div>
              <div class="text-[0.55rem] text-slate-400 dark:text-teal-300">Jitter ms</div>
            </div>
            <div>
              <div class="text-sm font-semibold text-slate-100 dark:text-sky-100">{{ livePacketLoss?.toFixed(1) ?? '--' }}</div>
              <div class="text-[0.55rem] text-slate-400 dark:text-teal-300">Loss %</div>
            </div>
          </div>
        </div>

        <div class="space-y-2">
          <div
            v-for="t in pulseTargets"
            :key="t.target"
            class="rounded-md border bg-black/40 px-2 py-1.5 border-amber-500/15 dark:border-teal-500/20"
          >
            <div class="flex items-center justify-between">
              <span class="font-mono text-slate-100 dark:text-sky-100 text-[0.7rem]">
                {{ t.label }}
              </span>
              <span class="text-[0.7rem] text-slate-100 dark:text-sky-100">
                <template v-if="t.latency_ms != null">
                  {{ t.latency_ms.toFixed(1) }} ms
                </template>
                <template v-else>
                  n/a
                </template>
              </span>
            </div>
            <div
              class="mt-0.5 flex items-center justify-between text-[0.65rem] text-slate-400 dark:text-teal-300"
            >
              <span>
                Jitter:
                <template v-if="t.jitter_ms != null">
                  {{ t.jitter_ms.toFixed(1) }} ms
                </template>
                <template v-else>n/a</template>
              </span>
              <span>
                Loss:
                <template v-if="t.packet_loss_pct != null">
                  {{ t.packet_loss_pct.toFixed(1) }}%
                </template>
                <template v-else>n/a</template>
              </span>
            </div>
          </div>
          <p
            v-if="!pulseTargets.length && !pulseLoading && liveLatency === null"
            class="text-[0.7rem] text-slate-400 dark:text-teal-300"
          >
            Waiting for Pulse data from latency monitor...
          </p>
        </div>
      </div>
    </div>

    <!-- Path Diagnosis Banner -->
    <div
      v-if="pathDiagnosis"
      class="rounded-md border px-3 py-2 text-xs flex items-start gap-2"
      :class="{
        'border-emerald-500/40 bg-emerald-500/5': pathDiagnosis.level === 'ok',
        'border-amber-500/40 bg-amber-500/5': pathDiagnosis.level === 'warning',
        'border-rose-500/40 bg-rose-500/10': pathDiagnosis.level === 'critical',
      }"
    >
      <span class="shrink-0 text-base leading-none mt-0.5">{{ pathDiagnosis.icon }}</span>
      <div>
        <span
          class="font-semibold text-[0.7rem] uppercase tracking-wider"
          :class="{
            'text-emerald-400': pathDiagnosis.level === 'ok',
            'text-amber-400': pathDiagnosis.level === 'warning',
            'text-rose-400': pathDiagnosis.level === 'critical',
          }"
        >
          {{ pathDiagnosis.level === 'ok' ? 'All Clear' : 'Issue Detected' }}
          <span class="font-normal normal-case tracking-normal text-slate-400 dark:text-teal-300 ml-1">
            — {{ pathDiagnosis.where }}
          </span>
        </span>
        <p class="mt-0.5 text-[0.7rem] text-slate-400 dark:text-teal-300">{{ pathDiagnosis.detail }}</p>
      </div>
    </div>
  </section>
</template>
