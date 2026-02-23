<script setup lang="ts">
import axios from "axios";
import { computed, onBeforeUnmount, onMounted, ref } from "vue";

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

let metricsSocket: WebSocket | null = null;
const liveMetricsEnabled = ref(true);
const liveLatency = ref<number | null>(null);
const liveJitter = ref<number | null>(null);
const livePacketLoss = ref<number | null>(null);

const isSysAdmin = ref(false);

function updateThemeDetection() {
  isSysAdmin.value = document.body.classList.contains("theme-sysadmin");
}

const latestInternetHealth = computed(() => {
  if (!internetHealthPoints.value.length) return 0;
  return internetHealthPoints.value[internetHealthPoints.value.length - 1].value;
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
  if (metricsSocket) {
    metricsSocket.close();
    metricsSocket = null;
  }

  const token = localStorage.getItem("access_token");
  if (!token) return;

  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/api/ws/metrics?token=${encodeURIComponent(token)}`;

  try {
    const socket = new WebSocket(wsUrl);
    metricsSocket = socket;

    socket.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.event === "metrics" && payload.data) {
          const data = payload.data;
          liveLatency.value = data.latency_ms;
          liveJitter.value = data.jitter_ms;
          livePacketLoss.value = data.packet_loss_pct;

          if (liveMetricsEnabled.value) {
            const point: InternetHealthPoint = {
              timestamp: data.timestamp,
              value: data.internet_health,
            };
            internetHealthPoints.value = [
              ...internetHealthPoints.value.slice(-29),
              point,
            ];
            pulseChartOption.value = buildPulseChartOption(internetHealthPoints.value);
          }
        }
      } catch {
      }
    };

    socket.onclose = () => {
      if (metricsSocket === socket) {
        metricsSocket = null;
        if (liveMetricsEnabled.value) {
          setTimeout(connectMetricsSocket, 5000);
        }
      }
    };

    socket.onerror = () => {
      socket.close();
    };
  } catch {
  }
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

onMounted(() => {
  updateThemeDetection();
  const observer = new MutationObserver(() => updateThemeDetection());
  observer.observe(document.body, { attributes: true, attributeFilter: ['class'] });
  loadPulse();
  connectMetricsSocket();

  pulseInterval = window.setInterval(() => {
    if (!metricsSocket || metricsSocket.readyState !== WebSocket.OPEN) {
      loadPulse();
    }
  }, 30000);
});

onBeforeUnmount(() => {
  if (pulseInterval !== undefined) {
    clearInterval(pulseInterval);
  }
  if (metricsSocket) {
    liveMetricsEnabled.value = false;
    metricsSocket.close();
    metricsSocket = null;
  }
});
</script>

<template>
  <section
    class="np-panel relative grid gap-4 p-4 np-scanlines overflow-hidden"
  >
    <header class="np-panel-header">
      <div class="flex items-center gap-2">
        <span class="np-panel-title np-text-glow">Pulse: Internet Health</span>
        <span class="text-[0.6rem] uppercase tracking-[0.18em] text-[var(--np-muted-text)]">
          Latency · Jitter · Packet Loss
        </span>
      </div>
      <div class="flex items-center gap-3 text-xs text-[var(--np-muted-text)]">
        <span>Gateway / ISP / Cloudflare</span>
        <span class="h-1 w-10 rounded-full" :class="isSysAdmin ? 'bg-amber-400/60' : 'bg-emerald-400/60'"></span>
        <button
          @click="downloadReport"
          :disabled="isDownloadingReport"
          class="ml-2 flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-[0.7rem] font-medium transition-colors
                 border-[var(--np-border)] bg-[var(--np-surface)]/50 text-[var(--np-muted-text)] hover:text-[var(--np-text)]
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
          class="relative h-48 w-full rounded-md border bg-black/40"
          style="border-color: var(--np-border)"
        >
          <v-chart
            v-if="!pulseLoading && internetHealthPoints.length"
            :option="pulseChartOption"
            autoresize
            class="h-48 w-full"
          />
          <div
            v-else-if="pulseLoading"
            class="absolute inset-0 flex items-center justify-center text-xs text-[var(--np-muted-text)]"
          >
            Loading Internet Health...
          </div>
          <div
            v-else
            class="absolute inset-0 flex flex-col items-center justify-center gap-2 text-center px-4"
          >
            <svg xmlns="http://www.w3.org/2000/svg" class="w-8 h-8 text-[var(--np-accent-primary)] opacity-40" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" />
            </svg>
            <span class="text-xs text-[var(--np-muted-text)]">Collecting network data...</span>
            <span class="text-[0.65rem] text-[var(--np-muted-text)] opacity-60">The latency monitor runs every 15 seconds. Charts will appear once enough data points are collected.</span>
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

        <div v-if="liveLatency !== null" class="rounded-md border bg-black/40 p-2" style="border-color: var(--np-border)">
          <div class="flex items-center gap-1 mb-2">
            <span class="w-2 h-2 rounded-full animate-pulse" :class="isSysAdmin ? 'bg-green-500' : 'bg-emerald-400'"></span>
            <span class="text-[0.6rem] uppercase tracking-widest text-[var(--np-muted-text)]">Live</span>
          </div>
          <div class="grid grid-cols-3 gap-2 text-center">
            <div>
              <div class="text-sm font-semibold text-[var(--np-text)]">{{ liveLatency?.toFixed(1) ?? '--' }}</div>
              <div class="text-[0.55rem] text-[var(--np-muted-text)]">Latency ms</div>
            </div>
            <div>
              <div class="text-sm font-semibold text-[var(--np-text)]">{{ liveJitter?.toFixed(1) ?? '--' }}</div>
              <div class="text-[0.55rem] text-[var(--np-muted-text)]">Jitter ms</div>
            </div>
            <div>
              <div class="text-sm font-semibold text-[var(--np-text)]">{{ livePacketLoss?.toFixed(1) ?? '--' }}</div>
              <div class="text-[0.55rem] text-[var(--np-muted-text)]">Loss %</div>
            </div>
          </div>
        </div>

        <div class="space-y-2">
          <div
            v-for="t in pulseTargets"
            :key="t.target"
            class="rounded-md border bg-black/40 px-2 py-1.5"
            style="border-color: var(--np-border)"
          >
            <div class="flex items-center justify-between">
              <span class="font-mono text-[var(--np-text)] text-[0.7rem]">
                {{ t.label }}
              </span>
              <span class="text-[0.7rem] text-[var(--np-text)]">
                <template v-if="t.latency_ms != null">
                  {{ t.latency_ms.toFixed(1) }} ms
                </template>
                <template v-else>
                  n/a
                </template>
              </span>
            </div>
            <div
              class="mt-0.5 flex items-center justify-between text-[0.65rem] text-[var(--np-muted-text)]"
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
            class="text-[0.7rem] text-[var(--np-muted-text)]"
          >
            Waiting for Pulse data from latency monitor...
          </p>
        </div>
      </div>
    </div>
  </section>
</template>
