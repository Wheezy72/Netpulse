<script setup lang="ts">
/**
 * Dashboard.vue
 *
 * Single Pane layout with four panels:
 *  - Pulse: latency, jitter, Internet Health.
 *  - Eye: topology & reconnaissance.
 *  - Brain: automation and scripting.
 *  - Vault: PCAP capture and quick inspection.
 */

import axios from "axios";
import cytoscape, { Core as CytoscapeCore } from "cytoscape";
import { computed, onBeforeUnmount, onMounted, ref } from "vue";

interface Props {
  infoMode: "full" | "compact";
}

const props = defineProps<Props>();
const emit = defineEmits<{
  (e: "update:infoMode", value: "full" | "compact"): void;
}>();

type ReconTargetService = {
  port: number;
  protocol: string;
  service: string;
};

type NmapRecommendation = {
  reason: string;
  scripts: string[];
};

type TopologyNode = {
  id: number;
  label: string;
  ip_address: string;
  hostname?: string | null;
  device_type?: string | null;
  is_gateway: boolean;
  vulnerability_severity?: string | null;
  vulnerability_count: number;
  last_seen?: string | null;
};

type TopologyEdge = {
  source: number;
  target: number;
  kind: string;
};

type PacketHeaderView = {
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  protocol: string;
  length: number;
  info: string | null;
};

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

// Recon / Nmap state
const selectedTarget = ref("");
const selectedServices = ref<ReconTargetService[]>([]);
const recommendations = ref<NmapRecommendation[]>([]);
const isScanning = ref(false);
const scanError = ref<string | null>(null);

// Topology state
const topologyLoading = ref(false);
const topologyError = ref<string | null>(null);
const hoveredNode = ref<TopologyNode | null>(null);
const selectedNode = ref<TopologyNode | null>(null);
let cy: CytoscapeCore | null = null;

// Pulse / Internet Health chart state
const pulseLoading = ref(false);
const pulseError = ref<string | null>(null);
const internetHealthPoints = ref<InternetHealthPoint[]>([]);
const pulseChartOption = ref<any>({});
const pulseTargets = ref<PulseTargetSummary[]>([]);

// Vault / PCAP capture state
const isCapturingPcap = ref(false);
const pcapTaskId = ref<string | null>(null);
const pcapStatus = ref<string>("idle");
const pcapCaptureId = ref<number | null>(null);
const pcapError = ref<string | null>(null);
const captureHeaders = ref<PacketHeaderView[]>([]);

// Device quick action state
const isRunningAction = ref(false);
const actionStatus = ref<string | null>(null);

// Brain console log stream
const brainLogs = ref<string[]>([]);
let logSocket: WebSocket | null = null;

const hasRecommendations = computed(() => recommendations.value.length > 0);
const hasPcapReady = computed(
  () => pcapStatus.value === "ready" && pcapCaptureId.value !== null
);
const latestInternetHealth = computed(() => {
  if (!internetHealthPoints.value.length) return 0;
  return internetHealthPoints.value[internetHealthPoints.value.length - 1].value;
});

/**
 * Build an ECharts option object for the Pulse Internet Health chart.
 */
function buildPulseChartOption(points: InternetHealthPoint[]): any {
  const categories = points.map((p) =>
    p.timestamp.split("T")[1]?.slice(0, 8) ?? p.timestamp
  );
  const values = points.map((p) => p.value);

  return {
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
      axisLine: { lineStyle: { color: "#22d3ee55" } },
      axisLabel: {
        color: "#a5f3fc",
        fontSize: 10,
      },
    },
    yAxis: {
      type: "value",
      min: 0,
      max: 100,
      axisLine: { lineStyle: { color: "#22d3ee55" } },
      splitLine: { lineStyle: { color: "#164e635" } },
      axisLabel: {
        color: "#a5f3fc",
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
          color: "#22c55e",
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
              { offset: 0, color: "rgba(34,197,94,0.6)" },
              { offset: 1, color: "rgba(15,23,42,0.1)" },
            ],
          },
        },
      },
    ],
  };
}

/**
 * Load recent Internet Health metrics for the Pulse panel.
 */
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

/**
 * Trigger an on-demand Nmap scan for the selected target.
 * The backend returns detected services and recommended Nmap scripts.
 */
async function scanTarget(): Promise<void> {
  scanError.value = null;

  const target = selectedTarget.value.trim();
  if (!target) {
    scanError.value = "Please enter a target hostname or IP address.";
    return;
  }

  isScanning.value = true;
  try {
    const { data } = await axios.post("/api/recon/scan", { target });
    selectedServices.value = data.services ?? [];
    recommendations.value = data.recommendations ?? [];
  } catch {
    scanError.value =
      "Scan failed. Ensure the backend can reach the target and Nmap is installed.";
    selectedServices.value = [];
    recommendations.value = [];
  } finally {
    isScanning.value = false;
  }
}

/**
 * Load topology data and initialize Cytoscape graph.
 * Nodes glow red when high/critical vulnerabilities are present.
 */
async function loadTopology(): Promise<void> {
  topologyError.value = null;
  topologyLoading.value = true;

  try {
    const { data } = await axios.get<{ nodes: TopologyNode[]; edges: TopologyEdge[] }>(
      "/api/devices/topology"
    );

    const elements = [
      ...data.nodes.map((n) => ({
        data: {
          id: String(n.id),
          label: n.label,
          ip: n.ip_address,
          hostname: n.hostname,
          deviceType: n.device_type,
          isGateway: n.is_gateway,
          vulnerabilitySeverity: n.vulnerability_severity,
          vulnerabilityCount: n.vulnerability_count,
          lastSeen: n.last_seen,
        },
      })),
      ...data.edges.map((e, index) => ({
        data: {
          id: `e-${index}`,
          source: String(e.source),
          target: String(e.target),
          kind: e.kind,
        },
      })),
    ];

    const container = document.getElementById("topology-graph") as HTMLElement | null;
    if (!container) {
      topologyError.value = "Topology container not found.";
      return;
    }

    if (!cy) {
      cy = cytoscape({
        container,
        elements,
        style: [
          {
            selector: "node",
            style: {
              "background-color": "#00f3ff",
              "border-width": 2,
              "border-color": "#22d3ee",
              "label": "data(label)",
              "font-size": 8,
              "text-outline-width": 1,
              "text-outline-color": "#000000",
              color: "#e0f7ff",
              "overlay-opacity": 0,
            },
          },
          {
            selector: "node[?isGateway]",
            style: {
              "background-color": "#22c55e",
              "border-color": "#bbf7d0",
              shape: "hexagon",
            },
          },
          {
            selector:
              "node[vulnerabilitySeverity = 'high'], node[vulnerabilitySeverity = 'critical']",
            style: {
              "background-color": "#ef4444",
              "border-color": "#fecaca",
              "shadow-blur": 20,
              "shadow-color": "#ef4444",
              "shadow-opacity": 0.9,
            },
          },
          {
            selector: "edge",
            style: {
              width: 1,
              "line-color": "#22d3ee55",
              "target-arrow-color": "#22d3eeaa",
              "target-arrow-shape": "triangle",
              "curve-style": "bezier",
            },
          },
        ],
        layout: {
          name: "cose",
          animate: false,
        },
      });

      cy.on("mouseover", "node", (event) => {
        const data = event.target.data();
        hoveredNode.value = {
          id: Number(data.id),
          label: data.label,
          ip_address: data.ip,
          hostname: data.hostname,
          device_type: data.deviceType,
          is_gateway: Boolean(data.isGateway),
          vulnerability_severity: data.vulnerabilitySeverity,
          vulnerability_count: Number(data.vulnerabilityCount ?? 0),
          last_seen: data.lastSeen,
        };
      });

      cy.on("mouseout", "node", () => {
        hoveredNode.value = null;
      });

      cy.on("tap", "node", (event) => {
        const data = event.target.data();
        selectedNode.value = {
          id: Number(data.id),
          label: data.label,
          ip_address: data.ip,
          hostname: data.hostname,
          device_type: data.deviceType,
          is_gateway: Boolean(data.isGateway),
          vulnerability_severity: data.vulnerabilitySeverity,
          vulnerability_count: Number(data.vulnerabilityCount ?? 0),
          last_seen: data.lastSeen,
        };
      });
    } else {
      cy.elements().remove();
      cy.add(elements);
      cy.layout({ name: "cose", animate: false }).run();
    }
  } catch {
    topologyError.value = "Failed to load topology.";
  } finally {
    topologyLoading.value = false;
  }
}

/**
 * Vault: start a timed packet capture and prepare a PCAP for download.
 */
async function startRecentPcapCapture(): Promise<void> {
  if (isCapturingPcap.value) {
    return;
  }

  pcapError.value = null;
  pcapStatus.value = "starting";
  isCapturingPcap.value = true;
  captureHeaders.value = [];

  try {
    const { data } = await axios.post<{ task_id: string }>("/api/vault/pcap/recent", {
      duration_seconds: 300,
    });
    pcapTaskId.value = data.task_id;
    pcapStatus.value = "capturing";

    // Poll task status until capture is ready.
    const poll = async () => {
      if (!pcapTaskId.value) {
        return;
      }
      try {
        const { data } = await axios.get<{
          ready: boolean;
          capture_id: number | null;
          state: string;
          error: string | null;
        }>(`/api/vault/pcap/task/${pcapTaskId.value}`);

        if (!data.ready) {
          pcapStatus.value = `capturing (${data.state})`;
          setTimeout(poll, 5000);
          return;
        }

        if (data.error) {
          pcapStatus.value = "error";
          pcapError.value = data.error;
          isCapturingPcap.value = false;
          return;
        }

        if (data.capture_id != null) {
          pcapCaptureId.value = data.capture_id;

          // Fetch header summaries for quick inspection
          try {
            const { data: cap } = await axios.get<{
              capture: unknown;
              headers: PacketHeaderView[];
            }>(`/api/vault/pcap/${data.capture_id}`);
            captureHeaders.value = (cap.headers || []).slice(0, 50);
          } catch {
            // Non-fatal; user can still download the PCAP.
          }

          pcapStatus.value = "ready";
          isCapturingPcap.value = false;
        }
      } catch {
        pcapStatus.value = "error";
        pcapError.value = "Failed to query capture status.";
        isCapturingPcap.value = false;
      }
    };

    setTimeout(poll, 5000);
  } catch {
    pcapStatus.value = "error";
    pcapError.value = "Failed to start capture.";
    isCapturingPcap.value = false;
  }
}

/**
 * Run a prebuilt Smart Script against the currently selected node.
 * This is wired to offensive/defensive templates (e.g., malformed packets).
 */
function attachLogStream(jobId: number): void {
  const token = window.localStorage.getItem("np-token");
  if (!token) {
    brainLogs.value.push("[log] No auth token available for log stream.");
    return;
  }

  if (logSocket) {
    logSocket.close();
    logSocket = null;
  }

  const apiBase =
    (import.meta as any).env?.VITE_API_BASE_URL || window.location.origin;
  const wsBase = apiBase.replace(/^http/, "ws");
  const url = `${wsBase}/api/ws/scripts/${jobId}?token=${encodeURIComponent(
    token
  )}`;

  try {
    const socket = new WebSocket(url);
    logSocket = socket;
    brainLogs.value.push(`[log] Attached to job #${jobId}`);

    socket.onmessage = (event: MessageEvent) => {
      try {
        const payload = JSON.parse(event.data as string);
        if (payload.event === "log") {
          brainLogs.value.push(payload.message);
        } else if (payload.event === "complete") {
          brainLogs.value.push(
            `[log] Job completed with status: ${payload.status}`
          );
        } else if (payload.event === "error") {
          brainLogs.value.push(`[error] ${payload.message}`);
        }
      } catch {
        brainLogs.value.push("[error] Failed to parse log message.");
      }
    };

    socket.onclose = () => {
      if (logSocket === socket) {
        logSocket = null;
      }
    };
  } catch {
    brainLogs.value.push("[error] Could not open log WebSocket.");
  }
}

async function runPrebuiltScriptForDevice(
  scriptName: string,
  extraParams: Record<string, unknown> = {}
): Promise<void> {
  const node = selectedNode.value;
  if (!node) {
    return;
  }

  isRunningAction.value = true;
  actionStatus.value = null;

  try {
    const payload = {
      script_name: scriptName,
      params: {
        target_ip: node.ip_address,
        ...extraParams,
      },
    };
    const { data } = await axios.post<{ job_id: number }>(
      "/api/scripts/prebuilt/run",
      payload
    );
    const jobId = data.job_id;
    actionStatus.value = `Script queued (job #${jobId}).`;

    // Attach log stream to Brain console
    attachLogStream(jobId);
  } catch {
    actionStatus.value = "Failed to queue script for this device.";
  } finally {
    isRunningAction.value = false;
  }
}

/**
 * Run a prebuilt Smart Script without binding it to a specific device.
 * Results and logs are streamed into the Brain console.
 */
async function runPrebuiltScript(
  scriptName: string,
  params: Record<string, unknown> = {}
): Promise<void> {
  isRunningAction.value = true;
  actionStatus.value = null;

  try {
    const payload = {
      script_name: scriptName,
      params,
    };
    const { data } = await axios.post<{ job_id: number }>(
      "/api/scripts/prebuilt/run",
      payload
    );
    const jobId = data.job_id;
    actionStatus.value = `Script queued (job #${jobId}).`;
    attachLogStream(jobId);
  } catch {
    actionStatus.value = "Failed to queue script.";
  } finally {
    isRunningAction.value = false;
  }
}

async function runWanHealthReport(): Promise<void> {
  await runPrebuiltScript("wan_health_report.py");
}

async function runNewDeviceReport(): Promise<void> {
  await runPrebuiltScript("new_device_report.py");
}

async function runConfigDriftReport(): Promise<void> {
  await runPrebuiltScript("config_drift_report.py");
}

async function runNmapWebRecon(): Promise<void> {
  const target = selectedTarget.value.trim();
  if (!target) {
    actionStatus.value = "Set a target in Recon Playbook first.";
    return;
  }
  await runPrebuiltScript("nmap_web_recon.py", { target });
}

async function runNmapSmbAudit(): Promise<void> {
  const target = selectedTarget.value.trim();
  if (!target) {
    actionStatus.value = "Set a target in Recon Playbook first.";
    return;
  }
  await runPrebuiltScript("nmap_smb_audit.py", { target });
}

let pulseInterval: number | undefined;
let topologyInterval: number | undefined;

onMounted(() => {
  // Initial load
  loadPulse();
  loadTopology();

  // Periodic refresh for a \"live\" dashboard view.
  // Pulse metrics are updated frequently; topology changes more slowly.
  pulseInterval = window.setInterval(() => {
    loadPulse();
  }, 15000);

  topologyInterval = window.setInterval(() => {
    loadTopology();
  }, 60000);
});

onBeforeUnmount(() => {
  if (pulseInterval !== undefined) {
    clearInterval(pulseInterval);
  }
  if (topologyInterval !== undefined) {
    clearInterval(topologyInterval);
  }
  if (logSocket) {
    logSocket.close();
    logSocket = null;
  }
  if (cy) {
    cy.destroy();
    cy = null;
  }
});
</script>

<template>
  <div class="grid gap-4 xl:grid-cols-3 xl:grid-rows-6">
    <!-- Pulse: Real-Time Telemetry -->
    <section
      class="np-panel relative col-span-3 grid gap-4 p-4 xl:col-span-2 xl:row-span-2 np-scanlines overflow-hidden"
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
          <span class="h-1 w-10 rounded-full bg-emerald-400/60"></span>
        </div>
      </header>

      <div class="grid gap-4 md:grid-cols-4">
        <div class="md:col-span-3">
          <div
            class="relative h-48 w-full rounded-md border border-cyan-400/30 bg-black/40"
          >
            <v-chart
              v-if="infoMode === 'full' && !pulseLoading && internetHealthPoints.length"
              :option="pulseChartOption"
              autoresize
              class="h-48 w-full"
            />
            <div
              v-else-if="pulseLoading"
              class="absolute inset-0 flex items-center justify-center text-xs text-cyan-200/70"
            >
              Loading Internet Health…
            </div>
            <div
              v-else-if="infoMode === 'full'"
              class="absolute inset-0 flex items-center justify-center text-xs text-cyan-200/70"
            >
              No Internet Health data yet.
            </div>
            <div
              v-else
              class="absolute inset-0 flex items-center justify-center text-xs text-cyan-200/70"
            >
              Compact mode: Internet Health
              {{ latestInternetHealth.toFixed(0) }}%.
            </div>
          </div>
          <p v-if="pulseError" class="mt-2 text-[0.7rem] text-rose-300">
            {{ pulseError }}
          </p>
        </div>

        <div class="flex flex-col gap-3 text-xs">
          <div class="rounded-md border border-emerald-400/40 bg-black/50 p-3">
            <div class="flex items-baseline justify-between">
              <span class="text-[0.6rem] uppercase tracking-[0.18em] text-emerald-300">
                Internet Health
              </span>
              <span class="text-lg font-semibold text-emerald-300">
                {{ latestInternetHealth.toFixed(0) }}%
              </span>
            </div>
            <p class="mt-1 text-[0.7rem] text-cyan-100/80">
              Based on current latency, jitter and packet loss across your WAN.
            </p>
          </div>

          <!-- Dynamic per-target Pulse summary -->
          <div class="space-y-2">
            <div
              v-for="target in pulseTargets"
              :key="target.target"
              class="flex items-center justify-between"
            >
              <span>{{ target.label }}</span>
              <span class="text-cyan-200">
                <template v-if="target.latency_ms != null">
                  {{ target.latency_ms.toFixed(1) }} ms
                </template>
                <template v-else>
                  n/a
                </template>
              </span>
            </div>
            <p
              v-if="!pulseTargets.length && !pulseLoading"
              class="text-[0.7rem] text-[var(--np-muted-text)]"
            >
              Waiting for Pulse data from latency monitor…
            </p>
          </div>
        </div>
      </div>
    </section>

    <!-- Eye: Topology & Recon -->
    <section
      class="np-panel relative col-span-3 grid gap-4 p-4 xl:col-span-1 xl:row-span-3"
    >
      <header class="np-panel-header">
        <div class="flex flex-col">
          <span class="np-panel-title">Eye: Topology &amp; Recon</span>
          <span class="text-[0.7rem] text-[var(--np-muted-text)]">
            Passive discovery + Nmap insights.
          </span>
        </div>
        <span class="text-[0.65rem] uppercase tracking-[0.16em] text-[var(--np-muted-text)]">
          Cytoscape.js Graph
        </span>
      </header>

      <div class="grid gap-3 lg:grid-rows-[minmax(0,2fr)_minmax(0,1.4fr)]">
        <div
          id="topology-graph"
          class="relative h-52 w-full rounded-md border border-cyan-400/30 bg-black/40"
        >
          <div
            v-if="topologyLoading"
            class="absolute inset-0 flex items-center justify-center text-xs text-cyan-200/70"
          >
            Building network graph…
          </div>
          <div
            v-else-if="topologyError"
            class="absolute inset-0 flex items-center justify-center text-xs text-rose-300"
          >
            {{ topologyError }}
          </div>
        </div>

        <div
          v-if="hoveredNode"
          class="rounded-md border border-cyan-400/40 bg-black/70 p-3 text-xs"
        >
          <div class="flex items-center justify-between">
            <div>
              <p class="text-[0.7rem] uppercase tracking-[0.16em] text-cyan-200">
                Device Focus
              </p>
              <p class="mt-1 font-mono text-cyan-100">
                {{ hoveredNode.hostname || hoveredNode.ip_address }}
              </p>
            </div>
            <span
              v-if="hoveredNode.vulnerability_severity"
              class="np-danger-glow rounded px-2 py-0.5 text-[0.65rem]"
            >
              {{ hoveredNode.vulnerability_severity.toUpperCase() }}
            </span>
          </div>
          <dl class="mt-2 grid grid-cols-2 gap-1 text-[0.7rem]">
            <div>
              <dt class="text-[var(--np-muted-text)]">IP</dt>
              <dd class="font-mono text-cyan-100">{{ hoveredNode.ip_address }}</dd>
            </div>
            <div>
              <dt class="text-[var(--np-muted-text)]">Type</dt>
              <dd>{{ hoveredNode.device_type || "unknown" }}</dd>
            </div>
            <div>
              <dt class="text-[var(--np-muted-text)]">Gateway</dt>
              <dd>{{ hoveredNode.is_gateway ? "yes" : "no" }}</dd>
            </div>
            <div>
              <dt class="text-[var(--np-muted-text)]">Vulnerabilities</dt>
              <dd>{{ hoveredNode.vulnerability_count }}</dd>
            </div>
          </dl>

          <div v-if="selectedNode && selectedNode.id === hoveredNode.id" class="mt-3 space-y-2">
            <p class="text-[0.65rem] uppercase tracking-[0.16em] text-cyan-200">
              Quick Actions
            </p>
            <div class="flex flex-wrap gap-2">
              <button
                type="button"
                @click="runPrebuiltScriptForDevice('malformed_syn_flood.py', { count: 30 })"
                class="rounded-md border border-cyan-400/40 bg-black/80 px-2 py-0.5 text-[0.65rem]
                       text-cyan-200 hover:bg-cyan-500/10 disabled:opacity-50"
                :disabled="isRunningAction"
              >
                SYN Storm (template)
              </button>
              <button
                type="button"
                @click="runPrebuiltScriptForDevice('malformed_xmas_scan.py')"
                class="rounded-md border border-cyan-400/40 bg-black/80 px-2 py-0.5 text-[0.65rem]
                       text-cyan-200 hover:bg-cyan-500/10 disabled:opacity-50"
                :disabled="isRunningAction"
              >
                Xmas Scan (template)
              </button>
              <button
                type="button"
                @click="runPrebuiltScriptForDevice('malformed_overlap_fragments.py')"
                class="rounded-md border border-cyan-400/40 bg-black/80 px-2 py-0.5 text-[0.65rem]
                       text-cyan-200 hover:bg-cyan-500/10 disabled:opacity-50"
                :disabled="isRunningAction"
              >
                Overlap Fragments
              </button>
            </div>
            <p v-if="actionStatus" class="text-[0.65rem] text-cyan-100/80">
              {{ actionStatus }}
            </p>
          </div>
        </div>

        <!-- Nmap script advisor / recon playbook -->
        <div class="rounded-md border border-cyan-400/30 bg-black/40 p-3 text-xs">
          <div class="flex items-center justify-between">
            <div>
              <h3 class="text-[0.7rem] uppercase tracking-[0.16em] text-cyan-200">
                Recon Playbook
              </h3>
              <p class="mt-0.5 text-[0.7rem] text-cyan-100/80">
                Select a target and get context-aware Nmap script recommendations.
              </p>
            </div>
            <span class="rounded-full border border-cyan-400/40 px-2 py-0.5 text-[0.6rem]">
              Eye · Advisor
            </span>
          </div>

          <div class="mt-2 flex flex-col gap-2">
            <label class="text-[0.7rem] text-[var(--np-muted-text)]">
              Target (IP / Hostname)
              <input
                v-model="selectedTarget"
                type="text"
                class="mt-1 w-full rounded-md border bg-black/60 px-2 py-1 text-[0.75rem]
                       focus:outline-none focus:ring-1 focus:ring-cyan-400"
                placeholder="10.0.0.15"
              />
            </label>

            <div class="flex items-center gap-2 text-[0.7rem]">
              <button
                type="button"
                @click="scanTarget"
                class="inline-flex items-center justify-center rounded-md border
                       border-cyan-400/60 bg-black/80 px-2.5 py-1 text-[0.7rem] font-medium
                       text-cyan-200 hover:bg-cyan-500/10 disabled:opacity-50"
                :disabled="isScanning"
              >
                <span v-if="!isScanning">Scan with Nmap</span>
                <span v-else>Scanning…</span>
              </button>
              <span v-if="scanError" class="text-rose-300">
                {{ scanError }}
              </span>
            </div>

            <div v-if="selectedServices.length" class="mt-2 grid gap-2 md:grid-cols-2">
              <div v-for="svc in selectedServices" :key="`${svc.protocol}-${svc.port}`" class="text-[0.7rem]">
                <div class="flex items-center justify-between">
                  <span class="font-mono text-cyan-200">
                    {{ svc.protocol }}/{{ svc.port }}
                  </span>
                  <span class="rounded bg-cyan-500/10 px-1.5 py-0.5 text-[0.65rem]">
                    {{ svc.service }}
                  </span>
                </div>
              </div>
            </div>

            <div class="mt-2 border-t border-cyan-400/20 pt-2">
              <div v-if="hasRecommendations" class="space-y-2">
                <div
                  v-for="(rec, idx) in recommendations"
                  :key="idx"
                  class="rounded-md border border-cyan-400/30 bg-black/60 p-2"
                >
                  <p class="text-[0.7rem] font-semibold text-cyan-200">
                    {{ rec.reason }}
                  </p>
                  <p class="mt-1 text-[0.7rem] text-cyan-100/80">
                    Suggested Nmap scripts:
                  </p>
                  <div class="mt-1 flex flex-wrap gap-1">
                    <span
                      v-for="script in rec.scripts"
                      :key="script"
                      class="rounded border border-cyan-400/40 bg-black/70 px-1.5 py-0.5 text-[0.65rem] font-mono"
                    >
                      {{ script }}
                    </span>
                  </div>
                </div>
              </div>
              <p v-else class="text-[0.7rem] text-cyan-100/80">
                Enter a target and run a scan to see tailored Nmap script suggestions.
              </p>
            </div>
          </div>
        </div>
    </</div>
  </</section>

    <!-- Brain: Automation & Script Hub -->
   <<section class="np-panel col-span-3 xl:col-span-2 xl:row-span-2 p-4">
     <<header class="np-panel-header">
        <div class="flex flex-col">
          <span class="np-panel-title">Brain: Automation Hub</span>
          <span class="text-[0.7rem] text-[var(--np-muted-text)]">
            Upload Python scripts, orchestrate offensive/defensive playbooks.
          </span>
        </div>
        <span class="text-[0.65rem] uppercase tracking-[0.16em] text-[var(--np-muted-text)]">
          XTerm.js Console
        </span>
      </header>

      <div class="grid gap-4 md:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
        <div
          id="brain-terminal"
          class="relative h-56 rounded-md border border-cyan-400/30 bg-black/90 np-scanlines overflow-auto"
        >
          <div
            v-if="brainLogs.length === 0"
            class="absolute inset-0 flex items-center justify-center text-xs text-cyan-200/70"
          >
            XTerm.js terminal placeholder (script output, interactive shell)
          </div>
          <pre
            v-else
            class="h-full w-full whitespace-pre-wrap break-words bg-transparent p-2 text-xs font-mono text-cyan-100"
          >
{{ brainLogs.join('\n') }}
          </pre>
        </div>

        <div class="flex flex-col gap-3 text-xs">
          <div class="rounded-md border border-cyan-400/30 bg-black/50 p-3">
            <h3 class="text-[0.7rem] uppercase tracking-[0.16em] text-cyan-200">
              Script Hub
            </h3>
            <p class="mt-1 text-[0.7rem] text-cyan-100/80">
              Drag &amp; drop Python files to run them as Smart Scripts. NetPulse will capture
              logs, results, and surface them here.
            </p>
          </div>

          <ul class="space-y-1 text-[0.7rem]">
            <li class="flex items-center justify-between">
              <span class="font-mono text-cyan-200">backup_switch.py</span>
              <span class="rounded bg-emerald-500/20 px-2 py-0.5 text-emerald-300">
                Prebuilt · Config Backup
              </span>
            </li>
            <li class="flex items-center justify-between">
              <span class="font-mono text-cyan-200">device_inventory_export.py</span>
              <span class="rounded bg-sky-500/20 px-2 py-0.5 text-sky-300">
                Prebuilt · Inventory Export
              </span>
            </li>
            <li class="flex items-center justify-between">
              <span class="font-mono text-cyan-200">wan_health_report.py</span>
              <span class="rounded bg-sky-500/20 px-2 py-0.5 text-sky-300">
                Prebuilt · WAN Health Report
              </span>
            </li>
            <li class="flex items-center justify-between">
              <span class="font-mono text-cyan-200">new_device_report.py</span>
              <span class="rounded bg-emerald-500/20 px-2 py-0.5 text-emerald-300">
                Prebuilt · New Device Report
              </span>
            </li>
            <li class="flex items-center justify-between">
              <span class="font-mono text-cyan-200">config_drift_report.py</span>
              <span class="rounded bg-emerald-500/20 px-2 py-0.5 text-emerald-300">
                Prebuilt · Config Drift
              </span>
            </li>
            <li class="flex items-center justify-between">
              <span class="font-mono text-cyan-200">nmap_web_recon.py</span>
              <span class="rounded bg-sky-500/20 px-2 py-0.5 text-sky-300">
                Prebuilt · Web Recon Profile
              </span>
            </li>
            <li class="flex items-center justify-between">
              <span class="font-mono text-cyan-200">nmap_smb_audit.py</span>
              <span class="rounded bg-sky-500/20 px-2 py-0.5 text-sky-300">
                Prebuilt · SMB Audit Profile
              </span>
            </li>
            <li class="flex items-center justify-between">
              <span class="font-mono text-cyan-200">kill_switch.py</span>
              <span class="rounded bg-rose-500/20 px-2 py-0.5 text-rose-300">
                Prebuilt · Connection Reset
              </span>
            </li>
            <li class="flex items-center justify-between">
              <span class="font-mono text-cyan-200">custom_probe.py</span>
              <span class="rounded bg-sky-500/20 px-2 py-0.5 text-sky-300">
                Your custom Smart Script
              </span>
            </li>
          </ul>

          <!-- Settings panel for information density -->
          <div class="rounded-md border border-cyan-400/30 bg-black/50 p-3">
            <h3 class="text-[0.7rem] uppercase tracking-[0.16em] text-cyan-200">
              Settings
            </h3>
            <p class="mt-1 text-[0.7rem] text-cyan-100/80">
              Toggle between a detailed console and a compact quick-look mode.
            </p>
            <div class="mt-2 flex items-center gap-3 text-[0.7rem]">
              <button
                type="button"
                @click="emit('update:infoMode', 'full')"
                class="rounded border px-2 py-1"
                :class="[
                  infoMode === 'full'
                    ? 'border-emerald-400/60 bg-emerald-500/20 text-emerald-300'
                    : 'border-cyan-400/40 text-cyan-200 hover:bg-cyan-500/10'
                ]"
              >
                Full detail
              </button>
              <button
                type="button"
                @click="emit('update:infoMode', 'compact')"
                class="rounded border px-2 py-1"
                :class="[
                  infoMode === 'compact'
                    ? 'border-emerald-400/60 bg-emerald-500/20 text-emerald-300'
                    : 'border-cyan-400/40 text-cyan-200 hover:bg-cyan-500/10'
                ]"
              >
                Quick view
              </button>
            </div>
          </div>

          <!-- Quick actions for prebuilt scripts -->
          <div class="rounded-md border border-cyan-400/30 bg-black/50 p-3 space-y-2">
            <h3 class="text-[0.7rem] uppercase tracking-[0.16em] text-cyan-200">
              Script Shortcuts
            </h3>
            <p class="text-[0.7rem] text-cyan-100/80">
              Run common automation playbooks and Nmap profiles. Output appears in the Brain console.
            </p>
            <div class="flex flex-wrap gap-2">
              <button
                type="button"
                @click="runWanHealthReport"
                class="rounded-md border border-cyan-400/40 bg-black/80 px-2 py-0.5 text-[0.65rem]
                       text-cyan-200 hover:bg-cyan-500/10 disabled:opacity-50"
                :disabled="isRunningAction"
              >
                WAN Health Report
              </button>
              <button
                type="button"
                @click="runNewDeviceReport"
                class="rounded-md border border-cyan-400/40 bg-black/80 px-2 py-0.5 text-[0.65rem]
                       text-cyan-200 hover:bg-cyan-500/10 disabled:opacity-50"
                :disabled="isRunningAction"
              >
                New Device Report
              </button>
              <button
                type="button"
                @click="runConfigDriftReport"
                class="rounded-md border border-cyan-400/40 bg-black/80 px-2 py-0.5 text-[0.65rem]
                       text-cyan-200 hover:bg-cyan-500/10 disabled:opacity-50"
                :disabled="isRunningAction"
              >
                Config Drift Report
              </button>
              <button
                type="button"
                @click="runNmapWebRecon"
                class="rounded-md border border-cyan-400/40 bg-black/80 px-2 py-0.5 text-[0.65rem]
                       text-cyan-200 hover:bg-cyan-500/10 disabled:opacity-50"
                :disabled="isRunningAction"
              >
                Web Recon Profile
              </button>
              <button
                type="button"
                @click="runNmapSmbAudit"
                class="rounded-md border border-cyan-400/40 bg-black/80 px-2 py-0.5 text-[0.65rem]
                       text-cyan-200 hover:bg-cyan-500/10 disabled:opacity-50"
                :disabled="isRunningAction"
              >
                SMB Audit Profile
              </button>
            </div>
            <p v-if="actionStatus" class="text-[0.65rem] text-cyan-100/80">
              {{ actionStatus }}
            </p>
          </div>
        </div>
      </div>
    </section>

    <!-- Vault: Time Machine & PCAP Export -->
    <section class="np-panel col-span-3 xl:col-span-1 xl:row-span-2 p-4">
      <header class="np-panel-header">
        <div class="flex flex-col">
          <span class="np-panel-title">Vault: Time Machine</span>
          <span class="text-[0.7rem] text-[var(--np-muted-text)]">
            Scroll back in time, export PCAP slices.
          </span>
        </div>
      </header>

      <div class="flex h-full flex-col gap-3 text-xs">
        <div
          v-if="infoMode === 'full'"
          class="rounded-md border border-cyan-400/30 bg-black/50 p-3"
        >
          <label class="flex flex-col gap-1 text-[0.7rem]">
            Time Window
            <input
              type="datetime-local"
              class="rounded-md border border-cyan-400/30 bg-black/70 px-2 py-1 text-[0.75rem]
                     focus:outline-none focus:ring-1 focus:ring-cyan-400"
            />
          </label>
          <p class="mt-1 text-[0.7rem] text-cyan-100/80">
            Choose a point in time (e.g. yesterday 3:00 PM) to replay metrics in the Pulse
            panel.
          </p>
        </div>

        <button
          type="button"
          @click="startRecentPcapCapture"
          class="mt-auto inline-flex items-center justify-center rounded-md border
                 border-cyan-400/40 bg-black/70 px-3 py-2 text-[0.75rem] font-medium
                 text-cyan-200 hover:bg-cyan-500/10 disabled:opacity-50"
          :disabled="isCapturingPcap"
        >
          <span v-if="!isCapturingPcap">Export Last 5 Minutes as PCAP</span>
          <span v-else>Capturing traffic…</span>
        </button>

        <div class="mt-2 text-[0.7rem]">
          <p v-if="pcapStatus === 'capturing'" class="text-cyan-100/80">
            Capture in progress. This may take several minutes depending on the duration.
          </p>
          <p v-if="pcapError" class="text-rose-300">
            {{ pcapError }}
          </p>
          <p v-if="hasPcapReady" class="text-emerald-300">
            Capture ready:
            <a
              :href="`/api/vault/pcap/${pcapCaptureId}/download`"
              class="underline hover:text-emerald-200"
              >Download PCAP</a
            >
          </p>
        </div>

        <div v-if="captureHeaders.length" class="mt-3 max-h-40 overflow-auto rounded border border-cyan-400/30 bg-black/60">
          <table class="min-w-full text-[0.65rem]">
            <thead class="bg-black/70 text-cyan-200">
              <tr>
                <th class="px-2 py-1 text-left">Time</th>
                <th class="px-2 py-1 text-left">Src</th>
                <th class="px-2 py-1 text-left">Dst</th>
                <th class="px-2 py-1 text-left">Proto</th>
                <th class="px-2 py-1 text-right">Len</th>
                <th class="px-2 py-1 text-left">Info</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="(pkt, idx) in captureHeaders"
                :key="idx"
                class="border-t border-cyan-400/10 text-cyan-100"
              >
                <td class="px-2 py-1 whitespace-nowrap">
                  {{ pkt.timestamp.split("T")[1]?.slice(0, 12) ?? pkt.timestamp }}
                </td>
                <td class="px-2 py-1">
                  {{ pkt.src_ip }}<span v-if="pkt.src_port">:{{ pkt.src_port }}</span>
                </td>
                <td class="px-2 py-1">
                  {{ pkt.dst_ip }}<span v-if="pkt.dst_port">:{{ pkt.dst_port }}</span>
                </td>
                <td class="px-2 py-1">
                  {{ pkt.protocol }}
                </td>
                <td class="px-2 py-1 text-right">
                  {{ pkt.length }}
                </td>
                <td class="px-2 py-1">
                  {{ pkt.info || "" }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>
  </div>
</template>