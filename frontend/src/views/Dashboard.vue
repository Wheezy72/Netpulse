<script setup lang="ts">
/**
 * Dashboard.vue
 *
 * This is the "Single Pane of Glass" layout. It exposes:
 *  - Pulse: real-time telemetry (latency, jitter, Internet Health).
 *  - Eye: topology & reconnaissance.
 *  - Brain: automation and scripting.
 *  - Vault: historical data and PCAP exports.
 *
 * It is intentionally structured with clear regions so you can swap,
 * resize, or add panels without refactoring the entire layout.
 */

import axios from "axios";
import cytoscape, { Core as CytoscapeCore } from "cytoscape";
import { computed, onBeforeUnmount, onMounted, ref } from "vue";

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

const selectedTarget = ref("");
const selectedServices = ref<ReconTargetService[]>([]);
const recommendations = ref<NmapRecommendation[]>([]);
const isScanning = ref(false);
const scanError = ref<string | null>(null);

const topologyLoading = ref(false);
const topologyError = ref<string | null>(null);
const hoveredNode = ref<TopologyNode | null>(null);
let cy: CytoscapeCore | null = null;

// Vault / PCAP capture state
const isCapturingPcap = ref(false);
const pcapTaskId = ref<string | null>(null);
const pcapStatus = ref<string>("idle");
const pcapCaptureId = ref<number | null>(null);
const pcapError = ref<string | null>(null);

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
    scanError.value = "Scan failed. Ensure the backend can reach the target and Nmap is installed.";
    selectedServices.value = [];
    recommendations.value = [];
  } finally {
    isScanning.value = false;
  }
}

const hasRecommendations = computed(() => recommendations.value.length > 0);

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
          lastSeen: n.last_seen
        }
      })),
      ...data.edges.map((e, index) => ({
        data: {
          id: `e-${index}`,
          source: String(e.source),
          target: String(e.target),
          kind: e.kind
        }
      }))
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
              "overlay-opacity": 0
            }
          },
          {
            selector: "node[?isGateway]",
            style: {
              "background-color": "#22c55e",
              "border-color": "#bbf7d0",
              "shape": "hexagon"
            }
          },
          {
            selector:
              "node[vulnerabilitySeverity = 'high'], node[vulnerabilitySeverity = 'critical']",
            style: {
              "background-color": "#ef4444",
              "border-color": "#fecaca",
              "shadow-blur": 20,
              "shadow-color": "#ef4444",
              "shadow-opacity": 0.9
            }
          },
          {
            selector: "edge",
            style: {
              width: 1,
              "line-color": "#22d3ee55",
              "target-arrow-color": "#22d3eeaa",
              "target-arrow-shape": "triangle",
              "curve-style": "bezier"
            }
          }
        ],
        layout: {
          name: "cose",
          animate: false
        }
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
          last_seen: data.lastSeen
        };
      });

      cy.on("mouseout", "node", () => {
        hoveredNode.value = null;
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

  try {
    const { data } = await axios.post<{ task_id: string }>("/api/vault/pcap/recent", {
      duration_seconds: 300
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
          pcapStatus.value = "ready";
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

const hasPcapReady = computed(
  () => pcapStatus.value === "ready" && pcapCaptureId.value !== null
);

onMounted(() => {
  loadTopology();
});

onBeforeUnmount(() => {
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
            id="pulse-chart"
            class="relative h-48 w-full rounded-md border border-cyan-400/30 bg-black/40"
          >
            <div
              class="absolute inset-0 flex items-center justify-center text-xs text-cyan-200/70"
            >
              Telemetry chart placeholder (Apache ECharts)
            </div>
          </div>
        </div>

        <div class="flex flex-col gap-3 text-xs">
          <div class="rounded-md border border-emerald-400/40 bg-black/50 p-3">
            <div class="flex items-baseline justify-between">
              <span class="text-[0.6rem] uppercase tracking-[0.18em] text-emerald-300">
                Internet Health
              </span>
              <span class="text-lg font-semibold text-emerald-300">92%</span>
            </div>
            <p class="mt-1 text-[0.7rem] text-cyan-100/80">
              Based on current latency, jitter and packet loss across your WAN.
            </p>
          </div>

          <div class="space-y-2">
            <div class="flex items-center justify-between">
              <span>Gateway</span>
              <span class="text-cyan-200">4 ms</span>
            </div>
            <div class="flex items-center justify-between">
              <span>ISP Edge</span>
              <span class="text-cyan-200">18 ms</span>
            </div>
            <div class="flex items-center justify-between">
              <span>Cloudflare</span>
              <span class="text-cyan-200">22 ms</span>
            </div>
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
      </div>
    </section>

    <!-- Brain: Automation & Script Hub -->
    <section class="np-panel col-span-3 xl:col-span-2 xl:row-span-2 p-4">
      <header class="np-panel-header">
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
          class="relative h-56 rounded-md border border-cyan-400/30 bg-black/90 np-scanlines"
        >
          <div
            class="absolute inset-0 flex items-center justify-center text-xs text-cyan-200/70"
          >
            XTerm.js terminal placeholder (script output, interactive shell)
          </div>
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
        <div class="rounded-md border border-cyan-400/30 bg-black/50 p-3">
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
      </div>
    </section>
  </div>
</template>