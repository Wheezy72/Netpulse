<script setup lang="ts">
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
  zone?: string | null;
  vulnerability_severity?: string | null;
  vulnerability_count: number;
  last_seen?: string | null;
};

type TopologyEdge = {
  source: number;
  target: number;
  kind: string;
};

type DeviceDetail = {
  device: {
    id: number;
    hostname?: string | null;
    ip_address: string;
    mac_address?: string | null;
    device_type?: string | null;
    is_gateway: boolean;
    zone?: string | null;
    last_seen?: string | null;
  };
  type_guess?: string | null;
  type_confidence?: number | null;
  vulnerabilities: {
    id: number;
    title: string;
    severity: string;
    port?: number | null;
    detected_at?: string | null;
  }[];
  scripts: {
    id: number;
    script_name: string;
    status: string;
    created_at: string;
  }[];
  metrics: {
    metric_type: string;
    timestamp: string;
    value: number;
  }[];
};

interface Props {
  isAdmin: boolean;
}

const props = defineProps<Props>();

const emit = defineEmits<{
  (e: "node-selected", payload: { ip: string; mac: string | null; type: string | null }): void;
}>();

const selectedTarget = ref("");
const selectedServices = ref<ReconTargetService[]>([]);
const recommendations = ref<NmapRecommendation[]>([]);
const isScanning = ref(false);
const scanError = ref<string | null>(null);

const topologyLoading = ref(false);
const topologyError = ref<string | null>(null);
const hoveredNode = ref<TopologyNode | null>(null);
const selectedNode = ref<TopologyNode | null>(null);
const zones = ref<string[]>([]);
const selectedZone = ref<string | null>(null);
let cy: CytoscapeCore | null = null;

const isRunningAction = ref(false);
const actionStatus = ref<string | null>(null);

const deviceDetail = ref<DeviceDetail | null>(null);
const deviceDetailLoading = ref(false);
const deviceDetailError = ref<string | null>(null);

const canRunRecon = computed(() => props.isAdmin);
const hasRecommendations = computed(() => recommendations.value.length > 0);

let logSocket: WebSocket | null = null;

function attachLogStream(jobId: number): void {
  const token = window.localStorage.getItem("np-token");
  if (!token) return;

  if (logSocket) {
    logSocket.close();
    logSocket = null;
  }

  const apiBase =
    (import.meta as any).env?.VITE_API_BASE_URL || window.location.origin;
  const wsBase = apiBase.replace(/^http/, "ws");
  const url = `${wsBase}/api/ws/scripts/${jobId}?token=${encodeURIComponent(token)}`;

  try {
    const socket = new WebSocket(url);
    logSocket = socket;
    socket.onclose = () => {
      if (logSocket === socket) logSocket = null;
    };
  } catch {
  }
}

async function runPrebuiltScriptForDevice(
  scriptName: string,
  extraParams: Record<string, unknown> = {}
): Promise<void> {
  if (!props.isAdmin) {
    actionStatus.value = "Admin access required to execute scripts.";
    return;
  }

  const node = selectedNode.value;
  if (!node) return;

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
    actionStatus.value = `Script queued (job #${data.job_id}).`;
    attachLogStream(data.job_id);
  } catch {
    actionStatus.value = "Failed to queue script for this device.";
  } finally {
    isRunningAction.value = false;
  }
}

async function scanTarget(): Promise<void> {
  scanError.value = null;

  if (!props.isAdmin) {
    scanError.value = "Admin access required to run scans.";
    return;
  }

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

async function loadTopology(): Promise<void> {
  topologyError.value = null;
  topologyLoading.value = true;

  try {
    const params: Record<string, string> = {};
    if (selectedZone.value) {
      params.zone = selectedZone.value;
    }
    const { data } = await axios.get<{ nodes: TopologyNode[]; edges: TopologyEdge[] }>(
      "/api/devices/topology",
      { params }
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
          zone: n.zone,
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
              "background-color": "#14b8a6",
              "border-width": 2,
              "border-color": "#2dd4bf",
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
              "line-color": "#14b8a655",
              "target-arrow-color": "#14b8a6aa",
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
          zone: data.zone,
          vulnerability_severity: data.vulnerabilitySeverity,
          vulnerability_count: Number(data.vulnerabilityCount ?? 0),
          last_seen: data.lastSeen,
        };
      });

      cy.on("mouseout", "node", () => {
        hoveredNode.value = null;
      });

      cy.on("tap", "node", async (event) => {
        const data = event.target.data();
        const tappedNode: TopologyNode = {
          id: Number(data.id),
          label: data.label,
          ip_address: data.ip,
          hostname: data.hostname,
          device_type: data.deviceType,
          is_gateway: Boolean(data.isGateway),
          zone: data.zone,
          vulnerability_severity: data.vulnerabilitySeverity,
          vulnerability_count: Number(data.vulnerabilityCount ?? 0),
          last_seen: data.lastSeen,
        };

        selectedNode.value = tappedNode;
        const detail = await loadDeviceDetail(tappedNode.id);

        const mac = detail?.device.mac_address ?? null;
        const type =
          detail?.type_guess ??
          detail?.device.device_type ??
          tappedNode.device_type ??
          null;

        emit("node-selected", { ip: tappedNode.ip_address, mac, type });
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

async function loadZones(): Promise<void> {
  try {
    const { data } = await axios.get<{ zones: string[] }>("/api/devices/zones");
    zones.value = data.zones ?? [];
    if (!selectedZone.value && zones.value.length) {
      selectedZone.value = zones.value[0];
    }
  } catch {
  }
}

async function loadDeviceDetail(deviceId: number): Promise<DeviceDetail | null> {
  deviceDetailLoading.value = true;
  deviceDetailError.value = null;

  try {
    const { data } = await axios.get<DeviceDetail>(`/api/devices/${deviceId}/detail`);
    deviceDetail.value = data;
    return data;
  } catch {
    deviceDetailError.value = "Failed to load device detail.";
    deviceDetail.value = null;
    return null;
  } finally {
    deviceDetailLoading.value = false;
  }
}

let topologyInterval: number | undefined;

onMounted(() => {
  loadZones().then(() => {
    loadTopology();
  });

  topologyInterval = window.setInterval(() => {
    loadTopology();
  }, 60000);
});

onBeforeUnmount(() => {
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
  <section class="np-panel relative grid gap-4 p-4">
    <header class="np-panel-header">
      <div class="flex flex-col">
        <span class="np-panel-title">Eye: Topology &amp; Recon</span>
        <span class="text-[0.7rem] text-[var(--np-muted-text)]">
          Passive discovery + Nmap insights.
        </span>
      </div>
      <div class="flex items-center gap-3 text-[0.7rem] text-[var(--np-muted-text)]">
        <span class="hidden sm:inline">Zone</span>
        <select
          v-model="selectedZone"
          @change="loadTopology"
          class="rounded border bg-black/40 px-2 py-0.5 text-[0.7rem] focus:outline-none focus:ring-1"
          style="border-color: var(--np-border); color: var(--np-text)"
        >
          <option :value="null">All zones</option>
          <option
            v-for="z in zones"
            :key="z"
            :value="z"
          >
            {{ z }}
          </option>
        </select>
      </div>
    </header>

    <div class="grid gap-3 lg:grid-rows-[minmax(0,2fr)_minmax(0,1.4fr)]">
      <div
        id="topology-graph"
        class="relative h-52 w-full rounded-md border bg-black/40"
        style="border-color: var(--np-border)"
      >
        <div
          v-if="topologyLoading"
          class="absolute inset-0 flex items-center justify-center text-xs text-[var(--np-muted-text)]"
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
        class="rounded-md border bg-black/70 p-3 text-xs"
        style="border-color: var(--np-border)"
      >
        <div class="flex items-center justify-between">
          <div>
            <p class="text-[0.7rem] uppercase tracking-[0.16em]" style="color: var(--np-accent-primary)">
              Device Focus
            </p>
            <p class="mt-1 font-mono text-[var(--np-text)]">
              {{ hoveredNode.hostname || hoveredNode.ip_address }}
            </p>
            <p v-if="hoveredNode.zone" class="text-[0.65rem] text-[var(--np-muted-text)]">
              Zone: {{ hoveredNode.zone }}
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
            <dd class="font-mono text-[var(--np-text)]">{{ hoveredNode.ip_address }}</dd>
          </div>
          <div>
            <dt class="text-[var(--np-muted-text)]">Type</dt>
            <dd>
              <span v-if="deviceDetail && deviceDetail.type_guess">
                {{ deviceDetail.type_guess }}
                <span v-if="deviceDetail.type_confidence != null">
                  ({{ (deviceDetail.type_confidence * 100).toFixed(0) }}%)
                </span>
              </span>
              <span v-else>
                {{ hoveredNode.device_type || "unknown" }}
              </span>
            </dd>
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

        <div
          v-if="props.isAdmin && selectedNode && selectedNode.id === hoveredNode.id"
          class="mt-3 space-y-2"
        >
          <p class="text-[0.65rem] uppercase tracking-[0.16em]" style="color: var(--np-accent-primary)">
            Quick Actions
          </p>
          <div class="flex flex-wrap gap-2">
            <button
              type="button"
              @click="runPrebuiltScriptForDevice('malformed_syn_flood.py', { count: 30 })"
              class="rounded-md border bg-black/80 px-2 py-0.5 text-[0.65rem]
                     text-[var(--np-text)] hover:bg-teal-500/10 disabled:opacity-50"
              style="border-color: var(--np-border)"
              :disabled="isRunningAction"
            >
              SYN Storm (template)
            </button>
            <button
              type="button"
              @click="runPrebuiltScriptForDevice('malformed_xmas_scan.py')"
              class="rounded-md border bg-black/80 px-2 py-0.5 text-[0.65rem]
                     text-[var(--np-text)] hover:bg-teal-500/10 disabled:opacity-50"
              style="border-color: var(--np-border)"
              :disabled="isRunningAction"
            >
              Xmas Scan (template)
            </button>
            <button
              type="button"
              @click="runPrebuiltScriptForDevice('malformed_overlap_fragments.py')"
              class="rounded-md border bg-black/80 px-2 py-0.5 text-[0.65rem]
                     text-[var(--np-text)] hover:bg-teal-500/10 disabled:opacity-50"
              style="border-color: var(--np-border)"
              :disabled="isRunningAction"
            >
              Overlap Fragments
            </button>
          </div>

          <div class="mt-3 border-t pt-2 space-y-2" style="border-color: var(--np-border)">
            <p class="text-[0.65rem] uppercase tracking-[0.16em]" style="color: var(--np-accent-primary)">
              Device Summary
            </p>
            <p v-if="deviceDetailLoading" class="text-[0.7rem] text-[var(--np-muted-text)]">
              Loading device detail...
            </p>
            <p v-else-if="deviceDetailError" class="text-[0.7rem] text-rose-300">
              {{ deviceDetailError }}
            </p>
            <div v-else-if="deviceDetail" class="space-y-1 text-[0.7rem]">
              <p v-if="deviceDetail.vulnerabilities.length">
                Recent vulns:
                <span
                  v-for="v in deviceDetail.vulnerabilities"
                  :key="v.id"
                  class="mr-2"
                >
                  [{{ v.severity }}] {{ v.title }}
                </span>
              </p>
              <p v-if="deviceDetail.scripts.length">
                Recent scripts:
                <span
                  v-for="s in deviceDetail.scripts"
                  :key="s.id"
                  class="mr-2"
                >
                  {{ s.script_name }} ({{ s.status }})
                </span>
              </p>
            </div>
          </div>
        </div>
      </div>

      <div class="rounded-md border bg-black/40 p-3 text-xs" style="border-color: var(--np-border)">
        <div class="flex items-center justify-between">
          <div>
            <h3 class="text-[0.7rem] uppercase tracking-[0.16em]" style="color: var(--np-accent-primary)">
              Quick Recon
            </h3>
            <p class="mt-0.5 text-[0.7rem] text-[var(--np-muted-text)]">
              Select a target and get context-aware Nmap script recommendations.
            </p>
          </div>
          <span class="rounded-full border px-2 py-0.5 text-[0.6rem]" style="border-color: var(--np-border); color: var(--np-muted-text)">
            Scanner
          </span>
        </div>

        <div class="mt-2 flex flex-col gap-2">
          <label class="text-[0.7rem] text-[var(--np-muted-text)]">
            Target (IP / Hostname)
            <input
              v-model="selectedTarget"
              type="text"
              class="mt-1 w-full rounded-md border bg-black/60 px-2 py-1 text-[0.75rem]
                     focus:outline-none focus:ring-1"
              style="border-color: var(--np-border); color: var(--np-text)"
              placeholder="10.0.0.15"
            />
          </label>

          <div class="flex items-center gap-2 text-[0.7rem]">
            <button
              type="button"
              @click="scanTarget"
              class="np-cyber-btn rounded-md px-2.5 py-1 text-[0.7rem] font-medium disabled:opacity-50"
              :disabled="isScanning || !canRunRecon"
            >
              <span v-if="!isScanning">Scan with Nmap</span>
              <span v-else>Scanning...</span>
            </button>
            <span v-if="scanError" class="text-rose-300">
              {{ scanError }}
            </span>
          </div>

          <div v-if="selectedServices.length" class="mt-2 grid gap-2 md:grid-cols-2">
            <div v-for="svc in selectedServices" :key="`${svc.protocol}-${svc.port}`" class="text-[0.7rem]">
              <div class="flex items-center justify-between">
                <span class="font-mono" style="color: var(--np-accent-primary)">
                  {{ svc.protocol }}/{{ svc.port }}
                </span>
                <span class="rounded bg-teal-500/10 px-1.5 py-0.5 text-[0.65rem]">
                  {{ svc.service }}
                </span>
              </div>
            </div>
          </div>

          <div class="mt-2 border-t pt-2" style="border-color: var(--np-border)">
            <div v-if="hasRecommendations" class="space-y-2">
              <div
                v-for="(rec, idx) in recommendations"
                :key="idx"
                class="rounded-md border bg-black/60 p-2"
                style="border-color: var(--np-border)"
              >
                <p class="text-[0.7rem] font-semibold" style="color: var(--np-accent-primary)">
                  {{ rec.reason }}
                </p>
                <p class="mt-1 text-[0.7rem] text-[var(--np-muted-text)]">
                  Suggested Nmap scripts:
                </p>
                <div class="mt-1 flex flex-wrap gap-1">
                  <span
                    v-for="script in rec.scripts"
                    :key="script"
                    class="rounded border bg-black/70 px-1.5 py-0.5 text-[0.65rem] font-mono"
                    style="border-color: var(--np-border)"
                  >
                    {{ script }}
                  </span>
                </div>
              </div>
            </div>
            <p v-else class="text-[0.7rem] text-[var(--np-muted-text)]">
              Enter a target and run a scan to see tailored Nmap script suggestions.
            </p>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>
