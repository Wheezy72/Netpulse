<script setup lang="ts">
import axios from "axios";
import { Network, Options } from "vis-network/standalone/esm/vis-network.mjs";
import { DataSet } from "vis-data/standalone/esm/vis-data.mjs";
import { Terminal } from "xterm";
import { FitAddon } from "xterm-addon-fit";
import "xterm/css/xterm.css";
import { computed, onBeforeUnmount, onMounted, ref, nextTick, watch } from "vue";
import { useRoute } from "vue-router";
import { resolveOui } from "../utils/oui";

const props = defineProps<{
  theme: "nightshade" | "sysadmin";
  isAdmin?: boolean;
}>();

const route = useRoute();

const isNightshade = computed(() => props.theme === "nightshade");

// Vis-network node/edge colour palette
const NODE_COLORS = {
  defaultBorder:    "#14b8a6",  // teal-500
  defaultBg:        "#090d16",  // slate-955
  defaultHighlight: "#5eead4",  // teal-300
  defaultHighBg:    "#111c33",  // slate-800 tinted
  gatewayBorder:    "#22c55e",  // green-500
  gatewayHighlight: "#bbf7d0",  // green-200
  dangerBorder:     "#ef4444",  // red-500
  dangerHighlight:  "#fecaca",  // red-200
  edgeColor:        "#14b8a633",
  edgeHighlight:    "#14b8a688",
  fontColor:        "#e2e8f0",
} as const;

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
};

type SwitchConfig = {
  filename: string;
  size_bytes: number;
  modified_at: string;
  content_preview?: string;
};

const topologyLoading = ref(false);
const topologyError = ref<string | null>(null);
const selectedNode = ref<TopologyNode | null>(null);
const deviceDetail = ref<DeviceDetail | null>(null);
const deviceDetailLoading = ref(false);
const deviceDetailError = ref<string | null>(null);

const zones = ref<string[]>([]);
const selectedZone = ref<string>("all");

const graphContainer = ref<HTMLElement | null>(null);
let network: Network | null = null;
let visNodes: DataSet<any> | null = null;
let visEdges: DataSet<any> | null = null;

// Tab selection in details panel: "info" | "ssh" | "configs"
const activeTab = ref<"info" | "ssh" | "configs">("info");

// Switch/Router config states
const configs = ref<SwitchConfig[]>([]);
const configsLoading = ref(false);
const selectedConfigText = ref<string | null>(null);
const selectedConfigName = ref<string | null>(null);
const configTextLoading = ref(false);

// SSH terminal credentials and state
const sshUsername = ref("admin");
const sshPassword = ref("");
const sshPort = ref(22);
const sshConnecting = ref(false);
const sshConnected = ref(false);
const sshError = ref<string | null>(null);

const terminalContainer = ref<HTMLDivElement | null>(null);
let term: Terminal | null = null;
let fitAddon: FitAddon | null = null;
let ws: WebSocket | null = null;

function disconnectSsh() {
  try {
    ws?.close();
  } catch {}
  ws = null;
  try {
    term?.dispose();
  } catch {}
  term = null;
  fitAddon = null;
  sshConnected.value = false;
  sshConnecting.value = false;
}

async function connectSsh() {
  if (!selectedNode.value) return;
  sshConnecting.value = true;
  sshError.value = null;

  await nextTick();

  if (!terminalContainer.value) {
    sshError.value = "Terminal container UI is not initialized.";
    sshConnecting.value = false;
    return;
  }

  const token = window.localStorage.getItem("np-token") || "";
  const apiBase = (import.meta as any).env?.VITE_API_BASE_URL || window.location.origin;
  const wsBase = apiBase.replace(/^http/, "ws");
  const wsUrl = `${wsBase}/api/ws/ssh?token=${encodeURIComponent(token)}` +
                `&ip=${encodeURIComponent(selectedNode.value.ip_address)}` +
                `&username=${encodeURIComponent(sshUsername.value)}` +
                `&password=${encodeURIComponent(sshPassword.value)}` +
                `&port=${sshPort.value}`;

  try {
    ws = new WebSocket(wsUrl);
  } catch (err: any) {
    sshError.value = `Failed to open socket: ${err.message || err}`;
    sshConnecting.value = false;
    return;
  }

  term = new Terminal({
    convertEol: true,
    cursorBlink: true,
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
    fontSize: 12,
    theme: {
      background: "#090d16",
      foreground: "#e2e8f0",
      cursor: "#10b981",
      cursorAccent: "#090d16",
      selectionBackground: "rgba(16, 185, 129, 0.3)"
    }
  });

  fitAddon = new FitAddon();
  term.loadAddon(fitAddon);

  ws.onopen = () => {
    sshConnected.value = true;
    sshConnecting.value = false;
    
    if (terminalContainer.value && term) {
      term.open(terminalContainer.value);
      fitAddon?.fit();
      term.focus();
      
      ws?.send(JSON.stringify({
        type: "resize",
        cols: term.cols,
        rows: term.rows
      }));
    }
  };

  ws.onmessage = (event) => {
    term?.write(event.data);
  };

  ws.onerror = () => {
    sshError.value = "WebSocket connection failed.";
    disconnectSsh();
  };

  ws.onclose = (event) => {
    if (event.code !== 1000 && !sshError.value) {
      sshError.value = `SSH Session Disconnected: ${event.reason || 'Code ' + event.code}`;
    }
    disconnectSsh();
  };

  term.onData((data) => {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(data);
    }
  });
}

// Vendor detection and secure connection tips
const connectionGuidelines = computed(() => {
  if (!selectedNode.value) return null;
  const mac = deviceDetail.value?.device.mac_address || "";
  const vendor = (mac ? resolveOui(mac) : null) || "";
  const vLower = vendor.toLowerCase();
  
  let brand = "Generic Network Node";
  let defaultUser = "admin / root";
  let securityNotice = "Ensure legacy protocols like Telnet (port 23) and SSH v1 are disabled. Restrict access using ACLs.";
  
  if (vLower.includes("cisco")) {
    brand = "Cisco IOS / Catalyst Switch or ASA Router";
    defaultUser = "cisco / admin";
    securityNotice = "Disable Telnet by configuring 'transport input ssh' on line vty. Implement AAA authorization to track actions.";
  } else if (vLower.includes("hp") || vLower.includes("hewlett") || vLower.includes("h3c")) {
    brand = "HP ProCurve / H3C Comware / Aruba Switch";
    defaultUser = "admin / manager";
    securityNotice = "Use SNMPv3 for secure telemetry. Change the default manager credentials and enforce SSH key-based access.";
  } else if (vLower.includes("juniper")) {
    brand = "Juniper Junos EX Switch or SRX Gateway";
    defaultUser = "root / admin";
    securityNotice = "Enforce administrative logins using distinct classes. Restrict SSH root logins using 'root-login deny'.";
  } else if (vLower.includes("ubiquiti") || vLower.includes("ubnt")) {
    brand = "Ubiquiti EdgeOS / UniFi Router";
    defaultUser = "ubnt / root";
    securityNotice = "Teardown default ubnt user credentials. Pin management interface access to a dedicated internal management VLAN.";
  } else if (vLower.includes("huawei")) {
    brand = "Huawei VRP Switch / AR Router";
    defaultUser = "admin / manager";
    securityNotice = "Configure Local AAA authentication. Enable SSH server authentication and forbid anonymous SSH sessions.";
  }
  
  return { brand, defaultUser, securityNotice };
});

async function loadConfigs() {
  if (!selectedNode.value) return;
  configsLoading.value = true;
  selectedConfigText.value = null;
  selectedConfigName.value = null;
  try {
    const { data } = await axios.get<SwitchConfig[]>(`/api/devices/${selectedNode.value.id}/configs`);
    configs.value = data;
  } catch {
    configs.value = [];
  } finally {
    configsLoading.value = false;
  }
}

async function viewConfig(filename: string) {
  if (!selectedNode.value) return;
  configTextLoading.value = true;
  selectedConfigName.value = filename;
  try {
    const { data } = await axios.get<string>(`/api/devices/${selectedNode.value.id}/configs/${filename}`);
    selectedConfigText.value = data;
  } catch {
    selectedConfigText.value = "Failed to load configuration contents.";
  } finally {
    configTextLoading.value = false;
  }
}

// Watch selected node to teardown SSH session and load configs
watch(selectedNode, () => {
  disconnectSsh();
  activeTab.value = "info";
  sshPassword.value = "";
  sshError.value = null;
  loadConfigs();
});

async function loadTopology(): Promise<void> {
  topologyError.value = null;
  topologyLoading.value = true;

  try {
    const params: Record<string, string> = {};
    if (selectedZone.value !== "all") {
      params.zone = selectedZone.value;
    }

    const { data } = await axios.get<{ nodes: TopologyNode[]; edges: TopologyEdge[] }>("/api/devices/topology", { params });

    await nextTick();
    if (!graphContainer.value) {
      topologyError.value = "Network graph container not mounted.";
      return;
    }

    const mappedNodes = data.nodes.map((n) => {
      let nodeColor: any = {
        border: NODE_COLORS.defaultBorder,
        background: NODE_COLORS.defaultBg,
        highlight: { border: NODE_COLORS.defaultHighlight, background: NODE_COLORS.defaultHighBg },
      };
      let nodeShape = "dot";
      let nodeShadow = false as any;

      if (n.is_gateway) {
        nodeShape = "diamond";
        nodeColor.border = NODE_COLORS.gatewayBorder;
        nodeColor.highlight.border = NODE_COLORS.gatewayHighlight;
      }

      if (n.vulnerability_severity === "high" || n.vulnerability_severity === "critical") {
        nodeColor.border = NODE_COLORS.dangerBorder;
        nodeColor.highlight.border = NODE_COLORS.dangerHighlight;
        nodeShadow = { enabled: true, color: NODE_COLORS.dangerBorder, size: 18, x: 0, y: 0 };
      }

      return {
        id: n.id,
        label: n.hostname || n.ip_address,
        shape: nodeShape,
        color: nodeColor,
        shadow: nodeShadow,
        font: { color: NODE_COLORS.fontColor, size: 12, face: "monospace" },
        size: n.is_gateway ? 22 : 14,
        borderWidth: 2,
        raw: n
      };
    });

    const mappedEdges = data.edges.map((e, index) => ({
      id: `e-${index}`,
      from: e.source,
      to: e.target,
      color: { color: NODE_COLORS.edgeColor, highlight: NODE_COLORS.edgeHighlight },
    }));

    if (!network) {
      visNodes = new DataSet(mappedNodes);
      visEdges = new DataSet(mappedEdges);

      const options: Options = {
        physics: {
          solver: "barnesHut",
          barnesHut: { gravitationalConstant: -2000, centralGravity: 0.3, springLength: 95, damping: 0.15 },
        },
        nodes: { borderWidth: 2 },
        edges: { width: 1, smooth: { enabled: true, type: "continuous", roundness: 0.5 } },
        interaction: { hover: true, tooltipDelay: 200 }
      };

      network = new Network(graphContainer.value, { nodes: visNodes, edges: visEdges }, options);

      network.on("selectNode", async (params) => {
        if (!visNodes) return;
        const nodeId = params.nodes[0];
        const tappedNode = (visNodes.get(nodeId) as any).raw as TopologyNode;
        selectedNode.value = tappedNode;
        await loadDeviceDetail(tappedNode.id);
      });
    } else {
      visNodes?.clear();
      visEdges?.clear();
      visNodes?.add(mappedNodes);
      visEdges?.add(mappedEdges);
    }

    // Handle deep-link selection from query params
    const selectNodeId = route.query.select ? Number(route.query.select) : null;
    if (selectNodeId && network && visNodes) {
      const tappedNode = (visNodes.get(selectNodeId) as any)?.raw as TopologyNode;
      if (tappedNode) {
        network.selectNodes([selectNodeId]);
        selectedNode.value = tappedNode;
        await loadDeviceDetail(tappedNode.id);
      }
    }
  } catch (err: any) {
    topologyError.value = "Failed to load network topology.";
  } finally {
    topologyLoading.value = false;
  }
}

async function loadDeviceDetail(deviceId: number): Promise<void> {
  deviceDetailLoading.value = true;
  deviceDetailError.value = null;
  try {
    const { data } = await axios.get<DeviceDetail>(`/api/devices/${deviceId}/detail`);
    deviceDetail.value = data;
  } catch (err: any) {
    deviceDetailError.value = "Failed to load device details.";
  } finally {
    deviceDetailLoading.value = false;
  }
}

async function loadZones(): Promise<void> {
  try {
    const { data } = await axios.get<{ zones: string[] }>("/api/devices/zones");
    zones.value = data.zones ?? [];
  } catch {}
}

function handleResize() {
  if (term && fitAddon) {
    fitAddon.fit();
    ws?.send(JSON.stringify({
      type: "resize",
      cols: term.cols,
      rows: term.rows
    }));
  }
}

onMounted(() => {
  loadZones().then(() => {
    loadTopology();
  });
  window.addEventListener("resize", handleResize);
});

onBeforeUnmount(() => {
  window.removeEventListener("resize", handleResize);
  disconnectSsh();
  if (network) {
    network.destroy();
    network = null;
  }
});
</script>

<template>
  <div class="space-y-6">
    <!-- Top Filter Header -->
    <header class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 p-5 rounded-2xl bg-[var(--np-glass-bg)] border border-[var(--np-glass-border)]">
      <div>
        <h1 class="text-lg font-bold tracking-widest text-[var(--np-accent-primary)] uppercase">
          Interactive Topology Map
        </h1>
        <p class="text-[0.65rem] text-[var(--np-text-dim)] uppercase tracking-wider mt-0.5">
          Passive Discovery &amp; Live Node Interaction
        </p>
      </div>

      <div class="flex items-center gap-3">
        <label class="text-[0.65rem] text-[var(--np-text-dim)] uppercase font-mono tracking-wider">
          Filter Zone:
        </label>
        <select
          v-model="selectedZone"
          @change="loadTopology"
          class="rounded-xl border bg-black/40 px-3 py-1.5 text-xs font-mono text-[var(--np-text)] border-[var(--np-glass-border)] focus:outline-none focus:ring-1 focus:ring-[var(--np-accent-primary)]"
        >
          <option value="all">All Zones</option>
          <option v-for="z in zones" :key="z" :value="z">{{ z }}</option>
        </select>
        <button
          @click="loadTopology"
          class="p-2 rounded-xl border border-[var(--np-glass-border)] bg-black/20 hover:bg-emerald-500/10 hover:border-emerald-500/30 text-[var(--np-text)] transition-all"
          title="Refresh Network Layout"
        >
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 7.89M9 11l3 3L22 4" />
          </svg>
        </button>
      </div>
    </header>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <!-- Vis Network Physics Graph -->
      <div class="lg:col-span-2 flex flex-col min-h-[500px] rounded-2xl bg-[var(--np-glass-bg)] border border-[var(--np-glass-border)] overflow-hidden relative shadow-2xl">
        <div
          ref="graphContainer"
          class="flex-1 w-full h-full min-h-[500px]"
        />
        <div v-if="topologyLoading" class="absolute inset-0 flex items-center justify-center bg-black/50 text-xs text-[var(--np-accent-primary)] font-mono pointer-events-none z-10">
          <span class="animate-pulse">BUILDING PHYSICS GRAPH...</span>
        </div>
        <div v-else-if="topologyError" class="absolute inset-0 flex items-center justify-center bg-black/60 text-xs text-rose-400 font-mono pointer-events-none z-10">
          {{ topologyError }}
        </div>
      </div>

      <!-- Right Panel: Node Details & Live SSH Console -->
      <div class="flex flex-col">
        <div v-if="selectedNode" class="rounded-2xl bg-[var(--np-glass-bg)] border border-[var(--np-glass-border)] shadow-lg flex flex-col p-5 h-full min-h-[500px]">
          <!-- Node Header -->
          <div class="flex items-center justify-between border-b border-[var(--np-border-subtle)] pb-3 mb-4 shrink-0">
            <div class="flex flex-col">
              <span class="text-xs font-bold uppercase tracking-wider text-[var(--np-accent-primary)]">Node Interactive Console</span>
              <span class="text-[0.65rem] font-mono text-[var(--np-text)] mt-0.5">{{ selectedNode.ip_address }}</span>
            </div>
            <span class="text-[0.55rem] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/25 uppercase">
              {{ selectedNode.is_gateway ? 'Gateway' : 'Host' }}
            </span>
          </div>

          <!-- Navigation tabs -->
          <div class="flex border-b border-[var(--np-border-subtle)] mb-4 shrink-0">
            <button
              @click="activeTab = 'info'"
              :class="[activeTab === 'info' ? 'border-emerald-500 text-emerald-400 font-bold' : 'border-transparent text-[var(--np-text-dim)]']"
              class="flex-1 py-2 border-b-2 text-xs uppercase tracking-wider font-mono text-center transition-all"
            >
              Info
            </button>
            <button
              @click="activeTab = 'ssh'"
              :class="[activeTab === 'ssh' ? 'border-emerald-500 text-emerald-400 font-bold' : 'border-transparent text-[var(--np-text-dim)]']"
              class="flex-1 py-2 border-b-2 text-xs uppercase tracking-wider font-mono text-center transition-all"
            >
              SSH Shell
            </button>
            <button
              @click="activeTab = 'configs'"
              :class="[activeTab === 'configs' ? 'border-emerald-500 text-emerald-400 font-bold' : 'border-transparent text-[var(--np-text-dim)]']"
              class="flex-1 py-2 border-b-2 text-xs uppercase tracking-wider font-mono text-center transition-all"
            >
              Configs
            </button>
          </div>

          <!-- Tab Contents -->
          <div class="flex-1 overflow-y-auto custom-scrollbar min-h-[350px]">
            <!-- Tab: Info -->
            <div v-if="activeTab === 'info'" class="space-y-5">
              <dl class="space-y-2.5 text-xs">
                <div class="flex justify-between border-b border-white/5 pb-1.5">
                  <dt class="text-[var(--np-text-dim)]">Hostname</dt>
                  <dd class="font-bold text-[var(--np-text)]">{{ selectedNode.hostname || '—' }}</dd>
                </div>
                <div class="flex justify-between border-b border-white/5 pb-1.5">
                  <dt class="text-[var(--np-text-dim)]">MAC Address</dt>
                  <dd class="font-mono text-[var(--np-text)]">{{ deviceDetail?.device.mac_address || '—' }}</dd>
                </div>
                <div class="flex justify-between border-b border-white/5 pb-1.5">
                  <dt class="text-[var(--np-text-dim)]">OUI Vendor</dt>
                  <dd class="text-[var(--np-text)]">
                    {{ deviceDetail?.device.mac_address ? (resolveOui(deviceDetail.device.mac_address) ?? 'Unknown') : '—' }}
                  </dd>
                </div>
                <div class="flex justify-between border-b border-white/5 pb-1.5">
                  <dt class="text-[var(--np-text-dim)]">Zone</dt>
                  <dd class="text-[var(--np-text)]">{{ selectedNode.zone || '—' }}</dd>
                </div>
                <div class="flex justify-between border-b border-white/5 pb-1.5">
                  <dt class="text-[var(--np-text-dim)]">Device Type</dt>
                  <dd class="text-[var(--np-text)]">{{ deviceDetail?.type_guess || selectedNode.device_type || '—' }}</dd>
                </div>
                <div class="flex justify-between border-b border-white/5 pb-1.5">
                  <dt class="text-[var(--np-text-dim)]">Last Seen</dt>
                  <dd class="text-[var(--np-text)]">{{ selectedNode.last_seen ? new Date(selectedNode.last_seen).toLocaleString() : '—' }}</dd>
                </div>
              </dl>

              <!-- Real Vulnerabilities section -->
              <div class="space-y-2 pt-2 border-t border-[var(--np-border-subtle)]">
                <span class="text-[0.55rem] uppercase tracking-widest text-[var(--np-text-dim)] font-bold block">
                  Vulnerabilities ({{ deviceDetail?.vulnerabilities?.length || 0 }})
                </span>
                <div class="space-y-1.5">
                  <div v-for="vuln in deviceDetail?.vulnerabilities" :key="vuln.id" class="flex justify-between items-center rounded-lg p-2.5 bg-[var(--np-surface-elevated)] border border-[var(--np-border-subtle)]">
                    <div class="flex items-center gap-2">
                      <span :class="[
                        vuln.severity === 'critical' ? 'text-red-500 font-bold' :
                        vuln.severity === 'high' ? 'text-orange-500 font-bold' :
                        vuln.severity === 'medium' ? 'text-yellow-500 font-bold' :
                        'text-emerald-400'
                      ]" class="font-mono text-[0.65rem] shrink-0">
                        [{{ vuln.severity.toUpperCase() }}]
                      </span>
                      <span class="text-[0.65rem] text-[var(--np-text)] truncate max-w-[180px]">{{ vuln.title }}</span>
                    </div>
                    <span v-if="vuln.port" class="text-[0.65rem] font-mono text-[var(--np-text-dim)]">:{{ vuln.port }}</span>
                  </div>
                  <div v-if="!deviceDetail?.vulnerabilities?.length" class="text-xs font-mono py-2 text-[var(--np-text-dim)] text-center">No vulnerabilities detected.</div>
                </div>
              </div>

              <!-- Real Scripts execution section -->
              <div class="space-y-2 pt-2 border-t border-[var(--np-border-subtle)]">
                <span class="text-[0.55rem] uppercase tracking-widest text-[var(--np-text-dim)] font-bold block">
                  Recent Script Jobs
                </span>
                <div class="space-y-1.5">
                  <div v-for="s in deviceDetail?.scripts" :key="s.id" class="flex justify-between items-center rounded-lg p-2 bg-[var(--np-surface-elevated)] border border-[var(--np-border-subtle)] text-[0.65rem]">
                    <span class="font-mono text-[var(--np-text)] truncate max-w-[180px]">{{ s.script_name }}</span>
                    <span :class="[
                      s.status === 'success' ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' :
                      s.status === 'failed' ? 'text-red-400 bg-red-500/10 border-red-500/20' :
                      'text-yellow-400 bg-yellow-500/10 border-yellow-500/20'
                    ]" class="px-1.5 py-0.5 rounded font-mono border text-[0.55rem] uppercase">
                      {{ s.status }}
                    </span>
                  </div>
                  <div v-if="!deviceDetail?.scripts?.length" class="text-xs font-mono py-2 text-[var(--np-text-dim)] text-center">No scripts executed.</div>
                </div>
              </div>
            </div>

            <!-- Tab: SSH Shell -->
            <div v-else-if="activeTab === 'ssh'" class="h-full flex flex-col gap-4">
              <!-- Connection Credentials Form -->
              <div v-if="!sshConnected && !sshConnecting" class="space-y-4">
                <div class="text-[0.65rem] font-mono text-[var(--np-text-dim)] uppercase tracking-wider mb-2">
                  SSH Remote Login
                </div>

                <div class="space-y-3.5">
                  <div>
                    <label class="block text-[0.6rem] uppercase tracking-wider mb-1.5 font-mono text-[var(--np-text-dim)]">Username</label>
                    <input
                      v-model="sshUsername"
                      type="text"
                      class="np-neon-input w-full rounded-lg px-3.5 py-2 text-xs font-mono bg-black/40 text-[var(--np-text)]"
                      placeholder="root"
                    />
                  </div>

                  <div>
                    <label class="block text-[0.6rem] uppercase tracking-wider mb-1.5 font-mono text-[var(--np-text-dim)]">Password</label>
                    <input
                      v-model="sshPassword"
                      type="password"
                      class="np-neon-input w-full rounded-lg px-3.5 py-2 text-xs font-mono bg-black/40 text-[var(--np-text)]"
                      placeholder="••••••••••••"
                    />
                  </div>

                  <div>
                    <label class="block text-[0.6rem] uppercase tracking-wider mb-1.5 font-mono text-[var(--np-text-dim)]">Port</label>
                    <input
                      v-model="sshPort"
                      type="number"
                      class="np-neon-input w-full rounded-lg px-3.5 py-2 text-xs font-mono bg-black/40 text-[var(--np-text)]"
                      placeholder="22"
                    />
                  </div>
                </div>

                <!-- Vendor Specific Helper / Guidelines -->
                <div v-if="connectionGuidelines" class="p-3.5 rounded-xl border border-emerald-500/20 bg-emerald-500/5 space-y-2">
                  <div class="text-[0.65rem] font-bold text-emerald-400 uppercase tracking-wide">
                    🔒 {{ connectionGuidelines.brand }} Security Guidelines
                  </div>
                  <div class="text-[0.58rem] text-[var(--np-text-muted)] space-y-1 font-mono">
                    <p><span class="text-[var(--np-text-dim)]">Default credentials suggestion:</span> {{ connectionGuidelines.defaultUser }}</p>
                    <p><span class="text-[var(--np-text-dim)]">Intrusion Prevention advice:</span> {{ connectionGuidelines.securityNotice }}</p>
                  </div>
                </div>

                <button
                  @click="connectSsh"
                  class="w-full py-2.5 rounded-xl text-xs font-bold uppercase tracking-wider bg-emerald-500/10 text-emerald-400 border border-emerald-500/25 hover:bg-emerald-500/20 transition-all flex items-center justify-center gap-2"
                >
                  Connect SSH Client
                </button>

                <p v-if="sshError" class="text-xs font-mono text-red-400 bg-red-500/5 border border-red-500/15 p-2 rounded-lg text-center mt-2">
                  {{ sshError }}
                </p>
              </div>

              <!-- Connecting Loader -->
              <div v-else-if="sshConnecting" class="flex-1 flex flex-col items-center justify-center gap-3 py-12">
                <svg class="w-8 h-8 animate-spin text-emerald-500" fill="none" viewBox="0 0 24 24">
                  <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
                  <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
                </svg>
                <span class="text-xs font-mono text-emerald-400 uppercase tracking-widest animate-pulse">Initializing PTY session...</span>
              </div>

              <!-- Live Interactive Terminal -->
              <div v-else class="flex-1 flex flex-col min-h-[350px]">
                <div class="flex items-center justify-between pb-2 mb-2 border-b border-white/5">
                  <span class="text-[0.6rem] font-mono text-emerald-400 animate-pulse flex items-center gap-1.5">
                    <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-ping" />
                    SSH LOGGED IN
                  </span>
                  <button
                    @click="disconnectSsh"
                    class="px-2.5 py-1 text-[0.6rem] font-bold uppercase tracking-wider bg-red-500/10 text-red-400 border border-red-500/25 hover:bg-red-500/20 rounded-md transition-all"
                  >
                    Disconnect
                  </button>
                </div>

                <div class="flex-1 relative rounded-lg border border-[var(--np-glass-border)] bg-[#090d16] overflow-hidden p-2">
                  <div
                    ref="terminalContainer"
                    class="w-full h-full min-h-[300px]"
                  />
                </div>
              </div>
            </div>

            <!-- Tab: Configs -->
            <div v-else-if="activeTab === 'configs'" class="space-y-4">
              <div class="flex items-center justify-between border-b border-white/5 pb-2">
                <span class="text-[0.65rem] font-mono text-[var(--np-text-dim)] uppercase tracking-wider">
                  Device configuration archives
                </span>
                <button
                  @click="loadConfigs"
                  class="text-[0.6rem] text-emerald-400 hover:underline uppercase tracking-widest"
                  :disabled="configsLoading"
                >
                  {{ configsLoading ? 'Reloading...' : 'Reload' }}
                </button>
              </div>

              <!-- Config list -->
              <div v-if="!selectedConfigText" class="space-y-2">
                <div
                  v-for="cfg in configs"
                  :key="cfg.filename"
                  class="p-3 rounded-xl border border-[var(--np-glass-border)] bg-black/30 hover:border-emerald-500/30 transition-all flex justify-between items-center"
                >
                  <div class="flex flex-col min-w-0">
                    <span class="font-mono text-xs text-[var(--np-text)] truncate max-w-[190px]">{{ cfg.filename }}</span>
                    <span class="text-[0.55rem] font-mono text-[var(--np-text-dim)] mt-0.5">
                      {{ new Date(cfg.modified_at).toLocaleString() }} • {{ (cfg.size_bytes / 1024).toFixed(2) }} KB
                    </span>
                  </div>
                  <button
                    @click="viewConfig(cfg.filename)"
                    class="px-2.5 py-1 text-[0.6rem] font-bold uppercase tracking-wider bg-emerald-500/10 text-emerald-400 border border-emerald-500/25 hover:bg-emerald-500/20 rounded-md transition-all shrink-0"
                  >
                    View
                  </button>
                </div>
                <div v-if="configs.length === 0" class="text-xs font-mono py-8 text-[var(--np-text-dim)] text-center">
                  No configuration backups found. Run the "backup_switch.py" script in the Toolbox to gather configuration files.
                </div>
              </div>

              <!-- Config Content View -->
              <div v-else class="space-y-3">
                <div class="flex items-center justify-between">
                  <span class="font-mono text-[0.6rem] text-[var(--np-text)] truncate max-w-[200px]">
                    {{ selectedConfigName }}
                  </span>
                  <button
                    @click="selectedConfigText = null; selectedConfigName = null"
                    class="text-[0.6rem] text-rose-400 hover:underline uppercase tracking-wider"
                  >
                    Back to List
                  </button>
                </div>

                <div class="p-3.5 rounded-lg border border-[var(--np-glass-border)] bg-[#090d16] font-mono text-[0.65rem] text-slate-300 overflow-x-auto whitespace-pre leading-relaxed custom-scrollbar max-h-[300px]">
                  {{ selectedConfigText }}
                </div>
              </div>
            </div>
          </div>
        </div>

        <div v-else class="rounded-2xl bg-[var(--np-glass-bg)] border border-[var(--np-glass-border)] p-12 text-center text-xs text-[var(--np-text-dim)] flex flex-col items-center justify-center min-h-[500px] shadow-2xl">
          <svg class="w-12 h-12 text-[var(--np-text-dim)]/35 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 20l-5.447-2.724A2 2 0 013 15.485V6.515a2 2 0 011.553-1.792L9 2l5.447 2.724A2 2 0 0116 6.515v8.97a2 2 0 01-1.553 1.792L9 20z" />
          </svg>
          <span class="font-mono uppercase tracking-wider">Select a node in the physics graph topology to inspect and interact.</span>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.custom-scrollbar::-webkit-scrollbar {
  width: 4px;
}
.custom-scrollbar::-webkit-scrollbar-track {
  background: transparent;
}
.custom-scrollbar::-webkit-scrollbar-thumb {
  background: var(--np-glass-border);
  border-radius: 9999px;
}
</style>
