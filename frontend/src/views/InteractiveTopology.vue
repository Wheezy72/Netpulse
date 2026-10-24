<script setup lang="ts">
import axios from "axios";
import { VueFlow, useVueFlow, type Edge, type Node } from "@vue-flow/core";
import { Background } from "@vue-flow/background";
import { Controls } from "@vue-flow/controls";
import { MiniMap } from "@vue-flow/minimap";
import { Terminal } from "xterm";
import { FitAddon } from "xterm-addon-fit";
import "xterm/css/xterm.css";
import "@vue-flow/core/dist/style.css";
import "@vue-flow/core/dist/theme-default.css";
import "@vue-flow/controls/dist/style.css";
import "@vue-flow/minimap/dist/style.css";
import { computed, onBeforeUnmount, onMounted, ref, nextTick, watch } from "vue";
import type { Component } from "vue";
import { useRoute } from "vue-router";
import { Cctv, Cpu, Laptop, LoaderCircle, Lock, Monitor, Printer, RefreshCw, Router, Server, Smartphone, Wifi, Waypoints } from "lucide-vue-next";

import { resolveOui } from "../utils/oui";
import { getStoredToken } from "../utils/token";

const props = defineProps<{
  theme: "nightshade" | "sysadmin";
  isAdmin?: boolean;
}>();

const route = useRoute();

const isNightshade = computed(() => props.theme === "nightshade");

const NODE_W = 132;
const NODE_H = 112;

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

// Each network keeps its own inventory, so the map is drawn for one network
// at a time — the one this machine is attached to unless another is picked.
type NetworkRow = { id: number; name: string; cidr: string; is_current: boolean };
const networks = ref<NetworkRow[]>([]);
const selectedNetwork = ref<string>("all");

async function loadNetworks(): Promise<void> {
  try {
    const { data } = await axios.get<NetworkRow[]>("/api/networks");
    networks.value = data;
    const current = data.find((n) => n.is_current);
    if (current && selectedNetwork.value === "all") {
      selectedNetwork.value = String(current.id);
    }
  } catch {}
}

type DeviceNodeData = { device: TopologyNode };

const flowNodes = ref<Node[]>([]);
const flowEdges = ref<Edge[]>([]);
const searchTerm = ref("");
const selectedNodeId = ref<number | null>(null);
const { fitView, onNodesInitialized } = useVueFlow();

// Fit once real node dimensions are known – otherwise the viewport can be
// computed against zero-sized nodes and clip the outer ring.
onNodesInitialized(() => {
  fitView({ padding: 0.06, duration: 300 });
});
function deviceOf(node: Node): TopologyNode {
  return node.data?.device as TopologyNode;
}

/** Ids of the selected node plus everything directly linked to it. */
const focusIds = computed<Set<number>>(() => {
  const ids = new Set<number>();
  if (selectedNodeId.value == null) return ids;
  ids.add(selectedNodeId.value);
  for (const edge of flowEdges.value) {
    const source = Number(edge.source);
    const target = Number(edge.target);
    if (source === selectedNodeId.value) ids.add(target);
    if (target === selectedNodeId.value) ids.add(source);
  }
  return ids;
});

function isDimmed(device: TopologyNode): boolean {
  if (!matchesSearch(device)) return true;
  if (selectedNodeId.value == null) return false;
  return !focusIds.value.has(device.id);
}

/** Edges stay visible but only the focused node's links stay lit. */
function paintEdgeFocus(): void {
  const focus = selectedNodeId.value;
  for (const edge of flowEdges.value) {
    const active = focus != null && (Number(edge.source) === focus || Number(edge.target) === focus);
    const dimmed = focus != null && !active;
    edge.class = ["np-flow-edge", active && "np-flow-edge--active", dimmed && "np-flow-edge--dim"]
      .filter(Boolean)
      .join(" ");
  }
  // New array reference so Vue Flow re-renders the edge layer.
  flowEdges.value = flowEdges.value.slice();
}
watch(selectedNodeId, paintEdgeFocus);

/** Plain array view of the flow nodes; avoids deep generic inference in computeds. */
function currentDevices(): TopologyNode[] {
  const nodes = flowNodes.value as unknown as Array<{ data?: DeviceNodeData }>;
  return nodes.map((node) => node.data?.device).filter((device): device is TopologyNode => Boolean(device));
}

const deviceCount = computed<number>(() => currentDevices().length);
const gatewayCount = computed<number>(() => currentDevices().filter((d) => d.is_gateway).length);
const alertCount = computed<number>(
  () => currentDevices().filter((d) => nodeDangerLevel(d) !== null).length
);
function matchesSearch(device: TopologyNode): boolean {
  const q = searchTerm.value.trim().toLowerCase();
  if (!q) return true;
  return [device.hostname, device.ip_address, device.device_type, device.zone]
    .some((value) => (value || "").toLowerCase().includes(q));
}

const ICON_PATHS = {
  gateway: Router,
  switch: Waypoints,
  server: Server,
  printer: Printer,
  laptop: Laptop,
  camera: Cctv,
  ap: Wifi,
  phone: Smartphone,
  iot: Cpu,
  endpoint: Monitor,
} satisfies Record<string, Component>;

function deviceIcon(type?: string | null): Component {
  const t = (type || "").toLowerCase();
  if (t.includes("router") || t.includes("gateway") || t.includes("firewall")) return ICON_PATHS.gateway;
  if (t.includes("switch") || t.includes("bridge")) return ICON_PATHS.switch;
  if (t.includes("server") || t.includes("nas") || t.includes("storage")) return ICON_PATHS.server;
  if (t.includes("printer")) return ICON_PATHS.printer;
  if (t.includes("camera")) return ICON_PATHS.camera;
  if (t.includes("access point") || t === "ap" || t.includes("wireless") || t.includes("wap")) return ICON_PATHS.ap;
  if (t.includes("phone") || t.includes("mobile")) return ICON_PATHS.phone;
  if (t.includes("iot") || t.includes("sensor") || t.includes("smart")) return ICON_PATHS.iot;
  if (t.includes("laptop") || t.includes("workstation") || t.includes("desktop")) return ICON_PATHS.laptop;
  return ICON_PATHS.endpoint;
}

/** Legend category for a device: gateway / infrastructure / endpoint. */
function deviceCategory(device: TopologyNode): "gw" | "infra" | "endpoint" {
  if (device.is_gateway) return "gw";
  const tier = nodeTier(device);
  return tier <= 2 ? "infra" : "endpoint";
}

function nodeDangerLevel(device: TopologyNode): "critical" | "high" | null {
  const sev = (device.vulnerability_severity || "").toLowerCase();
  if (sev === "critical") return "critical";
  if (sev === "high") return "high";
  return null;
}

function nodeTier(device: TopologyNode): number {
  const type = (device.device_type || "").toLowerCase();
  if (type.includes("switch") || type.includes("access point") || type === "ap") return 1;
  if (type.includes("server") || type.includes("nas")) return 2;
  return 3;
}

/**
 * Radial network map layout.
 *
 * Gateways sit at the centre, infrastructure (switches/APs) on the first ring,
 * servers on the second, and endpoints on the outer ring. This reads as a
 * network map rather than a hierarchical UML chart, and stays legible at any
 * device count because each ring grows to fit its nodes.
 */
function layoutRadial(nodes: Node[]): { nodes: Node[]; orbits: Node[] } {
  const positions = new Map<string, { x: number; y: number }>();
  const gateways = nodes.filter((node) => deviceOf(node).is_gateway);
  const others = nodes.filter((node) => !deviceOf(node).is_gateway);

  if (gateways.length === 1) {
    // The uplink sits dead centre so every ring radiates from the real hub.
    positions.set(gateways[0].id, { x: -NODE_W / 2, y: -NODE_H / 2 });
  } else if (gateways.length > 1) {
    const clusterRadius = 170;
    gateways.forEach((gateway, index) => {
      const angle = (index / gateways.length) * Math.PI * 2 - Math.PI / 2;
      positions.set(gateway.id, {
        x: Math.cos(angle) * clusterRadius - NODE_W / 2,
        y: Math.sin(angle) * clusterRadius - NODE_H / 2,
      });
    });
  }

  const tiers = new Map<number, Node[]>();
  others.forEach((node) => {
    const tier = nodeTier(deviceOf(node));
    if (!tiers.has(tier)) tiers.set(tier, []);
    tiers.get(tier)!.push(node);
  });

  const baseRadii: Record<number, number> = { 1: 175, 2: 285, 3: 390 };
  const orbits: Node[] = [];

  tiers.forEach((list, tier) => {
    // Circumference must fit every orb plus breathing room; grow the ring if needed.
    const minimumRadius = (list.length * (NODE_W + 26)) / (2 * Math.PI);
    const radius = Math.max(baseRadii[tier] ?? 390, minimumRadius);
    const offset = tier % 2 === 0 ? Math.PI / 2 : 0;

    list.forEach((node, index) => {
      const angle = (index / list.length) * Math.PI * 2 - Math.PI / 2 + offset;
      positions.set(node.id, {
        x: Math.cos(angle) * radius - NODE_W / 2,
        y: Math.sin(angle) * radius - NODE_H / 2,
      });
    });

    // Non-interactive ring guide that pans/zooms with the graph, so the map
    // reads as concentric orbits around the uplink instead of a flowchart.
    orbits.push({
      id: `orbit-${tier}`,
      type: "orbit",
      class: "np-orbit-node",
      position: { x: -radius, y: -radius },
      width: radius * 2,
      height: radius * 2,
      draggable: false,
      selectable: false,
      connectable: false,
      data: { radius },
    });
  });

  return {
    nodes: nodes.map((node) => ({
      ...node,
      position: positions.get(node.id) ?? { x: 0, y: 0 },
    })),
    orbits,
  };
}

async function onNodeClick({ node }: { node: Node }): Promise<void> {
  const device = node.data?.device as TopologyNode | undefined;
  if (!device) return;
  selectedNodeId.value = device.id;
  selectedNode.value = device;
  await loadDeviceDetail(device.id);
}

function clearSelection(): void {
  selectedNodeId.value = null;
  selectedNode.value = null;
  deviceDetail.value = null;
}

function onFlowInit(): void {
  fitView({ padding: 0.06, duration: 400 });
}

/** Mini-map swatches: orbit guides stay invisible, devices use category accents. */
function minimapNodeColor(node: { type?: string; data?: { device?: TopologyNode } }): string {
  if (node.type === "orbit") return "transparent";
  const device = node.data?.device;
  if (!device) return "transparent";
  if (nodeDangerLevel(device) === "critical") return "#ef4444";
  if (device.is_gateway) return "#22c55e";
  return deviceCategory(device) === "infra" ? "#38bdf8" : "#a78bfa";
}

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

  const token = getStoredToken();
  const apiBase = (import.meta as any).env?.VITE_API_BASE_URL || window.location.origin;
  const wsBase = apiBase.replace(/^http/, "ws");
  // Only the target address goes in the URL. The token, username and
  // password travel in the first frame, so none of them reach an access log,
  // a proxy log or browser history.
  const wsUrl = `${wsBase}/api/ws/ssh?ip=${encodeURIComponent(selectedNode.value.ip_address)}`;

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
      cursor: "#a5b4fc",
      cursorAccent: "#090d16",
      selectionBackground: "rgba(79, 70, 229, 0.35)"
    }
  });

  fitAddon = new FitAddon();
  term.loadAddon(fitAddon);

  ws.onopen = () => {
    // First frame is always the handshake; the server closes with 4400 if it
    // arrives as anything else.
    ws.send(
      JSON.stringify({
        type: "auth",
        token,
        username: sshUsername.value,
        password: sshPassword.value,
        port: sshPort.value,
      })
    );
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

let topologyRefreshTimer: number | undefined;

async function loadTopology(background = false): Promise<void> {
  // Background refreshes must not blank the view behind a loading state or
  // yank the operator's viewport — they silently swap in fresher data.
  if (!background) {
    topologyError.value = null;
    topologyLoading.value = true;
  }

  try {
    const params: Record<string, string> = {};
    if (selectedZone.value !== "all") {
      params.zone = selectedZone.value;
    }
    if (selectedNetwork.value !== "all") {
      params.network_id = selectedNetwork.value;
    }

    const { data } = await axios.get<{ nodes: TopologyNode[]; edges: TopologyEdge[] }>("/api/devices/topology", { params });

    const nodes: Node<DeviceNodeData>[] = data.nodes.map((n) => ({
      id: String(n.id),
      type: "device",
      position: { x: 0, y: 0 },
      // Explicit dimensions let Vue Flow compute fitView bounds before the DOM
      // has been measured, which otherwise clips the outer ring on first paint.
      width: NODE_W,
      height: NODE_H,
      data: { device: n },
    }));

    const edges: Edge[] = data.edges.map((e, index) => ({
      id: `e-${index}`,
      source: String(e.source),
      target: String(e.target),
      type: "straight",
      class: "np-flow-edge",
      style: { stroke: "var(--map-edge, #14b8a6)", strokeWidth: 1.25 },
    }));

    const layout = layoutRadial(nodes);
    // Orbit guides go first so they paint behind the device orbs.
    flowNodes.value = [...layout.orbits, ...layout.nodes];
    flowEdges.value = edges;

    if (background) {
      // Keep the operator's selection across refreshes; only drop it when the
      // selected device genuinely left the network.
      if (selectedNodeId.value && !data.nodes.some((n) => n.id === selectedNodeId.value)) {
        selectedNodeId.value = null;
        selectedNode.value = null;
        deviceDetail.value = null;
      }
      return;
    }

    selectedNodeId.value = null;
    selectedNode.value = null;
    deviceDetail.value = null;

    await nextTick();
    setTimeout(() => fitView({ padding: 0.06, duration: 450 }), 260);

    // Handle deep-link selection from query params
    const selectNodeId = route.query.select ? Number(route.query.select) : null;
    if (selectNodeId) {
      const tappedNode = data.nodes.find((n) => n.id === selectNodeId);
      if (tappedNode) {
        selectedNodeId.value = tappedNode.id;
        selectedNode.value = tappedNode;
        await loadDeviceDetail(tappedNode.id);
      }
    }
  } catch (err: any) {
    // A failed background poll keeps showing the last good map instead of
    // replacing it with an error page.
    if (!background) topologyError.value = "Failed to load network topology.";
  } finally {
    if (!background) topologyLoading.value = false;
  }
}

// Targeted "test" scan for the selected node. The backend already knows the
// device, so this is a single-host service scan — never a subnet sweep.
const testingNode = ref(false);
const testMessage = ref<string | null>(null);
const testMessageKind = ref<"ok" | "warn" | "err">("ok");

async function testSelectedNode(): Promise<void> {
  const node = selectedNode.value;
  if (!node || testingNode.value) return;
  testingNode.value = true;
  testMessage.value = null;
  try {
    const { data } = await axios.post<{
      ports: { port: number }[];
      warnings?: string[];
    }>(`/api/devices/${node.id}/deep-scan`);

    const portCount = data.ports?.length ?? 0;
    testMessage.value = portCount
      ? `Scan complete — ${portCount} open port${portCount === 1 ? "" : "s"} found.`
      : "Scan complete — nothing listening on the probed ports.";
    testMessageKind.value = data.warnings?.length ? "warn" : "ok";
    if (data.warnings?.length) testMessage.value += ` ${data.warnings[0]}`;

    await loadDeviceDetail(node.id);
    await loadTopology();
  } catch (err: any) {
    testMessage.value =
      err?.response?.data?.detail || "The test scan could not be started.";
    testMessageKind.value = "err";
  } finally {
    testingNode.value = false;
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
  void loadNetworks().then(() => {
    loadZones().then(() => {
      loadTopology();
    });
  });
  // The map used to render whatever the inventory held at mount time and
  // never look again — it read as "cached" on a live network. Quietly
  // re-poll while the tab is visible; skip while the drawer is open so the
  // operator's inspection isn't disturbed.
  topologyRefreshTimer = window.setInterval(() => {
    if (document.visibilityState === "visible" && !selectedNodeId.value) {
      void loadTopology(true);
    }
  }, 15_000);
  window.addEventListener("resize", handleResize);
});

onBeforeUnmount(() => {
  if (topologyRefreshTimer !== undefined) window.clearInterval(topologyRefreshTimer);
  window.removeEventListener("resize", handleResize);
  disconnectSsh();
});
</script>

<template>
  <div class="space-y-6">
    <!-- Page heading -->
    <div class="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <p class="text-[0.6rem] font-mono uppercase tracking-[0.35em] text-[var(--np-text-dim)]">Network map</p>
        <h1 class="mt-1 text-2xl font-bold tracking-tight text-[var(--np-text)]">Interactive topology</h1>
        <p class="mt-1 text-xs text-[var(--np-text-muted)]">
          Radial map of discovered hosts — the uplink sits at the core, infrastructure and endpoints orbit around it.
        </p>
      </div>

      <div class="flex flex-wrap items-center gap-2">
        <input
          v-model="searchTerm"
          type="search"
          placeholder="Find device…"
          class="w-36 sm:w-48 rounded-xl border border-[var(--np-border-subtle)] bg-[var(--np-input-bg)] px-3 py-2 text-xs font-mono text-[var(--np-text)] focus:outline-none focus:ring-1 focus:ring-[var(--np-accent)]"
        />
        <select
          v-if="networks.length > 1"
          v-model="selectedNetwork"
          @change="loadTopology"
          title="Each network keeps its own inventory"
          class="rounded-xl border border-[var(--np-border-subtle)] bg-[var(--np-input-bg)] px-3 py-2 text-xs font-mono text-[var(--np-text)] focus:outline-none focus:ring-1 focus:ring-[var(--np-accent)]"
        >
          <option value="all">All networks</option>
          <option v-for="n in networks" :key="n.id" :value="String(n.id)">
            {{ n.name }}{{ n.is_current ? " (current)" : "" }}
          </option>
        </select>
        <select
          v-model="selectedZone"
          @change="loadTopology"
          class="rounded-xl border border-[var(--np-border-subtle)] bg-[var(--np-input-bg)] px-3 py-2 text-xs font-mono text-[var(--np-text)] focus:outline-none focus:ring-1 focus:ring-[var(--np-accent)]"
        >
          <option value="all">All zones</option>
          <option v-for="z in zones" :key="z" :value="z">{{ z }}</option>
        </select>
        <button
          @click="loadTopology"
          class="flex h-9 w-9 items-center justify-center rounded-xl border border-[var(--np-border-subtle)] bg-[var(--np-surface-elevated)]/60 text-[var(--np-text-dim)] transition-all hover:border-[var(--np-accent-border)] hover:text-[var(--np-accent)]"
          title="Refresh network layout"
        >
          <RefreshCw class="h-4 w-4" :stroke-width="1.7" />
        </button>
      </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <!-- Interactive Vue Flow topology graph -->
      <div
        class="np-map glass-card lg:col-span-2 flex flex-col overflow-hidden relative h-[460px] sm:h-[560px] lg:h-[calc(100vh-17rem)]"
        :class="{ 'np-map--light': !isNightshade }"
      >
        <VueFlow
          :nodes="flowNodes"
          :edges="flowEdges"
          :min-zoom="0.12"
          :max-zoom="2.5"
          :nodes-connectable="false"
          :elements-selectable="true"
          :nodes-draggable="true"
          class="np-topology-flow w-full h-full"
          @init="onFlowInit"
          @node-click="onNodeClick"
          @pane-click="clearSelection"
        >
          <!-- Concentric orbit guides -->
          <template #node-orbit="{ data }">
            <div
              class="np-orbit"
              :style="{ width: `${(data as any).radius * 2}px`, height: `${(data as any).radius * 2}px` }"
            />
          </template>

          <!-- Device orb: icon core, status ring, label underneath -->
          <template #node-device="{ data, selected }">
            <div
              class="np-node"
              :class="{
                [`np-node--${deviceCategory(data.device)}`]: true,
                'np-node--selected': selected,
                'np-node--critical': nodeDangerLevel(data.device) === 'critical',
                'np-node--high': nodeDangerLevel(data.device) === 'high',
                'np-node--dim': isDimmed(data.device),
              }"
            >
              <div class="np-orb">
                <span v-if="data.device.is_gateway" class="np-orb-ping" />
                <span class="np-orb-disc">
                  <component :is="deviceIcon(data.device.device_type)" :stroke-width="1.7" />
                </span>
                <span v-if="nodeDangerLevel(data.device)" class="np-orb-alert">!</span>
              </div>
              <div class="np-label">
                <span class="np-label-name">{{ data.device.hostname || data.device.ip_address }}</span>
                <span class="np-label-ip">{{ data.device.ip_address }}</span>
              </div>
            </div>
          </template>

          <Background :gap="20" :size="1.2" pattern-color="transparent" />
          <Controls />
          <MiniMap
            pannable
            zoomable
            :node-color="minimapNodeColor"
            mask-color="var(--map-minimap-mask)"
            :width="120"
            :height="84"
            class="hidden sm:block"
          />
        </VueFlow>

        <!-- Map key -->
        <div class="absolute left-3 top-3 z-10 hidden items-center gap-3 rounded-full border border-[var(--np-border-subtle)] bg-[var(--np-glass-bg)]/85 px-3.5 py-1.5 backdrop-blur-md pointer-events-none sm:flex">
          <span class="flex items-center gap-1.5 text-[0.6rem] font-medium text-[var(--np-text-muted)]"><span class="np-legend-dot np-legend-dot--gw" /> Gateway</span>
          <span class="flex items-center gap-1.5 text-[0.6rem] font-medium text-[var(--np-text-muted)]"><span class="np-legend-dot np-legend-dot--infra" /> Infrastructure</span>
          <span class="flex items-center gap-1.5 text-[0.6rem] font-medium text-[var(--np-text-muted)]"><span class="np-legend-dot" /> Endpoint</span>
          <span class="flex items-center gap-1.5 text-[0.6rem] font-medium text-[var(--np-text-muted)]"><span class="np-legend-dot np-legend-dot--danger" /> Alert</span>
        </div>

        <!-- Live counters -->
        <div class="absolute right-3 top-3 z-10 hidden items-center gap-1.5 sm:flex">
          <span class="np-chip">{{ deviceCount }} nodes</span>
          <span class="np-chip np-chip--accent">{{ gatewayCount }} uplink{{ gatewayCount === 1 ? '' : 's' }}</span>
          <span v-if="alertCount" class="np-chip np-chip--danger">{{ alertCount }} alerts</span>
        </div>

        <div v-if="topologyLoading" class="absolute inset-0 z-10 flex items-center justify-center bg-[var(--np-bg)]/55 backdrop-blur-[2px] pointer-events-none">
          <span class="animate-pulse font-mono text-[0.65rem] uppercase tracking-[0.3em] text-[var(--np-accent)]">Resolving orbits…</span>
        </div>
        <div v-else-if="topologyError" class="absolute inset-0 z-10 flex items-center justify-center bg-[var(--np-bg)]/60 font-mono text-xs text-rose-400 pointer-events-none">
          {{ topologyError }}
        </div>
        <div v-else-if="deviceCount === 0" class="absolute inset-0 z-10 flex items-center justify-center font-mono text-xs text-[var(--np-text-dim)] pointer-events-none">
          No devices discovered yet — run a scan to populate the map.
        </div>
      </div>

      <!-- Right Panel: Node Details & Live SSH Console -->
      <div class="flex flex-col">
        <div v-if="selectedNode" class="glass-card flex h-full min-h-[500px] flex-col p-5">
          <!-- Node Header -->
          <div class="flex items-center justify-between border-b border-[var(--np-border-subtle)] pb-3 mb-4 shrink-0">
            <div class="flex flex-col">
              <span class="text-xs font-bold uppercase tracking-wider text-[var(--np-accent-primary)]">Node Interactive Console</span>
              <span class="text-[0.65rem] font-mono text-[var(--np-text)] mt-0.5">{{ selectedNode.ip_address }}</span>
            </div>
            <span class="np-role-chip">
              {{ selectedNode.is_gateway ? 'Gateway' : 'Host' }}
            </span>
          </div>

          <!-- Navigation tabs -->
          <div class="flex border-b border-[var(--np-border-subtle)] mb-4 shrink-0">
            <button
              @click="activeTab = 'info'"
              :class="[activeTab === 'info' ? 'border-[var(--np-accent)] text-[var(--np-accent)] font-bold' : 'border-transparent text-[var(--np-text-dim)]']"
              class="flex-1 py-2 border-b-2 text-xs uppercase tracking-wider font-mono text-center transition-all"
            >
              Info
            </button>
            <button
              @click="activeTab = 'ssh'"
              :class="[activeTab === 'ssh' ? 'border-[var(--np-accent)] text-[var(--np-accent)] font-bold' : 'border-transparent text-[var(--np-text-dim)]']"
              class="flex-1 py-2 border-b-2 text-xs uppercase tracking-wider font-mono text-center transition-all"
            >
              SSH Shell
            </button>
            <button
              @click="activeTab = 'configs'"
              :class="[activeTab === 'configs' ? 'border-[var(--np-accent)] text-[var(--np-accent)] font-bold' : 'border-transparent text-[var(--np-text-dim)]']"
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
                <div class="flex justify-between border-b border-[var(--np-border-subtle)] pb-1.5">
                  <dt class="text-[var(--np-text-dim)]">Hostname</dt>
                  <dd class="font-bold text-[var(--np-text)]">{{ selectedNode.hostname || '—' }}</dd>
                </div>
                <div class="flex justify-between border-b border-[var(--np-border-subtle)] pb-1.5">
                  <dt class="text-[var(--np-text-dim)]">MAC Address</dt>
                  <dd class="font-mono text-[var(--np-text)]">{{ deviceDetail?.device.mac_address || '—' }}</dd>
                </div>
                <div class="flex justify-between border-b border-[var(--np-border-subtle)] pb-1.5">
                  <dt class="text-[var(--np-text-dim)]">OUI Vendor</dt>
                  <dd class="text-[var(--np-text)]">
                    {{ deviceDetail?.device.mac_address ? (resolveOui(deviceDetail.device.mac_address) ?? 'Unknown') : '—' }}
                  </dd>
                </div>
                <div class="flex justify-between border-b border-[var(--np-border-subtle)] pb-1.5">
                  <dt class="text-[var(--np-text-dim)]">Zone</dt>
                  <dd class="text-[var(--np-text)]">{{ selectedNode.zone || '—' }}</dd>
                </div>
                <div class="flex justify-between border-b border-[var(--np-border-subtle)] pb-1.5">
                  <dt class="text-[var(--np-text-dim)]">Device Type</dt>
                  <dd class="text-[var(--np-text)]">{{ deviceDetail?.type_guess || selectedNode.device_type || '—' }}</dd>
                </div>
                <div class="flex justify-between border-b border-[var(--np-border-subtle)] pb-1.5">
                  <dt class="text-[var(--np-text-dim)]">Last Seen</dt>
                  <dd class="text-[var(--np-text)]">{{ selectedNode.last_seen ? new Date(selectedNode.last_seen).toLocaleString() : '—' }}</dd>
                </div>
              </dl>

              <!-- Real Vulnerabilities section -->
              <div class="space-y-2 pt-2 border-t border-[var(--np-border-subtle)]">
                <div class="flex items-center justify-between gap-2">
                  <span class="text-[0.55rem] uppercase tracking-widest text-[var(--np-text-dim)] font-bold block">
                    Vulnerabilities ({{ deviceDetail?.vulnerabilities?.length || 0 }})
                  </span>
                  <button
                    v-if="isAdmin"
                    type="button"
                    class="np-cyber-btn px-2.5 py-1 text-[0.6rem] uppercase tracking-wider"
                    :disabled="testingNode"
                    :title="`Run a targeted service scan against ${selectedNode.ip_address}`"
                    @click="testSelectedNode"
                  >
                    {{ testingNode ? "Testing…" : "Test this node" }}
                  </button>
                </div>
                <p
                  v-if="testMessage"
                  class="text-[0.6rem] font-mono leading-relaxed"
                  :class="testMessageKind === 'ok' ? 'text-[var(--np-accent)]' : testMessageKind === 'warn' ? 'text-[var(--np-warning)]' : 'text-[var(--np-danger)]'"
                >
                  {{ testMessage }}
                </p>
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
                      class="np-neon-input w-full rounded-lg px-3.5 py-2 text-xs font-mono bg-[var(--np-surface-elevated)] text-[var(--np-text)]"
                      placeholder="root"
                    />
                  </div>

                  <div>
                    <label class="block text-[0.6rem] uppercase tracking-wider mb-1.5 font-mono text-[var(--np-text-dim)]">Password</label>
                    <input
                      v-model="sshPassword"
                      type="password"
                      class="np-neon-input w-full rounded-lg px-3.5 py-2 text-xs font-mono bg-[var(--np-surface-elevated)] text-[var(--np-text)]"
                      placeholder="••••••••••••"
                    />
                  </div>

                  <div>
                    <label class="block text-[0.6rem] uppercase tracking-wider mb-1.5 font-mono text-[var(--np-text-dim)]">Port</label>
                    <input
                      v-model="sshPort"
                      type="number"
                      class="np-neon-input w-full rounded-lg px-3.5 py-2 text-xs font-mono bg-[var(--np-surface-elevated)] text-[var(--np-text)]"
                      placeholder="22"
                    />
                  </div>
                </div>

                <!-- Vendor Specific Helper / Guidelines -->
                <div v-if="connectionGuidelines" class="p-3.5 rounded-xl border border-[var(--np-accent-border)] bg-[var(--np-accent-soft)] space-y-2">
                  <div class="flex items-center gap-1.5 text-[0.65rem] font-bold text-[var(--np-accent)] uppercase tracking-wide">
                    <Lock class="h-3 w-3 shrink-0" :stroke-width="1.7" />
                    {{ connectionGuidelines.brand }} Security Guidelines
                  </div>
                  <div class="text-[0.58rem] text-[var(--np-text-muted)] space-y-1 font-mono">
                    <p><span class="text-[var(--np-text-dim)]">Default credentials suggestion:</span> {{ connectionGuidelines.defaultUser }}</p>
                    <p><span class="text-[var(--np-text-dim)]">Intrusion Prevention advice:</span> {{ connectionGuidelines.securityNotice }}</p>
                  </div>
                </div>

                <button
                  @click="connectSsh"
                  class="w-full py-2.5 rounded-xl text-xs font-bold uppercase tracking-wider bg-[var(--np-accent-soft)] text-[var(--np-accent)] border border-[var(--np-accent-border)] hover:bg-[var(--np-accent-soft)] transition-all flex items-center justify-center gap-2"
                >
                  Connect SSH Client
                </button>

                <p v-if="sshError" class="text-xs font-mono text-red-400 bg-red-500/5 border border-red-500/15 p-2 rounded-lg text-center mt-2">
                  {{ sshError }}
                </p>
              </div>

              <!-- Connecting Loader -->
              <div v-else-if="sshConnecting" class="flex-1 flex flex-col items-center justify-center gap-3 py-12">
                <LoaderCircle class="w-8 h-8 animate-spin text-[var(--np-accent)]" :stroke-width="1.7" />
                <span class="text-xs font-mono text-[var(--np-accent)] uppercase tracking-widest animate-pulse">Initializing PTY session...</span>
              </div>

              <!-- Live Interactive Terminal -->
              <div v-else class="flex-1 flex flex-col min-h-[350px]">
                <div class="flex items-center justify-between pb-2 mb-2 border-b border-[var(--np-border-subtle)]">
                  <span class="text-[0.6rem] font-mono text-[var(--np-accent)] animate-pulse flex items-center gap-1.5">
                    <span class="w-1.5 h-1.5 rounded-full bg-[var(--np-accent)] animate-ping" />
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
              <div class="flex items-center justify-between border-b border-[var(--np-border-subtle)] pb-2">
                <span class="text-[0.65rem] font-mono text-[var(--np-text-dim)] uppercase tracking-wider">
                  Device configuration archives
                </span>
                <button
                  @click="loadConfigs"
                  class="text-[0.6rem] text-[var(--np-accent)] hover:underline uppercase tracking-widest"
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
                  class="p-3 rounded-xl border border-[var(--np-glass-border)] bg-[var(--np-surface-elevated)] hover:border-[var(--np-accent-border)] transition-all flex justify-between items-center"
                >
                  <div class="flex flex-col min-w-0">
                    <span class="font-mono text-xs text-[var(--np-text)] truncate max-w-[190px]">{{ cfg.filename }}</span>
                    <span class="text-[0.55rem] font-mono text-[var(--np-text-dim)] mt-0.5">
                      {{ new Date(cfg.modified_at).toLocaleString() }} • {{ (cfg.size_bytes / 1024).toFixed(2) }} KB
                    </span>
                  </div>
                  <button
                    @click="viewConfig(cfg.filename)"
                    class="px-2.5 py-1 text-[0.6rem] font-bold uppercase tracking-wider bg-[var(--np-accent-soft)] text-[var(--np-accent)] border border-[var(--np-accent-border)] hover:bg-[var(--np-accent-soft)] rounded-md transition-all shrink-0"
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

                <div class="p-3.5 rounded-lg border border-[var(--np-glass-border)] bg-[#090d16] font-mono text-[0.65rem] text-[var(--np-text-muted)] overflow-x-auto whitespace-pre leading-relaxed custom-scrollbar max-h-[300px]">
                  {{ selectedConfigText }}
                </div>
              </div>
            </div>
          </div>
        </div>

        <div v-else class="glass-card flex min-h-[500px] flex-col items-center justify-center p-12 text-center">
          <div class="relative mb-4 flex h-16 w-16 items-center justify-center">
            <span class="absolute inset-0 rounded-full border border-dashed border-[var(--np-border)]" />
            <span class="absolute inset-3 rounded-full border border-[var(--np-accent-border)]" />
            <span class="h-1.5 w-1.5 rounded-full bg-[var(--np-accent)] shadow-[0_0_12px_var(--np-accent-glow)]" />
          </div>
          <span class="font-mono text-[0.65rem] uppercase tracking-[0.2em] text-[var(--np-text-dim)]">
            Select a node to inspect
          </span>
          <p class="mt-2 max-w-[16rem] text-xs leading-relaxed text-[var(--np-text-muted)]">
            Click any orb on the map to open its inventory record, vulnerability list and console.
          </p>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
/* Theme hooks for the map surface */
.np-map {
  --map-edge: #14b8a6;
  --map-canvas: rgba(3, 7, 18, 0.55);
  --map-grid: rgba(148, 163, 184, 0.09);
  --map-ring: rgba(148, 163, 184, 0.3);
  --map-minimap-mask: rgba(3, 7, 18, 0.72);
  --map-node-fg: #e8eef7;
  --map-node-dim: #94a3b8;
  --map-control-bg: rgba(9, 13, 22, 0.92);
  --map-control-fg: #cbd5e1;
  --map-chip-bg: rgba(9, 13, 22, 0.72);
  --map-chip-fg: #cbd5e1;
  --map-glow: rgba(20, 184, 166, 0.10);
}

.np-map--light {
  /* Indigo, matching the light theme's accent. Teal here read as "green
     leaking" into light mode. */
  --map-edge: #4f46e5;
  --map-canvas: #ffffff;
  --map-grid: rgba(9, 9, 11, 0.06);
  --map-ring: rgba(9, 9, 11, 0.2);
  --map-minimap-mask: rgba(244, 244, 245, 0.72);
  --map-node-fg: #09090b;
  --map-node-dim: #52525b;
  --map-control-bg: rgba(255, 255, 255, 0.95);
  --map-control-fg: #3f3f46;
  --map-chip-bg: rgba(255, 255, 255, 0.9);
  --map-chip-fg: #3f3f46;
  --map-glow: rgba(79, 70, 229, 0.06);
}

/* Radar-style concentric backdrop */
.np-topology-flow {
  background-color: var(--map-canvas);
  background-image:
    radial-gradient(circle at 50% 50%, var(--map-glow, rgba(20, 184, 166, 0.10)), transparent 45%),
    linear-gradient(var(--map-grid) 1px, transparent 1px),
    linear-gradient(90deg, var(--map-grid) 1px, transparent 1px);
  background-size: auto, 44px 44px, 44px 44px;
}

/* ---- Orbit guides (non-interactive rings around the uplink) ---- */
/* The ring covers most of the canvas, so it must never swallow pan/zoom input. */
.np-topology-flow :deep(.vue-flow__node.np-orbit-node) { pointer-events: none; }
.np-orbit {
  border-radius: 9999px;
  border: 1px dashed var(--map-ring);
  pointer-events: none;
}

/* ---- Device orbs ---- */
.np-node {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 7px;
  width: 132px;
  padding-top: 4px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  cursor: pointer;
  transition: opacity 0.2s ease, transform 0.2s ease;
}
.np-node:hover { transform: translateY(-2px); }

/* Per-category accent palette */
.np-node--gw {
  --orb-fg: #4ade80;
  --orb-border: rgba(74, 222, 128, 0.55);
  --orb-bg: radial-gradient(circle at 32% 26%, rgba(74, 222, 128, 0.32), rgba(9, 13, 22, 0.96));
  --orb-ring: rgba(34, 197, 94, 0.14);
}
.np-node--infra {
  --orb-fg: #7dd3fc;
  --orb-border: rgba(56, 189, 248, 0.5);
  --orb-bg: radial-gradient(circle at 32% 26%, rgba(56, 189, 248, 0.28), rgba(9, 13, 22, 0.96));
  --orb-ring: rgba(56, 189, 248, 0.13);
}
.np-node--endpoint {
  --orb-fg: #c4b5fd;
  --orb-border: rgba(167, 139, 250, 0.45);
  --orb-bg: radial-gradient(circle at 32% 26%, rgba(167, 139, 250, 0.24), rgba(9, 13, 22, 0.96));
  --orb-ring: rgba(167, 139, 250, 0.12);
}

.np-orb {
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 62px;
  height: 62px;
}
.np-node--gw .np-orb { width: 80px; height: 80px; }

.np-orb-disc {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 46px;
  height: 46px;
  border-radius: 9999px;
  border: 1px solid var(--orb-border);
  background: var(--orb-bg);
  color: var(--orb-fg);
  box-shadow: 0 0 0 5px var(--orb-ring), 0 10px 24px rgba(0, 0, 0, 0.42);
  transition: transform 0.18s ease, box-shadow 0.18s ease, border-color 0.18s ease;
}
.np-orb-disc svg { width: 21px; height: 21px; }
.np-node--gw .np-orb-disc { width: 60px; height: 60px; }
.np-node--gw .np-orb-disc svg { width: 26px; height: 26px; }

.np-node:hover .np-orb-disc {
  transform: scale(1.07);
  border-color: var(--orb-fg);
}

.np-node--critical {
  --orb-fg: #f87171;
  --orb-border: rgba(248, 113, 113, 0.85);
  --orb-bg: radial-gradient(circle at 32% 26%, rgba(248, 113, 113, 0.3), rgba(9, 13, 22, 0.96));
  --orb-ring: rgba(239, 68, 68, 0.16);
}
.np-node--high {
  --orb-fg: #fb923c;
  --orb-border: rgba(251, 146, 60, 0.8);
  --orb-ring: rgba(251, 146, 60, 0.15);
}

.np-node--selected .np-orb-disc {
  border-color: #5eead4;
  box-shadow:
    0 0 0 5px var(--orb-ring),
    0 0 0 2px rgba(45, 212, 191, 0.9),
    0 16px 34px rgba(20, 184, 166, 0.28);
}
.np-node--dim { opacity: 0.22; filter: saturate(0.35); }
.np-map--light .np-node--dim { opacity: 0.4; filter: saturate(0.5); }

/* Expanding halo on the uplink */
.np-orb-ping {
  position: absolute;
  inset: -5px;
  border-radius: 9999px;
  border: 1px solid rgba(74, 222, 128, 0.5);
  animation: np-orb-pulse 2.8s ease-out infinite;
}
@keyframes np-orb-pulse {
  0% { transform: scale(0.9); opacity: 0.75; }
  70% { transform: scale(1.4); opacity: 0; }
  100% { transform: scale(1.4); opacity: 0; }
}

.np-orb-alert {
  position: absolute;
  top: 0;
  right: 6px;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 16px;
  height: 16px;
  border-radius: 9999px;
  background: #ef4444;
  color: #fff;
  font-family: ui-monospace, monospace;
  font-size: 9px;
  font-weight: 800;
  box-shadow: 0 0 0 2px rgba(9, 13, 22, 0.95);
}

.np-label {
  display: flex;
  flex-direction: column;
  align-items: center;
  max-width: 132px;
  line-height: 1.25;
}
.np-label-name {
  max-width: 128px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0.01em;
  color: var(--map-node-fg);
  text-align: center;
}
.np-label-ip {
  margin-top: 2px;
  font-size: 9.5px;
  letter-spacing: 0.05em;
  color: var(--map-node-dim);
}

/* Light-theme tuning keeps the same accents but on white orbs */
.np-map--light .np-orb-disc { box-shadow: 0 0 0 5px var(--orb-ring), 0 8px 20px rgba(9, 9, 11, 0.12); }
.np-map--light .np-node--gw {
  --orb-fg: #4338ca;
  --orb-border: rgba(79, 70, 229, 0.45);
  --orb-bg: radial-gradient(circle at 32% 26%, rgba(79, 70, 229, 0.16), #ffffff);
  --orb-ring: rgba(79, 70, 229, 0.14);
}
.np-map--light .np-node--infra {
  --orb-fg: #0369a1;
  --orb-border: rgba(3, 105, 161, 0.35);
  --orb-bg: radial-gradient(circle at 32% 26%, rgba(56, 189, 248, 0.16), #ffffff);
}
.np-map--light .np-node--endpoint {
  --orb-fg: #6d28d9;
  --orb-border: rgba(109, 40, 217, 0.3);
  --orb-bg: radial-gradient(circle at 32% 26%, rgba(167, 139, 250, 0.16), #ffffff);
}
.np-map--light .np-node--critical {
  --orb-fg: #dc2626;
  --orb-border: rgba(220, 38, 38, 0.6);
  --orb-bg: radial-gradient(circle at 32% 26%, rgba(248, 113, 113, 0.18), #ffffff);
}
.np-map--light .np-orb-alert { box-shadow: 0 0 0 2px #ffffff; }

/* ---- Role chip in the detail console ---- */
.np-role-chip {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  border-radius: 9999px;
  border: 1px solid color-mix(in srgb, var(--np-accent) 35%, transparent);
  background: color-mix(in srgb, var(--np-accent) 14%, transparent);
  color: var(--np-accent);
  font-family: var(--np-mono-family);
  font-size: 0.55rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

/* ---- Legend + counters ---- */
.np-legend-dot {
  width: 8px;
  height: 8px;
  border-radius: 9999px;
  background: #a78bfa;
  box-shadow: 0 0 8px rgba(167, 139, 250, 0.55);
}
.np-legend-dot--gw {
  background: #22c55e;
  box-shadow: 0 0 8px rgba(34, 197, 94, 0.7);
}
.np-legend-dot--infra {
  background: #38bdf8;
  box-shadow: 0 0 8px rgba(56, 189, 248, 0.55);
}
.np-legend-dot--danger {
  background: #ef4444;
  box-shadow: 0 0 8px rgba(239, 68, 68, 0.7);
}

.np-chip {
  border-radius: 9999px;
  border: 1px solid var(--np-glass-border);
  background: var(--map-chip-bg);
  padding: 3px 9px;
  font-family: ui-monospace, monospace;
  font-size: 9px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--map-chip-fg);
  backdrop-filter: blur(8px);
}
.np-chip--accent {
  color: var(--np-accent);
  border-color: color-mix(in srgb, var(--np-accent) 32%, transparent);
}
.np-map--light .np-legend-dot--gw {
  background: #4f46e5;
  box-shadow: 0 0 0 2px rgba(79, 70, 229, 0.18);
}
.np-chip--danger { color: #fca5a5; border-color: rgba(239, 68, 68, 0.35); }

/* ---- Edges: animated traffic flow ---- */
.np-topology-flow :deep(.np-flow-edge .vue-flow__edge-path) {
  stroke-dasharray: 5 9;
  opacity: 0.42;
  animation: np-edge-flow 1.7s linear infinite;
  filter: drop-shadow(0 0 3px color-mix(in srgb, var(--map-edge) 40%, transparent));
  transition: opacity 0.2s ease;
}
.np-topology-flow :deep(.np-flow-edge--active .vue-flow__edge-path) {
  stroke-width: 2 !important;
  stroke-dasharray: 10 7;
  opacity: 0.95;
  animation-duration: 0.9s;
  filter: drop-shadow(0 0 6px color-mix(in srgb, var(--map-edge) 70%, transparent));
}
.np-topology-flow :deep(.np-flow-edge--dim .vue-flow__edge-path) {
  opacity: 0.09;
}
@keyframes np-edge-flow {
  to { stroke-dashoffset: -28; }
}

.np-topology-flow :deep(.vue-flow__controls) {
  border-radius: 10px;
  overflow: hidden;
  box-shadow: 0 4px 14px rgba(0, 0, 0, 0.25);
}
.np-topology-flow :deep(.vue-flow__controls-button) {
  background: var(--map-control-bg);
  border-bottom: 1px solid var(--map-grid);
  color: var(--map-control-fg);
  fill: var(--map-control-fg);
}
.np-topology-flow :deep(.vue-flow__controls-button:hover) {
  background: rgba(20, 184, 166, 0.15);
}
.np-topology-flow :deep(.vue-flow__minimap) {
  border-radius: 12px;
  overflow: hidden;
  border: 1px solid var(--map-grid);
  background: var(--map-control-bg);
}
.np-topology-flow :deep(.vue-flow__attribution) {
  background: transparent;
  color: rgba(148, 163, 184, 0.35);
  font-size: 8px;
}

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
