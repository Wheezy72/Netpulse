<script setup lang="ts">
import axios from "axios";
import { computed, onMounted, ref, nextTick } from "vue";
import { Download, ExternalLink, FileText, Route, ScanSearch, Search, TriangleAlert, Wifi, X } from "lucide-vue-next";

import DeviceDrawer from "../components/features/DeviceDrawer.vue";
import { noticeStyle, useDeviceDiscovery } from "../composables/useDeviceDiscovery";
import { resolveOui } from "../utils/oui";

const props = defineProps<{
  theme: "nightshade" | "sysadmin";
  isAdmin?: boolean;
}>();

const isNightshade = computed(() => props.theme === "nightshade");
const isAdmin = computed(() => !!props.isAdmin);

// Drawer state – no routing, the table stays interactive beneath it.
const drawerOpen = ref(false);
const drawerDeviceId = ref<number | null>(null);

function openDrawer(device: DeviceRow) {
  selectedDevice.value = device;
  drawerDeviceId.value = device.id;
  drawerOpen.value = true;
  closeContextMenu();
}

function closeDrawer() {
  drawerOpen.value = false;
  drawerDeviceId.value = null;
}

/** Reload the inventory after the drawer's deep scan changed a device. */
function onDeviceUpdated(): void {
  void loadDevices();
}

// Device discovery: finds hosts only, no port scanning. Deep per-device detail
// is requested separately from the drawer.
const discoverTarget = ref("");
const { discovering, notice: discoveryNotice, discover } = useDeviceDiscovery();

async function runDiscovery(): Promise<void> {
  const result = await discover(discoverTarget.value);
  if (result) {
    await Promise.all([loadDevices(), loadZones()]);
  }
}

type DeviceRow = {
  id: number;
  hostname: string | null;
  ip_address: string;
  mac_address: string | null;
  device_type: string | null;
  is_gateway: boolean;
  zone: string | null;
  last_seen: string | null;
  // Listed by the router's own ARP/DHCP tables on the last pull. Without it a
  // row is only "observed": it answered our probes, which a stale neighbour
  // entry can also do.
  verified?: boolean;
  verified_at?: string | null;
  verified_source?: string | null;
  // Multiple interface records belonging to this console are rendered as one
  // computer row; each address remains available for probing/navigation.
  interface_ips?: string[];
  member_ids?: number[];
  // True when the MAC belongs to the machine running this console. It answers
  // on every interface it holds (Wi-Fi + a USB adapter is common), so turn
  // those rows into a labelled fact instead of a "duplicate device" mystery.
  is_self?: boolean;
};

function verificationLabel(device: DeviceRow): string {
  if (!device.verified) return "Observed";
  return device.verified_source ? `Verified · ${device.verified_source}` : "Verified";
}

function verificationTitle(device: DeviceRow): string {
  if (device.verified) {
    const when = device.verified_at ? new Date(device.verified_at).toLocaleString() : "the last pull";
    return `The router's own tables listed this device at ${when}.`;
  }
  return (
    "Only this console has seen it (probe / ARP table). " +
    "The router did not confirm it on the last pull, so it may be a stale entry."
  );
}

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

const devices = ref<DeviceRow[]>([]);
const zones = ref<string[]>([]);
const selectedZone = ref<string | null>(null);

// Networks are the address spaces this install has been plugged into. Home
// networks reuse the same 192.168.x addresses, so the list is scoped to one
// network at a time and defaults to the one the machine is on right now.
type NetworkRow = {
  id: number;
  name: string;
  cidr: string;
  device_count: number;
  is_current: boolean;
};
const networks = ref<NetworkRow[]>([]);
const selectedNetwork = ref<number | null>(null);

async function loadNetworks(): Promise<void> {
  try {
    const { data } = await axios.get<NetworkRow[]>("/api/networks");
    networks.value = data;
    const current = data.find((n) => n.is_current);
    if (selectedNetwork.value === null && current) {
      selectedNetwork.value = current.id;
    }
  } catch {
    // non-fatal: the list still works unscoped
  }
}
const search = ref("");
const loading = ref(false);
const error = ref<string | null>(null);
const actionNotice = ref<{ type: "success" | "error" | "warning" | "info"; message: string } | null>(null);

const selectedDevice = ref<DeviceRow | null>(null);
const deviceDetail = ref<DeviceDetail | null>(null);
const deviceDetailLoading = ref(false);
const deviceDetailError = ref<string | null>(null);

const aiAnswer = ref<string | null>(null);
const aiLoading = ref(false);
const aiError = ref<string | null>(null);

const blockedDevices = ref<Set<string>>(new Set());
const kickLoadingIp = ref<string | null>(null);

// Right-click context menu
const contextMenu = ref<{ visible: boolean; x: number; y: number; device: DeviceRow | null }>({
  visible: false,
  x: 0,
  y: 0,
  device: null,
});

function openContextMenu(event: MouseEvent, device: DeviceRow) {
  event.preventDefault();
  contextMenu.value = {
    visible: true,
    x: event.clientX,
    y: event.clientY,
    device,
  };
}

function closeContextMenu() {
  contextMenu.value.visible = false;
}

async function quickAction(action: "ping" | "trace" | "portscan", device: DeviceRow) {
  closeContextMenu();
  if (!props.isAdmin && action !== "ping") {
    actionNotice.value = { type: "warning", message: "Admin access required for this action." };
    return;
  }
  const cmdMap = {
    ping: `nmap -sn -T4 ${device.ip_address}`,
    trace: `nmap -traceroute -T4 ${device.ip_address}`,
    portscan: `nmap -sV -T4 -F ${device.ip_address}`,
  };
  try {
    const { data } = await axios.post<{ id: string }>("/api/nmap/execute", {
      command: cmdMap[action],
      target: device.ip_address,
      save_results: true,
    });
    actionNotice.value = { type: "info", message: `${action.charAt(0).toUpperCase() + action.slice(1)} started for ${device.ip_address} (scan ID: ${data.id})` };
  } catch (e: any) {
    actionNotice.value = { type: "error", message: e.response?.data?.detail || `Failed to run ${action}` };
  }
}

// Smart regex + shorthand filter
// Supports: ip:192.168.*, status:down, status:gateway, plus plain text and regex
const filteredDevices = computed(() => {
  let list = devices.value;
  if (selectedZone.value) {
    list = list.filter((d) => d.zone === selectedZone.value);
  }
  const raw = search.value.trim();
  if (!raw) return list;

  // Parse shorthand tokens
  const shorthandRe = /^(ip|status|type|zone):(.+)$/i;
  const match = raw.match(shorthandRe);
  if (match) {
    const [, field, val] = match;
    const v = val.toLowerCase();
    switch (field.toLowerCase()) {
      case "ip":
        try {
          const pattern = new RegExp(v.replace(/\*/g, ".*"), "i");
          return list.filter((d) => pattern.test(d.ip_address));
        } catch {
          return list.filter((d) => d.ip_address.includes(v));
        }
      case "status":
        if (v === "gateway") return list.filter((d) => d.is_gateway);
        if (v === "down") return list.filter((d) => !d.last_seen);
        if (v === "blocked") return list.filter((d) => blockedDevices.value.has(d.ip_address));
        if (v === "verified") return list.filter((d) => d.verified);
        if (v === "observed") return list.filter((d) => !d.verified);
        return list;
      case "type":
        return list.filter((d) => (d.device_type ?? "").toLowerCase().includes(v));
      case "zone":
        return list.filter((d) => (d.zone ?? "").toLowerCase().includes(v));
    }
  }

  // Try as regex, fall back to plain substring
  let pattern: RegExp | null = null;
  try {
    pattern = new RegExp(raw, "i");
  } catch {
    // invalid regex — fall back to plain text
  }
  return list.filter((d) => {
    const haystack = [d.ip_address, d.hostname ?? "", d.device_type ?? "", d.zone ?? ""].join(" ");
    return pattern ? pattern.test(haystack) : haystack.toLowerCase().includes(raw.toLowerCase());
  });
});

async function loadZones(): Promise<void> {
  try {
    const { data } = await axios.get<{ zones: string[] }>("/api/devices/zones");
    zones.value = data.zones ?? [];
  } catch {
    // non-fatal
  }
}

async function loadDevices(): Promise<void> {
  loading.value = true;
  error.value = null;
  try {
    const params: Record<string, string> = {};
    if (selectedZone.value) {
      params.zone = selectedZone.value;
    }
    if (selectedNetwork.value !== null) {
      params.network_id = String(selectedNetwork.value);
    }
    const { data } = await axios.get<DeviceRow[]>("/api/devices", { params });
    devices.value = data;
  } catch {
    error.value = "Failed to load devices.";
    devices.value = [];
  } finally {
    loading.value = false;
  }
}

async function loadDeviceDetail(deviceId: number): Promise<void> {
  deviceDetailLoading.value = true;
  deviceDetailError.value = null;
  aiAnswer.value = null;
  aiError.value = null;
  try {
    const { data } = await axios.get<DeviceDetail>(`/api/devices/${deviceId}/detail`);
    deviceDetail.value = data;
  } catch {
    deviceDetailError.value = "Failed to load device detail.";
    deviceDetail.value = null;
  } finally {
    deviceDetailLoading.value = false;
  }
}

function selectDevice(row: DeviceRow): void {
  selectedDevice.value = row;
  loadDeviceDetail(row.id);
}

async function askAiAboutDevice(): Promise<void> {
  if (!selectedDevice.value) return;
  aiLoading.value = true;
  aiError.value = null;
  aiAnswer.value = null;
  try {
    const { data } = await axios.post<{ answer: string }>("/api/assist/analyze", {
      mode: "device",
      target_id: selectedDevice.value.id,
      question: null,
    });
    aiAnswer.value = data.answer;
  } catch {
    aiError.value = "Analysis unavailable. Check provider configuration in Settings.";
  } finally {
    aiLoading.value = false;
  }
}

function downloadDeviceReport(): void {
  const list = filteredDevices.value;
  if (!list.length) {
    error.value = "No devices to export.";
    return;
  }
  const headers = ["IP Address", "MAC Address", "Hostname", "Vendor", "Status", "First Seen", "Last Seen"];
  const rows = list.map((d) => [
    d.ip_address,
    d.mac_address || "",
    d.hostname || "",
    d.device_type || "",
    d.last_seen ? "Online" : "Unknown",
    "",
    d.last_seen || "",
  ]);
  const csv = [headers.join(","), ...rows.map((r) => r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(","))].join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `netpulse_devices_${new Date().toISOString().slice(0, 10)}.csv`;
  link.click();
  URL.revokeObjectURL(url);
}

async function downloadDevicesPDF(): Promise<void> {
  try {
    const response = await axios.get("/api/reports/devices/pdf", {
      responseType: "blob",
    });
    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement("a");
    link.href = url;
    link.download = `Devices_${new Date().toISOString().slice(0, 10)}.pdf`;
    link.click();
    window.URL.revokeObjectURL(url);
  } catch {
    error.value = "Failed to download PDF report";
  }
}

async function loadBlockedDevices(): Promise<void> {
  try {
    const { data } = await axios.get<{ ip: string }[]>("/api/device-actions/blocked");
    blockedDevices.value = new Set(data.map((d) => d.ip));
  } catch {
    // non-fatal
  }
}

async function blockDevice(ip: string): Promise<void> {
  try {
    await axios.post("/api/device-actions/block", {
      ip,
      reason: "Manual block from console",
    });
    blockedDevices.value.add(ip);
    blockedDevices.value = new Set(blockedDevices.value);
  } catch (e: any) {
    error.value = e.response?.data?.detail || "Failed to block device";
  }
}

async function unblockDevice(ip: string): Promise<void> {
  try {
    await axios.post("/api/device-actions/unblock", { ip });
    blockedDevices.value.delete(ip);
    blockedDevices.value = new Set(blockedDevices.value);
  } catch (e: any) {
    error.value = e.response?.data?.detail || "Failed to unblock device";
  }
}

async function attemptKick(ip: string): Promise<void> {
  actionNotice.value = null;
  if (!isAdmin.value) {
    actionNotice.value = { type: "warning", message: "Admin access required to perform this action." };
    return;
  }
  kickLoadingIp.value = ip;
  try {
    const { data } = await axios.post<{ status: string; duration_s?: number }>(
      "/api/device-actions/attempt-kick",
      { ip, duration_s: 15.0 }
    );
    const duration = data.duration_s != null ? ` (${data.duration_s}s)` : "";
    actionNotice.value = { type: "info", message: `Kick attempt scheduled for ${ip}${duration}.` };
  } catch (e: any) {
    actionNotice.value = { type: "error", message: e.response?.data?.detail || "Failed to trigger kick attempt" };
  } finally {
    if (kickLoadingIp.value === ip) {
      kickLoadingIp.value = null;
    }
  }
}


onMounted(async () => {
  await loadNetworks();
  await Promise.all([loadZones(), loadDevices(), loadBlockedDevices()]);
  // Close context menu on global click
  document.addEventListener("click", closeContextMenu);
});
</script>

<template>
  <!-- Context menu portal -->
  <Teleport to="body">
    <Transition name="np-fade">
      <div
        v-if="contextMenu.visible && contextMenu.device"
        class="fixed z-[200] min-w-[180px] rounded border shadow-xl py-1 np-glass"
        style="border-color: var(--np-glass-border);"
        :style="{ left: `${contextMenu.x}px`, top: `${contextMenu.y}px` }"
      >
        <div class="px-3 py-1.5 border-b text-[0.6rem] uppercase tracking-widest text-[var(--np-text-dim)]/50" style="border-color: var(--np-border-subtle);">
          {{ contextMenu.device.ip_address }}
        </div>
        <button
          type="button"
          class="w-full flex items-center gap-2.5 px-3 py-2 text-xs text-[var(--np-text-muted)] hover:text-[var(--np-accent-primary)] hover:bg-[var(--np-surface-hover)] transition-colors text-left"
          @click.stop="quickAction('ping', contextMenu.device!)"
        >
          <Wifi class="w-3.5 h-3.5 shrink-0" :stroke-width="1.7" />
          Ping Sweep
        </button>
        <button
          type="button"
          class="w-full flex items-center gap-2.5 px-3 py-2 text-xs text-zinc-300 hover:text-zinc-100 hover:bg-zinc-800/60 transition-colors text-left"
          @click.stop="quickAction('trace', contextMenu.device!)"
        >
          <Route class="w-3.5 h-3.5 shrink-0" :stroke-width="1.7" />
          Traceroute
        </button>
        <button
          type="button"
          class="w-full flex items-center gap-2.5 px-3 py-2 text-xs text-zinc-300 hover:text-zinc-100 hover:bg-zinc-800/60 transition-colors text-left"
          @click.stop="quickAction('portscan', contextMenu.device!)"
        >
          <ScanSearch class="w-3.5 h-3.5 shrink-0" :stroke-width="1.7" />
          Port Scan (Quick)
        </button>
        <div class="border-t my-1" style="border-color: var(--np-border-subtle);"></div>
        <button
          type="button"
          class="w-full flex items-center gap-2.5 px-3 py-2 text-xs text-zinc-300 hover:text-zinc-100 hover:bg-zinc-800/60 transition-colors text-left"
          @click.stop="openDrawer(contextMenu.device!)"
        >
          <ExternalLink class="w-3.5 h-3.5 shrink-0" :stroke-width="1.7" />
          View Details
        </button>
      </div>
    </Transition>
  </Teleport>

  <div class="space-y-4">
    <!-- Inventory -->
    <div class="np-panel p-4 space-y-4">
      <header class="np-panel-header -mx-4 -mt-4 mb-2 px-4">
        <div class="flex flex-col">
          <span class="np-panel-title">Devices</span>
          <span class="text-[0.7rem] text-[var(--np-text-dim)]/50">
            Inventory of discovered hosts. Right-click any row for quick actions.
          </span>
        </div>
        <div class="flex items-center gap-2">
          <button
            @click="downloadDeviceReport"
            class="np-cyber-btn flex items-center gap-1"
            title="Download Device Inventory CSV"
          >
            <Download class="w-3.5 h-3.5" :stroke-width="1.7" />
            CSV
          </button>
          <button
            @click="downloadDevicesPDF"
            class="np-cyber-btn flex items-center gap-1"
            title="Download Device Inventory PDF"
          >
            <FileText class="w-3.5 h-3.5" :stroke-width="1.7" />
            PDF
          </button>
        </div>
      </header>

      <!-- Discovery: hosts only, deliberately no port scan -->
      <div
        class="flex flex-col gap-2 rounded border p-3 lg:flex-row lg:items-center"
        :style="{ borderColor: 'var(--np-border)', background: 'var(--np-surface-elevated)' }"
      >
        <div class="flex-1">
          <p class="text-[0.65rem] uppercase tracking-widest" :style="{ color: 'var(--np-text-dim)' }">
            Find devices
          </p>
          <p class="mt-0.5 text-[0.7rem]" :style="{ color: 'var(--np-text-muted)' }">
            Leave blank to sweep the attached subnet.
          </p>
        </div>
        <input
          v-model="discoverTarget"
          type="text"
          placeholder="192.168.1.0/24 (optional)"
          class="np-neon-input px-3 py-1.5 text-xs lg:w-56"
          @keyup.enter="runDiscovery"
        />
        <button
          type="button"
          class="np-cyber-btn flex items-center justify-center disabled:cursor-not-allowed disabled:opacity-40"
          :style="{ color: 'var(--np-accent-primary)', borderColor: 'var(--np-accent-primary)' }"
          :disabled="discovering || !isAdmin"
          :title="isAdmin ? 'Sweep for hosts and add them to the inventory' : 'Admin access required to scan'"
          @click="runDiscovery"
        >
          {{ discovering ? 'Scanning…' : 'Scan for devices' }}
        </button>
      </div>

      <!-- Discovery result -->
      <div
        v-if="discoveryNotice"
        class="flex items-center justify-between rounded border p-2 text-xs"
        :style="noticeStyle(discoveryNotice.kind)"
      >
        <span>{{ discoveryNotice.text }}</span>
        <button class="ml-3 opacity-70 hover:opacity-100" aria-label="Dismiss" @click="discoveryNotice = null"><X class="h-3.5 w-3.5" :stroke-width="1.7" /></button>
      </div>

      <!-- Search + zone filter -->
      <div class="flex flex-col sm:flex-row gap-2">
        <div class="relative flex-1">
          <Search class="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--np-text-dim)]" :stroke-width="1.7" />
          <input
            v-model="search"
            type="text"
            placeholder="Search or use ip:, status:, type:, zone: prefixes…"
            class="np-neon-input w-full pl-8 pr-3 py-1.5 text-xs"
          />
        </div>
        <select
          v-if="networks.length > 1"
          v-model="selectedNetwork"
          class="np-neon-input px-3 py-1.5 text-xs"
          title="Inventory is tracked per network"
        >
          <option v-for="n in networks" :key="n.id" :value="n.id">
            {{ n.name }}{{ n.is_current ? " (current)" : "" }}
          </option>
        </select>
        <select
          v-model="selectedZone"
          class="np-neon-input px-3 py-1.5 text-xs"
        >
          <option :value="null">All Zones</option>
          <option v-for="z in zones" :key="z" :value="z">{{ z }}</option>
        </select>
      </div>

      <!-- Action notice -->
      <div
        v-if="actionNotice"
        class="rounded p-2 text-xs border flex justify-between items-center"
        :style="{
          borderColor: actionNotice.type === 'success' ? 'var(--np-success)' :
                       actionNotice.type === 'error' ? 'var(--np-danger)' :
                       actionNotice.type === 'warning' ? 'var(--np-warning)' :
                       'var(--np-border)',
          color: actionNotice.type === 'success' ? 'var(--np-success)' :
                 actionNotice.type === 'error' ? 'var(--np-danger)' :
                 actionNotice.type === 'warning' ? 'var(--np-warning)' :
                 'var(--np-text)',
          background: actionNotice.type === 'success' ? 'rgba(16, 185, 129, 0.05)' :
                      actionNotice.type === 'error' ? 'rgba(244, 63, 94, 0.05)' :
                      actionNotice.type === 'warning' ? 'rgba(245, 158, 11, 0.05)' :
                      'rgba(168, 85, 247, 0.05)',
        }"
      >
        <span>{{ actionNotice.message }}</span>
        <button @click="actionNotice = null" class="opacity-70 hover:opacity-100 ml-3" aria-label="Dismiss"><X class="h-3.5 w-3.5" :stroke-width="1.7" /></button>
      </div>

      <!-- Skeleton loader -->
      <template v-if="loading">
        <div class="space-y-2">
          <div v-for="i in 6" :key="i" class="np-skeleton h-10 rounded"></div>
        </div>
      </template>

      <!-- Error state -->
      <div v-else-if="error" class="text-xs text-red-400 py-2">{{ error }}</div>

      <!-- Device table -->
      <div v-else class="overflow-x-auto rounded border" style="border-color: var(--np-border);">
        <table class="w-full text-left text-xs tabular-nums">
          <thead>
            <tr>
              <th class="px-3 py-2">Target</th>
              <th class="px-3 py-2 hidden sm:table-cell">Type</th>
              <th class="px-3 py-2 hidden md:table-cell">Zone</th>
              <th class="px-3 py-2">Status</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="d in filteredDevices"
              :key="d.id"
              class="cursor-pointer transition-colors hover:bg-[var(--np-surface-hover)]"
              @click="openDrawer(d)"
              @contextmenu.prevent="openContextMenu($event, d)"
            >
              <td class="px-3" :class="'py-2.5'">
                <div class="font-mono text-[var(--np-text)] font-semibold">{{ d.is_self && d.interface_ips?.length ? d.interface_ips.join(' · ') : d.ip_address }}</div>
                <div class="mt-0.5 flex flex-wrap items-center gap-1">
                  <span class="text-[0.65rem] text-[var(--np-text-dim)]">{{ d.is_self ? 'This computer' : (d.hostname || d.mac_address || 'Unknown') }}</span>
                  <span
                    v-if="d.is_self"
                    class="rounded px-1.5 py-0.5 text-[0.55rem] font-semibold uppercase tracking-wide border border-[var(--np-accent-border)] bg-[var(--np-accent-soft)] text-[var(--np-accent)]"
                    title="This machine runs the NetPulse console. It answers on every interface it holds — Wi-Fi and a USB adapter (e.g. the Archer T2U) — so it shows one row per address."
                  >
                    This PC
                  </span>
                </div>
              </td>
              <td class="px-3 hidden sm:table-cell" :class="'py-2.5'">
                <div class="flex flex-wrap items-center gap-1.5">
                  <span class="sp-badge">{{ d.is_gateway ? 'Gateway' : (d.device_type || 'Unknown') }}</span>
                  <span
                    class="rounded px-1.5 py-0.5 text-[0.55rem] uppercase tracking-wide border"
                    :class="d.verified
                      ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400'
                      : 'border-[var(--np-border-subtle)] text-[var(--np-text-dim)]'"
                    :title="verificationTitle(d)"
                  >
                    {{ verificationLabel(d) }}
                  </span>
                </div>
              </td>
              <td class="px-3 hidden md:table-cell text-[var(--np-text-dim)]/50" :class="'py-2.5'">
                {{ d.zone || '—' }}
              </td>
              <td class="px-3 text-center" :class="'py-2.5'" @click.stop>
                <div v-if="blockedDevices.has(d.ip_address)" class="flex flex-col gap-1 items-center justify-center">
                  <span class="sp-badge-danger flex items-center gap-1 rounded cursor-help px-2 py-0.5" title="Manual router intervention required to drop MAC.">
                    <TriangleAlert class="h-3 w-3" :stroke-width="1.7" />
                    Rogue
                  </span>
                  <button
                    type="button"
                    @click="attemptKick(d.ip_address)"
                    class="rounded px-1.5 py-0.5 text-[0.55rem] font-semibold uppercase border transition-colors disabled:opacity-50 border-red-500/40 bg-red-500/10 text-red-400 hover:bg-red-500/20"
                    :disabled="kickLoadingIp === d.ip_address || !isAdmin"
                    title="Best-effort L2 disruption via ARP poisoning."
                  >
                    {{ kickLoadingIp === d.ip_address ? 'Kicking…' : 'Attempt Kick' }}
                  </button>
                </div>
                <span v-else class="text-zinc-600">—</span>
              </td>
            </tr>
            <tr v-if="filteredDevices.length === 0">
              <td colspan="4" class="px-3 py-6 text-center text-[var(--np-text-dim)]/30">
                No devices found.
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

  </div>

  <!-- Device detail drawer -->
  <DeviceDrawer
    :device-id="drawerDeviceId"
    :open="drawerOpen"
    :theme="props.theme"
    :is-admin="isAdmin"
    @close="closeDrawer"
    @updated="onDeviceUpdated"
  />
</template>

