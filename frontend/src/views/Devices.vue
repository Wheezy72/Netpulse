<script setup lang="ts">
import axios from "axios";
import { computed, onMounted, ref, nextTick } from "vue";
import Uptime from "./Uptime.vue";
import DeviceDrawer from "../components/features/DeviceDrawer.vue";
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

const activeTab = ref<string>("inventory");

type DeviceRow = {
  id: number;
  hostname: string | null;
  ip_address: string;
  mac_address: string | null;
  device_type: string | null;
  is_gateway: boolean;
  zone: string | null;
  last_seen: string | null;
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

type SnmpResultRow = {
  oid: string;
  label: string;
  value: string;
  type: string;
};

const devices = ref<DeviceRow[]>([]);
const zones = ref<string[]>([]);
const selectedZone = ref<string | null>(null);
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

const snmpTarget = ref("");
const snmpCommunity = ref("public");
const snmpVersion = ref("2c");
const snmpLoading = ref(false);
const snmpError = ref<string | null>(null);
const snmpResults = ref<SnmpResultRow[]>([]);
const snmpWalkOid = ref("1.3.6.1.2.1.1");
const snmpWalkLoading = ref(false);
const snmpWalkResults = ref<SnmpResultRow[]>([]);

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

async function snmpPoll(): Promise<void> {
  if (!snmpTarget.value.trim()) return;
  snmpLoading.value = true;
  snmpError.value = null;
  snmpResults.value = [];
  try {
    const { data } = await axios.post<{ results: SnmpResultRow[] }>("/api/snmp/poll", {
      target: snmpTarget.value.trim(),
      community: snmpCommunity.value,
      version: snmpVersion.value,
    });
    snmpResults.value = data.results;
  } catch (e: any) {
    snmpError.value = e.response?.data?.detail || "SNMP poll failed";
  } finally {
    snmpLoading.value = false;
  }
}

async function snmpWalk(): Promise<void> {
  if (!snmpTarget.value.trim() || !snmpWalkOid.value.trim()) return;
  snmpWalkLoading.value = true;
  snmpError.value = null;
  snmpWalkResults.value = [];
  try {
    const { data } = await axios.post<{ results: SnmpResultRow[] }>("/api/snmp/walk", {
      target: snmpTarget.value.trim(),
      community: snmpCommunity.value,
      oid: snmpWalkOid.value.trim(),
    });
    snmpWalkResults.value = data.results;
  } catch (e: any) {
    snmpError.value = e.response?.data?.detail || "SNMP walk failed";
  } finally {
    snmpWalkLoading.value = false;
  }
}

onMounted(async () => {
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
        <div class="px-3 py-1.5 border-b text-[0.6rem] uppercase tracking-widest text-zinc-500" style="border-color: var(--np-border-subtle);">
          {{ contextMenu.device.ip_address }}
        </div>
        <button
          type="button"
          class="w-full flex items-center gap-2.5 px-3 py-2 text-xs text-zinc-300 hover:text-zinc-100 hover:bg-zinc-800/60 transition-colors text-left"
          @click.stop="quickAction('ping', contextMenu.device!)"
        >
          <svg class="w-3.5 h-3.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.141 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0" />
          </svg>
          Ping Sweep
        </button>
        <button
          type="button"
          class="w-full flex items-center gap-2.5 px-3 py-2 text-xs text-zinc-300 hover:text-zinc-100 hover:bg-zinc-800/60 transition-colors text-left"
          @click.stop="quickAction('trace', contextMenu.device!)"
        >
          <svg class="w-3.5 h-3.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M7.5 21L3 16.5m0 0L7.5 12M3 16.5h13.5m0-13.5L21 7.5m0 0L16.5 12M21 7.5H7.5" />
          </svg>
          Traceroute
        </button>
        <button
          type="button"
          class="w-full flex items-center gap-2.5 px-3 py-2 text-xs text-zinc-300 hover:text-zinc-100 hover:bg-zinc-800/60 transition-colors text-left"
          @click.stop="quickAction('portscan', contextMenu.device!)"
        >
          <svg class="w-3.5 h-3.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
          </svg>
          Port Scan (Quick)
        </button>
        <div class="border-t my-1" style="border-color: var(--np-border-subtle);"></div>
        <button
          type="button"
          class="w-full flex items-center gap-2.5 px-3 py-2 text-xs text-zinc-300 hover:text-zinc-100 hover:bg-zinc-800/60 transition-colors text-left"
          @click.stop="openDrawer(contextMenu.device!)"
        >
          <svg class="w-3.5 h-3.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
          </svg>
          View Details
        </button>
      </div>
    </Transition>
  </Teleport>

  <div class="space-y-4">
    <!-- Tab bar -->
    <div class="flex items-center gap-1 border-b" style="border-color: var(--np-border);">
      <button
        v-for="tab in ['inventory', 'uptime', 'snmp']"
        :key="tab"
        type="button"
        @click="activeTab = tab"
        class="px-4 py-2.5 text-xs uppercase tracking-wider font-semibold transition-all duration-200 border-b-2 -mb-px"
        :class="[
          activeTab === tab
            ? isNightshade
              ? 'border-blue-500 text-blue-400'
              : 'border-amber-500 text-amber-400'
            : 'border-transparent text-zinc-500 hover:text-zinc-200 hover:border-zinc-600',
        ]"
      >
        {{ tab === 'inventory' ? 'Inventory' : tab === 'uptime' ? 'Uptime Monitor' : 'SNMP Monitor' }}
      </button>
    </div>

    <!-- Inventory tab -->
    <div v-if="activeTab === 'inventory'" class="np-panel p-4 space-y-4">
      <header class="np-panel-header -mx-4 -mt-4 mb-2 px-4">
        <div class="flex flex-col">
          <span class="np-panel-title">Devices</span>
          <span class="text-[0.7rem] text-zinc-500">
            Inventory of discovered hosts. Right-click any row for quick actions.
          </span>
        </div>
        <div class="flex items-center gap-2">
          <button
            @click="downloadDeviceReport"
            class="np-cyber-btn flex items-center gap-1"
            title="Download Device Inventory CSV"
          >
            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
            </svg>
            CSV
          </button>
          <button
            @click="downloadDevicesPDF"
            class="np-cyber-btn flex items-center gap-1"
            title="Download Device Inventory PDF"
          >
            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
            </svg>
            PDF
          </button>
        </div>
      </header>

      <!-- Search + zone filter -->
      <div class="flex flex-col sm:flex-row gap-2">
        <div class="relative flex-1">
          <svg class="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-zinc-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            v-model="search"
            type="text"
            placeholder="Search or use ip:, status:, type:, zone: prefixes…"
            class="np-neon-input w-full pl-8 pr-3 py-1.5 text-xs"
          />
        </div>
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
        :class="{
          'border-blue-500/40 text-blue-300 bg-blue-500/5': actionNotice.type === 'info',
          'border-emerald-500/40 text-emerald-300 bg-emerald-500/5': actionNotice.type === 'success',
          'border-red-500/40 text-red-300 bg-red-500/5': actionNotice.type === 'error',
          'border-amber-500/40 text-amber-300 bg-amber-500/5': actionNotice.type === 'warning',
        }"
      >
        <span>{{ actionNotice.message }}</span>
        <button @click="actionNotice = null" class="opacity-70 hover:opacity-100 ml-3">✕</button>
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
        <table class="w-full text-left text-xs">
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
              class="cursor-pointer transition-colors hover:bg-white/[0.03]"
              @click="openDrawer(d)"
              @contextmenu.prevent="openContextMenu($event, d)"
            >
              <td class="px-3 py-2.5">
                <div class="font-mono text-zinc-100">{{ d.ip_address }}</div>
                <div class="text-[0.65rem] text-zinc-500 mt-0.5">{{ d.hostname || d.mac_address || 'Unknown' }}</div>
              </td>
              <td class="px-3 py-2.5 hidden sm:table-cell">
                <span class="sp-badge">{{ d.is_gateway ? 'Gateway' : (d.device_type || 'Unknown') }}</span>
              </td>
              <td class="px-3 py-2.5 hidden md:table-cell text-zinc-500">
                {{ d.zone || '—' }}
              </td>
              <td class="px-3 py-2.5 text-center" @click.stop>
                <div v-if="blockedDevices.has(d.ip_address)" class="flex flex-col gap-1 items-center justify-center">
                  <span class="sp-badge-danger flex items-center gap-1 rounded cursor-help px-2 py-0.5" title="Manual router intervention required to drop MAC.">
                    ⚠ ROGUE
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
              <td colspan="4" class="px-3 py-6 text-center text-zinc-600">
                No devices found.
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Uptime tab -->
    <div v-if="activeTab === 'uptime'" class="np-panel p-4">
      <Uptime :is-admin="isAdmin" />
    </div>

    <!-- SNMP tab -->
    <div v-if="activeTab === 'snmp'" class="np-panel p-4 space-y-4">
      <p class="text-xs text-zinc-500">SNMP Polling interface active.</p>
    </div>
  </div>

  <!-- Device detail drawer -->
  <DeviceDrawer
    :device-id="drawerDeviceId"
    :open="drawerOpen"
    :theme="props.theme"
    @close="closeDrawer"
  />
</template>

