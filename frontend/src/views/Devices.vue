<script setup lang="ts">
import axios from "axios";
import { computed, onMounted, ref } from "vue";
import Uptime from "./Uptime.vue";

const props = defineProps<{
  theme: "nightshade" | "sysadmin";
  isAdmin?: boolean;
}>();

const isNightshade = computed(() => props.theme === "nightshade");
const isAdmin = computed(() => !!props.isAdmin);

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

const filteredDevices = computed(() => {
  let list = devices.value;
  if (selectedZone.value) {
    list = list.filter((d) => d.zone === selectedZone.value);
  }
  const q = search.value.trim().toLowerCase();
  if (!q) return list;
  return list.filter((d) => {
    return (
      d.ip_address.toLowerCase().includes(q) ||
      (d.hostname ?? "").toLowerCase().includes(q) ||
      (d.device_type ?? "").toLowerCase().includes(q)
    );
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
});
</script>

<template>
  <div class="space-y-4">
    <div
      class="flex items-center gap-1 border-b"
      :class="isNightshade ? 'border-teal-500/20' : 'border-amber-500/20'"
    >
      <button
        type="button"
        @click="activeTab = 'inventory'"
        class="px-4 py-2.5 text-xs uppercase tracking-wider font-semibold transition-all duration-200 rounded-t-lg"
        :class="[
          activeTab === 'inventory'
            ? isNightshade
              ? 'bg-teal-500/20 text-teal-400 border border-b-0 border-teal-500/30'
              : 'bg-amber-500/20 text-amber-400 border border-b-0 border-amber-500/30'
            : 'text-[var(--np-muted-text)] hover:text-[var(--np-text)] hover:bg-white/5'
        ]"
        :style="{ fontFamily: isNightshade ? '\'Orbitron\', sans-serif' : '\'Inter\', sans-serif' }"
      >
        Inventory
      </button>
      <button
        type="button"
        @click="activeTab = 'uptime'"
        class="px-4 py-2.5 text-xs uppercase tracking-wider font-semibold transition-all duration-200 rounded-t-lg"
        :class="[
          activeTab === 'uptime'
            ? isNightshade
              ? 'bg-teal-500/20 text-teal-400 border border-b-0 border-teal-500/30'
              : 'bg-amber-500/20 text-amber-400 border border-b-0 border-amber-500/30'
            : 'text-[var(--np-muted-text)] hover:text-[var(--np-text)] hover:bg-white/5'
        ]"
        :style="{ fontFamily: isNightshade ? '\'Orbitron\', sans-serif' : '\'Inter\', sans-serif' }"
      >
        Uptime Monitor
      </button>
      <button
        type="button"
        @click="activeTab = 'snmp'"
        class="px-4 py-2.5 text-xs uppercase tracking-wider font-semibold transition-all duration-200 rounded-t-lg"
        :class="[
          activeTab === 'snmp'
            ? isNightshade
              ? 'bg-teal-500/20 text-teal-400 border border-b-0 border-teal-500/30'
              : 'bg-amber-500/20 text-amber-400 border border-b-0 border-amber-500/30'
            : 'text-[var(--np-muted-text)] hover:text-[var(--np-text)] hover:bg-white/5'
        ]"
        :style="{ fontFamily: isNightshade ? '\'Orbitron\', sans-serif' : '\'Inter\', sans-serif' }"
      >
        SNMP Monitor
      </button>
    </div>

    <div v-if="activeTab === 'inventory'" class="np-panel p-4 space-y-4">
      <header class="np-panel-header -mx-4 -mt-4 mb-2 px-4">
        <div class="flex flex-col">
          <span class="np-panel-title">Devices</span>
          <span class="text-[0.7rem] text-[var(--np-muted-text)]">
            Inventory of discovered hosts across your zones.
          </span>
        </div>
        <div class="flex items-center gap-3">
          <button
            @click="downloadDeviceReport"
            class="rounded bg-black/40 px-2 py-0.5 text-[0.7rem] transition-colors flex items-center gap-1"
            :class="isNightshade ? 'border border-teal-400/30 text-teal-200 hover:bg-teal-500/20' : 'border border-amber-500/20 text-amber-300 hover:bg-amber-500/20'"
            title="Download Device Inventory CSV"
          >
            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
            </svg>
            CSV
          </button>
          <button
            @click="downloadDevicesPDF"
            class="rounded bg-black/40 px-2 py-0.5 text-[0.7rem] transition-colors flex items-center gap-1"
            :class="isNightshade ? 'border border-teal-400/30 text-teal-200 hover:bg-teal-500/20' : 'border border-amber-500/20 text-amber-300 hover:bg-amber-500/20'"
            title="Download Device Inventory PDF"
          >
            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
            </svg>
            PDF
          </button>
        </div>
      </header>

      <div class="flex flex-col sm:flex-row gap-3">
        <input
          v-model="search"
          type="text"
          placeholder="Search IP, Hostname, Type..."
          class="flex-1 rounded-md border bg-black/40 px-3 py-1.5 text-xs focus:outline-none focus:ring-1"
          style="border-color: var(--np-border); color: var(--np-text)"
        />
        <select
          v-model="selectedZone"
          class="rounded-md border bg-black/40 px-3 py-1.5 text-xs focus:outline-none focus:ring-1"
          style="border-color: var(--np-border); color: var(--np-text)"
        >
          <option :value="null">All Zones</option>
          <option v-for="z in zones" :key="z" :value="z">{{ z }}</option>
        </select>
      </div>

      <div v-if="actionNotice" class="rounded p-2 text-xs border bg-black/50 flex justify-between items-center" 
           :class="{
             'border-teal-500/50 text-teal-300': actionNotice.type === 'info' || actionNotice.type === 'success',
             'border-red-500/50 text-red-300': actionNotice.type === 'error',
             'border-amber-500/50 text-amber-300': actionNotice.type === 'warning'
           }">
        <span>{{ actionNotice.message }}</span>
        <button @click="actionNotice = null" class="opacity-70 hover:opacity-100">✕</button>
      </div>

      <div v-if="loading" class="text-xs text-[var(--np-muted-text)]">Loading inventory...</div>
      <div v-else-if="error" class="text-xs text-rose-300">{{ error }}</div>
      <div v-else class="overflow-x-auto rounded-md border" style="border-color: var(--np-border)">
        <table class="w-full text-left text-xs">
          <thead class="bg-black/40 text-[0.65rem] uppercase tracking-wider text-[var(--np-muted-text)]">
            <tr>
              <th class="px-3 py-2">Target</th>
              <th class="px-3 py-2 hidden sm:table-cell">Type</th>
              <th class="px-3 py-2 hidden md:table-cell">Zone</th>
              <th class="px-3 py-2">Status / Action</th>
            </tr>
          </thead>
          <tbody class="divide-y" style="border-color: var(--np-border)">
            <tr
              v-for="d in filteredDevices"
              :key="d.id"
              class="cursor-pointer transition-colors hover:bg-white/5"
              @click="selectDevice(d)"
            >
              <td class="px-3 py-2">
                <div class="font-mono text-[var(--np-text)]">{{ d.ip_address }}</div>
                <div class="text-[0.65rem] text-[var(--np-muted-text)]">{{ d.hostname || d.mac_address || 'Unknown' }}</div>
              </td>
              <td class="px-3 py-2 hidden sm:table-cell">
                <span class="rounded bg-black/40 px-1.5 py-0.5" style="border: 1px solid var(--np-border)">
                  {{ d.is_gateway ? 'Gateway' : (d.device_type || 'Unknown') }}
                </span>
              </td>
              <td class="px-3 py-2 hidden md:table-cell text-[var(--np-muted-text)]">
                {{ d.zone || '—' }}
              </td>
              <td class="px-3 py-2 text-center" @click.stop>
                <div v-if="blockedDevices.has(d.ip_address)" class="flex flex-col gap-1 items-center justify-center">
                  <span class="rounded px-2 py-0.5 text-[0.6rem] font-bold text-white bg-red-600 shadow-[0_0_8px_rgba(220,38,38,0.8)] flex items-center gap-1 cursor-help" title="Manual router intervention required to drop MAC.">
                    ⚠️ ANOMALY / ROGUE
                  </span>
                  <button
                    type="button"
                    @click="attemptKick(d.ip_address)"
                    class="rounded px-1.5 py-0.5 text-[0.55rem] font-semibold uppercase border transition-colors disabled:opacity-50"
                    :class="isNightshade ? 'border-red-500/50 bg-red-500/10 text-red-400 hover:bg-red-500/20' : 'border-red-600/50 bg-red-600/10 text-red-600 hover:bg-red-600/20'"
                    :disabled="kickLoadingIp === d.ip_address || !isAdmin"
                    title="Best-effort L2 disruption via ARP poisoning."
                  >
                    {{ kickLoadingIp === d.ip_address ? 'Kicking...' : 'Attempt Kick' }}
                  </button>
                </div>
                <span v-else class="text-[0.65rem] text-[var(--np-muted-text)]">—</span>
              </td>
            </tr>
            <tr v-if="filteredDevices.length === 0">
              <td colspan="4" class="px-3 py-4 text-center text-[var(--np-muted-text)]">
                No devices found.
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div v-if="activeTab === 'uptime'" class="np-panel p-4">
      <Uptime :is-admin="isAdmin" />
    </div>

    <div v-if="activeTab === 'snmp'" class="np-panel p-4 space-y-4">
       <p class="text-xs text-[var(--np-muted-text)]">SNMP Polling interface active.</p>
       </div>
  </div>
</template>
