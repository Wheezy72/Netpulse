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
      { ip }
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
              <path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
            </svg>
            PDF
          </button>
          <select
            v-model="selectedZone"
            @change="loadDevices"
            class="rounded border bg-black/40 px-2 py-0.5 text-[0.7rem] focus:outline-none focus:ring-1 focus:ring-[var(--np-accent-primary)]"
          >
            <option :value="null">All zones</option>
            <option v-for="z in zones" :key="z" :value="z">
              {{ z }}
            </option>
          </select>
          <input
            v-model="search"
            type="text"
            placeholder="Search by IP, hostname, type..."
            class="rounded border bg-black/60 px-2 py-0.5 text-[0.7rem] text-[var(--np-text)]
                   focus:outline-none focus:ring-1 focus:ring-[var(--np-accent-primary)]"
            :class="isNightshade ? 'border-teal-400/40' : 'border-amber-500/30'"
          />
        </div>
      </header>

      <div
        v-if="blockedDevices.size > 0"
        class="rounded-md border p-3 space-y-2"
        :class="isNightshade ? 'border-rose-400/30 bg-rose-500/5' : 'border-rose-500/20 bg-rose-500/5'"
      >
        <p class="text-[0.7rem] uppercase tracking-[0.16em] font-semibold text-rose-300">
          Anomaly / Rogue Devices
        </p>
        <div class="flex flex-wrap gap-2">
          <div
            v-for="ip in Array.from(blockedDevices)"
            :key="ip"
            class="flex items-center gap-2 rounded border px-2 py-1 text-[0.7rem]"
            :class="isNightshade ? 'border-rose-400/30 bg-black/40 text-rose-200' : 'border-rose-500/20 bg-black/40 text-rose-300'"
          >
            <span class="font-mono">{{ ip }}</span>
            <button
              v-if="isAdmin"
              type="button"
              @click="unblockDevice(ip)"
              class="rounded px-1.5 py-0.5 text-[0.6rem] font-semibold uppercase transition-colors"
              :class="isNightshade ? 'bg-teal-500/20 text-teal-300 hover:bg-teal-500/30' : 'bg-amber-500/20 text-amber-300 hover:bg-amber-500/30'"
            >
              Unblock
            </button>
          </div>
        </div>
      </div>

      <div class="grid gap-4 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)] text-xs">
      <section class="space-y-2">
        <div
          class="rounded-md border bg-black/60 max-h-80 overflow-auto"
          :class="isNightshade ? 'border-teal-400/30' : 'border-amber-500/20'"
        >
          <table class="min-w-full text-[0.7rem]">
            <thead class="bg-black/70" :class="isNightshade ? 'text-teal-200' : 'text-amber-300'">
              <tr>
                <th class="px-2 py-1 text-left">IP / Hostname</th>
                <th class="px-2 py-1 text-left">Type</th>
                <th class="px-2 py-1 text-left">Zone</th>
                <th class="px-2 py-1 text-left">MAC</th>
                <th class="px-2 py-1 text-left">Last seen</th>
                <th class="px-2 py-1 text-center">GW</th>
                <th class="px-2 py-1 text-center">Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-if="loading"
                class="text-[var(--np-text)]"
              >
                <td colspan="7" class="px-2 py-2 text-center">
                  Loading devices...
                </td>
              </tr>
              <tr
                v-else-if="!filteredDevices.length"
                class="text-[var(--np-text)]"
              >
                <td colspan="7" class="px-2 py-2 text-center">
                  No devices found for current filters.
                </td>
              </tr>
              <tr
                v-for="d in filteredDevices"
                :key="d.id"
                @click="selectDevice(d)"
                class="cursor-pointer border-t text-[var(--np-text)]"
                :class="[
                  isNightshade ? 'border-teal-400/20 hover:bg-teal-500/10' : 'border-amber-500/15 hover:bg-amber-500/10',
                  selectedDevice && selectedDevice.id === d.id ? (isNightshade ? 'bg-teal-500/20' : 'bg-amber-500/20') : ''
                ]"
              >
                <td class="px-2 py-1">
                  <div class="flex flex-col">
                    <span class="font-mono">{{ d.ip_address }}</span>
                    <span v-if="d.hostname" class="text-[0.65rem] text-[var(--np-muted-text)]">
                      {{ d.hostname }}
                    </span>
                  </div>
                </td>
                <td class="px-2 py-1">
                  {{ d.device_type || "unknown" }}
                </td>
                <td class="px-2 py-1">
                  {{ d.zone || "—" }}
                </td>
                <td class="px-2 py-1">
                  <span class="font-mono text-[0.65rem]">
                    {{ d.mac_address || "—" }}
                  </span>
                </td>
                <td class="px-2 py-1 text-[0.65rem]">
                  <span v-if="d.last_seen">
                    {{ d.last_seen.split("T")[0] }} {{ d.last_seen.split("T")[1]?.slice(0, 8) }}
                  </span>
                  <span v-else>—</span>
                </td>
                <td class="px-2 py-1 text-center">
                  {{ d.is_gateway ? "●" : "" }}
                </td>
                <td class="px-2 py-1 text-center" @click.stop>
                  <template v-if="isAdmin">
                    <button
                      v-if="blockedDevices.has(d.ip_address)"
                      type="button"
                      @click="unblockDevice(d.ip_address)"
                      class="rounded px-2 py-0.5 text-[0.6rem] font-semibold uppercase transition-colors"
                      :class="isNightshade ? 'bg-teal-500/20 text-teal-300 hover:bg-teal-500/30 border border-teal-400/30' : 'bg-amber-500/20 text-amber-300 hover:bg-amber-500/30 border border-amber-500/30'"
                    >
                      Unblock
                    </button>
                    <button
                      v-else
                      type="button"
                      @click="blockDevice(d.ip_address)"
                      class="rounded px-2 py-0.5 text-[0.6rem] font-semibold uppercase transition-colors border border-rose-400/30 bg-rose-500/10 text-rose-300 hover:bg-rose-500/20"
                    >
                      Block
                    </button>
                  </template>
                  <template v-else>
                    <span
                      v-if="blockedDevices.has(d.ip_address)"
                      class="rounded px-2 py-0.5 text-[0.6rem] font-semibold uppercase border border-rose-400/30 bg-rose-500/10 text-rose-300"
                      title="Manual router/AP isolation recommended — NetPulse cannot enforce this block."
                    >
                      ⚠️ ANOMALY / ROGUE
                    </span>
                    <span v-else class="text-[0.65rem] text-[var(--np-muted-text)]">—</span>
                  </template>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <p v-if="error" class="text-[0.7rem] text-rose-300">
          {{ error }}
        </p>
      </section>

      <section class="space-y-2">
        <div class="rounded-md border bg-black/70 p-3" :class="isNightshade ? 'border-teal-400/30' : 'border-amber-500/20'">
          <p class="text-[0.7rem] uppercase tracking-[0.16em]" :class="isNightshade ? 'text-teal-200' : 'text-amber-300'">
            Device Overview
          </p>
          <div v-if="!selectedDevice" class="mt-2 text-[0.7rem] text-[var(--np-muted-text)]">
            Select a device from the table to see its profile and recent activity.
          </div>
          <div v-else class="mt-2 space-y-2 text-[0.7rem]">
            <div class="flex items-start justify-between gap-3">
              <div>
                <p class="font-mono text-[var(--np-text)]">
                  {{ selectedDevice.hostname || selectedDevice.ip_address }}
                </p>
                <p class="text-[0.65rem] text-[var(--np-muted-text)]">
                  IP {{ selectedDevice.ip_address }} · Zone {{ selectedDevice.zone || "n/a" }}
                </p>
              </div>
              <div class="flex flex-col items-end gap-1">
                <span
                  v-if="blockedDevices.has(selectedDevice.ip_address)"
                  class="rounded border px-2 py-0.5 text-[0.65rem] font-semibold uppercase"
                  :class="isNightshade ? 'border-rose-400/60 bg-rose-500/20 text-rose-200' : 'border-rose-500/60 bg-rose-500/20 text-rose-200'"
                  title="Manual router/AP isolation recommended — NetPulse cannot enforce this block."
                >
                  ⚠️ ANOMALY / ROGUE
                </span>
                <button
                  v-if="isAdmin && blockedDevices.has(selectedDevice.ip_address)"
                  type="button"
                  @click="attemptKick(selectedDevice.ip_address)"
                  :disabled="kickLoadingIp === selectedDevice.ip_address"
                  class="rounded border px-2 py-1 text-[0.65rem] font-semibold uppercase tracking-wide transition-colors disabled:opacity-50"
                  :class="isNightshade ? 'border-rose-400/40 bg-black/60 text-rose-200 hover:bg-rose-500/10' : 'border-rose-500/30 bg-black/60 text-rose-200 hover:bg-rose-500/10'"
                  title="Best-effort: attempts to disrupt the host on the local LAN via ARP poisoning. Requires same L2 segment and elevated privileges."
                >
                  {{ kickLoadingIp === selectedDevice.ip_address ? "Attempting..." : "Attempt to Kick (ARP Spoof)" }}
                </button>
                <p
                  v-if="isAdmin && blockedDevices.has(selectedDevice.ip_address)"
                  class="max-w-[16rem] text-right text-[0.6rem] text-[var(--np-muted-text)]"
                >
                  Manual router/AP isolation is recommended. Best-effort only; may fail depending on topology/permissions.
                </p>
                <span
                  v-if="selectedDevice.is_gateway"
                  class="rounded border px-2 py-0.5 text-[0.65rem]"
                  :class="isNightshade ? 'border-emerald-400/60 bg-emerald-500/20 text-emerald-200' : 'border-green-500/60 bg-green-500/20 text-green-200'"
                >
                  Gateway
                </span>
              </div>
            </div>

            <p
              v-if="actionNotice"
              class="text-[0.7rem]"
              :class="
                actionNotice.type === 'error'
                  ? 'text-rose-300'
                  : actionNotice.type === 'warning'
                    ? 'text-amber-300'
                    : isNightshade
                      ? 'text-teal-200'
                      : 'text-amber-200'
              "
            >
              {{ actionNotice.message }}
            </p>

            <div class="mt-1">
              <p v-if="deviceDetailLoading" class="text-[var(--np-muted-text)]">
                Loading device detail...
              </p>
              <p v-else-if="deviceDetailError" class="text-rose-300">
                {{ deviceDetailError }}
              </p>
              <div v-else-if="deviceDetail" class="space-y-1">
                <p>
                  Type:
                  <span v-if="deviceDetail.type_guess">
                    {{ deviceDetail.type_guess }}
                    <span v-if="deviceDetail.type_confidence != null">
                      ({{ (deviceDetail.type_confidence * 100).toFixed(0) }}%)
                    </span>
                  </span>
                  <span v-else>
                    {{ selectedDevice.device_type || "unknown" }}
                  </span>
                </p>
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

            <div class="mt-2 space-y-1">
              <div class="flex items-center justify-between">
                <p class="text-[0.65rem] uppercase tracking-[0.16em]" :class="isNightshade ? 'text-teal-200' : 'text-amber-300'">
                  Device Analysis
                </p>
                <button
                  type="button"
                  @click="askAiAboutDevice"
                  class="rounded border bg-black/80 px-2 py-0.5 text-[0.65rem] disabled:opacity-50"
                  :class="isNightshade ? 'border-teal-400/40 text-teal-200 hover:bg-teal-500/10' : 'border-amber-500/30 text-amber-300 hover:bg-amber-500/10'"
                  :disabled="aiLoading"
                >
                  {{ aiLoading ? "Analyzing..." : "Analyze Device" }}
                </button>
              </div>
              <p v-if="aiError" class="text-[0.7rem] text-rose-300">
                {{ aiError }}
              </p>
              <div
                v-if="aiAnswer"
                class="mt-1 max-h-32 overflow-auto rounded border bg-black/80 p-2 text-[0.7rem] text-[var(--np-text)]"
                :class="isNightshade ? 'border-teal-400/20' : 'border-amber-500/15'"
              >
                {{ aiAnswer }}
              </div>
            </div>
          </div>
        </div>
      </section>
      </div>
    </div>

    <Uptime v-else-if="activeTab === 'uptime'" :theme="theme" />

    <div v-else-if="activeTab === 'snmp'" class="np-panel p-4 space-y-6">
      <header class="np-panel-header -mx-4 -mt-4 mb-2 px-4">
        <div class="flex flex-col">
          <span class="np-panel-title">SNMP Monitor</span>
          <span class="text-[0.7rem] text-[var(--np-muted-text)]">
            Poll devices via SNMP and walk OID trees.
          </span>
        </div>
      </header>

      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div>
          <label class="block text-[0.7rem] uppercase tracking-wider font-semibold" :class="isNightshade ? 'text-teal-200' : 'text-amber-300'">
            Target IP
          </label>
          <input
            v-model="snmpTarget"
            type="text"
            placeholder="192.168.1.1"
            class="mt-1 w-full rounded-md border px-3 py-2 text-sm bg-black/40"
            style="border-color: var(--np-border); color: var(--np-text)"
          />
        </div>
        <div>
          <label class="block text-[0.7rem] uppercase tracking-wider font-semibold" :class="isNightshade ? 'text-teal-200' : 'text-amber-300'">
            Community String
          </label>
          <input
            v-model="snmpCommunity"
            type="text"
            placeholder="public"
            class="mt-1 w-full rounded-md border px-3 py-2 text-sm bg-black/40"
            style="border-color: var(--np-border); color: var(--np-text)"
          />
        </div>
        <div>
          <label class="block text-[0.7rem] uppercase tracking-wider font-semibold" :class="isNightshade ? 'text-teal-200' : 'text-amber-300'">
            SNMP Version
          </label>
          <select
            v-model="snmpVersion"
            class="mt-1 w-full rounded-md border px-3 py-2 text-sm bg-black/40"
            style="border-color: var(--np-border); color: var(--np-text)"
          >
            <option value="1">v1</option>
            <option value="2c">v2c</option>
            <option value="3">v3</option>
          </select>
        </div>
        <div class="flex items-end">
          <button
            type="button"
            @click="snmpPoll"
            :disabled="snmpLoading || !snmpTarget.trim()"
            class="w-full rounded-md px-4 py-2 text-sm font-semibold uppercase tracking-wider transition-all disabled:opacity-40"
            :class="isNightshade
              ? 'bg-teal-500/20 text-teal-400 border border-teal-500/30 hover:bg-teal-500/30'
              : 'bg-amber-500/20 text-amber-400 border border-amber-500/30 hover:bg-amber-500/30'"
          >
            {{ snmpLoading ? "Polling..." : "Poll Device" }}
          </button>
        </div>
      </div>

      <p v-if="snmpError" class="rounded-md border border-rose-400/30 bg-rose-500/10 px-3 py-2 text-[0.7rem] text-rose-300">
        {{ snmpError }}
      </p>

      <div v-if="snmpResults.length > 0" class="space-y-2">
        <p class="text-[0.7rem] uppercase tracking-[0.16em] font-semibold" :class="isNightshade ? 'text-teal-200' : 'text-amber-300'">
          Poll Results
        </p>
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          <div
            v-for="(r, idx) in snmpResults"
            :key="idx"
            class="rounded-md border p-3 space-y-1"
            :class="isNightshade ? 'border-teal-400/20 bg-black/30' : 'border-slate-700 bg-slate-800/50'"
          >
            <p class="text-[0.65rem] uppercase tracking-wider" :class="isNightshade ? 'text-teal-300' : 'text-amber-300'">
              {{ r.label }}
            </p>
            <p class="text-sm font-mono text-[var(--np-text)] break-all">
              {{ r.value }}
            </p>
            <p class="text-[0.6rem] text-[var(--np-muted-text)]">
              {{ r.type }} &middot; {{ r.oid }}
            </p>
          </div>
        </div>
      </div>

      <div class="border-t pt-4" :class="isNightshade ? 'border-teal-500/20' : 'border-amber-500/20'">
        <p class="text-[0.7rem] uppercase tracking-[0.16em] font-semibold mb-3" :class="isNightshade ? 'text-teal-200' : 'text-amber-300'">
          Walk OID
        </p>
        <div class="flex gap-3 items-end">
          <div class="flex-1">
            <label class="block text-[0.65rem] uppercase tracking-wider text-[var(--np-muted-text)]">
              OID
            </label>
            <input
              v-model="snmpWalkOid"
              type="text"
              placeholder="1.3.6.1.2.1.1"
              class="mt-1 w-full rounded-md border px-3 py-2 text-sm bg-black/40"
              style="border-color: var(--np-border); color: var(--np-text)"
            />
          </div>
          <button
            type="button"
            @click="snmpWalk"
            :disabled="snmpWalkLoading || !snmpTarget.trim() || !snmpWalkOid.trim()"
            class="rounded-md px-4 py-2 text-sm font-semibold uppercase tracking-wider transition-all disabled:opacity-40"
            :class="isNightshade
              ? 'bg-teal-500/20 text-teal-400 border border-teal-500/30 hover:bg-teal-500/30'
              : 'bg-amber-500/20 text-amber-400 border border-amber-500/30 hover:bg-amber-500/30'"
          >
            {{ snmpWalkLoading ? "Walking..." : "Walk" }}
          </button>
        </div>
      </div>

      <div v-if="snmpWalkResults.length > 0" class="space-y-2">
        <p class="text-[0.7rem] uppercase tracking-[0.16em] font-semibold" :class="isNightshade ? 'text-teal-200' : 'text-amber-300'">
          Walk Results ({{ snmpWalkResults.length }} entries)
        </p>
        <div
          class="rounded-md border bg-black/60 max-h-80 overflow-auto"
          :class="isNightshade ? 'border-teal-400/30' : 'border-amber-500/20'"
        >
          <table class="min-w-full text-[0.7rem]">
            <thead class="bg-black/70 sticky top-0" :class="isNightshade ? 'text-teal-200' : 'text-amber-300'">
              <tr>
                <th class="px-3 py-1.5 text-left">OID</th>
                <th class="px-3 py-1.5 text-left">Label</th>
                <th class="px-3 py-1.5 text-left">Value</th>
                <th class="px-3 py-1.5 text-left">Type</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="(w, idx) in snmpWalkResults"
                :key="idx"
                class="border-t text-[var(--np-text)]"
                :class="isNightshade ? 'border-teal-400/10' : 'border-amber-500/10'"
              >
                <td class="px-3 py-1 font-mono text-[0.65rem] text-[var(--np-muted-text)]">{{ w.oid }}</td>
                <td class="px-3 py-1">{{ w.label }}</td>
                <td class="px-3 py-1 font-mono break-all max-w-xs">{{ w.value }}</td>
                <td class="px-3 py-1 text-[0.65rem] text-[var(--np-muted-text)]">{{ w.type }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</template>
