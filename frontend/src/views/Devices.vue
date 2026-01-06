<script setup lang="ts">
import axios from "axios";
import { computed, onMounted, ref } from "vue";

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

const devices = ref<DeviceRow[]>([]);
const zones = ref<string[]>([]);
const selectedZone = ref<string | null>(null);
const search = ref("");
const loading = ref(false);
const error = ref<string | null>(null);

const selectedDevice = ref<DeviceRow | null>(null);
const deviceDetail = ref<DeviceDetail | null>(null);
const deviceDetailLoading = ref(false);
const deviceDetailError = ref<string | null>(null);

const aiAnswer = ref<string | null>(null);
const aiLoading = ref(false);
const aiError = ref<string | null>(null);

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
    aiError.value = "AI analysis failed. Check AI provider configuration.";
  } finally {
    aiLoading.value = false;
  }
}

onMounted(async () => {
  await Promise.all([loadZones(), loadDevices()]);
});
</script>

<template>
  <div class="np-panel p-4 space-y-4">
    <header class="np-panel-header -mx-4 -mt-4 mb-2 px-4">
      <div class="flex flex-col">
        <span class="np-panel-title">Devices</span>
        <span class="text-[0.7rem] text-[var(--np-muted-text)]">
          Inventory of discovered hosts across your zones.
        </span>
      </div>
      <div class="flex items-center gap-3">
        <select
          v-model="selectedZone"
          @change="loadDevices"
          class="rounded border bg-black/40 px-2 py-0.5 text-[0.7rem] focus:outline-none focus:ring-1 focus:ring-cyan-400"
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
          class="rounded border border-cyan-400/40 bg-black/60 px-2 py-0.5 text-[0.7rem] text-cyan-100
                 focus:outline-none focus:ring-1 focus:ring-cyan-400"
        />
      </div>
    </header>

    <div class="grid gap-4 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)] text-xs">
      <section class="space-y-2">
        <div
          class="rounded-md border border-cyan-400/30 bg-black/60 max-h-80 overflow-auto"
        >
          <table class="min-w-full text-[0.7rem]">
            <thead class="bg-black/70 text-cyan-200">
              <tr>
                <th class="px-2 py-1 text-left">IP / Hostname</th>
                <th class="px-2 py-1 text-left">Type</th>
                <th class="px-2 py-1 text-left">Zone</th>
                <th class="px-2 py-1 text-left">MAC</th>
                <th class="px-2 py-1 text-left">Last seen</th>
                <th class="px-2 py-1 text-center">GW</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-if="loading"
                class="text-cyan-100"
              >
                <td colspan="6" class="px-2 py-2 text-center">
                  Loading devices...
                </td>
              </tr>
              <tr
                v-else-if="!filteredDevices.length"
                class="text-cyan-100"
              >
                <td colspan="6" class="px-2 py-2 text-center">
                  No devices found for current filters.
                </td>
              </tr>
              <tr
                v-for="d in filteredDevices"
                :key="d.id"
                @click="selectDevice(d)"
                class="cursor-pointer border-t border-cyan-400/20 text-cyan-100 hover:bg-cyan-500/10"
                :class="selectedDevice && selectedDevice.id === d.id ? 'bg-cyan-500/20' : ''"
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
              </tr>
            </tbody>
          </table>
        </div>
        <p v-if="error" class="text-[0.7rem] text-rose-300">
          {{ error }}
        </p>
      </section>

      <section class="space-y-2">
        <div class="rounded-md border border-cyan-400/30 bg-black/70 p-3">
          <p class="text-[0.7rem] uppercase tracking-[0.16em] text-cyan-200">
            Device Overview
          </p>
          <div v-if="!selectedDevice" class="mt-2 text-[0.7rem] text-[var(--np-muted-text)]">
            Select a device from the table to see its profile, recent activity, and AI analysis.
          </div>
          <div v-else class="mt-2 space-y-2 text-[0.7rem]">
            <div class="flex items-center justify-between">
              <div>
                <p class="font-mono text-cyan-100">
                  {{ selectedDevice.hostname || selectedDevice.ip_address }}
                </p>
                <p class="text-[0.65rem] text-[var(--np-muted-text)]">
                  IP {{ selectedDevice.ip_address }} · Zone {{ selectedDevice.zone || "n/a" }}
                </p>
              </div>
              <span
                v-if="selectedDevice.is_gateway"
                class="rounded border border-emerald-400/60 bg-emerald-500/20 px-2 py-0.5 text-[0.65rem] text-emerald-200"
              >
                Gateway
              </span>
            </div>

            <div class="mt-1">
              <p v-if="deviceDetailLoading" class="text-cyan-100/80">
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
                <p class="text-[0.65rem] uppercase tracking-[0.16em] text-cyan-200">
                  AI Copilot
                </p>
                <button
                  type="button"
                  @click="askAiAboutDevice"
                  class="rounded border border-cyan-400/40 bg-black/80 px-2 py-0.5 text-[0.65rem]
                         text-cyan-200 hover:bg-cyan-500/10 disabled:opacity-50"
                  :disabled="aiLoading"
                >
                  {{ aiLoading ? "Asking..." : "Ask about this device" }}
                </button>
              </div>
              <p v-if="aiError" class="text-[0.7rem] text-rose-300">
                {{ aiError }}
              </p>
              <div
                v-if="aiAnswer"
                class="mt-1 max-h-32 overflow-auto rounded border border-cyan-400/20 bg-black/80 p-2 text-[0.7rem] text-cyan-100"
              >
                {{ aiAnswer }}
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  </div>
</template>