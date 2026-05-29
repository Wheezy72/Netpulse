<script setup lang="ts">
/**
 * Device Detail Drawer (slide-over Sheet).
 *
 * Opens from the right when a device row is clicked in the Devices table.
 * The main table remains interactive behind it – no page navigation.
 */
import { ref, watch } from "vue";
import axios from "axios";
import { resolveOui } from "../../utils/oui";

interface Vulnerability {
  id: number;
  title: string;
  severity: string;
  port?: number | null;
  detected_at?: string | null;
}

interface DeviceDetail {
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
  vulnerabilities: Vulnerability[];
}

const props = defineProps<{
  deviceId: number | null;
  open: boolean;
  theme: "nightshade" | "sysadmin";
}>();

const emit = defineEmits<{
  (e: "close"): void;
}>();

const detail = ref<DeviceDetail | null>(null);
const loading = ref(false);
const error = ref<string | null>(null);

const isNightshade = () => props.theme === "nightshade";

const severityColor: Record<string, string> = {
  Critical: "text-red-400",
  High: "text-orange-400",
  Medium: "text-yellow-400",
  Low: "text-blue-400",
};

watch(
  () => props.deviceId,
  async (id) => {
    if (!id) { detail.value = null; return; }
    loading.value = true;
    error.value = null;
    try {
      const { data } = await axios.get<DeviceDetail>(`/api/devices/${id}`);
      detail.value = data;
    } catch (e: any) {
      error.value = e?.response?.data?.error?.message ?? "Failed to load device";
    } finally {
      loading.value = false;
    }
  }
);
</script>

<template>
  <!-- Backdrop -->
  <Teleport to="body">
    <Transition name="np-fade">
      <div
        v-if="open"
        class="fixed inset-0 z-30 bg-black/40"
        @click="emit('close')"
      />
    </Transition>

    <!-- Sheet -->
    <Transition name="np-slide-right">
      <aside
        v-if="open"
        class="fixed inset-y-0 right-0 z-40 w-full max-w-lg flex flex-col border-l overflow-y-auto
               bg-gray-900 dark:bg-[#0a0f1e] border-amber-500/15 dark:border-teal-500/20"
      >
        <!-- Header -->
        <div
          class="flex items-center justify-between px-6 py-4 border-b border-amber-500/15 dark:border-teal-500/20"
        >
          <h2 class="font-semibold text-sm text-slate-100 dark:text-sky-100">
            Device Detail
          </h2>
          <button
            type="button"
            class="p-1.5 rounded hover:bg-white/10 transition-colors text-slate-400 dark:text-teal-300"
            @click="emit('close')"
          >
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <!-- Loading -->
        <div v-if="loading" class="flex-1 flex items-center justify-center text-sm text-slate-400 dark:text-teal-300">
          Loading…
        </div>

        <!-- Error -->
        <div v-else-if="error" class="px-6 py-4 text-red-400 text-sm">{{ error }}</div>

        <!-- Content -->
        <div v-else-if="detail" class="flex-1 px-6 py-4 space-y-6">

          <!-- Identity section -->
          <section>
            <h3 class="text-xs uppercase tracking-widest mb-3 text-slate-400 dark:text-teal-300">Identity</h3>
            <dl class="space-y-2 text-sm">
              <div class="flex justify-between">
                <dt class="text-slate-400 dark:text-teal-300">IP Address</dt>
                <dd class="font-mono text-amber-500 dark:text-teal-500">{{ detail.device.ip_address }}</dd>
              </div>
              <div class="flex justify-between">
                <dt class="text-slate-400 dark:text-teal-300">Hostname</dt>
                <dd class="text-slate-100 dark:text-sky-100">{{ detail.device.hostname || '—' }}</dd>
              </div>
              <div class="flex justify-between">
                <dt class="text-slate-400 dark:text-teal-300">MAC Address</dt>
                <dd class="font-mono text-xs text-slate-100 dark:text-sky-100">{{ detail.device.mac_address || '—' }}</dd>
              </div>
              <div class="flex justify-between">
                <dt class="text-slate-400 dark:text-teal-300">Vendor (OUI)</dt>
                <dd class="text-slate-100 dark:text-sky-100">
                  {{ detail.device.mac_address ? (resolveOui(detail.device.mac_address) ?? 'Unknown') : '—' }}
                </dd>
              </div>
              <div class="flex justify-between">
                <dt class="text-slate-400 dark:text-teal-300">Type</dt>
                <dd class="text-slate-100 dark:text-sky-100">{{ detail.device.device_type || detail.type_guess || '—' }}</dd>
              </div>
              <div class="flex justify-between">
                <dt class="text-slate-400 dark:text-teal-300">Zone</dt>
                <dd class="text-slate-100 dark:text-sky-100">{{ detail.device.zone || '—' }}</dd>
              </div>
              <div class="flex justify-between">
                <dt class="text-slate-400 dark:text-teal-300">Gateway</dt>
                <dd :class="detail.device.is_gateway ? 'text-green-500 dark:text-emerald-400' : 'text-slate-400 dark:text-teal-300'">
                  {{ detail.device.is_gateway ? 'Yes' : 'No' }}
                </dd>
              </div>
              <div class="flex justify-between">
                <dt class="text-slate-400 dark:text-teal-300">Last Seen</dt>
                <dd class="text-slate-100 dark:text-sky-100">{{ detail.device.last_seen ?? '—' }}</dd>
              </div>
            </dl>
          </section>

          <!-- Vulnerabilities -->
          <section>
            <h3 class="text-xs uppercase tracking-widest mb-3 text-slate-400 dark:text-teal-300">
              Vulnerabilities ({{ detail.vulnerabilities.length }})
            </h3>
            <div v-if="detail.vulnerabilities.length === 0" class="text-xs text-slate-400 dark:text-teal-300">
              No vulnerabilities detected.
            </div>
            <ul v-else class="space-y-2">
              <li
                v-for="vuln in detail.vulnerabilities"
                :key="vuln.id"
                class="flex items-start gap-2 text-xs"
              >
                <span :class="[severityColor[vuln.severity] ?? 'text-gray-400', 'font-mono shrink-0']">
                  [{{ vuln.severity }}]
                </span>
                <span class="text-slate-100 dark:text-sky-100">{{ vuln.title }}</span>
                <span v-if="vuln.port" class="ml-auto font-mono shrink-0 text-slate-400 dark:text-teal-300">
                  :{{ vuln.port }}
                </span>
              </li>
            </ul>
          </section>
        </div>

        <!-- Empty state -->
        <div v-else class="flex-1 flex items-center justify-center text-sm text-slate-400 dark:text-teal-300">
          Select a device to view details.
        </div>
      </aside>
    </Transition>
  </Teleport>
</template>
