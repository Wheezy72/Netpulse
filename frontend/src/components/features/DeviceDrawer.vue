<script setup lang="ts">
/**
 * Device Detail Drawer (slide-over Sheet).
 *
 * Opens from the right when a device row is clicked in the Devices table.
 * The main table remains interactive behind it – no page navigation.
 */
import { ref, watch } from "vue";
import axios from "axios";
import { resolveOui } from "../utils/oui";

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
        class="fixed inset-y-0 right-0 z-40 w-full max-w-lg flex flex-col border-l overflow-y-auto"
        :style="{
          background: 'var(--np-surface)',
          borderColor: 'var(--np-border)',
        }"
      >
        <!-- Header -->
        <div
          class="flex items-center justify-between px-6 py-4 border-b"
          :style="{ borderColor: 'var(--np-border)' }"
        >
          <h2 class="font-semibold text-sm" :style="{ color: 'var(--np-text)' }">
            Device Detail
          </h2>
          <button
            type="button"
            class="p-1.5 rounded hover:bg-white/10 transition-colors"
            :style="{ color: 'var(--np-muted-text)' }"
            @click="emit('close')"
          >
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <!-- Loading -->
        <div v-if="loading" class="flex-1 flex items-center justify-center text-sm" :style="{ color: 'var(--np-muted-text)' }">
          Loading…
        </div>

        <!-- Error -->
        <div v-else-if="error" class="px-6 py-4 text-red-400 text-sm">{{ error }}</div>

        <!-- Content -->
        <div v-else-if="detail" class="flex-1 px-6 py-4 space-y-6">

          <!-- Identity section -->
          <section>
            <h3 class="text-xs uppercase tracking-widest mb-3" :style="{ color: 'var(--np-muted-text)' }">Identity</h3>
            <dl class="space-y-2 text-sm">
              <div class="flex justify-between">
                <dt :style="{ color: 'var(--np-muted-text)' }">IP Address</dt>
                <dd class="font-mono" :style="{ color: 'var(--np-accent-primary)' }">{{ detail.device.ip_address }}</dd>
              </div>
              <div class="flex justify-between">
                <dt :style="{ color: 'var(--np-muted-text)' }">Hostname</dt>
                <dd :style="{ color: 'var(--np-text)' }">{{ detail.device.hostname || '—' }}</dd>
              </div>
              <div class="flex justify-between">
                <dt :style="{ color: 'var(--np-muted-text)' }">MAC Address</dt>
                <dd class="font-mono text-xs" :style="{ color: 'var(--np-text)' }">{{ detail.device.mac_address || '—' }}</dd>
              </div>
              <div class="flex justify-between">
                <dt :style="{ color: 'var(--np-muted-text)' }">Vendor (OUI)</dt>
                <dd :style="{ color: 'var(--np-text)' }">
                  {{ detail.device.mac_address ? (resolveOui(detail.device.mac_address) ?? 'Unknown') : '—' }}
                </dd>
              </div>
              <div class="flex justify-between">
                <dt :style="{ color: 'var(--np-muted-text)' }">Type</dt>
                <dd :style="{ color: 'var(--np-text)' }">{{ detail.device.device_type || detail.type_guess || '—' }}</dd>
              </div>
              <div class="flex justify-between">
                <dt :style="{ color: 'var(--np-muted-text)' }">Zone</dt>
                <dd :style="{ color: 'var(--np-text)' }">{{ detail.device.zone || '—' }}</dd>
              </div>
              <div class="flex justify-between">
                <dt :style="{ color: 'var(--np-muted-text)' }">Gateway</dt>
                <dd :style="{ color: detail.device.is_gateway ? 'var(--np-success)' : 'var(--np-muted-text)' }">
                  {{ detail.device.is_gateway ? 'Yes' : 'No' }}
                </dd>
              </div>
              <div class="flex justify-between">
                <dt :style="{ color: 'var(--np-muted-text)' }">Last Seen</dt>
                <dd :style="{ color: 'var(--np-text)' }">{{ detail.device.last_seen ?? '—' }}</dd>
              </div>
            </dl>
          </section>

          <!-- Vulnerabilities -->
          <section>
            <h3 class="text-xs uppercase tracking-widest mb-3" :style="{ color: 'var(--np-muted-text)' }">
              Vulnerabilities ({{ detail.vulnerabilities.length }})
            </h3>
            <div v-if="detail.vulnerabilities.length === 0" class="text-xs" :style="{ color: 'var(--np-muted-text)' }">
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
                <span :style="{ color: 'var(--np-text)' }">{{ vuln.title }}</span>
                <span v-if="vuln.port" class="ml-auto font-mono shrink-0" :style="{ color: 'var(--np-muted-text)' }">
                  :{{ vuln.port }}
                </span>
              </li>
            </ul>
          </section>
        </div>

        <!-- Empty state -->
        <div v-else class="flex-1 flex items-center justify-center text-sm" :style="{ color: 'var(--np-muted-text)' }">
          Select a device to view details.
        </div>
      </aside>
    </Transition>
  </Teleport>
</template>
