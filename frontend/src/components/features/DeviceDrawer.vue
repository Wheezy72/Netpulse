<script setup lang="ts">
/**
 * Device detail drawer (slide-over sheet).
 *
 * Opens when a row is clicked in the Devices table; the table stays interactive
 * behind it. Two layers of information, matching how the data is collected:
 *
 *   1. Identity + risk  — known from the discovery sweep and past scans.
 *   2. Services         — only filled in by an explicit per-device deep scan,
 *                         because the light sweep deliberately collects no ports.
 *
 * Every section renders its own empty state, so a device that was only just
 * discovered still reads as "not yet looked at" rather than as broken.
 */
import axios from "axios";
import { computed, nextTick, onBeforeUnmount, ref, watch } from "vue";
import { X } from "lucide-vue-next";

import { resolveOui } from "../../utils/oui";

type Theme = "nightshade" | "sysadmin";

interface DeviceIdentity {
  id: number;
  hostname?: string | null;
  ip_address: string;
  mac_address?: string | null;
  device_type?: string | null;
  os?: string | null;
  vendor?: string | null;
  is_gateway: boolean;
  zone?: string | null;
  last_seen?: string | null;
  created_at?: string | null;
}

interface Vulnerability {
  id: number;
  title: string;
  severity: string;
  port?: number | null;
  detected_at?: string | null;
}

interface ScannedPort {
  port: number;
  protocol: string;
  state?: string | null;
  service?: string | null;
  product?: string | null;
  version?: string | null;
  extra_info?: string | null;
}

interface ScanSummary {
  id: string;
  profile: string;
  target: string;
  status: string;
  created_at: string;
  completed_at?: string | null;
}

interface ScriptSummary {
  id: number;
  script_name: string;
  status: string;
  created_at: string;
}

interface MetricSummary {
  metric_type: string;
  timestamp: string;
  value: number;
}

interface DeviceDetail {
  device: DeviceIdentity;
  type_guess?: string | null;
  type_confidence?: number | null;
  vulnerability_counts: Record<string, number>;
  vulnerabilities: Vulnerability[];
  ports: ScannedPort[];
  scripts: ScriptSummary[];
  scans: ScanSummary[];
  metrics: MetricSummary[];
}

const props = defineProps<{
  deviceId: number | null;
  open: boolean;
  theme: Theme;
  isAdmin?: boolean;
}>();

const emit = defineEmits<{
  (e: "close"): void;
  (e: "updated", deviceId: number): void;
}>();

const detail = ref<DeviceDetail | null>(null);
const loading = ref(false);
const error = ref<string | null>(null);

const scanning = ref(false);
const scanNotice = ref<{ kind: "ok" | "warn" | "error"; text: string } | null>(null);

const closeButton = ref<HTMLButtonElement | null>(null);

/* ------------------------------------------------------------------ tokens */

// Severity colours come from the shared token set. VulnerabilitySeverity is
// lower_case on the wire, so normalise before lookup — the previous map keyed
// on capitalised names and therefore never matched anything.
const SEVERITY_COLORS: Record<string, string> = {
  critical: "var(--np-danger)",
  high: "var(--np-warning)",
  medium: "#eab308",
  low: "var(--np-text-dim)",
  info: "var(--np-text-dim)",
};

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

/* ------------------------------------------------------------- formatting */

function relativeTime(value?: string | null): string {
  if (!value) return "—";
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return "—";

  const seconds = Math.round((Date.now() - then) / 1000);
  const suffix = seconds >= 0 ? "ago" : "from now";
  const size = Math.abs(seconds);

  if (size < 45) return seconds >= 0 ? "just now" : "in a moment";
  if (size < 3600) return `${Math.round(size / 60)} min ${suffix}`;
  if (size < 86400) return `${Math.round(size / 3600)} h ${suffix}`;
  return `${Math.round(size / 86400)} d ${suffix}`;
}

function absoluteTime(value?: string | null): string {
  if (!value) return "No timestamp recorded";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "No timestamp recorded" : date.toLocaleString();
}

/** Render a stored MAC (canonical 12 hex chars) in the conventional form. */
function formatMac(value?: string | null): string {
  if (!value) return "—";
  const clean = value.replace(/[^0-9A-Fa-f]/g, "").toUpperCase();
  if (clean.length !== 12) return value;
  const pairs = clean.match(/.{2}/g);
  return pairs ? pairs.join(":") : value;
}

/** Coarse freshness of the last sighting, for the status dot. */
const freshness = computed<{ label: string; color: string }>(() => {
  const lastSeen = detail.value?.device.last_seen;
  if (!lastSeen) {
    return { label: "Never seen", color: "var(--np-text-dim)" };
  }
  const ageMinutes = (Date.now() - new Date(lastSeen).getTime()) / 60000;
  if (Number.isNaN(ageMinutes)) {
    return { label: "Never seen", color: "var(--np-text-dim)" };
  }
  if (ageMinutes < 5) return { label: "Seen recently", color: "var(--np-success)" };
  if (ageMinutes < 120) return { label: "Seen this session", color: "var(--np-warning)" };
  return { label: "Not seen recently", color: "var(--np-text-dim)" };
});

const deviceLabel = computed(() => {
  const device = detail.value?.device;
  if (!device) return "Device";
  return device.hostname || device.ip_address;
});

const typeLabel = computed(() => {
  const device = detail.value?.device;
  if (!device) return "—";
  if (device.is_gateway) return "Gateway";
  return device.device_type || detail.value?.type_guess || "Unclassified";
});

const typeConfidence = computed(() => {
  const confidence = detail.value?.type_confidence;
  if (confidence === null || confidence === undefined) return null;
  return Math.round(confidence * 100);
});

const vendorLabel = computed(() => {
  const device = detail.value?.device;
  if (!device) return "—";
  return device.vendor || (device.mac_address ? resolveOui(device.mac_address) : null) || "Unknown";
});

const severityRows = computed(() => {
  const counts = detail.value?.vulnerability_counts ?? {};
  return SEVERITY_ORDER.filter((sev) => counts[sev]).map((sev) => ({
    severity: sev,
    count: counts[sev],
    color: SEVERITY_COLORS[sev] ?? "var(--np-text-dim)",
  }));
});

const totalFindings = computed(() =>
  Object.values(detail.value?.vulnerability_counts ?? {}).reduce((sum, n) => sum + n, 0),
);

const openPortCount = computed(
  () => detail.value?.ports.filter((p) => p.state === "open" || p.state === "open|filtered").length ?? 0,
);

const scanned = computed(() => (detail.value?.ports.length ?? 0) > 0);

/* -------------------------------------------------------------------- data */

async function load(): Promise<void> {
  if (!props.deviceId) {
    detail.value = null;
    return;
  }
  loading.value = true;
  error.value = null;
  scanNotice.value = null;
  try {
    const { data } = await axios.get<DeviceDetail>(`/api/devices/${props.deviceId}/detail`);
    detail.value = data;
  } catch (e: any) {
    error.value = e?.response?.data?.detail || "Failed to load device detail.";
    detail.value = null;
  } finally {
    loading.value = false;
  }
}

async function runDeepScan(): Promise<void> {
  if (!props.deviceId || scanning.value) return;
  scanning.value = true;
  scanNotice.value = null;
  try {
    const { data } = await axios.post<{
      created: number;
      updated: number;
      removed: number;
      warnings: string[];
    }>(`/api/devices/${props.deviceId}/deep-scan`);

    if (data.warnings.length > 0) {
      scanNotice.value = { kind: "warn", text: data.warnings.join(" ") };
    } else {
      const parts = [`${data.created + data.updated} port(s) listening`];
      if (data.removed) parts.push(`${data.removed} no longer responding`);
      scanNotice.value = { kind: "ok", text: `Deep scan complete — ${parts.join(", ")}.` };
    }

    await load();
    emit("updated", props.deviceId);
  } catch (e: any) {
    scanNotice.value = {
      kind: "error",
      text: e?.response?.data?.detail || "Deep scan failed.",
    };
  } finally {
    scanning.value = false;
  }
}

function copyAddress(): void {
  const address = detail.value?.device.ip_address;
  if (address && navigator.clipboard) {
    void navigator.clipboard.writeText(address);
  }
}

/* ------------------------------------------------------------------ drawer */

function onKeydown(event: KeyboardEvent): void {
  if (event.key === "Escape" && props.open) emit("close");
}

// Reload when the target device changes *or* when the drawer is reopened:
// clicking the same row twice must not show a stale snapshot.
watch(
  [() => props.deviceId, () => props.open],
  ([, isOpen]) => {
    if (isOpen) void load();
  },
);

watch(
  () => props.open,
  async (isOpen) => {
    if (isOpen) {
      document.addEventListener("keydown", onKeydown);
      await nextTick();
      closeButton.value?.focus();
    } else {
      document.removeEventListener("keydown", onKeydown);
    }
  },
);

onBeforeUnmount(() => document.removeEventListener("keydown", onKeydown));
</script>

<template>
  <Teleport to="body">
    <!-- Backdrop -->
    <Transition name="np-fade">
      <div v-if="open" class="fixed inset-0 z-30 bg-[var(--np-surface-elevated)]" @click="emit('close')" />
    </Transition>

    <!-- Sheet -->
    <Transition name="np-slide-right">
      <aside
        v-if="open"
        class="fixed inset-y-0 right-0 z-40 flex w-full max-w-xl flex-col border-l"
        :style="{ background: 'var(--np-surface)', borderColor: 'var(--np-border)' }"
        role="dialog"
        aria-modal="true"
        :aria-label="`Details for ${deviceLabel}`"
      >
        <!-- Header -->
        <header
          class="flex items-start justify-between gap-4 border-b px-6 py-4"
          :style="{ borderColor: 'var(--np-border)' }"
        >
          <div class="min-w-0">
            <p
              class="text-[0.65rem] uppercase tracking-widest"
              :style="{ color: 'var(--np-text-dim)' }"
            >
              Device
            </p>
            <h2
              class="mt-0.5 truncate text-base font-semibold"
              :style="{ color: 'var(--np-text)' }"
            >
              {{ deviceLabel }}
            </h2>
          </div>
          <button
            ref="closeButton"
            type="button"
            class="rounded p-1.5 transition-colors hover:bg-[var(--np-surface-hover)] focus:outline-none focus-visible:ring-2"
            :style="{ color: 'var(--np-text-muted)' }"
            aria-label="Close device details"
            @click="emit('close')"
          >
            <X class="h-5 w-5" :stroke-width="1.7" />
          </button>
        </header>

        <!-- Loading -->
        <div v-if="loading" class="flex-1 space-y-3 px-6 py-5">
          <div class="np-skeleton h-20 rounded" />
          <div class="np-skeleton h-32 rounded" />
          <div class="np-skeleton h-24 rounded" />
        </div>

        <!-- Error -->
        <div v-else-if="error" class="flex-1 px-6 py-6">
          <div
            class="rounded border p-4"
            :style="{ borderColor: 'var(--np-danger)', color: 'var(--np-danger)' }"
          >
            <p class="text-sm">{{ error }}</p>
            <button
              type="button"
              class="np-cyber-btn mt-3 text-xs"
              :style="{ color: 'var(--np-danger)', borderColor: 'var(--np-danger)' }"
              @click="load"
            >
              Retry
            </button>
          </div>
        </div>

        <!-- Empty -->
        <div
          v-else-if="!detail"
          class="flex flex-1 items-center justify-center px-6 text-sm"
          :style="{ color: 'var(--np-text-muted)' }"
        >
          Select a device to see its details.
        </div>

        <!-- Content -->
        <div v-else class="flex-1 space-y-6 overflow-y-auto px-6 py-5">
          <!-- Identity summary -->
          <section
            class="rounded border p-4"
            :style="{ borderColor: 'var(--np-border)', background: 'var(--np-surface-elevated)' }"
          >
            <div class="flex flex-wrap items-center gap-x-3 gap-y-2">
              <span
                class="font-mono text-lg font-semibold"
                :style="{ color: 'var(--np-accent-primary)' }"
              >
                {{ detail.device.ip_address }}
              </span>
              <span class="sp-badge inline-flex items-center gap-1.5 text-[0.7rem]">
                <span
                  class="h-1.5 w-1.5 rounded-full"
                  :style="{ background: freshness.color }"
                  aria-hidden="true"
                />
                {{ freshness.label }}
              </span>
              <span v-if="detail.device.is_gateway" class="sp-badge text-[0.7rem]">Gateway</span>
              <span v-if="detail.device.zone" class="sp-badge text-[0.7rem]">
                {{ detail.device.zone }}
              </span>
            </div>

            <p class="mt-2 text-xs" :style="{ color: 'var(--np-text-muted)' }">
              {{ typeLabel }}
              <span v-if="typeConfidence" :style="{ color: 'var(--np-text-dim)' }">
                · {{ typeConfidence }}% confidence
              </span>
            </p>

            <div class="mt-4 flex flex-wrap gap-2">
              <button
                type="button"
                class="np-cyber-btn text-xs disabled:cursor-not-allowed disabled:opacity-40"
                :style="{ color: 'var(--np-accent-secondary)', borderColor: 'var(--np-accent-secondary)' }"
                :disabled="scanning || !isAdmin"
                :title="isAdmin ? 'Probe this host for listening services' : 'Admin access required to probe a host'"
                @click="runDeepScan"
              >
                {{ scanning ? "Scanning…" : scanned ? "Re-scan services" : "Deep scan services" }}
              </button>
              <button
                type="button"
                class="np-cyber-btn text-xs"
                :style="{ color: 'var(--np-text-muted)', borderColor: 'var(--np-border)' }"
                title="Copy IP address"
                @click="copyAddress"
              >
                Copy IP
              </button>
            </div>

            <p
              v-if="scanNotice"
              class="mt-3 text-xs"
              :style="{
                color:
                  scanNotice.kind === 'ok'
                    ? 'var(--np-success)'
                    : scanNotice.kind === 'warn'
                      ? 'var(--np-warning)'
                      : 'var(--np-danger)',
              }"
            >
              {{ scanNotice.text }}
            </p>
          </section>

          <!-- Facts -->
          <section>
            <h3
              class="mb-3 text-[0.65rem] uppercase tracking-widest"
              :style="{ color: 'var(--np-text-dim)' }"
            >
              Identity
            </h3>
            <dl class="grid grid-cols-1 gap-x-6 gap-y-2.5 text-sm sm:grid-cols-2">
              <div class="flex justify-between gap-3">
                <dt :style="{ color: 'var(--np-text-muted)' }">Hostname</dt>
                <dd class="truncate text-right" :style="{ color: 'var(--np-text)' }">
                  {{ detail.device.hostname || "—" }}
                </dd>
              </div>
              <div class="flex justify-between gap-3">
                <dt :style="{ color: 'var(--np-text-muted)' }">Vendor</dt>
                <dd class="truncate text-right" :style="{ color: 'var(--np-text)' }">
                  {{ vendorLabel }}
                </dd>
              </div>
              <div class="flex justify-between gap-3">
                <dt :style="{ color: 'var(--np-text-muted)' }">MAC</dt>
                <dd class="font-mono text-xs" :style="{ color: 'var(--np-text)' }">
                  {{ formatMac(detail.device.mac_address) }}
                </dd>
              </div>
              <div class="flex justify-between gap-3">
                <dt :style="{ color: 'var(--np-text-muted)' }">System</dt>
                <dd class="truncate text-right" :style="{ color: 'var(--np-text)' }">
                  {{ detail.device.os || "—" }}
                </dd>
              </div>
              <div class="flex justify-between gap-3">
                <dt :style="{ color: 'var(--np-text-muted)' }">First seen</dt>
                <dd :title="absoluteTime(detail.device.created_at)" :style="{ color: 'var(--np-text)' }">
                  {{ relativeTime(detail.device.created_at) }}
                </dd>
              </div>
              <div class="flex justify-between gap-3">
                <dt :style="{ color: 'var(--np-text-muted)' }">Last seen</dt>
                <dd :title="absoluteTime(detail.device.last_seen)" :style="{ color: 'var(--np-text)' }">
                  {{ relativeTime(detail.device.last_seen) }}
                </dd>
              </div>
            </dl>
          </section>

          <!-- Services -->
          <section>
            <div class="mb-3 flex items-baseline justify-between gap-3">
              <h3 class="text-[0.65rem] uppercase tracking-widest" :style="{ color: 'var(--np-text-dim)' }">
                Services
              </h3>
              <span v-if="scanned" class="text-[0.7rem]" :style="{ color: 'var(--np-text-muted)' }">
                {{ openPortCount }} listening
              </span>
            </div>

            <p v-if="!scanned" class="text-xs" :style="{ color: 'var(--np-text-muted)' }">
              No services recorded yet. Run a deep scan to find what this device is listening on.
            </p>

            <div
              v-else
              class="overflow-hidden rounded border"
              :style="{ borderColor: 'var(--np-border)' }"
            >
              <table class="w-full text-left text-xs">
                <thead :style="{ background: 'var(--np-thead-bg)' }">
                  <tr :style="{ color: 'var(--np-text-muted)' }">
                    <th class="px-3 py-2 font-medium">Port</th>
                    <th class="px-3 py-2 font-medium">Service</th>
                    <th class="px-3 py-2 font-medium">Version</th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="port in detail.ports"
                    :key="`${port.protocol}-${port.port}`"
                    class="border-t"
                    :style="{ borderColor: 'var(--np-border-subtle)' }"
                  >
                    <td class="px-3 py-2 font-mono" :style="{ color: 'var(--np-text)' }">
                      {{ port.port }}<span :style="{ color: 'var(--np-text-dim)' }">/{{ port.protocol }}</span>
                    </td>
                    <td class="px-3 py-2" :style="{ color: 'var(--np-text)' }">
                      {{ port.service || "unknown" }}
                    </td>
                    <td class="px-3 py-2" :style="{ color: 'var(--np-text-muted)' }">
                      {{ [port.product, port.version].filter(Boolean).join(" ") || "—" }}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          <!-- Findings -->
          <section>
            <div class="mb-3 flex items-baseline justify-between gap-3">
              <h3 class="text-[0.65rem] uppercase tracking-widest" :style="{ color: 'var(--np-text-dim)' }">
                Findings
              </h3>
              <span v-if="totalFindings" class="text-[0.7rem]" :style="{ color: 'var(--np-text-muted)' }">
                {{ totalFindings }} total
              </span>
            </div>

            <div v-if="severityRows.length" class="mb-3 flex flex-wrap gap-2">
              <span
                v-for="row in severityRows"
                :key="row.severity"
                class="rounded border px-2 py-0.5 font-mono text-[0.65rem] uppercase tracking-wide"
                :style="{ color: row.color, borderColor: row.color }"
              >
                {{ row.severity }} {{ row.count }}
              </span>
            </div>

            <p
              v-if="detail.vulnerabilities.length === 0"
              class="text-xs"
              :style="{ color: 'var(--np-text-muted)' }"
            >
              No findings recorded for this device.
            </p>
            <ul v-else class="space-y-2">
              <li
                v-for="vuln in detail.vulnerabilities"
                :key="vuln.id"
                class="flex items-start gap-2 text-xs"
              >
                <span
                  class="shrink-0 font-mono uppercase"
                  :style="{ color: SEVERITY_COLORS[String(vuln.severity).toLowerCase()] ?? 'var(--np-text-dim)' }"
                >
                  {{ vuln.severity }}
                </span>
                <span :style="{ color: 'var(--np-text)' }">{{ vuln.title }}</span>
                <span
                  v-if="vuln.port"
                  class="ml-auto shrink-0 font-mono"
                  :style="{ color: 'var(--np-text-muted)' }"
                >
                  :{{ vuln.port }}
                </span>
              </li>
            </ul>
          </section>

          <!-- Activity -->
          <section>
            <h3 class="mb-3 text-[0.65rem] uppercase tracking-widest" :style="{ color: 'var(--np-text-dim)' }">
              Activity
            </h3>

            <div v-if="detail.scans.length" class="mb-3 space-y-1.5">
              <p class="text-[0.7rem] uppercase tracking-wide" :style="{ color: 'var(--np-text-dim)' }">
                Scans against this address
              </p>
              <div
                v-for="scan in detail.scans"
                :key="scan.id"
                class="flex items-center justify-between gap-3 text-xs"
              >
                <span class="truncate" :style="{ color: 'var(--np-text)' }">{{ scan.profile }}</span>
                <span class="shrink-0 font-mono" :style="{ color: 'var(--np-text-muted)' }">
                  {{ scan.status }}
                </span>
                <span class="shrink-0" :title="absoluteTime(scan.created_at)" :style="{ color: 'var(--np-text-dim)' }">
                  {{ relativeTime(scan.created_at) }}
                </span>
              </div>
            </div>

            <div v-if="detail.scripts.length" class="mb-3 space-y-1.5">
              <p class="text-[0.7rem] uppercase tracking-wide" :style="{ color: 'var(--np-text-dim)' }">
                Automation runs
              </p>
              <div
                v-for="script in detail.scripts"
                :key="script.id"
                class="flex items-center justify-between gap-3 text-xs"
              >
                <span class="truncate" :style="{ color: 'var(--np-text)' }">{{ script.script_name }}</span>
                <span class="shrink-0 font-mono" :style="{ color: 'var(--np-text-muted)' }">
                  {{ script.status }}
                </span>
                <span class="shrink-0" :title="absoluteTime(script.created_at)" :style="{ color: 'var(--np-text-dim)' }">
                  {{ relativeTime(script.created_at) }}
                </span>
              </div>
            </div>

            <p
              v-if="!detail.scans.length && !detail.scripts.length"
              class="text-xs"
              :style="{ color: 'var(--np-text-muted)' }"
            >
              Nothing has been run against this device yet.
            </p>
          </section>

          <!-- Metrics -->
          <section v-if="detail.metrics.length">
            <h3 class="mb-3 text-[0.65rem] uppercase tracking-widest" :style="{ color: 'var(--np-text-dim)' }">
              Metrics
            </h3>
            <div
              v-for="metric in detail.metrics"
              :key="`${metric.metric_type}-${metric.timestamp}`"
              class="flex items-center justify-between gap-3 text-xs"
            >
              <span :style="{ color: 'var(--np-text)' }">{{ metric.metric_type }}</span>
              <span class="font-mono" :style="{ color: 'var(--np-text-muted)' }">
                {{ metric.value }}
              </span>
              <span class="shrink-0" :title="absoluteTime(metric.timestamp)" :style="{ color: 'var(--np-text-dim)' }">
                {{ relativeTime(metric.timestamp) }}
              </span>
            </div>
          </section>
        </div>
      </aside>
    </Transition>
  </Teleport>
</template>
