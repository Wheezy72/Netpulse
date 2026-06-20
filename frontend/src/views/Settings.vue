<script setup lang="ts">
import axios from "axios";
import { computed, onMounted, ref, watch } from "vue";
import ToggleSwitch from "../components/ui/ToggleSwitch.vue";

type Theme = "nightshade" | "sysadmin";
type InfoMode = "full" | "compact";

type SettingsTab = "general" | "notifications" | "network" | "schedule" | "threat" | "backup";

interface Props {
  theme: Theme;
  infoMode: InfoMode;
  isAdmin?: boolean;
}

interface NetworkSegment {
  id?: number;
  name: string;
  cidr: string;
  description: string | null;
  vlan_id: number | null;
  is_active: boolean;
  scan_enabled: boolean;
}

interface NotificationSettings {
  email_enabled: boolean;
  email_address: string;
  whatsapp_enabled: boolean;
  whatsapp_number: string;
  alert_on_critical: boolean;
  alert_on_warning: boolean;
  alert_on_device_down: boolean;
  daily_digest: boolean;
}

interface ThreatIntelSettings {
  abuseipdb_enabled: boolean;
  abuseipdb_api_key_configured: boolean;
  abuseipdb_max_age: number;
}

interface ScanScheduleSettings {
  enabled: boolean;
  frequency: string;
  time: string;
  scan_type: string;
  segments: number[];
  notify_on_complete: boolean;
}

interface BackupFile {
  filename: string;
  size: number;
  created_at: string;
}

interface RestoreResult {
  status: string;
  tables: Record<string, number>;
}

const props = defineProps<Props>();
const emit = defineEmits<{ (e: "update:infoMode", value: InfoMode): void }>();

const isNightshade = computed(() => props.theme === "nightshade");
const isAdmin = computed(() => !!props.isAdmin);

const activeSettingsTab = ref<SettingsTab>("general");

const localInfoMode = ref<InfoMode>(props.infoMode);
watch(
  () => props.infoMode,
  (val) => {
    localInfoMode.value = val;
  }
);
function setInfoMode(mode: InfoMode): void {
  localInfoMode.value = mode;
  emit("update:infoMode", mode);
}

// Network
const segments = ref<NetworkSegment[]>([]);
const segmentsLoading = ref(false);
const segmentsError = ref<string | null>(null);
const showAddSegment = ref(false);
const newSegment = ref<NetworkSegment>({
  name: "",
  cidr: "",
  description: null,
  vlan_id: null,
  is_active: true,
  scan_enabled: true,
});

async function loadNetworkSegments(): Promise<void> {
  segmentsLoading.value = true;
  segmentsError.value = null;
  try {
    const { data } = await axios.get<NetworkSegment[]>("/api/network-segments");
    segments.value = data;
  } catch {
    segmentsError.value = "Failed to load network segments.";
    segments.value = [];
  } finally {
    segmentsLoading.value = false;
  }
}

const isDetectingGateway = ref(false);

async function detectGateway(): Promise<void> {
  isDetectingGateway.value = true;
  segmentsError.value = null;
  try {
    const { data } = await axios.get<{ gateway_ip: string }>("/api/network-segments/detect-gateway");
    const ip = data.gateway_ip;
    if (ip) {
      const octets = ip.split(".");
      if (octets.length === 4) {
        newSegment.value.cidr = `${octets[0]}.${octets[1]}.${octets[2]}.0/24`;
        if (!newSegment.value.name) {
          newSegment.value.name = `Auto-Detected LAN`;
        }
        if (!newSegment.value.description) {
          newSegment.value.description = `Gateway IP: ${ip}`;
        }
      } else {
        newSegment.value.cidr = ip;
      }
    }
  } catch (e: any) {
    segmentsError.value = e.response?.data?.detail || "Failed to detect default gateway.";
  } finally {
    isDetectingGateway.value = false;
  }
}

async function addNetworkSegment(): Promise<void> {
  if (!isAdmin.value) return;
  if (!newSegment.value.name || !newSegment.value.cidr) return;
  try {
    await axios.post("/api/network-segments", newSegment.value);
    showAddSegment.value = false;
    newSegment.value = {
      name: "",
      cidr: "",
      description: null,
      vlan_id: null,
      is_active: true,
      scan_enabled: true,
    };
    await loadNetworkSegments();
  } catch (e: any) {
    segmentsError.value = e.response?.data?.detail || "Failed to add network segment.";
  }
}

async function toggleSegmentScan(segment: NetworkSegment): Promise<void> {
  if (!isAdmin.value) return;
  if (!segment.id) return;
  try {
    await axios.put(`/api/network-segments/${segment.id}`, {
      scan_enabled: !segment.scan_enabled,
    });
    await loadNetworkSegments();
  } catch (e: any) {
    segmentsError.value = e.response?.data?.detail || "Failed to update segment.";
  }
}

async function deleteSegment(segment: NetworkSegment): Promise<void> {
  if (!isAdmin.value) return;
  if (!segment.id) return;
  try {
    await axios.delete(`/api/network-segments/${segment.id}`);
    await loadNetworkSegments();
  } catch (e: any) {
    segmentsError.value = e.response?.data?.detail || "Failed to delete segment.";
  }
}

// Notifications
const notifications = ref<NotificationSettings>({
  email_enabled: false,
  email_address: "",
  whatsapp_enabled: false,
  whatsapp_number: "",
  alert_on_critical: true,
  alert_on_warning: false,
  alert_on_device_down: true,
  daily_digest: false,
});
const notificationsSaving = ref(false);
const notificationsMessage = ref<string | null>(null);

async function loadNotificationSettings(): Promise<void> {
  try {
    const { data } = await axios.get<NotificationSettings>("/api/settings/notifications");
    notifications.value = { ...notifications.value, ...data };
  } catch {
    // non-fatal
  }
}

async function saveNotificationSettings(): Promise<void> {
  notificationsSaving.value = true;
  notificationsMessage.value = null;
  try {
    await axios.put("/api/settings/notifications", notifications.value);
    notificationsMessage.value = "Notification settings saved.";
    setTimeout(() => (notificationsMessage.value = null), 3000);
  } catch {
    notificationsMessage.value = "Failed to save notification settings.";
  } finally {
    notificationsSaving.value = false;
  }
}


// Threat intel
const threatIntel = ref<ThreatIntelSettings>({
  abuseipdb_enabled: false,
  abuseipdb_api_key_configured: false,
  abuseipdb_max_age: 90,
});
const threatIntelSaving = ref(false);
const threatIntelMessage = ref<string | null>(null);

async function loadThreatIntelSettings(): Promise<void> {
  try {
    const { data } = await axios.get("/api/settings/threat-intel");
    threatIntel.value = {
      abuseipdb_enabled: data.abuseipdb_enabled ?? false,
      abuseipdb_api_key_configured: data.abuseipdb_api_key_configured ?? false,
      abuseipdb_max_age: data.abuseipdb_max_age ?? 90,
    };
  } catch {
    // non-fatal
  }
}

async function saveThreatIntelSettings(): Promise<void> {
  threatIntelSaving.value = true;
  threatIntelMessage.value = null;
  try {
    await axios.put("/api/settings/threat-intel", {
      abuseipdb_enabled: threatIntel.value.abuseipdb_enabled,
      abuseipdb_max_age: threatIntel.value.abuseipdb_max_age,
    });
    threatIntelMessage.value = "Threat intel settings saved.";
    setTimeout(() => (threatIntelMessage.value = null), 3000);
    await loadThreatIntelSettings();
  } catch {
    threatIntelMessage.value = "Failed to save threat intel settings.";
  } finally {
    threatIntelSaving.value = false;
  }
}

// Scheduler
const scanSchedule = ref<ScanScheduleSettings>({
  enabled: false,
  frequency: "daily",
  time: "02:00",
  scan_type: "quick",
  segments: [],
  notify_on_complete: true,
});
const scanScheduleSaving = ref(false);
const scanScheduleMessage = ref<string | null>(null);

const frequencyOptions = ref<{ value: string; label: string }[]>([
  { value: "hourly", label: "Hourly" },
  { value: "daily", label: "Daily" },
  { value: "weekly", label: "Weekly" },
  { value: "monthly", label: "Monthly" },
]);

const scanTypeOptions = ref<{ value: string; label: string }[]>([
  { value: "quick", label: "Quick Scan" },
  { value: "full", label: "Full Scan" },
  { value: "vuln", label: "Vulnerability Scan" },
  { value: "service", label: "Service Detection" },
]);

async function loadScanSchedule(): Promise<void> {
  try {
    const [scheduleRes, optionsRes] = await Promise.all([
      axios.get("/api/settings/scan-schedule"),
      axios.get("/api/settings/scan-schedule/options"),
    ]);
    scanSchedule.value = scheduleRes.data;
    frequencyOptions.value = optionsRes.data.frequencies ?? frequencyOptions.value;
    scanTypeOptions.value = optionsRes.data.scan_types ?? scanTypeOptions.value;
  } catch {
    // non-fatal
  }
}

async function saveScanSchedule(): Promise<void> {
  scanScheduleSaving.value = true;
  scanScheduleMessage.value = null;
  try {
    await axios.put("/api/settings/scan-schedule", scanSchedule.value);
    scanScheduleMessage.value = "Scan schedule saved.";
    setTimeout(() => (scanScheduleMessage.value = null), 3000);
  } catch {
    scanScheduleMessage.value = "Failed to save scan schedule.";
  } finally {
    scanScheduleSaving.value = false;
  }
}

// Backup
const backups = ref<BackupFile[]>([]);
const backupsLoading = ref(false);
const backupExporting = ref(false);
const backupMessage = ref<string | null>(null);
const backupRestoreFile = ref<File | null>(null);
const backupRestoring = ref(false);
const restoreResult = ref<RestoreResult | null>(null);

function formatFileSize(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

async function loadBackups(): Promise<void> {
  backupsLoading.value = true;
  try {
    const { data } = await axios.get<BackupFile[]>("/api/backup/list");
    backups.value = data;
  } catch {
    backups.value = [];
  } finally {
    backupsLoading.value = false;
  }
}

async function exportBackup(): Promise<void> {
  if (!isAdmin.value) return;
  backupExporting.value = true;
  backupMessage.value = null;
  try {
    const response = await axios.post("/api/backup/export", {}, { responseType: "blob" });
    const contentDisposition = response.headers["content-disposition"];
    let filename = "netpulse_backup.json";
    if (contentDisposition) {
      const match = contentDisposition.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/);
      if (match && match[1]) filename = match[1].replace(/['"]/g, "");
    }
    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", filename);
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
    backupMessage.value = "Backup exported.";
    setTimeout(() => (backupMessage.value = null), 3000);
    await loadBackups();
  } catch {
    backupMessage.value = "Failed to export backup.";
  } finally {
    backupExporting.value = false;
  }
}

async function downloadBackup(filename: string): Promise<void> {
  try {
    const response = await axios.get(`/api/backup/${filename}`, { responseType: "blob" });
    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", filename);
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  } catch {
    backupMessage.value = "Failed to download backup.";
  }
}

async function deleteBackup(filename: string): Promise<void> {
  if (!isAdmin.value) return;
  try {
    await axios.delete(`/api/backup/${filename}`);
    backupMessage.value = "Backup deleted.";
    setTimeout(() => (backupMessage.value = null), 3000);
    await loadBackups();
  } catch {
    backupMessage.value = "Failed to delete backup.";
  }
}

function onBackupFileChange(event: Event): void {
  const target = event.target as HTMLInputElement;
  if (target.files && target.files.length > 0) backupRestoreFile.value = target.files[0];
}

async function restoreBackup(): Promise<void> {
  if (!isAdmin.value) return;
  if (!backupRestoreFile.value) return;
  backupRestoring.value = true;
  backupMessage.value = null;
  restoreResult.value = null;
  try {
    const formData = new FormData();
    formData.append("file", backupRestoreFile.value);
    const { data } = await axios.post<RestoreResult>("/api/backup/restore", formData, {
      headers: { "Content-Type": "multipart/form-data" },
    });
    restoreResult.value = data;
    backupMessage.value = "Restore completed.";
    setTimeout(() => (backupMessage.value = null), 5000);
    backupRestoreFile.value = null;
    await loadBackups();
  } catch {
    backupMessage.value = "Failed to restore backup.";
  } finally {
    backupRestoring.value = false;
  }
}

onMounted(async () => {
  await Promise.all([
    loadNetworkSegments(),
    loadNotificationSettings(),
    loadThreatIntelSettings(),
    loadScanSchedule(),
  ]);
  if (isAdmin.value) await loadBackups();
});
</script>

<template>
  <div class="space-y-4 np-fade-in">
    <div class="flex gap-1 flex-wrap border-b pb-0 border-[var(--np-border-subtle)]">
      <button
        v-for="tab in [
          { key: 'general', label: 'General' },
          { key: 'notifications', label: 'Alerts' },
          { key: 'network', label: 'Network' },
          { key: 'schedule', label: 'Scheduler' },
          { key: 'threat', label: 'Threat Intel' },
          { key: 'backup', label: 'Backup' },
        ]"
        :key="tab.key"
        type="button"
        @click="activeSettingsTab = tab.key as any"
        class="flex items-center gap-1.5 px-3 py-2.5 text-xs transition-all duration-300 border-b-2 -mb-px np-subtab-btn"
        :class="{ 'active': activeSettingsTab === tab.key }"
      >
        {{ tab.label }}
      </button>
    </div>

    <div v-if="!isAdmin" class="rounded-xl border p-3.5 text-xs font-semibold bg-amber-500/5 border-amber-500/20 text-amber-500 flex items-center gap-2">
      <span>🔒</span>
      <span>You are signed in as an <span class="font-bold underline">Operator</span>. Destructive settings and actions are locked.</span>
    </div>

    <!-- General -->
    <section v-if="activeSettingsTab === 'general'" class="np-panel p-4 space-y-4">
      <header class="np-panel-header -mx-4 -mt-4 mb-2 px-4">
        <div class="flex flex-col">
          <span class="np-panel-title">Console Settings</span>
          <span class="text-[0.7rem] text-slate-400 dark:text-teal-300">View density and theme.</span>
        </div>
      </header>

      <div class="np-settings-section">
        <p class="np-settings-section-title">View Density</p>
        <div class="flex gap-2 flex-wrap">
          <button
            type="button"
            @click="setInfoMode('full')"
            class="rounded border px-4 py-2 text-[0.75rem] font-medium transition-all"
            :class="[
              localInfoMode === 'full'
                ? isNightshade
                  ? 'border-emerald-400/80 bg-emerald-500/25 text-emerald-300 ring-1 ring-emerald-400/50'
                  : 'border-amber-500 bg-amber-500/20 text-amber-300 ring-1 ring-amber-500/50'
                : isNightshade
                  ? 'border-teal-400/40 text-teal-200 hover:bg-teal-500/10'
                  : 'border-amber-600/40 text-amber-200/80 hover:bg-amber-600/10'
            ]"
          >
            Full Detail
          </button>
          <button
            type="button"
            @click="setInfoMode('compact')"
            class="rounded border px-4 py-2 text-[0.75rem] font-medium transition-all"
            :class="[
              localInfoMode === 'compact'
                ? isNightshade
                  ? 'border-emerald-400/80 bg-emerald-500/25 text-emerald-300 ring-1 ring-emerald-400/50'
                  : 'border-amber-500 bg-amber-500/20 text-amber-300 ring-1 ring-amber-500/50'
                : isNightshade
                  ? 'border-teal-400/40 text-teal-200 hover:bg-teal-500/10'
                  : 'border-amber-600/40 text-amber-200/80 hover:bg-amber-600/10'
            ]"
          >
            Quick View
          </button>
        </div>
      </div>

      <div class="np-settings-section">
        <p class="np-settings-section-title">Current Theme</p>
        <p class="text-[0.75rem]" :class="isNightshade ? 'text-teal-100/80' : 'text-slate-300'">
          {{ props.theme === 'nightshade' ? 'Nightshade' : 'SysAdmin' }}
        </p>
      </div>
    </section>

    <!-- Notifications -->
    <section v-else-if="activeSettingsTab === 'notifications'" class="np-panel p-4 space-y-6">
      <header class="np-panel-header -mx-4 -mt-4 mb-4 px-4">
        <div class="flex flex-col">
          <span class="np-panel-title text-sm uppercase tracking-wider font-bold">Alert &amp; Notification Routing</span>
          <span class="text-[0.7rem] text-[var(--np-text-dim)]">Configure notification routes and severity dispatch criteria.</span>
        </div>
      </header>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <!-- Dispatch Routes Card -->
        <div class="p-4 rounded-xl border border-[var(--np-border-subtle)] bg-[var(--np-surface-elevated)] space-y-4">
          <div class="flex flex-col gap-1 border-b border-[var(--np-border-subtle)] pb-2 mb-2">
            <h4 class="text-xs uppercase tracking-wider font-bold text-[var(--np-text)]">Alert Destinations</h4>
            <p class="text-[0.65rem] text-[var(--np-text-dim)]">Where alert dispatches will be routed.</p>
          </div>

          <div class="space-y-4">
            <!-- Email Option -->
            <div class="space-y-2">
              <div class="flex items-center justify-between">
                <div class="flex flex-col">
                  <span class="text-xs font-semibold text-[var(--np-text)]">Email Gateway</span>
                  <span class="text-[0.65rem] text-[var(--np-text-dim)]">Send email notification reports</span>
                </div>
                <ToggleSwitch v-model="notifications.email_enabled" :theme="theme" />
              </div>
              <input 
                v-if="notifications.email_enabled" 
                v-model="notifications.email_address" 
                class="np-neon-input w-full rounded-lg px-3 py-2 text-xs font-mono" 
                type="email" 
                placeholder="admin@example.com" 
              />
            </div>

            <!-- WhatsApp Option -->
            <div class="space-y-2">
              <div class="flex items-center justify-between">
                <div class="flex flex-col">
                  <span class="text-xs font-semibold text-[var(--np-text)]">WhatsApp Integration</span>
                  <span class="text-[0.65rem] text-[var(--np-text-dim)]">Send urgent chat messages via gateway</span>
                </div>
                <ToggleSwitch v-model="notifications.whatsapp_enabled" :theme="theme" />
              </div>
              <input 
                v-if="notifications.whatsapp_enabled" 
                v-model="notifications.whatsapp_number" 
                class="np-neon-input w-full rounded-lg px-3 py-2 text-xs font-mono" 
                type="tel" 
                placeholder="+1 555 123 4567" 
              />
            </div>
          </div>
        </div>

        <!-- Alert Policies Card -->
        <div class="p-4 rounded-xl border border-[var(--np-border-subtle)] bg-[var(--np-surface-elevated)] space-y-4">
          <div class="flex flex-col gap-1 border-b border-[var(--np-border-subtle)] pb-2 mb-2">
            <h4 class="text-xs uppercase tracking-wider font-bold text-[var(--np-text)]">Dispatch Policy</h4>
            <p class="text-[0.65rem] text-[var(--np-text-dim)]">Define when alerts should be fired.</p>
          </div>

          <div class="grid grid-cols-1 gap-4">
            <div class="flex items-center justify-between">
              <div class="flex flex-col">
                <span class="text-xs font-semibold text-[var(--np-text)]">Critical Vulnerability Alerts</span>
                <span class="text-[0.65rem] text-[var(--np-text-dim)]">Fire instantly on CVSS Score >= 9.0</span>
              </div>
              <ToggleSwitch v-model="notifications.alert_on_critical" :theme="theme" />
            </div>

            <div class="flex items-center justify-between">
              <div class="flex flex-col">
                <span class="text-xs font-semibold text-[var(--np-text)]">Warning Anomalies</span>
                <span class="text-[0.65rem] text-[var(--np-text-dim)]">Fire on minor warnings or state changes</span>
              </div>
              <ToggleSwitch v-model="notifications.alert_on_warning" :theme="theme" />
            </div>

            <div class="flex items-center justify-between">
              <div class="flex flex-col">
                <span class="text-xs font-semibold text-[var(--np-text)]">Host Offline Detection</span>
                <span class="text-[0.65rem] text-[var(--np-text-dim)]">Notify when an active host goes offline</span>
              </div>
              <ToggleSwitch v-model="notifications.alert_on_device_down" :theme="theme" />
            </div>

            <div class="flex items-center justify-between">
              <div class="flex flex-col">
                <span class="text-xs font-semibold text-[var(--np-text)]">Daily Console Digest</span>
                <span class="text-[0.65rem] text-[var(--np-text-dim)]">Send daily network metrics summary</span>
              </div>
              <ToggleSwitch v-model="notifications.daily_digest" :theme="theme" />
            </div>
          </div>
        </div>
      </div>

      <div class="flex items-center justify-between border-t border-[var(--np-border-subtle)] pt-4">
        <p v-if="notificationsMessage" class="text-[0.7rem] font-mono" :class="notificationsMessage.includes('Failed') ? 'text-rose-400' : 'text-emerald-400'">
          {{ notificationsMessage }}
        </p>
        <div v-else></div>
        <button type="button" class="np-cyber-btn rounded-xl px-5 py-2.5 text-xs font-bold uppercase tracking-wider" @click="saveNotificationSettings" :disabled="notificationsSaving">
          {{ notificationsSaving ? 'Saving...' : 'Save Settings Policy' }}
        </button>
      </div>
    </section>

    <!-- Network -->
    <section v-else-if="activeSettingsTab === 'network'" class="np-panel p-4 space-y-4">
      <header class="np-panel-header -mx-4 -mt-4 mb-2 px-4">
        <div class="flex flex-col">
          <span class="np-panel-title">Network Segments</span>
          <span class="text-[0.7rem] text-[var(--np-text-dim)] font-semibold">Subnets for scheduled scanning.</span>
        </div>
        <button v-if="isAdmin" type="button" class="np-cyber-btn rounded px-3 py-1.5 text-[0.75rem]" @click="showAddSegment = !showAddSegment">
          {{ showAddSegment ? 'Cancel' : '+ Add Segment' }}
        </button>
      </header>

      <div v-if="showAddSegment" class="np-settings-section space-y-3">
        <p class="np-settings-section-title">New segment</p>
        <div class="grid gap-3 md:grid-cols-2">
          <input v-model="newSegment.name" class="np-neon-input rounded px-3 py-2 text-[0.8rem]" placeholder="Name" />
          <div class="relative flex items-center">
            <input v-model="newSegment.cidr" class="np-neon-input rounded pl-3 pr-24 py-2 text-[0.8rem] font-mono w-full" placeholder="192.168.1.0/24" />
            <button
              type="button"
              class="absolute right-1 text-[0.65rem] px-2 py-1 rounded bg-[var(--np-surface-hover)] border border-[var(--np-border-subtle)] text-[var(--np-accent-primary)] hover:text-[var(--np-text)] transition-all font-semibold disabled:opacity-50"
              @click="detectGateway"
              :disabled="isDetectingGateway"
            >
              {{ isDetectingGateway ? 'Detecting...' : 'Auto-Detect' }}
            </button>
          </div>
          <input v-model.number="newSegment.vlan_id" class="np-neon-input rounded px-3 py-2 text-[0.8rem]" placeholder="VLAN (optional)" type="number" />
          <input v-model="newSegment.description" class="np-neon-input rounded px-3 py-2 text-[0.8rem]" placeholder="Description" />
        </div>
        <div class="flex justify-end">
          <button type="button" class="np-cyber-btn rounded px-4 py-2 text-[0.75rem]" @click="addNetworkSegment">Add Segment</button>
        </div>
      </div>

      <p v-if="segmentsLoading" class="text-[0.75rem] text-[var(--np-text-dim)] font-semibold">Loading...</p>
      <p v-else-if="segmentsError" class="text-[0.75rem] text-rose-400">{{ segmentsError }}</p>

      <div v-else class="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        <div
          v-for="seg in segments"
          :key="seg.id"
          class="np-info-card"
        >
          <div class="flex items-start justify-between gap-3">
            <div>
              <h4 class="np-info-card-title">{{ seg.name }}</h4>
              <p class="np-info-card-value mt-1">{{ seg.cidr }}</p>
              <p v-if="seg.vlan_id" class="np-info-card-text mt-1">VLAN {{ seg.vlan_id }}</p>
              <p v-if="seg.description" class="np-info-card-text mt-1">{{ seg.description }}</p>
            </div>

            <div class="flex flex-col gap-2 items-end">
              <button
                type="button"
                class="rounded px-2 py-1 text-[0.65rem] uppercase tracking-wide font-medium transition-all border animate-none"
                :disabled="!isAdmin"
                @click="toggleSegmentScan(seg)"
                :class="[
                  seg.scan_enabled
                    ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/35'
                    : 'bg-slate-500/10 text-slate-400 border-slate-500/30',
                  !isAdmin ? 'opacity-50 cursor-not-allowed' : ''
                ]"
              >
                {{ seg.scan_enabled ? 'Active' : 'Paused' }}
              </button>

              <button
                v-if="isAdmin"
                type="button"
                class="rounded px-2 py-1 text-[0.65rem] uppercase tracking-wide font-medium transition-all border border-red-500/40 text-red-500 hover:bg-red-600/20"
                @click="deleteSegment(seg)"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- Scheduler -->
    <section v-else-if="activeSettingsTab === 'schedule'" class="np-panel p-4 space-y-4">
      <header class="np-panel-header -mx-4 -mt-4 mb-2 px-4">
        <div class="flex flex-col">
          <span class="np-panel-title">Scan Scheduler</span>
          <span class="text-[0.7rem] text-[var(--np-text-dim)] font-semibold">Configure automatic scans.</span>
        </div>
      </header>

      <div class="np-settings-section space-y-3 text-xs">
        <div class="flex items-center justify-between">
          <span :class="isNightshade ? 'text-teal-100' : 'text-slate-300'">Enabled</span>
          <ToggleSwitch v-model="scanSchedule.enabled" :theme="theme" />
        </div>

        <div class="grid gap-3 md:grid-cols-2">
          <label class="flex flex-col gap-1">
            <span :class="isNightshade ? 'text-teal-200' : 'text-slate-300'">Frequency</span>
            <select v-model="scanSchedule.frequency" class="np-neon-input rounded px-3 py-2 text-[0.8rem]">
              <option v-for="f in frequencyOptions" :key="f.value" :value="f.value">{{ f.label }}</option>
            </select>
          </label>
          <label class="flex flex-col gap-1">
            <span :class="isNightshade ? 'text-teal-200' : 'text-slate-300'">Time (HH:MM)</span>
            <input v-model="scanSchedule.time" type="time" class="np-neon-input rounded px-3 py-2 text-[0.8rem]" />
          </label>
          <label class="flex flex-col gap-1 md:col-span-2">
            <span :class="isNightshade ? 'text-teal-200' : 'text-slate-300'">Scan Type</span>
            <select v-model="scanSchedule.scan_type" class="np-neon-input rounded px-3 py-2 text-[0.8rem]">
              <option v-for="t in scanTypeOptions" :key="t.value" :value="t.value">{{ t.label }}</option>
            </select>
          </label>
        </div>

        <div class="text-[0.75rem]" :class="isNightshade ? 'text-teal-100/70' : 'text-slate-300'">
          Target segments:
          <div class="mt-2 flex flex-wrap gap-2">
            <label v-for="seg in segments" :key="seg.id" class="flex items-center gap-2 rounded border px-2 py-1 text-[0.7rem]" :class="isNightshade ? 'border-teal-400/20' : 'border-amber-500/20'">
              <input type="checkbox" :value="seg.id" v-model="scanSchedule.segments" />
              <span class="font-mono">{{ seg.name }}</span>
            </label>
          </div>
        </div>

        <div class="flex items-center justify-between">
          <p v-if="scanScheduleMessage" class="text-[0.7rem]" :class="scanScheduleMessage.includes('Failed') ? 'text-rose-400' : (isNightshade ? 'text-emerald-400' : 'text-green-500')">
            {{ scanScheduleMessage }}
          </p>
          <button type="button" class="np-cyber-btn rounded px-4 py-2 text-[0.75rem]" @click="saveScanSchedule" :disabled="scanScheduleSaving">
            {{ scanScheduleSaving ? 'Saving...' : 'Save Schedule' }}
          </button>
        </div>
      </div>
    </section>

    <!-- Threat intel -->
    <section v-else-if="activeSettingsTab === 'threat'" class="np-panel p-4 space-y-4">
      <header class="np-panel-header -mx-4 -mt-4 mb-2 px-4">
        <div class="flex flex-col">
          <span class="np-panel-title">Threat Intelligence</span>
          <span class="text-[0.7rem] text-[var(--np-text-dim)] font-semibold">AbuseIPDB configuration.</span>
        </div>
      </header>

      <div class="np-settings-section space-y-3 text-xs">
        <div class="flex items-center justify-between">
          <span :class="isNightshade ? 'text-teal-100' : 'text-slate-700 font-bold'">Enable AbuseIPDB</span>
          <ToggleSwitch v-model="threatIntel.abuseipdb_enabled" :theme="theme" />
        </div>

        <label class="flex flex-col gap-1">
          <span :class="isNightshade ? 'text-teal-200' : 'text-slate-700 font-bold'">Max age (days)</span>
          <input v-model.number="threatIntel.abuseipdb_max_age" type="number" min="1" max="365" class="np-neon-input rounded px-3 py-2 text-[0.8rem]" />
        </label>

        <p class="text-[0.7rem] font-bold" :class="threatIntel.abuseipdb_api_key_configured ? 'text-emerald-400' : 'text-rose-400'">
          {{ threatIntel.abuseipdb_api_key_configured ? 'API key configured via environment.' : 'API key not configured.' }}
        </p>

        <div class="flex items-center justify-between">
          <p v-if="threatIntelMessage" class="text-[0.7rem]" :class="threatIntelMessage.includes('Failed') ? 'text-rose-400' : 'text-emerald-400'">
            {{ threatIntelMessage }}
          </p>
          <button type="button" class="np-cyber-btn rounded px-4 py-2 text-[0.75rem]" @click="saveThreatIntelSettings" :disabled="threatIntelSaving">
            {{ threatIntelSaving ? 'Saving...' : 'Save Threat Intel' }}
          </button>
        </div>
      </div>
    </section>

    <!-- Backup -->
    <section v-else-if="activeSettingsTab === 'backup'" class="np-panel p-4 space-y-4">
      <header class="np-panel-header -mx-4 -mt-4 mb-2 px-4">
        <div class="flex flex-col">
          <span class="np-panel-title">Backup</span>
          <span class="text-[0.7rem] text-[var(--np-text-dim)] font-semibold">Export / restore database snapshots.</span>
        </div>
      </header>

      <div v-if="!isAdmin" class="np-settings-section">
        <p class="text-[0.75rem] text-[var(--np-text-dim)] font-semibold">Backup export/restore is admin-only.</p>
      </div>

      <div v-else class="space-y-4">
        <div class="np-settings-section">
          <p class="np-settings-section-title">Export Database</p>
          <button type="button" class="np-cyber-btn rounded px-4 py-2 text-[0.75rem]" @click="exportBackup" :disabled="backupExporting">
            {{ backupExporting ? 'Exporting...' : 'Export Database' }}
          </button>
        </div>

        <div class="np-settings-section">
          <p class="np-settings-section-title">Available Backups</p>
          <p v-if="backupsLoading" class="text-[0.75rem] text-[var(--np-text-dim)] font-semibold">Loading...</p>
          <div v-else-if="backups.length === 0" class="text-[0.75rem] text-[var(--np-text-dim)] font-semibold">No backups found.</div>
          <div v-else class="space-y-2">
            <div v-for="b in backups" :key="b.filename" class="flex items-center justify-between np-info-card">
              <div class="min-w-0">
                <p class="font-mono text-[0.75rem] truncate np-info-card-value">{{ b.filename }}</p>
                <p class="text-[0.65rem] np-info-card-text mt-1">{{ formatFileSize(b.size) }} · {{ new Date(b.created_at).toLocaleString() }}</p>
              </div>
              <div class="flex gap-2">
                <button type="button" class="rounded px-2.5 py-1 text-[0.65rem] font-medium border border-[var(--np-border-subtle)] text-[var(--np-text)] hover:bg-[var(--np-surface-hover)]" @click="downloadBackup(b.filename)">Download</button>
                <button type="button" class="rounded px-2.5 py-1 text-[0.65rem] font-medium border border-rose-500/40 text-rose-500 hover:bg-rose-500/20" @click="deleteBackup(b.filename)">Delete</button>
              </div>
            </div>
          </div>
        </div>

        <div class="np-settings-section">
          <p class="np-settings-section-title">Restore from Backup</p>
          <p class="text-[0.7rem] font-bold text-rose-400">⚠ This will replace existing data in the restored tables.</p>
          <div class="flex items-center gap-3 flex-wrap mt-2">
            <input type="file" accept=".json" @change="onBackupFileChange" class="np-neon-input rounded px-3 py-2 text-[0.8rem]" />
            <button type="button" class="np-cyber-btn rounded px-4 py-2 text-[0.75rem]" @click="restoreBackup" :disabled="backupRestoring || !backupRestoreFile">
              {{ backupRestoring ? 'Restoring...' : 'Restore' }}
            </button>
          </div>

          <div v-if="restoreResult" class="mt-3 rounded border p-3 bg-emerald-500/10 border-emerald-500/35">
            <p class="text-[0.75rem] font-bold mb-2 text-emerald-400">Restore Complete</p>
            <div class="space-y-1">
              <div v-for="(count, table) in restoreResult.tables" :key="table" class="flex items-center justify-between text-[0.7rem]">
                <span class="text-[var(--np-text-dim)] font-semibold">{{ table }}</span>
                <span class="font-mono text-[var(--np-nav-active-text)] font-extrabold">{{ count }} records</span>
              </div>
            </div>
          </div>
        </div>

        <p v-if="backupMessage" class="text-[0.7rem]" :class="backupMessage.includes('Failed') ? 'text-rose-400' : 'text-emerald-400'">
          {{ backupMessage }}
        </p>
      </div>
    </section>
  </div>
</template>
